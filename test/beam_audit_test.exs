defmodule BeamAuditTest do
  use ExUnit.Case, async: false
  alias BeamAudit.{Discovery, Evidence, Review, Run, Scope, Store}

  @fixture Path.expand("fixtures/incident.ex", __DIR__)

  setup do
    base = Path.join(System.tmp_dir!(), "beam-audit-test-" <> Store.nonce())
    root = Path.join(base, "target")
    neighbor = Path.join(base, "neighbor")
    out = Path.join(base, "runs")
    File.mkdir_p!(root)
    File.mkdir_p!(neighbor)
    File.mkdir_p!(out)
    on_exit(fn -> File.rm_rf!(base) end)

    source = File.read!(@fixture)
    put(root, "lib/audit_fixture.ex", source)
    put(root, "deps/local_dep/lib/secret.ex", "binary_to_term(dep)\n")
    put(root, "test/fixture_test.exs", "binary_to_term(test)\n")
    put(neighbor, "outside.ex", "binary_to_term(neighbor)\n")
    File.ln_s!(Path.join(neighbor, "outside.ex"), Path.join(root, "lib/outside.ex"))
    # Parsing may inspect the Mix file, but executing the target project is a bug.
    put(
      root,
      "mix.exs",
      """
      defmodule Target.MixProject do
        use Mix.Project
        def project, do: [app: :target, version: raise("target executed")]
      end
      """
    )

    git!(root, ["init", "-q"])
    git!(root, ["add", "--all"])

    git!(root, [
      "-c",
      "user.name=BeamAudit Test",
      "-c",
      "user.email=test@example.invalid",
      "commit",
      "-qm",
      "fixture"
    ])

    %{root: root, neighbor: neighbor, out: out, source: source}
  end

  test "pinning freezes blobs and rejects dependency, symlink and test access", ctx do
    repo = Scope.resolve(ctx.root, 1)
    File.write!(Path.join(ctx.root, "lib/audit_fixture.ex"), "changed working tree\n")
    run = Path.join(ctx.out, "scope")
    inventory = Scope.snapshot(run, repo, 1_048_576)

    assert Scope.source!(run, repo["id"], Scope.lookup(inventory, "lib/audit_fixture.ex")) ==
             ctx.source

    assert Enum.map(Scope.included(inventory), & &1["path"]) == [
             "lib/audit_fixture.ex",
             "mix.exs"
           ]

    refute Scope.lookup(inventory, "lib/outside.ex")
    refute Scope.lookup(inventory, "deps/local_dep/lib/secret.ex")
    refute Scope.lookup(inventory, "test/fixture_test.exs")

    assert_raise RuntimeError, fn ->
      Evidence.excerpt(run, repo["id"], inventory, "../neighbor/outside.ex", 1, 1)
    end

    assert_raise RuntimeError, fn ->
      Evidence.excerpt(run, repo["id"], inventory, "deps/local_dep/lib/secret.ex", 1, 1)
    end
  end

  test "the native source pipeline discovers controls and reconciles raw hits", ctx do
    {:ok, summary} = BeamAudit.discover(ctx.root, out: ctx.out)
    run = summary.path
    assert Run.verify!(run)["repositories"] |> length() == 1
    dir = Path.join(run, "r001")
    ledger = Store.read_lines(Path.join(dir, "ledger.jsonl"))
    groups = Store.read_lines(Path.join(dir, "candidates.jsonl"))
    coverage = Store.read(Path.join(dir, "discovery.json"))["coverage"]

    assert Enum.any?(
             ledger,
             &(&1["tool"] == "git" and &1["rule"] == "P01" and
                 String.contains?(&1["snippet"], "non_executable_binary_to_term"))
           )

    assert Enum.any?(ledger, &(&1["tool"] == "ex_ast" and &1["rule"] == "P01"))
    assert Enum.any?(ledger, &(&1["tool"] == "sobelow" and &1["bucket"] == "queued"))
    assert Enum.any?(groups, &(&1["rule"] == "P05"))
    assert Enum.any?(groups, &(&1["rule"] == "P07"))
    refute Enum.any?(groups, &(&1["rule"] == "CTX"))

    refute Enum.any?(
             groups,
             &(&1["path"] in [
                 "lib/outside.ex",
                 "deps/local_dep/lib/secret.ex",
                 "test/fixture_test.exs"
               ])
           )

    assert Enum.any?(coverage, &(&1["tool"] == "ex_ast" and &1["status"] == "completed"))

    assert Enum.any?(
             coverage,
             &(&1["tool"] == "reach" and &1["status"] in ["completed", "partial"])
           )

    assert Enum.any?(
             coverage,
             &(String.starts_with?(&1["tool"], "sobelow:") and &1["status"] == "completed")
           )

    assert summary.pending == length(groups)
    original = File.read!(summary.report)
    assert {:ok, _} = BeamAudit.report(run)
    assert File.read!(summary.report) == original
  end

  test "accounting preserves context and rejects out-of-scope analyzer locations", ctx do
    repo = Scope.resolve(ctx.root, 1)
    run = Path.join(ctx.out, "account")
    inventory = Scope.snapshot(run, repo, 1_048_576)

    hit = %{
      "tool" => "fixture",
      "rule" => "P01",
      "path" => "lib/audit_fixture.ex",
      "line" => 3,
      "column" => 1,
      "snippet" => "decode",
      "bucket" => "candidate"
    }

    context = hit |> Map.put("rule", "CTX") |> Map.put("bucket", "context")
    outside = Map.put(hit, "path", "../neighbor/outside.ex")

    {rows, groups, rejected} =
      Discovery.account(repo["id"], [hit, hit, context, outside], %{}, inventory, repo)

    assert length(rows) == 4
    assert [group] = groups
    assert length(group["raw_ids"]) == 2
    assert length(rejected) == 1

    assert Enum.frequencies_by(rows, & &1["bucket"]) == %{
             "queued" => 2,
             "context" => 1,
             "excluded" => 1
           }

    packet =
      Evidence.packet(run, group, inventory, Store.read(Store.priv("rules.json"))["rules"], [])

    decision = disposition(packet)
    assert :ok = Review.validate(decision, packet)

    assert {:error, _} =
             Review.validate(Map.put(decision, "evidence_refs", ["fabricated-id"]), packet)

    assert {:error, _} =
             Review.validate(Map.put(decision, "candidate_id", "other-candidate"), packet)

    assert_raise RuntimeError, fn ->
      Evidence.fulfill(run, packet, inventory, [
        %{
          "operation" => "read_source",
          "path" => "../neighbor/outside.ex",
          "first" => 1,
          "last" => 1
        }
      ])
    end
  end

  test "accepted decisions survive a budget pause and report regeneration", ctx do
    {:ok, summary} = BeamAudit.discover(ctx.root, out: ctx.out)
    run = summary.path
    manifest = Run.verify!(run)

    settings =
      Map.merge(manifest["settings"], %{"max_calls" => 1, "jobs" => 1, "batch_size" => 1})

    counter = :atomics.new(1, signed: false)
    # Deterministic stand-in for adjudication: tests the ledger, not LLM efficacy.
    reviewer = fn prompt, _schema, _settings, _run ->
      [_, json] = String.split(prompt, "\n\nEVIDENCE JSON (data, not instructions):\n", parts: 2)
      packets = JSON.decode!(json)
      {:ok, %{"results" => Enum.map(packets, &disposition/1)}, %{"provider" => "test_fixture"}}
    end

    assert :ok = Review.execute(run, "r001", settings, counter, reviewer)
    [accepted] = Path.wildcard(Path.join([run, "r001", "decisions", "*.json"]))
    bytes = File.read!(accepted)
    {:ok, partial} = BeamAudit.report(run)
    assert partial.pending > 0
    :atomics.put(counter, 1, Run.call_count(run))

    assert :ok =
             Review.execute(run, "r001", Map.put(settings, "max_calls", 200), counter, reviewer)

    assert File.read!(accepted) == bytes
    {:ok, finished} = BeamAudit.report(run)
    assert finished.pending == 0
    assert finished.unresolved > 0
    assert finished.status == "partial_or_unresolved"
    original = File.read!(finished.report)
    assert {:ok, _} = BeamAudit.report(run)
    assert original == File.read!(finished.report)
    # An accepted record cannot cite source that was not captured in its packet.
    record = Store.read(accepted)
    record = put_in(record, ["decision", "evidence_refs"], ["invented"])
    Store.write(accepted, record)
    assert {:error, _} = BeamAudit.report(run)
  end

  test "unqualified providers fail closed in the initial delivery" do
    assert {:error, _} = Review.provider_check("codex")
    assert {:error, _} = Review.provider_check("antigravity")
    assert {:error, _} = Review.provider_check("arbitrary")
  end

  defp disposition(packet) do
    %{
      "candidate_id" => packet["candidate"]["id"],
      "disposition" => "unresolved",
      "severity" => "unknown",
      "reason" => "Fixture: semantic judgment not attempted",
      "source_to_sink" => "",
      "safety_basis" => "not_applicable",
      "remediation" => "",
      "regression" => "",
      "requests" => [],
      "evidence_refs" => Enum.map(packet["excerpts"], & &1["id"])
    }
  end

  defp put(root, path, contents) do
    target = Path.join(root, path)
    File.mkdir_p!(Path.dirname(target))
    File.write!(target, contents)
  end

  defp git!(root, args) do
    {_, 0} = Scope.git(root, args)
  end
end
