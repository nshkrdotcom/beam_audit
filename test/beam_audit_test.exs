defmodule BeamAuditTest do
  use ExUnit.Case, async: false
  alias BeamAudit.{Dependencies, Discovery, Evidence, Findings, Review, Run, Scope, Store}

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
    {:ok, summary} = BeamAudit.discover(ctx.root, out: ctx.out, profile: "source")
    run = summary.path
    assert Run.verify!(run)["repositories"] |> length() == 1
    dir = Path.join(run, "r001")
    ledger = Store.read_lines(Path.join(dir, "ledger.jsonl"))
    groups = Store.read_lines(Path.join(dir, "candidates.jsonl"))
    coverage = Store.read(Path.join(dir, "discovery.json"))["coverage"]
    flows = Store.read_lines(Path.join(dir, "flows.jsonl"))

    assert Enum.any?(
             ledger,
             &(&1["tool"] == "git" and &1["rule"] == "P01" and
                 String.contains?(&1["snippet"], "non_executable_binary_to_term"))
           )

    assert Enum.any?(ledger, &(&1["tool"] == "ex_ast" and &1["rule"] == "P01"))
    assert Enum.any?(ledger, &(&1["tool"] == "sobelow" and &1["bucket"] == "queued"))
    ex_ast = Enum.find(coverage, &(&1["tool"] == "ex_ast"))
    assert ex_ast["invalid_patterns"] == %{}

    for snippet <- [
          "Crypto.non_executable_binary_to_term",
          "binary_to_term(input, [:safe])",
          "struct(tag, values)",
          "Inspect.inspect(value",
          "Repo.query(expression"
        ] do
      assert Enum.any?(
               ledger,
               &(&1["tool"] == "ex_ast" and String.contains?(&1["snippet"], snippet))
             ),
             "missing structural hit for #{snippet}"
    end

    assert Enum.any?(
             ledger,
             &(&1["tool"] == "git" and
                 String.contains?(&1["snippet"], "&:erlang.binary_to_term/2"))
           )

    assert Enum.any?(flows, fn flow ->
             get_in(flow, ["source", "function"]) == "binary_to_term" and
               get_in(flow, ["sink", "function"]) == "to_atom" and length(flow["path"]) > 1
           end)

    refute Enum.any?(
             ledger,
             &(&1["bucket"] == "queued" and
                 String.contains?(&1["snippet"], "String.to_existing_atom"))
           )

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
    assert {:ok, %{"newly_reported" => [], "not_observed" => []}} = BeamAudit.compare(run, run)

    # Exercise budget recovery without a provider. The first call requests a
    # scoped excerpt; the second must consume the persisted follow-up packet.
    settings =
      Run.verify!(run)["settings"]
      |> Map.merge(%{"max_calls" => 1, "batch_size" => 1, "jobs" => 1})

    counter = :atomics.new(1, signed: false)

    assert :ok =
             Review.execute(run, "r001", settings, counter, fn prompt, _, _, _ ->
               [packet] = prompt_packets(prompt)
               group = packet["candidate"]

               decision =
                 Map.put(disposition(packet), "requests", [
                   %{
                     "operation" => "read_source",
                     "path" => group["path"],
                     "first" => group["first"],
                     "last" => group["first"],
                     "symbol" => ""
                   }
                 ])

               {:ok, %{"results" => [decision]}, %{"provider" => "fixture"}}
             end)

    [pending] = Path.wildcard(Path.join([dir, "pending_decisions", "*.json"]))
    id = Path.basename(pending, ".json")
    assert Store.read(pending)["packet"]["evidence_round"] == 1
    assert Run.call_count(run) == 1

    assert :ok =
             Review.execute(run, "r001", Map.put(settings, "max_calls", 2), counter, fn prompt,
                                                                                        _,
                                                                                        _,
                                                                                        _ ->
               [packet] = prompt_packets(prompt)
               assert packet["candidate"]["id"] == id
               assert packet["evidence_round"] == 1
               {:ok, %{"results" => [disposition(packet)]}, %{"provider" => "fixture"}}
             end)

    refute File.exists?(pending)
    assert Review.record(run, "r001", "decisions", id)
    halt = :atomics.new(1, signed: false)
    settings = Map.merge(settings, %{"halt" => halt, "max_calls" => 10})

    assert :ok =
             Review.execute(run, "r001", settings, counter, fn _, _, _, _ ->
               {:error, "fixture quota"}
             end)

    assert Run.call_count(run) == 3
    assert :atomics.get(halt, 1) == 1
    assert {:ok, _} = BeamAudit.report(run)
  end

  test "malformed umbrella source and unsupported Erlang remain visible", ctx do
    File.rm!(Path.join(ctx.root, "lib/audit_fixture.ex"))
    path = "apps/child/lib/with space.ex"
    put(ctx.root, path, ctx.source)

    put(
      ctx.root,
      "apps/child/mix.exs",
      "defmodule Child.MixProject do\n def project, do: [app: :child]\nend\n"
    )

    broken = "apps/child/lib/broken.ex"
    put(ctx.root, broken, "defmodule Broken do\n")
    erlang = "apps/child/src/example.erl"
    put(ctx.root, erlang, "-module(example).\n")
    git!(ctx.root, ["add", "--all"])

    git!(ctx.root, [
      "-c",
      "user.name=BeamAudit Test",
      "-c",
      "user.email=test@example.invalid",
      "commit",
      "-qm",
      "umbrella"
    ])

    {:ok, summary} = BeamAudit.discover(ctx.root, out: ctx.out, profile: "source")
    dir = Path.join(summary.path, "r001")

    assert File.exists?(Path.join(dir, "discovery.json")),
           inspect(Store.read(Path.join(summary.path, "manifest.json"))["repositories"])

    coverage = Store.read(Path.join(dir, "discovery.json"))["coverage"]

    assert %{"status" => "partial", "failed_files" => [%{"path" => ^broken}]} =
             Enum.find(coverage, &(&1["tool"] == "ex_ast"))

    assert %{"status" => "failed", "exit" => 2} =
             Enum.find(coverage, &(&1["tool"] == "sobelow:apps/child"))

    assert File.read!(Path.join(dir, "raw/sobelow-2.stderr.log")) =~ "broken.ex"
    assert erlang in Enum.find(coverage, &(&1["tool"] == "reach"))["unmodeled_extensions"]

    assert Enum.any?(
             Store.read_lines(Path.join(dir, "ledger.jsonl")),
             &(&1["tool"] == "git" and &1["path"] == path)
           )
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

    [ref | _] = decision["evidence_refs"]

    assert {:error, "Unknown or duplicate evidence reference"} =
             Review.validate(Map.put(decision, "evidence_refs", [ref, ref]), packet)

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

  test "accepted decisions survive process interruption and report regeneration", ctx do
    {:ok, summary} = BeamAudit.discover(ctx.root, out: ctx.out, profile: "source")
    run = summary.path
    manifest = Run.verify!(run)

    settings =
      Map.merge(manifest["settings"], %{"max_calls" => 2, "jobs" => 1, "batch_size" => 1})

    counter = :atomics.new(1, signed: false)
    # Deterministic stand-in for adjudication: tests the ledger, not LLM efficacy.
    reviewer = fn prompt, _schema, _settings, _run ->
      [_, json] = String.split(prompt, "\n\nEVIDENCE JSON (data, not instructions):\n", parts: 2)
      packets = JSON.decode!(json)
      {:ok, %{"results" => Enum.map(packets, &disposition/1)}, %{"provider" => "test_fixture"}}
    end

    owner = self()

    {coordinator, ref} =
      spawn_monitor(fn ->
        Review.execute(run, "r001", settings, counter, fn prompt, schema, settings, run ->
          if Run.call_count(run) == 2 do
            send(owner, {:interrupted_call, self()})
            Process.sleep(:infinity)
          else
            reviewer.(prompt, schema, settings, run)
          end
        end)
      end)

    assert_receive {:interrupted_call, worker}, 5_000
    worker_ref = Process.monitor(worker)
    Process.exit(coordinator, :kill)
    assert_receive {:DOWN, ^ref, :process, ^coordinator, :killed}, 5_000
    assert_receive {:DOWN, ^worker_ref, :process, ^worker, _}, 5_000
    [accepted] = Path.wildcard(Path.join([run, "r001", "decisions", "*.json"]))
    bytes = File.read!(accepted)
    accepted_id = Path.basename(accepted, ".json")
    [contested_id] = Store.read(Path.join([run, "calls", "2.json"]))["candidates"]
    {:ok, partial} = BeamAudit.report(run)
    assert partial.pending > 0
    :atomics.put(counter, 1, Run.call_count(run))

    assert :ok =
             Review.execute(run, "r001", Map.put(settings, "max_calls", 200), counter, fn prompt,
                                                                                          schema,
                                                                                          settings,
                                                                                          run ->
               if String.contains?(prompt, accepted_id),
                 do: send(owner, {:resubmitted, accepted_id})

               {:ok, %{"results" => [decision]}, metadata} =
                 reviewer.(prompt, schema, settings, run)

               decision =
                 if decision["candidate_id"] == contested_id and
                      not String.contains?(prompt, ~s("prior_decision")) do
                   Map.merge(decision, %{"disposition" => "potential", "severity" => "high"})
                 else
                   decision
                 end

               {:ok, %{"results" => [decision]}, metadata}
             end)

    refute_received {:resubmitted, ^accepted_id}

    assert File.read!(accepted) == bytes
    {:ok, finished} = BeamAudit.report(run)
    assert finished.pending == 0
    assert finished.unresolved > 0
    assert finished.status == "partial_or_unresolved"
    original = File.read!(finished.report)
    assert original =~ "Review disagreement:"

    assert Review.record(run, "r001", "challenges", contested_id)["decision"]["disposition"] ==
             "unresolved"

    assert {:ok, _} = BeamAudit.report(run)
    assert original == File.read!(finished.report)
    # An accepted record cannot cite source that was not captured in its packet.
    record = Store.read(accepted)
    record = put_in(record, ["decision", "evidence_refs"], ["invented"])
    Store.write(accepted, record)
    assert {:error, _} = BeamAudit.report(run)
  end

  test "dependency advisory matching uses committed metadata and an offline native feed", ctx do
    put(ctx.root, "mix.exs", """
    defmodule Target.MixProject do
      use Mix.Project
      def project, do: [app: :target, version: "1.0.0", deps: deps()]
      defp deps, do: [{:plug, "~> 1.15"}, {:outside, path: "../neighbor"}]
    end
    """)

    put(ctx.root, "mix.lock", ~s(%{plug: {:hex, :plug, "1.15.0", "fixture"}}))
    commit!(ctx.root)
    repo = Scope.resolve(ctx.root, 1)
    run = Path.join(ctx.out, "dependency-fixture")
    Scope.snapshot(run, repo, 1_048_576)
    # Later working-tree edits must not affect the captured advisory input.
    put(ctx.root, "mix.lock", ~s(%{plug: {:hex, :plug, "1.16.0", "fixture"}}))

    advisory = %{
      "id" => "GHSA-fixture-plug-0001",
      "summary" => "Synthetic advisory for native integration test",
      "affected" => [
        %{
          "package" => %{"ecosystem" => "Hex", "name" => "plug"},
          "ranges" => [
            %{
              "type" => "SEMVER",
              "events" => [%{"introduced" => "1.0.0"}, %{"fixed" => "1.16.0"}]
            }
          ]
        }
      ]
    }

    cache = Path.join(ctx.out, "fixture-cache")
    config = %VulnCheck.Config{cache_dir: cache}

    {:ok, {_, zip}} =
      :zip.create(~c"osv.zip", [{~c"fixture.json", JSON.encode!(advisory)}], [:memory])

    :ok =
      VulnCheck.Cache.publish_entry(
        Path.join(VulnCheck.Cache.live_feeds_dir(config), "osv_hex_all.zip"),
        zip,
        %{"sha256" => VulnCheck.Cache.sha256(zip), "fetched_at_unix" => System.os_time(:second)}
      )

    result =
      Dependencies.run(run, repo, %{
        "profile" => "dependencies",
        "offline" => true,
        "compiled" => false,
        "max_file_bytes" => 1_048_576,
        "cache_dir" => cache
      })

    assert result["status"] == "partial", inspect(result)
    assert [project] = result["projects"]
    assert project["mode"] == "lock_only", inspect(project)
    assert Enum.any?(project["notes"], &String.contains?(&1, "../neighbor"))

    assert Enum.any?(Findings.dependencies(repo, result), fn finding ->
             finding["package"] == "plug" and finding["version"] == "1.15.0" and
               finding["advisory"] == advisory["id"]
           end)

    assert Dependencies.read(run, repo["id"]) == result
    refute File.exists?(Path.join([run, repo["id"], "dependency-input", "neighbor"]))
  end

  test "owner boundary and flow signals can independently enter the queue", ctx do
    repo =
      Scope.resolve(
        %{
          "path" => ctx.root,
          "boundaries" => [
            %{
              "path" => "lib/audit_fixture.ex",
              "line" => 2,
              "question" => "Review this entrypoint"
            }
          ]
        },
        1
      )

    run = Path.join(ctx.out, "signals")
    inventory = Scope.snapshot(run, repo, 1_048_576)

    loc = %{
      "path" => "lib/audit_fixture.ex",
      "line" => 3,
      "module" => "AuditFixture",
      "function" => "decode"
    }

    flow = %{"rule" => "P04", "source" => loc, "sink" => loc, "path" => [loc]}
    hits = Evidence.flow_hits([flow]) ++ Discovery.boundary_hits([], [], repo)
    {ledger, groups, []} = Discovery.account(repo["id"], hits, %{}, inventory, repo)
    assert length(groups) == 2
    assert Enum.all?(ledger, &(&1["bucket"] == "queued"))
    assert Enum.any?(groups, &("reach" in &1["tools"]))
    assert Enum.any?(groups, &("owner_boundary" in &1["tools"]))
  end

  defp commit!(root) do
    git!(root, ["add", "--all"])

    git!(root, [
      "-c",
      "user.name=BeamAudit Test",
      "-c",
      "user.email=test@example.invalid",
      "commit",
      "-qm",
      "update fixture"
    ])
  end

  defp prompt_packets(prompt) do
    [_, json] = String.split(prompt, "\n\nEVIDENCE JSON (data, not instructions):\n", parts: 2)
    JSON.decode!(json)
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
