defmodule BeamAudit.RunStorageTest do
  use ExUnit.Case, async: false
  alias BeamAudit.{Run, RunStorage, Store}

  @complete "accounted_within_declared_policy"
  @partial "partial_or_unresolved"

  setup do
    base = Path.join(System.tmp_dir!(), "beam-audit-storage-test-" <> Store.nonce())
    File.mkdir_p!(base)
    on_exit(fn -> File.rm_rf!(base) end)
    %{base: base, out: Path.join(base, "runs")}
  end

  test "results root precedence and read-only empty inventory", ctx do
    names = ~w(BEAM_AUDIT_OUT XDG_STATE_HOME)
    environment = Map.new(names, &{&1, System.get_env(&1)})
    configured = Application.fetch_env(:beam_audit, :out)

    on_exit(fn ->
      Enum.each(environment, fn {name, value} ->
        if is_nil(value), do: System.delete_env(name), else: System.put_env(name, value)
      end)

      case configured do
        {:ok, value} -> Application.put_env(:beam_audit, :out, value)
        :error -> Application.delete_env(:beam_audit, :out)
      end
    end)

    System.delete_env("BEAM_AUDIT_OUT")
    Application.delete_env(:beam_audit, :out)
    state = Path.join(ctx.base, "state")
    System.put_env("XDG_STATE_HOME", state)
    assert RunStorage.root([]) == Path.join(state, "beam_audit/runs")

    for value <- ["", "relative-state"] do
      System.put_env("XDG_STATE_HOME", value)
      assert RunStorage.root([]) == Path.join(System.user_home!(), ".local/state/beam_audit/runs")
    end

    System.delete_env("XDG_STATE_HOME")
    assert RunStorage.root([]) == Path.join(System.user_home!(), ".local/state/beam_audit/runs")

    app_root = Path.join(ctx.base, "configured")
    env_root = Path.join(ctx.base, "environment")
    Application.put_env(:beam_audit, :out, app_root)
    assert RunStorage.root([]) == app_root
    System.put_env("BEAM_AUDIT_OUT", env_root)
    assert RunStorage.root([]) == env_root
    assert RunStorage.root(out: ctx.out) == ctx.out

    assert {:ok, %{root: root, runs: [], total_bytes: 0}} = BeamAudit.list_runs(out: ctx.out)
    assert root == ctx.out
    refute File.exists?(ctx.out)
    assert {:error, _} = BeamAudit.list_runs(out: "")
  end

  test "inventory and explicit deletion do not follow symlinks or select unknown directories",
       ctx do
    run = fixture_run(ctx.out, 10, @partial)
    id = Path.basename(run)
    outside = Path.join(ctx.base, "outside")
    File.mkdir_p!(outside)
    sentinel = Path.join(outside, "sentinel")
    File.write!(sentinel, String.duplicate("x", 10_000))
    File.ln_s!(outside, Path.join(run, "outside-link"))
    linked_id = "123-" <> Store.nonce()
    File.ln_s!(outside, Path.join(ctx.out, linked_id))
    unknown = Path.join(ctx.out, "unrelated")
    File.mkdir_p!(unknown)
    File.write!(Path.join(unknown, "keep"), "keep me")

    expected =
      ~w(manifest.json summary.json payload)
      |> Enum.map(fn name -> File.stat!(Path.join(run, name)).size end)
      |> Enum.sum()

    assert {:ok, listing} = BeamAudit.list_runs(out: ctx.out)
    assert listing.ignored_entries == ["unrelated"]
    assert listing.total_bytes == expected
    assert row = Enum.find(listing.runs, &(&1.id == id))
    assert row.recognized and row.size_complete and not row.locked
    assert row.bytes == expected and row.status == @partial
    assert link = Enum.find(listing.runs, &(&1.id == linked_id))
    refute link.recognized
    assert link.bytes == 0

    for invalid <- [run, "../outside", "unrelated", linked_id] do
      assert {:error, _} = BeamAudit.delete_run(invalid, out: ctx.out, confirm: true)
    end

    assert {:ok, preview} = BeamAudit.delete_run(id, out: ctx.out)
    assert preview.dry_run and preview.deleted == []
    assert preview.selected_bytes == expected
    assert Enum.map(preview.selected, & &1.id) == [id]
    assert File.dir?(run)

    assert {:ok, applied} = BeamAudit.delete_run(id, out: ctx.out, confirm: true)
    refute applied.dry_run
    assert applied.deleted == [id]
    refute File.exists?(run)
    assert File.read!(sentinel) == String.duplicate("x", 10_000)
    assert File.read!(Path.join(unknown, "keep")) == "keep me"
    assert {:ok, %{type: :symlink}} = File.lstat(Path.join(ctx.out, linked_id))
    assert {:error, _} = BeamAudit.delete_run(id, out: ctx.out, confirm: true)
  end

  test "prune combines age and count, protects partial runs, and skips guards", ctx do
    newest = fixture_run(ctx.out, 1, @complete)
    recent = fixture_run(ctx.out, 2, @partial)
    middle = fixture_run(ctx.out, 40, @complete)
    old = fixture_run(ctx.out, 60, @complete)
    partial = fixture_run(ctx.out, 70, @partial)
    unreported = fixture_run(ctx.out, 80, nil)
    locked = fixture_run(ctx.out, 90, @complete)
    guard = RunStorage.guard_path(locked)
    File.mkdir!(guard)

    for invalid <- [[], [keep: -1], [older_than: 0], [confirm: "yes", keep: 1]] do
      assert {:error, _} = BeamAudit.prune_runs([out: ctx.out] ++ invalid)
    end

    assert {:ok, preview} = BeamAudit.prune_runs(out: ctx.out, older_than: 30, keep: 1)
    assert preview.dry_run
    assert Enum.map(preview.selected, & &1.path) == [old, middle]
    reasons = Map.new(preview.skipped, &{&1.id, &1.reason})
    assert reasons[Path.basename(newest)] == "keep_newest"
    assert reasons[Path.basename(recent)] == "not_old_enough"
    assert reasons[Path.basename(partial)] == "partial_or_unreported"
    assert reasons[Path.basename(unreported)] == "partial_or_unreported"
    assert reasons[Path.basename(locked)] == "busy_or_stale_guard"
    assert File.dir?(old)

    assert {:ok, applied} =
             BeamAudit.prune_runs(out: ctx.out, older_than: 30, keep: 3, confirm: true)

    assert applied.deleted == [Path.basename(old)]
    assert applied.errors == []
    refute File.exists?(old)
    assert Enum.all?([newest, recent, middle, partial, unreported, locked], &File.dir?/1)

    assert {:ok, applied} =
             BeamAudit.prune_runs(
               out: ctx.out,
               older_than: 30,
               keep: 3,
               include_partial: true,
               confirm: true
             )

    assert applied.deleted == Enum.map([unreported, partial], &Path.basename/1)
    refute File.exists?(partial)
    refute File.exists?(unreported)
    assert Enum.all?([newest, recent, middle, locked], &File.dir?/1)
    assert File.dir?(guard)
    assert {:error, _} = BeamAudit.delete_run(Path.basename(locked), out: ctx.out, confirm: true)
    File.rmdir!(guard)
  end

  test "unsupported or malformed run records cannot be removed by lifecycle commands", ctx do
    old = fixture_run(ctx.out, 10, @complete)
    manifest_path = Path.join(old, "manifest.json")
    manifest = Store.read(manifest_path)
    Store.write(manifest_path, Map.put(manifest, "schema", Run.schema() - 1))

    malformed = fixture_run(ctx.out, 20, @complete)
    File.write!(Path.join(malformed, "manifest.json"), "not json")

    assert {:ok, listing} = BeamAudit.list_runs(out: ctx.out)
    assert length(listing.runs) == 2
    refute Enum.any?(listing.runs, & &1.recognized)

    assert {:ok, result} =
             BeamAudit.prune_runs(out: ctx.out, keep: 0, include_partial: true, confirm: true)

    assert result.deleted == [] and result.selected == []
    assert {:error, _} = BeamAudit.delete_run(Path.basename(old), out: ctx.out, confirm: true)
    assert {:error, "Unsupported run format"} = BeamAudit.report(old)
    assert File.dir?(old) and File.dir?(malformed)
  end

  test "public run operations coordinate with cleanup and resume without provider calls", ctx do
    target = Path.join(ctx.base, "target")
    File.mkdir_p!(Path.join(target, "lib"))

    File.write!(
      Path.join(target, "lib/fixture.ex"),
      "defmodule Fixture do\n  def value, do: :ok\nend\n"
    )

    git!(target, ["init", "-q"])
    git!(target, ["add", "--all"])

    git!(target, [
      "-c",
      "user.name=BeamAudit Test",
      "-c",
      "user.email=test@example.invalid",
      "-c",
      "commit.gpgsign=false",
      "-c",
      "core.hooksPath=/dev/null",
      "commit",
      "-qm",
      "fixture"
    ])

    owner = self()

    assert {:ok, summary} =
             BeamAudit.discover(target,
               out: ctx.out,
               profile: "source",
               on_progress: fn
                 %{stage: :discovery, run: run} ->
                   send(owner, {:during_discovery, BeamAudit.list_runs(out: ctx.out)})

                   send(
                     owner,
                     {:delete_during_discovery,
                      BeamAudit.delete_run(Path.basename(run), out: ctx.out, confirm: true)}
                   )

                 _ ->
                   :ok
               end
             )

    run = summary.path
    id = summary.id
    assert_receive {:during_discovery, {:ok, %{runs: [%{id: ^id, locked: true}]}}}
    assert_receive {:delete_during_discovery, {:error, _}}
    refute File.exists?(RunStorage.guard_path(run))
    assert Run.resolve_run(id, out: ctx.out) == run
    assert {:ok, _} = BeamAudit.report(id, out: ctx.out)

    task =
      Task.async(fn ->
        RunStorage.with_guard(run, fn ->
          send(owner, :guard_held)

          receive do
            :release_guard -> :ok
          end
        end)
      end)

    try do
      assert_receive :guard_held, 1_000
      assert {:error, reason} = BeamAudit.resume(id, out: ctx.out, max_calls: 0)
      assert reason =~ "busy or has a stale guard"
      assert {:error, _} = BeamAudit.report(run)
      assert {:error, _} = BeamAudit.compare(run, run)
      assert {:error, _} = BeamAudit.delete_run(id, out: ctx.out, confirm: true)

      assert {:ok, %{deleted: [], selected: []}} =
               BeamAudit.prune_runs(out: ctx.out, keep: 0, include_partial: true, confirm: true)
    after
      send(task.pid, :release_guard)
    end

    assert :ok = Task.await(task)
    refute File.exists?(RunStorage.guard_path(run))

    assert_raise RuntimeError, "fixture failure", fn ->
      RunStorage.with_guard(run, fn -> raise "fixture failure" end)
    end

    refute File.exists?(RunStorage.guard_path(run))
    assert {:ok, resumed} = BeamAudit.resume(id, out: ctx.out, max_calls: 0)
    assert resumed.id == id and Run.call_count(run) == 0
    assert {:ok, _} = BeamAudit.compare(id, id, out: ctx.out)
    refute File.exists?(RunStorage.guard_path(run))

    # A missing summary is not a completed run, even if a report still exists.
    File.rm!(Path.join(run, "summary.json"))
    assert File.regular?(summary.report)
    assert {:ok, %{runs: [%{status: "unreported"}]}} = BeamAudit.list_runs(out: ctx.out)
    assert {:ok, %{selected: []}} = BeamAudit.prune_runs(out: ctx.out, keep: 0)
    assert {:ok, regenerated} = BeamAudit.report(run)

    # A current run interrupted before writing its dependency result is
    # incomplete, even if the intended profile was source-only.
    dependency = Path.join([run, "r001", "dependencies.json"])
    dependency_bytes = File.read!(dependency)
    File.rm!(dependency)
    assert {:ok, interrupted} = BeamAudit.report(run)
    assert interrupted.coverage_gaps == regenerated.coverage_gaps + 1
    File.write!(dependency, dependency_bytes)
    assert {:ok, _} = BeamAudit.report(run)

    assert {:ok, %{deleted: [^id]}} = BeamAudit.delete_run(id, out: ctx.out, confirm: true)
    refute File.exists?(run)
  end

  # Metadata-only fixtures exercise selection and deletion without scanners.
  defp fixture_run(out, age_days, status) do
    date = DateTime.add(DateTime.utc_now(), -age_days * 86_400, :second)
    id = "#{DateTime.to_unix(date)}-#{Store.nonce()}"
    run = Path.join(out, id)
    File.mkdir_p!(run)

    Store.write(Path.join(run, "manifest.json"), %{
      "schema" => Run.schema(),
      "id" => id,
      "created_at" => DateTime.to_iso8601(date),
      "repositories" => [%{"name" => "fixture"}],
      "settings" => %{},
      "rules_sha256" => "fixture",
      "prompts_sha256" => %{}
    })

    if status do
      Store.write(Path.join(run, "summary.json"), %{
        "id" => id,
        "status" => status,
        "pending" => if(status == @complete, do: 0, else: 1),
        "unresolved" => 0,
        "coverage_gaps" => 0
      })
    end

    File.write!(Path.join(run, "payload"), "fixture\n")
    run
  end

  defp git!(root, args) do
    {output, status} = System.cmd("git", ["-C", root | args], stderr_to_stdout: true)
    assert status == 0, output
    output
  end
end
