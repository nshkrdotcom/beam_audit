defmodule BeamAudit.Dependencies do
  @moduledoc """
  Pinned dependency inventory and native VulnCheck advisory/reachability reports.

  The default scan reads committed metadata only. Optional existing compiled
  artifacts are copied as data, never built or loaded into the target runtime.
  Advisory matches remain visible regardless of their reachability verdict.
  """
  alias BeamAudit.{Scope, Store}

  @manifests ~w(mix.exs rebar.config gleam.toml)
  @locks ~w(mix.lock rebar.lock manifest.toml)
  @artifact_limit 512 * 1024 * 1024
  @artifact_count 20_000

  @doc false
  def run(run, repo, settings) do
    dir = Path.join(run, repo["id"])

    result =
      case Store.safe(fn -> scan(run, repo, settings) end) do
        {:ok, result} -> result
        {:error, reason} -> %{"status" => "failed", "reason" => reason, "projects" => []}
      end

    path = Path.join(dir, "dependencies.json")
    Store.write(path, result)
    Store.atomic(Path.join(dir, "dependencies.sha256"), Store.digest(File.read!(path)))
    result
  end

  defp scan(_run, _repo, %{"profile" => "source"}),
    do: %{"status" => "not_requested", "projects" => []}

  defp scan(run, repo, settings) do
    {:ok, _} = Application.ensure_all_started(:vulncheck)
    inventory = Scope.inventory(run, repo["id"])
    dir = Path.join([run, repo["id"], "dependency-input"])
    File.mkdir_p!(dir)
    inputs = capture(run, repo, inventory, dir, settings["max_file_bytes"])
    roots = project_roots(inputs)
    artifacts = if settings["compiled"], do: capture_artifacts(repo, dir, roots), else: nil

    projects =
      Enum.map(roots, fn root ->
        case Store.safe(fn -> scan_project(dir, root, inputs, settings, artifacts) end) do
          {:ok, project} -> project
          {:error, reason} -> %{"path" => root, "status" => "failed", "reason" => reason}
        end
      end)

    status =
      cond do
        Enum.any?(inputs, &(&1["status"] == "unavailable")) -> "partial"
        roots == [] -> "not_applicable"
        Enum.any?(projects, &(&1["status"] != "completed")) -> "partial"
        artifacts && (artifacts["truncated"] or artifacts["files"] == []) -> "partial"
        true -> "completed"
      end

    %{
      "status" => status,
      "tool" => "vulncheck",
      "version" => VulnCheck.version(),
      "inputs" => inputs,
      "artifacts" => artifacts,
      "projects" => projects,
      "scope" =>
        "Resolved dependencies at captured revision; downstream consumer ranges and external path dependencies are not audited."
    }
  end

  # Metadata is kept separate from source, so it cannot pollute Git grep or source
  # review. Only already inventoried regular Git blobs are read.
  defp capture(run, repo, inventory, dir, max_bytes) do
    inventory
    |> Enum.filter(fn entry ->
      name = Path.basename(entry["path"])

      metadata =
        name in (@manifests ++ @locks) or String.ends_with?(name, ".app.src") or
          ("config" in Path.split(entry["path"]) and Path.extname(name) == ".exs")

      metadata and
        (entry["status"] == "included" or
           entry["reason"] in ~w(non_source_extension source_size_limit unsupported_source_encoding))
    end)
    |> Enum.map(fn entry ->
      path = entry["path"]
      record = Map.take(entry, ~w(path oid bytes))

      result =
        Store.safe(fn ->
          if entry["bytes"] > max_bytes or
               entry["reason"] in ~w(source_size_limit unsupported_source_encoding),
             do: raise("Metadata exceeds capture limits or is not valid source")

          bytes =
            if entry["status"] == "included" do
              Scope.source!(run, repo["id"], entry)
            else
              case Scope.git(repo["root"], ["cat-file", "blob", entry["oid"]]) do
                {bytes, 0} -> bytes
                {_, code} -> raise("Git metadata read failed (#{code})")
              end
            end

          unless byte_size(bytes) == entry["bytes"] and String.valid?(bytes) and
                   :binary.match(bytes, <<0>>) == :nomatch,
                 do: raise("Invalid metadata bytes")

          Store.atomic(Path.join(dir, path), bytes)
          Store.digest(bytes)
        end)

      case result do
        {:ok, hash} -> Map.merge(record, %{"status" => "captured", "sha256" => hash})
        {:error, reason} -> Map.merge(record, %{"status" => "unavailable", "reason" => reason})
      end
    end)
  end

  @doc false
  def project_roots(inputs) do
    paths = MapSet.new(inputs, & &1["path"])

    inputs
    |> Enum.filter(&(Path.basename(&1["path"]) in (@manifests ++ @locks)))
    |> Enum.map(&Path.dirname(&1["path"]))
    |> Enum.uniq()
    |> Enum.sort_by(&{length(Path.split(&1)), &1})
    |> Enum.reduce([], fn root, roots ->
      # A nested manifest with its own lock is an independent workspace. An
      # umbrella child without one belongs to its enclosing workspace.
      locked = Enum.any?(@locks, &MapSet.member?(paths, rel(root, &1)))

      parent =
        Enum.any?(roots, fn parent ->
          # Conventional umbrella layout only; nonstandard children remain
          # visible as separate workspaces instead of silently disappearing.
          prefix = rel(parent, "apps") <> "/"

          String.starts_with?(root, prefix) and
            length(Path.split(String.replace_prefix(root, prefix, ""))) == 1 and
            MapSet.member?(paths, rel(parent, "mix.lock"))
        end)

      if locked or not parent, do: roots ++ [root], else: roots
    end)
  end

  defp rel(".", name), do: name
  defp rel(root, name), do: Path.join(root, name)

  defp scan_project(dir, root, inputs, settings, artifacts) do
    project_dir = Path.expand(root, dir)

    config = %VulnCheck.Config{
      project_dir: project_dir,
      env: :prod,
      offline: settings["offline"],
      cache_dir: settings["cache_dir"],
      show_unreachable: true,
      fail_on: :none
    }

    declarations = declarations(dir, inputs, root)
    locked = Enum.any?(@locks, &File.regular?(Path.join(project_dir, &1)))

    if locked do
      scan_locked(dir, root, inputs, config, artifacts, declarations)
    else
      %{
        "path" => root,
        "status" => "partial",
        "mode" => "unlocked",
        "declarations" => declarations,
        "packages" => [],
        "reason" =>
          "No committed supported lockfile; declared requirements are not resolved versions."
      }
    end
  end

  defp scan_locked(dir, root, inputs, config, artifacts, declarations) do
    project_dir = config.project_dir
    # VulnCheck's Mix workspace reader follows path-dependency manifests and
    # apps_path. External paths must not silently introduce unpinned inputs.
    # Use its existing lock parser, feed matcher and solver in those cases.
    unsafe = external_mix_paths(dir, inputs, root)

    {report, mode, notes} =
      if File.regular?(Path.join(project_dir, "mix.lock")) and
           (unsafe != [] or not File.regular?(Path.join(project_dir, "mix.exs"))) do
        unsafe = if unsafe == [], do: ["No captured Mix manifest"], else: unsafe
        {lock_only(config, unsafe), "lock_only", unsafe}
      else
        case VulnCheck.scan(config, ignore: false) do
          {:ok, report} ->
            {report, if(artifacts, do: "selected_artifacts", else: "metadata_only"), []}

          {:error, reason} ->
            raise("VulnCheck: #{inspect(reason, limit: 20, printable_limit: 1000)}")
        end
      end

    # Use the upstream reporter instead of serializing private graph structs.
    native = report |> VulnCheck.Report.JSON.render(config) |> JSON.decode!()

    packages =
      report.workspace.packages
      |> Map.values()
      |> Enum.sort_by(& &1.name)
      |> Enum.map(fn package ->
        %{
          "name" => package.name,
          "version" => package.version,
          "source" => to_string(package.source),
          "scope" => to_string(package.scope),
          "dependencies" => package.deps,
          "hex_name" => package.hex_name,
          "git_ref" => package.git_ref,
          "lock_line" => package.lock_line
        }
      end)

    feed = native["feed"] || %{}

    feed_gaps =
      feed == %{} or feed["status"] == "stale" or
        (feed["rejected_records"] || 0) > 0 or not is_nil(feed["refresh_error"])

    warnings = native["warnings"] || []
    # Missing BEAMs are expected in metadata-only mode; they do not invalidate
    # the version match. Other native warnings remain visible and may limit it.
    advisory_warnings =
      if artifacts, do: warnings, else: Enum.reject(warnings, &expected_artifact_warning?/1)

    status =
      if notes != [] or feed_gaps or advisory_warnings != [], do: "partial", else: "completed"

    %{
      "path" => root,
      "status" => status,
      "mode" => mode,
      "notes" => notes,
      "declarations" => declarations,
      "packages" => packages,
      "native" => native,
      "reachability_limit" =>
        if(artifacts && mode == "selected_artifacts",
          do: "Selected existing BEAMs; build-to-commit correspondence is not proven.",
          else: "No matching compiled artifact evidence; advisory matching is still useful."
        ),
      "runtime_limit" =>
        "Native OTP version reflects the scanner host unless configured upstream; deployed runtime is not established."
    }
  end

  @doc false
  def external_mix_paths(dir, inputs, _root) do
    inputs
    |> Enum.filter(fn input ->
      Path.basename(input["path"]) == "mix.exs"
    end)
    |> Enum.flat_map(fn input ->
      file = Path.join(dir, input["path"])

      case VulnCheck.Workspace.MixProject.parse_file(file) do
        {:ok, project} ->
          paths = [project.apps_path | Enum.map(project.deps, & &1.path)]

          paths
          |> Enum.filter(&is_binary/1)
          |> Enum.reject(fn path ->
            resolved = Path.expand(path, Path.dirname(file))

            Path.type(path) == :relative and inside?(dir, resolved) and
              File.dir?(resolved)
          end)
          |> Enum.map(&"#{input["path"]}: unavailable or external workspace path #{&1}")

        {:error, reason} ->
          ["#{input["path"]}: #{inspect(reason)}"]
      end
    end)
  end

  defp expected_artifact_warning?(warning) do
    Enum.any?(
      ["no compiled build for", "no compiled .app file for"],
      &String.starts_with?(String.downcase(warning), &1)
    )
  end

  defp declarations(dir, inputs, root) do
    inputs
    |> Enum.filter(fn input ->
      Path.basename(input["path"]) == "mix.exs" and
        (root == "." or String.starts_with?(input["path"], root <> "/"))
    end)
    |> Enum.map(fn input ->
      case VulnCheck.Workspace.MixProject.parse_file(Path.join(dir, input["path"])) do
        {:ok, project} ->
          %{
            "path" => input["path"],
            "parsed" => project.deps_parsed,
            "dependencies" =>
              Enum.map(project.deps, fn dep ->
                %{
                  "name" => dep.name,
                  "requirement" => dep.requirement,
                  "path" => dep.path,
                  "runtime" => dep.runtime,
                  "only" => if(dep.only == :all, do: "all", else: dep.only),
                  "optional" => dep.optional,
                  "in_umbrella" => dep.in_umbrella,
                  "git" => dep.git
                }
              end)
          }

        {:error, reason} ->
          %{"path" => input["path"], "parsed" => false, "reason" => inspect(reason)}
      end
    end)
  end

  defp inside?(root, path), do: path == root or String.starts_with?(path, root <> "/")

  defp lock_only(config, notes) do
    alias VulnCheck.Types.{ScanReport, Summary, Workspace}
    lock = Path.join(config.project_dir, "mix.lock")
    {:ok, packages, warnings} = VulnCheck.Workspace.MixLock.parse_file_with_warnings(lock)

    workspace = %Workspace{
      root_dir: config.project_dir,
      project_name: Path.basename(config.project_dir),
      project_type: :mix,
      env: :prod,
      otp_release: System.otp_release(),
      elixir_version: System.version(),
      lockfile: lock,
      packages: packages,
      direct_deps_known: false,
      warnings: notes ++ warnings
    }

    {:ok, feed} = VulnCheck.Feeds.Store.load(workspace, config)
    findings = VulnCheck.Solver.solve(workspace, nil, nil, feed.advisories, config)

    %ScanReport{
      workspace: workspace,
      generated_at: Store.now(),
      tool_version: VulnCheck.version(),
      findings: findings,
      all_findings: findings,
      summary: Summary.from_findings(findings),
      warnings: notes ++ warnings ++ feed.warnings,
      stats: feed.stats,
      duration_ms: 0
    }
  end

  # Only opt-in, existing regular BEAM/application files, under the selected
  # repository's usual build layouts. No symlink traversal or build invocation.
  defp capture_artifacts(repo, dir, roots) do
    root = repo["root"]

    patterns =
      for project <- roots,
          pattern <- [
            "_build/*/lib/*/ebin/*",
            "_build/*/lib/*/consolidated/*",
            "build/*/erlang/*/ebin/*"
          ],
          do: Path.join([root, project, pattern])

    paths =
      patterns
      |> Enum.flat_map(&Path.wildcard/1)
      |> Enum.uniq()
      |> Enum.sort()
      |> Enum.filter(&(Path.extname(&1) in ~w(.beam .app)))

    {records, bytes, omitted} =
      Enum.reduce(paths, {[], 0, 0}, fn path, {records, bytes, omitted} ->
        relative = Path.relative_to(path, root)

        with true <- Scope.relative?(relative),
             true <- regular_tree?(root, relative),
             {:ok, %{size: size, type: :regular}} <- File.lstat(path),
             true <-
               size <= 64 * 1024 * 1024 and bytes + size <= @artifact_limit and
                 length(records) < @artifact_count,
             {:ok, data} <- File.read(path),
             true <- byte_size(data) == size do
          Store.atomic(Path.join(dir, relative), data)

          {[%{"path" => relative, "bytes" => size, "sha256" => Store.digest(data)} | records],
           bytes + size, omitted}
        else
          _ -> {records, bytes, omitted + 1}
        end
      end)

    %{
      "provenance" => "existing local artifacts; revision correspondence not established",
      "files" => Enum.reverse(records),
      "bytes" => bytes,
      "omitted" => omitted,
      "truncated" => omitted > 0
    }
  end

  defp regular_tree?(root, relative) do
    relative
    |> Path.split()
    |> Enum.reduce_while(root, fn part, parent ->
      child = Path.join(parent, part)

      case File.lstat(child) do
        {:ok, %{type: type}} when type in [:directory, :regular] -> {:cont, child}
        _ -> {:halt, false}
      end
    end) != false
  end

  @doc false
  def read(run, repo) do
    dir = Path.join(run, repo)
    path = Path.join(dir, "dependencies.json")

    if File.regular?(path) do
      unless Store.digest(File.read!(path)) == File.read!(Path.join(dir, "dependencies.sha256")),
        do: raise("Dependency report changed: #{repo}")

      Store.read(path)
    else
      %{"status" => "not_captured", "projects" => []}
    end
  end
end
