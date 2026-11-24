defmodule BeamAudit.Findings do
  @moduledoc """
  Conservative finding consolidation and cross-run comparison.

  Candidate identity remains revision-specific. Comparison fingerprints omit the
  revision and line number, but do not transfer safety decisions or prove fixes.
  """
  alias BeamAudit.{Report, Scope, Store, Run}

  @doc false
  def source(run, repo, inventory, rows) do
    rows
    |> Enum.filter(&(&1["effective"] in ~w(confirmed potential)))
    |> Enum.map(fn row ->
      group = row["candidate"]
      entry = Scope.lookup(inventory, group["path"])
      source = Scope.source!(run, repo["id"], entry) |> String.split("\n")
      anchors = Enum.map(group["lines"], &(Enum.at(source, &1 - 1, "") |> String.trim()))
      definition = group["definition"] || %{}

      key =
        Store.id([
          repo["root"],
          group["path"],
          group["rule"],
          definition["module"],
          definition["signature"] || "line:#{group["first"]}",
          anchors
        ])

      {key, row}
    end)
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
    |> Enum.map(fn {key, matches} ->
      matches =
        Enum.sort_by(matches, fn row ->
          {if(row["effective"] == "confirmed", do: 0, else: 1),
           severity(row["primary"]["decision"]["severity"]), row["candidate"]["id"]}
        end)

      row = hd(matches)
      group = row["candidate"]
      decision = row["primary"]["decision"]

      %{
        "kind" => "source",
        "fingerprint" => key,
        "repository" => repo["root"],
        "revision" => repo["commit"],
        "path" => group["path"],
        "rule" => group["rule"],
        "status" => row["effective"],
        "severity" => decision["severity"],
        "candidate_ids" => Enum.map(matches, & &1["candidate"]["id"]),
        "investigations" => matches
      }
    end)
    |> Enum.sort_by(&{severity(&1["severity"]), &1["fingerprint"]})
  end

  @doc false
  def dependencies(repo, data) do
    data["projects"]
    |> Enum.flat_map(fn project ->
      native = project["native"] || %{}

      Enum.map(native["findings"] || [], fn finding ->
        identity = [repo["root"], project["path"], finding["package"], finding["advisory_id"]]
        {Store.id(identity), project, finding}
      end)
    end)
    |> Enum.group_by(&elem(&1, 0))
    |> Enum.map(fn {key, rows} ->
      {_, project, finding} = hd(rows)
      native = rows |> Enum.map(&elem(&1, 2)) |> Enum.sort_by(&JSON.encode!/1)

      %{
        "kind" => "dependency",
        "fingerprint" => key,
        "repository" => repo["root"],
        "revision" => repo["commit"],
        "project" => project["path"],
        "package" => finding["package"],
        "advisory" => finding["advisory_id"],
        "version" => finding["installed_version"],
        "severity" => finding["severity"],
        "native_verdicts" => native |> Enum.map(& &1["verdict"]) |> Enum.uniq() |> Enum.sort(),
        "reachability_limit" => project["reachability_limit"],
        "status" => "advisory_match",
        "native_findings" => native
      }
    end)
    |> Enum.sort_by(&{severity(&1["severity"]), &1["fingerprint"]})
  end

  @doc false
  def compare(old_run, new_run) do
    old_manifest = Run.verify!(old_run)
    new_manifest = Run.verify!(new_run)

    for manifest <- [old_manifest, new_manifest] do
      selected = roots(manifest)

      if Enum.uniq(selected) != selected,
        do: raise("Compare runs with one revision per repository")
    end

    old_summary = Report.render(old_run)
    new_summary = Report.render(new_run)
    old = collect(old_run, old_manifest)
    new = collect(new_run, new_manifest)
    old_map = Map.new(old, &{&1["fingerprint"], &1})
    new_map = Map.new(new, &{&1["fingerprint"], &1})

    %{
      "old_run" => old_manifest["id"],
      "new_run" => new_manifest["id"],
      "old_status" => old_summary.status,
      "new_status" => new_summary.status,
      "policy_changed" => old_manifest["rules_sha256"] != new_manifest["rules_sha256"],
      "same_repository_roots" => roots(old_manifest) == roots(new_manifest),
      "newly_reported" => Enum.reject(new, &Map.has_key?(old_map, &1["fingerprint"])),
      "still_reported" =>
        Enum.flat_map(new, fn row ->
          case Map.get(old_map, row["fingerprint"]) do
            nil -> []
            prior -> [%{"before" => prior, "after" => row}]
          end
        end),
      "not_observed" => Enum.reject(old, &Map.has_key?(new_map, &1["fingerprint"])),
      "note" =>
        "Comparison is exact-fingerprint matching, not a proof of remediation. Changed call sites, review decisions, policy, feed or scope may change findings. Unobserved findings are not automatically fixed."
    }
  end

  defp roots(manifest), do: manifest["repositories"] |> Enum.map(& &1["root"]) |> Enum.sort()

  defp collect(run, manifest) do
    Enum.flat_map(manifest["repositories"], fn repo ->
      path = Path.join([run, repo["id"], "findings.jsonl"])

      if File.regular?(path) do
        Store.read_lines(path)
        |> Enum.map(&Map.drop(&1, ~w(investigations native_findings)))
      else
        []
      end
    end)
  end

  defp severity(value),
    do: Enum.find_index(~w(critical high medium low info unknown), &(&1 == value)) || 6
end
