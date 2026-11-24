defmodule BeamAudit.Report do
  @moduledoc """
  Render reports from immutable discovery records and accepted review results.
  Rendering never invokes a scanner, provider, or target repository.
  """
  alias BeamAudit.{Run, Scope, Store, Review}

  @doc false
  def render(run) do
    manifest = Run.verify!(run)
    review_path = Path.join(run, "review_status.json")

    review =
      if File.regular?(review_path),
        do: Store.read(review_path),
        else: %{"status" => "not_started"}

    parts = Enum.map(manifest["repositories"], &repository(run, &1))
    pending = Enum.sum(Enum.map(parts, & &1.pending))
    unresolved = Enum.sum(Enum.map(parts, & &1.unresolved))
    gaps = Enum.sum(Enum.map(parts, & &1.gaps))
    findings = Enum.sum(Enum.map(parts, & &1.findings))
    complete = pending == 0 and gaps == 0 and unresolved == 0
    status = if complete, do: "accounted_within_declared_policy", else: "partial_or_unresolved"

    text = [
      "# BeamAudit report\n\n",
      "Run: `#{manifest["id"]}`  \n",
      "Captured: #{manifest["created_at"]}  \n",
      "Status: **#{status}**  \n",
      "Review: #{review["status"]}  \n",
      "Pending: #{pending} · Unresolved: #{unresolved} · Coverage gaps: #{gaps}\n\n",
      if(review["reason"], do: "Review blocker: #{clean(review["reason"])}\n\n", else: ""),
      "This is a scoped first-party source audit under the captured rule policy, not a security certification. ",
      "No-match results, incomplete modeling and evidence-grounded review do not establish absence of vulnerabilities.\n\n",
      "## Provenance\n\n",
      "Rules SHA-256: `#{manifest["rules_sha256"]}`\n\n",
      Enum.map(Enum.sort(manifest["tools"]["libraries"]), fn {name, version} ->
        "- #{name}: #{version}\n"
      end),
      "\nReview attempts reserved: #{Run.call_count(run)}\n\n",
      Enum.map(parts, & &1.text)
    ]

    path = Path.join(run, "report.md")
    Store.atomic(path, text)

    summary = %{
      id: manifest["id"],
      path: run,
      report: path,
      status: status,
      review_status: review["status"],
      pending: pending,
      unresolved: unresolved,
      coverage_gaps: gaps,
      findings: findings,
      repository_count: length(parts)
    }

    Store.write(
      Path.join(run, "summary.json"),
      Map.new(summary, fn {key, value} -> {Atom.to_string(key), value} end)
    )

    summary
  end

  defp repository(run, repo) do
    dir = Path.join(run, repo["id"])
    heading = "## #{clean(repo["name"])} (`#{repo["commit"]}`)\n\n"

    if Run.ready?(run, repo) do
      inventory = Scope.inventory(run, repo["id"])
      included = Scope.included(inventory)
      data = Store.read(Path.join(dir, "discovery.json"))
      ledger = Store.read_lines(Path.join(dir, "ledger.jsonl"))
      groups = Store.read_lines(Path.join(dir, "candidates.jsonl"))
      decisions = Enum.map(groups, &effective(run, &1))
      counts = Enum.frequencies_by(decisions, & &1["effective"])
      buckets = Enum.frequencies_by(ledger, & &1["bucket"])
      excluded = Enum.reject(inventory, &(&1["status"] == "included"))
      exclusions = Enum.frequencies_by(excluded, & &1["reason"])

      coverage_gaps =
        Enum.count(
          data["coverage"],
          &(&1["status"] != "completed" or Map.get(&1, "unmodeled_extensions", []) != [])
        ) +
          length(data["scope_errors"]) +
          Enum.count(
            excluded,
            &(&1["reason"] in ~w(source_size_limit unsupported_source_encoding))
          )

      pending = Map.get(counts, "pending", 0) + Map.get(counts, "pending_challenge", 0)
      unresolved = Map.get(counts, "unresolved", 0)
      findings = Enum.filter(decisions, &(&1["effective"] in ~w(confirmed potential)))
      # Store a compact, deterministic machine-readable projection of every group.
      Store.write_lines(Path.join(dir, "dispositions.jsonl"), decisions)

      details =
        findings
        |> Enum.sort_by(
          &{severity_order(&1["primary"]["decision"]["severity"]), &1["candidate"]["id"]}
        )
        |> Enum.map(&finding/1)

      preliminary =
        Enum.filter(decisions, fn row ->
          (row["effective"] in ~w(pending_challenge unresolved) and
             row["primary"]) &&
            row["primary"]["decision"]["disposition"] in ~w(confirmed potential)
        end)

      issues =
        Enum.filter(decisions, &(&1["effective"] in ~w(pending pending_challenge unresolved)))

      text = [
        heading,
        "Tracked entries: #{length(inventory)}; included: #{length(included)}.\n\n",
        "Raw hits: #{length(ledger)}; review groups: #{length(groups)}.\n\n",
        "Buckets: #{counts_text(buckets)}.  \n",
        "Dispositions: #{counts_text(counts)}.  \n",
        "Excluded entries: #{counts_text(exclusions)}.\n\n",
        "### Tool coverage\n\n",
        Enum.map(data["coverage"], &coverage/1),
        "\n",
        "Out-of-scope/invalid analyzer hits: #{length(data["scope_errors"])}. See `#{repo["id"]}/ledger.jsonl`.\n\n",
        "### Actionable findings\n\n",
        if(details == [],
          do: "No accepted confirmed or potential findings. This may be an incomplete audit.\n\n",
          else: details
        ),
        if(preliminary == [],
          do: "",
          else: ["### Preliminary findings (not final)\n\n", Enum.map(preliminary, &finding/1)]
        ),
        "### Pending and unresolved\n\n",
        if(issues == [],
          do: "None under this candidate policy.\n\n",
          else: Enum.map(issues, &pending_line(run, &1))
        ),
        "\nAll accepted decisions, including safe dismissals and their challenge evidence, are in `#{repo["id"]}/dispositions.jsonl`.\n\n"
      ]

      %{
        text: text,
        pending: pending,
        unresolved: unresolved,
        gaps: coverage_gaps,
        findings: length(findings)
      }
    else
      failure = Path.join(dir, "discovery_failure.json")

      reason =
        repo["snapshot_error"] ||
          if(File.regular?(failure),
            do: Store.read(failure)["reason"],
            else: "Discovery did not complete"
          )

      %{
        text: [heading, "**Discovery incomplete:** #{clean(reason)}. No safety conclusions.\n\n"],
        pending: 0,
        unresolved: 0,
        gaps: 1,
        findings: 0
      }
    end
  end

  defp effective(run, group) do
    repo = group["repo"]
    id = group["id"]
    primary = Review.record(run, repo, "decisions", id)
    challenge = Review.record(run, repo, "challenges", id)

    disposition =
      cond do
        is_nil(primary) ->
          "pending"

        not Review.challenge_required?(primary["decision"], group) ->
          primary["decision"]["disposition"]

        is_nil(challenge) ->
          "pending_challenge"

        challenge["decision"]["disposition"] != primary["decision"]["disposition"] ->
          "unresolved"

        challenge["decision"]["severity"] != primary["decision"]["severity"] and
            primary["decision"]["disposition"] in ~w(confirmed potential) ->
          "unresolved"

        true ->
          primary["decision"]["disposition"]
      end

    # Packet data is kept in individual records; the summary references those
    # records instead of copying all source excerpts into a second ledger.
    %{
      "candidate" => group,
      "effective" => disposition,
      "primary" => compact(primary),
      "challenge" => compact(challenge)
    }
  end

  defp compact(nil), do: nil

  defp compact(rec) do
    refs = rec["decision"]["evidence_refs"]

    evidence =
      rec["packet"]["excerpts"]
      |> Enum.filter(&(&1["id"] in refs))
      |> Enum.map(&Map.drop(&1, ["text"]))

    rec |> Map.drop(["packet"]) |> Map.put("evidence", evidence)
  end

  defp finding(row) do
    group = row["candidate"]
    decision = row["primary"]["decision"]

    [
      "#### #{decision["severity"]} / #{row["effective"]} — #{clean(group["rule"])}\n\n",
      "Location: `#{clean(group["path"])}:#{group["first"]}-#{group["last"]}`  \n",
      "Candidate: `#{group["id"]}`\n\n",
      clean(decision["reason"]),
      "\n\n",
      "**Trace:** #{clean(decision["source_to_sink"])}\n\n",
      "**Proposed fix:** #{clean(decision["remediation"])}\n\n",
      "**Regression check:** #{clean(decision["regression"])}\n\n",
      "Evidence:\n",
      Enum.map(
        row["primary"]["evidence"],
        &"- `#{clean(&1["path"])}:#{&1["first"]}-#{&1["last"]}` (`#{&1["id"]}`)\n"
      ),
      "\n"
    ]
  end

  defp pending_line(run, row) do
    group = row["candidate"]
    phase = if row["effective"] == "pending_challenge", do: "challenges", else: "decisions"
    error = Path.join([run, group["repo"], "review_errors", phase, group["id"] <> ".json"])

    reason =
      cond do
        row["effective"] == "unresolved" and row["challenge"] ->
          "Review disagreement: #{row["challenge"]["decision"]["reason"]}"

        row["effective"] == "unresolved" ->
          row["primary"]["decision"]["reason"]

        File.regular?(error) ->
          Store.read(error)["reason"]

        true ->
          "Outstanding review"
      end

    "- `#{clean(group["path"])}:#{group["first"]}` #{group["rule"]} — #{row["effective"]}: #{clean(reason)} (`#{group["id"]}`)\n"
  end

  defp coverage(tool) do
    details =
      tool
      |> Map.drop(~w(tool status patterns args))
      |> Enum.sort()
      |> Enum.map(fn {key, value} -> "#{key}=#{JSON.encode!(value)}" end)
      |> Enum.join("; ")

    "- **#{clean(tool["tool"])}:** #{tool["status"]} — #{clean(details)}\n"
  end

  defp counts_text(counts),
    do: counts |> Enum.sort() |> Enum.map(fn {k, v} -> "#{k}=#{v}" end) |> Enum.join(", ")

  defp severity_order(value),
    do: Enum.find_index(~w(critical high medium low info unknown), &(&1 == value)) || 6

  # Model text is data. Suppress raw HTML and control characters in Markdown.
  defp clean(nil), do: ""

  defp clean(value),
    do:
      value
      |> to_string()
      |> String.replace(~r/[\x00-\x08\x0b\x0c\x0e-\x1f]/, "")
      |> String.replace("<", "&lt;")
      |> String.replace(">", "&gt;")
end
