defmodule BeamAudit.RunStorage do
  @moduledoc """
  Local run-directory selection, inventory and explicit retention operations.

  No index, background cleanup or automatic deletion. A sibling directory guard
  coordinates public operations on a run, including deletion. It is advisory:
  direct filesystem edits do not participate.
  """
  alias BeamAudit.{Run, Store}

  @guard_prefix ".beam-audit-lock-"
  @complete "accounted_within_declared_policy"
  @partial "partial_or_unresolved"

  @doc false
  def root(opts) do
    path =
      Keyword.get_lazy(opts, :out, fn ->
        System.get_env("BEAM_AUDIT_OUT") || Application.get_env(:beam_audit, :out) ||
          default_root()
      end)

    unless is_binary(path) and String.trim(path) != "", do: raise("Invalid results root")
    Path.expand(path)
  end

  defp default_root do
    state = System.get_env("XDG_STATE_HOME")

    base =
      if is_binary(state) and Path.type(state) == :absolute,
        do: state,
        else: Path.join(System.user_home!(), ".local/state")

    Path.join(base, "beam_audit/runs")
  end

  @doc false
  def run_id?(id), do: is_binary(id) and Regex.match?(~r/\A[0-9]+-[0-9a-f]{20}\z/, id)

  @doc false
  def guard_path(run), do: Path.join(Path.dirname(run), @guard_prefix <> Path.basename(run))

  @doc false
  def with_guard(run, fun) do
    unless run_id?(Path.basename(run)) and directory?(run),
      do: raise("Run directory missing or invalid: #{run}")

    guard = guard_path(run)

    case File.mkdir(guard) do
      :ok ->
        try do
          unless directory?(run), do: raise("Run directory disappeared: #{run}")
          fun.()
        after
          File.rmdir!(guard)
        end

      {:error, :eexist} ->
        raise "Run is busy or has a stale guard: #{guard}"

      {:error, reason} ->
        raise File.Error, reason: reason, action: "create run guard", path: guard
    end
  end

  @doc false
  def with_guards(runs, fun) do
    runs |> Enum.map(&Path.expand/1) |> Enum.uniq() |> Enum.sort() |> guard_all(fun)
  end

  defp guard_all([], fun), do: fun.()
  defp guard_all([run | rest], fun), do: with_guard(run, fn -> guard_all(rest, fun) end)

  @doc "List immediate run directories and their logical regular-file sizes."
  def list(opts \\ []), do: Store.safe(fn -> inventory(root(opts)) end)

  @doc "Preview deletion of one run ID in the selected root; pass `confirm: true` to delete."
  def delete(id, opts \\ []) do
    Store.safe(fn ->
      parent = root(opts)
      unless run_id?(id), do: raise("Deletion requires a run ID, not a path")
      confirm = boolean!(opts, :confirm)
      row = entry(parent, id)
      unless row.recognized, do: raise("Unrecognized or missing run: #{id}")
      if row.locked, do: raise("Run is busy or has a stale guard: #{guard_path(row.path)}")

      if confirm, do: remove(row, true)
      result(parent, confirm, [row], if(confirm, do: [id], else: []), [], [])
    end)
  end

  @doc "Preview or apply an explicit age/count retention policy within one results root."
  def prune(opts \\ []) do
    Store.safe(fn ->
      parent = root(opts)
      confirm = boolean!(opts, :confirm)
      include_partial = boolean!(opts, :include_partial)
      age = integer_option!(opts, :older_than, 1)
      keep = integer_option!(opts, :keep, 0)
      if is_nil(age) and is_nil(keep), do: raise("Prune requires older_than or keep")

      rows = inventory(parent).runs

      protected =
        rows
        |> Enum.filter(& &1.recognized)
        |> Enum.take(keep || 0)
        |> MapSet.new(& &1.id)

      cutoff = if age, do: System.os_time(:second) - age * 86_400

      {selected, skipped} =
        Enum.reduce(rows, {[], []}, fn row, {selected, skipped} ->
          reason =
            cond do
              not row.recognized -> "unrecognized"
              row.locked -> "busy_or_stale_guard"
              MapSet.member?(protected, row.id) -> "keep_newest"
              cutoff && row.created_unix >= cutoff -> "not_old_enough"
              not include_partial and row.status != @complete -> "partial_or_unreported"
              true -> nil
            end

          if reason,
            do: {selected, [%{id: row.id, reason: reason} | skipped]},
            else: {[row | selected], skipped}
        end)

      # Oldest first; a failed deletion never hides other successful deletions.
      {deleted, errors} =
        if confirm do
          Enum.reduce(selected, {[], []}, fn row, {deleted, errors} ->
            case Store.safe(fn -> remove(row, include_partial) end) do
              {:ok, _} -> {[row.id | deleted], errors}
              {:error, reason} -> {deleted, [%{id: row.id, reason: reason} | errors]}
            end
          end)
        else
          {[], []}
        end

      result(
        parent,
        confirm,
        selected,
        Enum.reverse(deleted),
        Enum.reverse(skipped),
        Enum.reverse(errors)
      )
    end)
  end

  defp result(parent, confirm, selected, deleted, skipped, errors) do
    %{
      root: parent,
      dry_run: not confirm,
      selected: selected,
      selected_bytes: Enum.sum(Enum.map(selected, & &1.bytes)),
      deleted: deleted,
      skipped: skipped,
      errors: errors
    }
  end

  defp remove(row, include_partial) do
    with_guard(row.path, fn ->
      # Recheck recognition and status after taking the guard, not just at plan time.
      current = metadata(row.path, row.id)

      unless current.recognized and current.created_at == row.created_at,
        do: raise("Run changed since selection: #{row.id}")

      unless include_partial or current.status == @complete,
        do: raise("Run is no longer fully accounted: #{row.id}")

      File.rm_rf!(row.path)
      :ok
    end)
  end

  defp inventory(parent) do
    names =
      case File.ls(parent) do
        {:ok, names} ->
          Enum.sort(names)

        {:error, :enoent} ->
          []

        {:error, reason} ->
          raise File.Error, reason: reason, action: "list results root", path: parent
      end

    rows =
      names
      |> Enum.filter(&run_id?/1)
      |> Enum.map(&entry(parent, &1))
      |> Enum.sort_by(&{&1.created_unix || 0, &1.created_at || "", &1.id}, :desc)

    %{
      root: parent,
      runs: rows,
      total_bytes: Enum.sum(Enum.map(rows, & &1.bytes)),
      incomplete_sizes: Enum.count(rows, &(not &1.size_complete)),
      guards: Enum.filter(names, &String.starts_with?(&1, @guard_prefix)),
      ignored_entries:
        Enum.reject(names, &(run_id?(&1) or String.starts_with?(&1, @guard_prefix)))
    }
  end

  defp entry(parent, id) do
    run = Path.join(parent, id)
    locked = exists?(guard_path(run))
    {bytes, complete} = size(run)
    locked = locked or exists?(guard_path(run))

    Map.merge(metadata(run, id), %{
      id: id,
      path: run,
      bytes: bytes,
      size_complete: complete and not locked,
      locked: locked
    })
  end

  defp metadata(run, id) do
    manifest = if directory?(run), do: record(Path.join(run, "manifest.json"))

    with %{
           "schema" => schema,
           "id" => ^id,
           "created_at" => created,
           "repositories" => repositories,
           "settings" => settings,
           "rules_sha256" => rules_hash,
           "prompts_sha256" => prompts
         } <- manifest,
         true <-
           schema == Run.schema() and is_binary(created) and is_list(repositories) and
             repositories != [] and Enum.all?(repositories, &is_map/1) and is_map(settings) and
             is_binary(rules_hash) and is_map(prompts),
         {:ok, timestamp, _} <- DateTime.from_iso8601(created) do
      summary = record(Path.join(run, "summary.json"))

      status =
        case summary do
          %{
            "id" => ^id,
            "status" => @complete,
            "pending" => 0,
            "unresolved" => 0,
            "coverage_gaps" => 0
          } ->
            @complete

          %{"id" => ^id, "status" => @partial} ->
            @partial

          _ ->
            "unreported"
        end

      %{
        recognized: true,
        status: status,
        created_at: created,
        created_unix: DateTime.to_unix(timestamp),
        repositories: Enum.map(repositories, &Map.get(&1, "name")),
        pending: if(is_map(summary), do: summary["pending"]),
        unresolved: if(is_map(summary), do: summary["unresolved"])
      }
    else
      _ ->
        %{
          recognized: false,
          status: "unrecognized",
          created_at: nil,
          created_unix: nil,
          repositories: [],
          pending: nil,
          unresolved: nil
        }
    end
  end

  # Read only regular metadata files, not symlink targets or special files.
  defp record(path) do
    with {:ok, %{type: :regular}} <- File.lstat(path),
         {:ok, data} <- Store.safe(fn -> Store.read(path) end),
         true <- is_map(data) do
      data
    else
      _ -> nil
    end
  end

  defp directory?(path), do: match?({:ok, %{type: :directory}}, File.lstat(path))
  defp exists?(path), do: File.lstat(path) != {:error, :enoent}

  # Logical bytes, not filesystem allocation. Do not traverse symlinks.
  defp size(path) do
    case File.lstat(path) do
      {:ok, %{type: :regular, size: bytes}} ->
        {bytes, true}

      {:ok, %{type: :directory}} ->
        case File.ls(path) do
          {:ok, names} ->
            Enum.reduce(names, {0, true}, fn name, {total, complete} ->
              {bytes, readable} = size(Path.join(path, name))
              {total + bytes, complete and readable}
            end)

          {:error, _} ->
            {0, false}
        end

      {:ok, _} ->
        {0, true}

      {:error, _} ->
        {0, false}
    end
  end

  defp boolean!(opts, key) do
    value = Keyword.get(opts, key, false)
    unless is_boolean(value), do: raise("Invalid #{key}")
    value
  end

  defp integer_option!(opts, key, minimum) do
    case Keyword.fetch(opts, key) do
      :error -> nil
      {:ok, value} when is_integer(value) and value >= minimum -> value
      _ -> raise "Invalid #{key}; expected an integer >= #{minimum}"
    end
  end
end
