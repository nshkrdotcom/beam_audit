defmodule BeamAudit.Scope do
  @moduledoc """
  Explicit Git revision scope, first-party inventory and source snapshots.

  Reads Git blobs directly. Never follows symlinks, gitlinks or path dependencies;
  never executes target project configuration. Assumes trusted local repository
  metadata and installed tools, not a hostile host or arbitrary untrusted repo.
  """
  alias BeamAudit.Store

  @extensions ~w(.ex .exs .eex .heex .leex .erl .hrl .gleam)
  @excluded ~w(.git deps _build vendor vendored node_modules .beam_audit)
  @test_dirs ~w(test tests test_support fixtures)
  @example_dirs ~w(example examples bench benchmarks)

  @doc false
  def git(root, args) do
    executable = System.find_executable("git") || raise("Git executable unavailable")
    System.cmd(executable, ["-C", root | args], stderr_to_stdout: true)
  end

  defp git!(root, args) do
    case git(root, args) do
      {out, 0} -> out
      {out, status} -> raise "Git #{hd(args)} failed (#{status}): #{String.slice(out, 0, 500)}"
    end
  end

  @doc false
  def resolve(spec, index) do
    spec = if is_binary(spec), do: %{"path" => spec}, else: spec
    root = spec |> Map.fetch!("path") |> Path.expand()
    top = root |> git!(["rev-parse", "--show-toplevel"]) |> String.trim()
    if Path.expand(top) != root, do: raise("Select the repository root explicitly: #{root}")
    revision = Map.get(spec, "revision", "HEAD")

    commit =
      root
      |> git!(["rev-parse", "--verify", "--end-of-options", revision <> "^{commit}"])
      |> String.trim()

    unless Regex.match?(~r/\A[0-9a-f]{40,64}\z/, commit), do: raise("Invalid Git commit")
    excludes = Map.get(spec, "exclude", [])
    unless is_list(excludes) and Enum.all?(excludes, &relative?/1), do: raise("Invalid exclusion")
    boundaries = Map.get(spec, "boundaries", [])

    unless is_list(boundaries) and
             Enum.all?(boundaries, &valid_boundary?/1),
           do: raise("Invalid boundary specifications")

    include_tests = Map.get(spec, "include_tests", false)
    unless is_boolean(include_tests), do: raise("include_tests must be boolean")

    %{
      "id" => "r" <> String.pad_leading(Integer.to_string(index), 3, "0"),
      "root" => root,
      "name" => Path.basename(root),
      "commit" => commit,
      "revision" => revision,
      "exclude" => excludes,
      "include_tests" => include_tests,
      "boundaries" => boundaries
    }
  end

  defp valid_boundary?(%{"path" => path, "line" => line, "question" => question}) do
    relative?(path) and is_integer(line) and line > 0 and is_binary(question) and
      byte_size(question) in 1..1000
  end

  defp valid_boundary?(_), do: false

  @doc false
  def snapshot(run, repo, max_bytes) do
    dir = snapshot_dir(run, repo["id"])
    File.mkdir_p!(dir)

    entries =
      repo["root"]
      |> git!(["ls-tree", "-r", "-l", "-z", "--full-tree", repo["commit"]])
      |> :binary.split(<<0>>, [:global, :trim_all])
      |> Enum.map(&entry/1)
      |> Enum.map(&materialize(&1, repo, dir, max_bytes))
      |> Enum.sort_by(& &1["path"])

    Store.write_lines(Path.join([run, repo["id"], "inventory.jsonl"]), entries)
    entries
  end

  defp entry(row) do
    [header, path] = :binary.split(row, "\t")
    [mode, type, oid, size] = String.split(header)

    unless relative?(path),
      do: raise("Unsupported Git path (must be UTF-8, relative, no control characters)")

    %{
      "path" => path,
      "mode" => mode,
      "type" => type,
      "oid" => oid,
      "bytes" => if(size == "-", do: nil, else: String.to_integer(size))
    }
  end

  @doc false
  def relative?(path) when is_binary(path) do
    String.valid?(path) and path != "" and Path.type(path) == :relative and
      not Regex.match?(~r/[\x00-\x1f\x7f\\]/, path) and
      Enum.all?(String.split(path, "/"), &(&1 not in ["", ".", "..", ".git"]))
  end

  def relative?(_), do: false

  defp materialize(e, repo, dir, max_bytes) do
    path = e["path"]
    parts = Path.split(path)
    role = role(parts)
    reason = exclusion_reason(e, repo, parts, role, max_bytes)
    base = Map.merge(e, %{"repo" => repo["id"], "role" => role})

    if reason do
      Map.merge(base, %{"status" => "excluded", "reason" => reason})
    else
      materialize_blob(e, repo, dir, base)
    end
  end

  defp exclusion_reason(e, repo, parts, role, max_bytes) do
    path = e["path"]
    extension = Path.extname(path)

    cond do
      e["type"] != "blob" or e["mode"] not in ["100644", "100755"] ->
        "not_regular_source"

      Enum.any?(parts, &(&1 in @excluded)) ->
        "dependency_or_build_tree"

      Enum.any?(repo["exclude"], &(path == &1 or String.starts_with?(path, &1 <> "/"))) ->
        "explicit_exclusion"

      role in ["test", "example"] and not repo["include_tests"] ->
        "test_or_example"

      true ->
        source_limit(extension, e["bytes"], max_bytes)
    end
  end

  defp source_limit(extension, bytes, max_bytes) do
    cond do
      extension not in @extensions -> "non_source_extension"
      bytes > max_bytes -> "source_size_limit"
      true -> nil
    end
  end

  defp materialize_blob(e, repo, dir, base) do
    path = e["path"]
    bytes = git!(repo["root"], ["cat-file", "blob", e["oid"]])

    if byte_size(bytes) != e["bytes"] or not String.valid?(bytes) or
         :binary.match(bytes, <<0>>) != :nomatch do
      Map.merge(base, %{"status" => "excluded", "reason" => "unsupported_source_encoding"})
    else
      dest = Path.join(dir, path)
      Store.atomic(dest, bytes)
      File.chmod!(dest, 0o400)

      Map.merge(base, %{
        "status" => "included",
        "sha256" => Store.digest(bytes),
        "lines" => length(String.split(bytes, "\n"))
      })
    end
  end

  defp role(parts) do
    cond do
      Enum.any?(parts, &(&1 in @test_dirs)) -> "test"
      Enum.any?(parts, &(&1 in @example_dirs)) -> "example"
      "config" in parts or List.last(parts) == "mix.exs" -> "config"
      "scripts" in parts or Path.extname(List.last(parts)) == ".exs" -> "script"
      Path.extname(List.last(parts)) in ~w(.eex .heex .leex) -> "template"
      true -> "production"
    end
  end

  @doc false
  def snapshot_dir(run, repo), do: Path.join([run, repo, "source"])

  @doc false
  def inventory(run, repo), do: Store.read_lines(Path.join([run, repo, "inventory.jsonl"]))

  @doc false
  def included(inventory), do: Enum.filter(inventory, &(&1["status"] == "included"))

  @doc false
  def source!(run, repo, entry) do
    path = entry["path"]

    unless entry["repo"] == repo and entry["status"] == "included" and relative?(path),
      do: raise("Out-of-scope source request")

    root = snapshot_dir(run, repo)
    unless File.lstat!(root).type == :directory, do: raise("Invalid snapshot root")
    # Never follow a modified snapshot symlink, including an intermediate directory.
    dest =
      Enum.reduce(Path.split(path), root, fn part, parent ->
        child = Path.join(parent, part)

        case File.lstat!(child) do
          %{type: :symlink} -> raise "Snapshot symlink: #{path}"
          _ -> child
        end
      end)

    unless File.lstat!(dest).type == :regular, do: raise("Snapshot is not a regular file")
    contents = File.read!(dest)
    unless Store.digest(contents) == entry["sha256"], do: raise("Snapshot changed: #{path}")
    contents
  end

  @doc false
  def lookup(inventory, path),
    do: Enum.find(inventory, &(&1["status"] == "included" and &1["path"] == path))

  @doc false
  def location_valid?(inventory, path, first, last) do
    case lookup(inventory, path) do
      nil ->
        false

      entry ->
        is_integer(first) and is_integer(last) and first >= 1 and first <= last and
          last <= entry["lines"]
    end
  end
end
