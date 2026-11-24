defmodule BeamAudit.Store do
  @moduledoc false

  def digest(binary), do: Base.encode16(:crypto.hash(:sha256, binary), case: :lower)
  def id(parts), do: digest(JSON.encode!(parts))
  def nonce, do: Base.encode16(:crypto.strong_rand_bytes(10), case: :lower)
  def now, do: DateTime.utc_now() |> DateTime.to_iso8601()
  def priv(file), do: Application.app_dir(:beam_audit, "priv/" <> file)
  def read(path), do: path |> File.read!() |> JSON.decode!()

  def read_lines(path) do
    path |> File.read!() |> String.split("\n", trim: true) |> Enum.map(&JSON.decode!/1)
  end

  def write(path, value), do: atomic(path, JSON.encode!(value) <> "\n")

  def write_lines(path, rows) do
    atomic(path, Enum.map(rows, &[JSON.encode!(&1), "\n"]))
  end

  # A same-directory rename prevents readers from seeing a half-written record.
  # Sync the file before rename; this is process-interruption recovery, not a
  # guarantee of filesystem durability after power loss.
  def atomic(path, data) do
    File.mkdir_p!(Path.dirname(path))
    tmp = path <> ".tmp-" <> nonce()

    try do
      File.open!(tmp, [:write, :binary, :exclusive], fn io ->
        :ok = IO.binwrite(io, data)
        :ok = :file.sync(io)
      end)

      File.chmod!(tmp, 0o600)
      File.rename!(tmp, path)
      :ok
    after
      File.rm(tmp)
    end
  end

  def versions do
    Map.new([:beam_audit, :ex_ast, :reach, :sobelow, :agent_session_manager], fn app ->
      Application.load(app)
      {Atom.to_string(app), to_string(Application.spec(app, :vsn) || "unavailable")}
    end)
  end

  def safe(fun) do
    try do
      {:ok, fun.()}
    rescue
      error -> {:error, Exception.message(error)}
    catch
      kind, value -> {:error, "#{kind}: #{inspect(value, limit: 10, printable_limit: 500)}"}
    end
  end

  # Only trusted installed BEAM code is placed on this worker's code path.
  # It runs outside the audited source tree, without evaluating target Mix files.
  def worker(expression, args, cwd, stderr_path \\ nil) do
    executable = System.find_executable("elixir") || raise "Elixir executable unavailable"

    paths =
      :code.get_path()
      |> Enum.map(&(&1 |> List.to_string() |> Path.expand()))
      |> Enum.filter(&File.dir?/1)
      |> Enum.uniq()
      |> Enum.flat_map(&["-pa", &1])

    args = paths ++ ["-e", expression, "--" | args]

    if stderr_path do
      atomic(stderr_path, "")

      redirect = ~S(stderr=$1; shift; exec "$@" 2>"$stderr")
      command = ["-c", redirect, "worker", stderr_path, executable | args]
      System.cmd("sh", command, cd: cwd)
    else
      System.cmd(executable, args, cd: cwd, stderr_to_stdout: true)
    end
  end
end
