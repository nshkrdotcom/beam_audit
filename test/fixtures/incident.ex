# Source-only positive and benign controls. Never compiled or executed.
defmodule AuditFixture do
  def decode(input), do: :erlang.binary_to_term(input, [:safe])
  def decode_pipe(input), do: input |> :erlang.binary_to_term([:safe])
  def decode_nonexec(input), do: Plug.Crypto.non_executable_binary_to_term(input, [:safe])

  def decode_checked(input) do
    case :erlang.binary_to_term(input, [:safe]) do
      value when is_integer(value) -> {:ok, value}
      _ -> {:error, :invalid_value}
    end
  end

  def execute(module, function, args), do: apply(module, function, args)
  def command(command), do: System.cmd(command, [])
  def new_atom(input), do: String.to_atom(input)
  def existing_atom(input), do: String.to_existing_atom(input)
  def inspect_decoded(input), do: inspect_value(decode(input))
  defp inspect_value(value), do: inspect(value)

  def ordinary(input), do: Enum.map(input, &inspect/1)
  def parse_json(input), do: Jason.decode(input)

  alias Plug.Crypto, as: Crypto
  import :erlang, only: [binary_to_term: 2]

  def decode_alias(input), do: Crypto.non_executable_binary_to_term(input, [:safe])
  def decode_import(input), do: binary_to_term(input, [:safe])
  def decoder, do: &:erlang.binary_to_term/2

  def flow(input), do: AuditFixture.atom_sink(AuditFixture.decode(input))
  def atom_sink(value), do: String.to_atom(value)
  def other_flow(input), do: AuditFixture.atom_sink(input)

  def cast(tag, values), do: struct(tag, values)
  def cast_checked(values), do: struct(__MODULE__, Map.take(values, [:value]))
  def shallow({:list, values}), do: is_list(values)
  def checked({:list, values}) when is_list(values), do: Enum.all?(values, &checked/1)
  def checked(value), do: is_integer(value)
  def rejected(value), do: {:error, Inspect.inspect(value, %Inspect.Opts{})}
  def rejected_checked(_value), do: {:error, :invalid_value}
  def query(expression), do: Repo.query(expression, [])
  def query_literal(value), do: Repo.query("SELECT $1", [value])
end
