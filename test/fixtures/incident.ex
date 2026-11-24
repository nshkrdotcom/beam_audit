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
end
