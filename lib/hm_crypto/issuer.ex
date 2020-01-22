defmodule HmCrypto.Issuer do
  defstruct name: nil, private_key: nil

  @type name :: <<_::32>>
  @type t :: %HmCrypto.Issuer{name: name, private_key: HmCrypto.Crypto.private_key()}

  alias __MODULE__

  @doc """
  Validates and creates new Issuer struct
  """
  @spec new(keyword() | map()) :: {:ok, %HmCrypto.Issuer{}} | {:error, :invalid_input}

  def new(attrs) when is_list(attrs) do
    attrs
    |> Enum.into(%{})
    |> new
  end

  def new(%{name: name, private_key: private_key} = attrs)
      when is_map(attrs) and byte_size(name) == 4 and byte_size(private_key) == 32 do
    {:ok, %Issuer{name: name, private_key: private_key}}
  end

  def new(_), do: {:error, :invalid_input}
end
