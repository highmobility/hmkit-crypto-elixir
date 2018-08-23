# HmCrypto
# Copyright (C) 2018 High-Mobility GmbH
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see http://www.gnu.org/licenses/.
#
# Please inquire about commercial licensing options at
# licensing@high-mobility.com

defmodule HmCrypto.Issuer do
  defstruct name: nil, private_key: nil

  @type name :: <<_::32>>
  @type t :: %{name: name, private_key: HmCrypto.Crypto.private_key()}

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
