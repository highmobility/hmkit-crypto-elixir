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

defmodule HmCrypto.ContainerHelper do
  alias HmCrypto.Crypto
  def add_paddings(<<>>), do: <<>>

  def add_paddings(<<first_byte>> <> rest) do
    escape_byte(first_byte) <> add_paddings(rest)
  end

  defp escape_byte(byte) when byte in [0x00, 0xFE, 0xFF], do: <<0xFE, byte>>
  defp escape_byte(byte), do: <<byte>>

  def session_key(private_key, public_key, nonce) do
    private_key
    |> Crypto.compute_key(public_key)
    |> Crypto.hmac(nonce)
  end

  def extract_inside_data(container_data, inside_size) do
    case container_data do
      <<0x00, inside_data::binary-size(inside_size), 0xFF>> -> {:ok, inside_data}
      _ -> {:error, :invalid_container_wrapper}
    end
  end

  def remove_paddings(<<>>) do
    <<>>
  end

  def remove_paddings(<<0xFE, data, rest::binary>>) do
    <<data>> <> remove_paddings(rest)
  end

  def remove_paddings(<<data, rest::binary>>) do
    <<data>> <> remove_paddings(rest)
  end
end
