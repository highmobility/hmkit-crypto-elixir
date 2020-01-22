# HmCrypto
# The MIT License
# 
# Copyright (c) 2018- High-Mobility GmbH (https://high-mobility.com)
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
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
