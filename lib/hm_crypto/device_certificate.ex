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
defmodule HmCrypto.DeviceCertificate do
  defstruct app_id: nil, serial_number: nil, public_key: nil, signature: nil, issuer_name: nil

  @type t :: %HmCrypto.DeviceCertificate{
          app_id: <<_::96>>,
          serial_number: <<_::72>>,
          public_key: HmCrypto.Crypto.public_key(),
          issuer_name: HmCrypto.Issuer.name(),
          signature: binary
        }

  alias __MODULE__
  alias HmCrypto.{Crypto, Issuer}

  @doc """
  Validates and creates new DeviceCertificate struct
  """
  @spec new(keyword() | map()) :: {:ok, t} | {:error, :invalid_input}
  def new(attrs) when is_list(attrs) do
    attrs
    |> Enum.into(%{})
    |> new
  end

  def new(%{app_id: app_id, serial_number: serial_number, public_key: public_key} = attrs)
      when is_map(attrs) and byte_size(app_id) == 12 and byte_size(serial_number) == 9 and
             byte_size(public_key) == 64 do
    {:ok,
     %DeviceCertificate{app_id: app_id, serial_number: serial_number, public_key: public_key}}
  end

  def new(_), do: {:error, :invalid_input}

  @doc """
  Signs device certificate using issuer's name and private key
  """
  def sign(%DeviceCertificate{} = dc, %Issuer{} = issuer) do
    dc = %{dc | issuer_name: issuer.name}
    signature = Crypto.sign(to_bin(dc, :no_signature), issuer.private_key)
    %{dc | signature: signature}
  end

  @doc """
  Returns a binary which corresponds to the Device Certificate
  """
  def to_bin(%DeviceCertificate{signature: signature} = dc) when not is_nil(signature) do
    to_bin(dc, :no_signature) <> dc.signature
  end

  def to_bin(%DeviceCertificate{issuer_name: issuer_name} = dc, :no_signature)
      when not is_nil(issuer_name) do
    dc.issuer_name <> dc.app_id <> dc.serial_number <> dc.public_key
  end
end
