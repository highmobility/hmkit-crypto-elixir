# HMCrypto
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

defmodule HMCrypto.DeviceCertificate do
  defstruct app_id: nil, serial_number: nil, public_key: nil, signature: nil, issuer_name: nil

  @type t :: %HMCrypto.DeviceCertificate{
          app_id: <<_::96>>,
          serial_number: <<_::72>>,
          public_key: HMCrypto.Crypto.public_key(),
          issuer_name: HMCrypto.Issuer.name(),
          signature: binary
        }

  alias __MODULE__
  alias HMCrypto.{Crypto, Issuer}

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
