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

defmodule HmCrypto.EncryptedContainer do
  defstruct target_serial: nil,
            sender_serial: nil,
            version: nil,
            request_id: nil,
            nonce: nil,
            encrypted_data: nil,
            encrypted_flag: nil,
            hmac: nil

  import HmCrypto.ContainerHelper
  alias HmCrypto.Crypto

  def from_bin(container_binary) do
    inside_size = byte_size(container_binary) - 2

    with {:ok, inside_binary} <- extract_inside_data(container_binary, inside_size),
         inside_binary <- remove_paddings(inside_binary),
         {:ok, struct} <- to_struct_v2(inside_binary) do
      {:ok, struct}
    end
  end

  defp to_struct_v2(inside_binary) do
    case inside_binary do
      <<0x02, sender_serial::binary-size(9), target_serial::binary-size(9), nonce::binary-size(9),
        request_id_size::integer-16, request_id::binary-size(request_id_size), encrypted_flag,
        encrypted_command_size::integer-32,
        encrypted_command::binary-size(encrypted_command_size),
        encrypted_command_hmac::binary-size(32)>> ->
        {:ok,
         %__MODULE__{
           target_serial: target_serial,
           sender_serial: sender_serial,
           encrypted_flag: encrypted_flag,
           nonce: nonce,
           encrypted_data: encrypted_command,
           request_id: request_id,
           hmac: encrypted_command_hmac,
           version: 2
         }}

      v1_data ->
        to_struct_v1(v1_data)
    end
  end

  def to_bin(encrypted_container, session_key) do
    request_id_data =
      <<byte_size(encrypted_container.request_id)::integer-16,
        encrypted_container.request_id::binary>>

    telematics_container =
      <<encrypted_container.version, encrypted_container.sender_serial::binary,
        encrypted_container.target_serial::binary, encrypted_container.nonce::binary,
        request_id_data::binary, encrypted_container.encrypted_flag,
        byte_size(encrypted_container.encrypted_data)::integer-32,
        encrypted_container.encrypted_data::binary>>

    telematics_container_with_hmac =
      telematics_container <> Crypto.hmac(session_key, encrypted_container.encrypted_data)

    <<0x00>> <> add_paddings(telematics_container_with_hmac) <> <<0xFF>>
  end

  def validate_hmac(encrypted_container, private_key, public_key) do
    session_key = session_key(private_key, public_key, encrypted_container.nonce)

    if Crypto.hmac(session_key, encrypted_container.encrypted_data) == encrypted_container.hmac do
      :ok
    else
      {:error, :invalid_hmac}
    end
  end

  defp to_struct_v1(inside_data) do
    case inside_data do
      <<target_serial::binary-size(9), nonce::binary-size(9), encrypted_flag,
        encrypted_data::binary>> ->
        {:ok,
         %__MODULE__{
           sender_serial: target_serial,
           nonce: nonce,
           encrypted_data: encrypted_data,
           encrypted_flag: encrypted_flag,
           version: 1
         }}

      _ ->
        {:error, :invalid_container_property}
    end
  end
end
