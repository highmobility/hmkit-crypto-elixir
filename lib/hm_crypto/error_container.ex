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

defmodule HmCrypto.ErrorContainer do
  @error_cmd_id 0x02
  @unknown_content_type 0x00
  @unknown_content_type_atom :unknown
  @encrypted_truned_off 0x00

  @errror_internal_error <<0x00, 0x01>>
  @error_invalid_data <<0x01, 0x04>>
  @error_timeout <<0x00, 0x09>>
  @error_invalid_hmac <<0x36, 0x08>>

  defstruct target_serial: nil,
            sender_serial: nil,
            version: nil,
            request_id: nil,
            nonce: nil,
            command: nil,
            command_binary: nil,
            encrypted_flag: 0,
            content_type: @unknown_content_type_atom

  import HmCrypto.ContainerHelper

  @type disclose_error ::
          :invalid_hmac
          | :invalid_secure_command
          | :unencrypted_command
          | :internal_error
          | :invalid_data
          | :timeout

  def to_bin(error_container) do
    command = <<@error_cmd_id>> <> command_to_binary(error_container.command)

    inner_data =
      <<error_container.version>> <>
        error_container.sender_serial <>
        error_container.target_serial <>
        error_container.nonce <>
        <<00::integer-16>> <>
        <<@encrypted_truned_off>> <>
        <<@unknown_content_type>> <> <<byte_size(command)::integer-32>> <> command

    <<0x00>> <> add_paddings(inner_data) <> <<0xFF>>
  end

  def from_bin(error_binary) do
    inside_size = byte_size(error_binary) - 2

    with {:ok, inside_binary} <- extract_inside_data(error_binary, inside_size),
         inside_binary <- remove_paddings(inside_binary),
         {:ok, struct} <- to_struct_v2(inside_binary) do
      {:ok, struct}
    end
  end

  def to_struct_v2(inside_binary) do
    case inside_binary do
      <<0x02, sender_serial::binary-size(9), target_serial::binary-size(9), nonce::binary-size(9),
        request_id_size::integer-16, request_id::binary-size(request_id_size), encrypted_flag,
        @unknown_content_type, error_command_size::integer-32,
        error_command::binary-size(error_command_size)>> ->
        {:ok,
         %__MODULE__{
           target_serial: target_serial,
           sender_serial: sender_serial,
           encrypted_flag: encrypted_flag,
           nonce: nonce,
           command_binary: error_command,
           request_id: request_id,
           content_type: @unknown_content_type_atom,
           version: 2
         }}

      <<serial_number::binary-size(9), nonce::binary-size(9), encrypted_flag,
        command::binary-size(3)>> ->
        {:ok,
         %__MODULE__{
           target_serial: serial_number,
           nonce: nonce,
           encrypted_flag: encrypted_flag,
           command_binary: command,
           version: 1,
           content_type: nil
         }}

      _ ->
        {:error, :invalid_container_wrapper}
    end
  end

  defp command_to_binary(:internal_error), do: @errror_internal_error
  defp command_to_binary(:timeout), do: @error_timeout

  defp command_to_binary(error_atom) when error_atom in [:invalid_data, :unencrypted_command] do
    @error_invalid_data
  end

  defp command_to_binary(error_atom)
       when error_atom in [:invalid_hmac, :invalid_secure_command] do
    @error_invalid_hmac
  end
end
