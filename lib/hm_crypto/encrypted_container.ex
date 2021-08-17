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
defmodule HmCrypto.EncryptedContainer do
  defstruct target_serial: nil,
            sender_serial: nil,
            version: nil,
            request_id: nil,
            nonce: nil,
            encrypted_data: nil,
            encrypted_flag: nil,
            content_type: nil,
            hmac: nil

  @type t :: %__MODULE__{}
  @type container_parser_error :: :invalid_container_property

  import HmCrypto.ContainerHelper
  alias HmCrypto.{Crypto, ContentType, AccessCertificate}

  @spec from_bin(binary) :: {:ok, t} | {:error, container_parser_error}
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
        content_type, encrypted_command_size::integer-32,
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
           content_type: ContentType.from_bin(content_type),
           version: 2
         }}

      v1_data ->
        to_struct_v1(v1_data)
    end
  end

  def to_bin(encrypted_container, session_key) do
    telematics_container = to_bin_message_container(encrypted_container)

    telematics_container_with_hmac =
      telematics_container <> Crypto.hmac(session_key, telematics_container)

    <<0x00>> <> add_paddings(telematics_container_with_hmac) <> <<0xFF>>
  end

  @spec validate_hmac(
          t,
          Crypto.private_key(),
          AccessCertificate.access_certificate_binary() | Crypto.public_key()
        ) :: :ok | {:error, :invalid_hmac}
  def validate_hmac(encrypted_container, private_key, public_key) do
    session_key = session_key(private_key, public_key, encrypted_container.nonce)

    if Crypto.hmac(session_key, to_bin_message_container(encrypted_container)) ==
         encrypted_container.hmac do
      :ok
    else
      {:error, :invalid_hmac}
    end
  end

  defp to_bin_message_container(encrypted_container) do
    request_id_data =
      <<byte_size(encrypted_container.request_id)::integer-16,
        encrypted_container.request_id::binary>>

    <<encrypted_container.version, encrypted_container.sender_serial::binary,
      encrypted_container.target_serial::binary, encrypted_container.nonce::binary,
      request_id_data::binary, encrypted_container.encrypted_flag,
      ContentType.to_bin(encrypted_container.content_type),
      byte_size(encrypted_container.encrypted_data)::integer-32,
      encrypted_container.encrypted_data::binary>>
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
