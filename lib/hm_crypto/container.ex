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

defmodule HMCrypto.Container do
  @moduledoc """
  Enclose / Disclose a commands
  """

  alias HMCrypto.Crypto

  @type disclose_error ::
          :invalid_hmac | :invalid_secure_command | :invalid_secure_command | :unencrypted_command
  @type nonce :: <<_::72>>
  @type command :: binary
  @type secure_command :: binary
  @type serial_number :: binary

  @doc """
  Creates a secure container command. It also escapes [0x00, 0xFE, 0xFF] with [orignal, 0xFE].

  When a party with this given serial_number and private_key want's to make HM container binary for other
  party using provided access_certificate

      iex> serial_number = <<93, 151, 197, 254, 242, 65, 186, 175, 170>>
      iex> private_key = "9JFamPU0SF35y3c4TOt1frNwamZUQcUSD5dvOOu7xpw="
      iex> access_cert = "985tN4j0KNRqnpm0SD3UekJJLTS8nu5TBKUmcqDwjolao1UgGntXgs5hxdZIXu77up96IpwKUIyDVWjtamZwyaqk6AGdDC9SARqs41rSMcXruBEIAws1EQkCCzUHEAf//f/v/6+MpCSOvbhpyQpDnRYi89It6XqEm9TAevyFu3GrCLIbBWNk1rwuRmOL4KRhfSnMCNkhsHXCUvkEBU4SzUgcEvg="
      iex> nonce = <<0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08>>
      iex> contained_msg = HMCrypto.Container.enclose(<<0x00>>, serial_number, Base.decode64!(private_key), Base.decode64!(access_cert), nonce)
      <<0x0, 0x5D, 0x97, 0xC5, 0xFE, 0xFE, 0xF2, 0x41, 0xBA, 0xAF, 0xAA, 0xFE, 0x0, \
      0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x1, 0xBC, 0xF5, 0x77, 0x41, 0xE9, \
      0xDD, 0x8F, 0x53, 0xD2, 0xFA, 0x2E, 0x19, 0xEE, 0x7A, 0xAF, 0x31, 0x5F, 0xB3, \
      0x11, 0xC7, 0xA0, 0xE9, 0x54, 0x2B, 0x2D, 0x25, 0x1F, 0x6F, 0xD, 0x7D, 0x45, \
      0xA4, 0x6C, 0x92, 0xEC, 0xC9, 0xE5, 0xFF>>
      iex> HMCrypto.Container.disclose(contained_msg, Base.decode64!(private_key), Base.decode64!(access_cert))
      {:ok, <<0x00>>}
  """
  @spec enclose(
          command,
          serial_number,
          HmAutoApi.Crypto.private_key(),
          HMCrypto.AccessCertificate.access_certificate(),
          nonce
        ) :: secure_command
  def enclose(command, serial_number, private_key, access_certificate, nonce) do
    data = enclose_command(command, private_key, access_certificate, nonce)
    <<0x00>> <> add_paddings(serial_number <> nonce <> <<0x01>> <> data) <> <<0xFF>>
  end

  @doc """
  Parses a secure_command and return the raw command unencrypted.

  Returns {:error, reason} if the provided command has encrypted_flag off or the data is not acceptable.

      iex> unencrypted_command = <<0x0, 0x5D, 0x97, 0xC5, 0xFE, 0xFE, 0xF2, 0x41, 0xBA, 0xAF, 0xAA, 0xFE, 0x0,\
                                  0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, \
                                  0xFE, 0x0, 0xFE, 0x0, 0x2, 0xFE, 0x0, 0xFE, 0x0, 0xFF>>
      iex> HMCrypto.Container.disclose(unencrypted_command, <<0x67, 0x61, 0x72, 0x62, 0x61, 0x67, 0x65>>, <<0x67, 0x61, 0x72, 0x62, 0x61, 0x67, 0x65>>)
      {:error, :unencrypted_command}
  """
  @spec disclose(
          secure_command,
          Crypto.private_key(),
          HMCrypto.AccessCertificate.access_certificate()
        ) :: {:ok, command} | {:error, disclose_error}
  def disclose(container_data, private_key, access_certificate) do
    %{command: command, encrypted_flag: encrypted_flag?, car_serial: _, nonce: nonce} =
      destruct_container(container_data)

    if encrypted_flag? == 0x00 do
      {:error, :unencrypted_command}
    else
      disclose_command(command, private_key, access_certificate, nonce)
    end
  end

  @doc """
  Parses an Error command.

  When `disclose` command returns {:error, :unencrypted_command}, the only acceptable command is when it's an error message.

  This function removes the paddings and container from the `container_data` and returns the raw command

      iex> unencrypted_command = <<0x0, 0x5D, 0x97, 0xC5, 0xFE, 0xFE, 0xF2, 0x41, 0xBA, 0xAF, 0xAA, 0xFE, 0x0,\
                                  0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, \
                                  0xFE, 0x0, 0xFE, 0x0, 0x2, 0xFE, 0x0, 0xFE, 0x0, 0xFF>>
      iex> HMCrypto.Container.disclose_error(unencrypted_command)
      <<0x02, 0x00, 0x00>>
  """
  def disclose_error(container_data) do
    %{command: command, encrypted_flag: 0x00} = destruct_container(container_data)
    command
  end

  defp destruct_container(command) do
    inside_size = byte_size(command) - 2
    <<0x00, inside_data::binary-size(inside_size), 0xFF>> = command
    inside_data = remove_paddings(inside_data)

    <<car_serial::binary-size(9), nonce::binary-size(9), encrypted_flag, command::binary>> =
      inside_data

    %{car_serial: car_serial, nonce: nonce, command: command, encrypted_flag: encrypted_flag}
  end

  defp add_paddings(<<>>), do: <<>>

  defp add_paddings(<<first_byte>> <> rest) do
    escape_byte(first_byte) <> add_paddings(rest)
  end

  defp escape_byte(byte) when byte in [0x00, 0xFE, 0xFF], do: <<0xFE, byte>>
  defp escape_byte(byte), do: <<byte>>

  defp remove_paddings(<<>>) do
    <<>>
  end

  defp remove_paddings(<<0xFE, data, rest::binary>>) do
    <<data>> <> remove_paddings(rest)
  end

  defp remove_paddings(<<data, rest::binary>>) do
    <<data>> <> remove_paddings(rest)
  end

  @doc """
  Encloses & encrypts command in a container

  Steps:

    1. Uses private_key and access_certificate to compute key
    2. Creates session_key(hmac) using compute_key as key and nonce as message
    3. Builds the continaer by concatenating <<0x036, 0x01, size of command>> and command
    4. Creates signature using session_key as result of step 3 as message
    5. Creates block encrypt using session key(first 16 byte) and nonce(first 7 bytes)
    6. Expands Encrypt binary from step 5 and matches the size of step 3 binary
    7. XOR steps 6 result with step 3 binary



  ```
  iex> private_key = "9JFamPU0SF35y3c4TOt1frNwamZUQcUSD5dvOOu7xpw="
  iex> access_cert = "985tN4j0KNRqnpm0SD3UekJJLTS8nu5TBKUmcqDwjolao1UgGntXgs5hxdZIXu77up96IpwKUIyDVWjtamZwyaqk6AGdDC9SARqs41rSMcXruBEIAws1EQkCCzUHEAf//f/v/6+MpCSOvbhpyQpDnRYi89It6XqEm9TAevyFu3GrCLIbBWNk1rwuRmOL4KRhfSnMCNkhsHXCUvkEBU4SzUgcEvg="
  iex> nonce = <<0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08>>
  iex> encrypted_data = HMCrypto.Container.enclose_command(<<0x00>>, Base.decode64!(private_key), Base.decode64!(access_cert), nonce)
  <<188, 245, 119, 65, 233, 221, 143, 83, 210, 250, 46, 25, 238, 122, \
      175, 49, 95, 179, 17, 199, 160, 233, 84, 43, 45, 37, 31, 111, 13, 125, 69, 164, 108, 146, 236, 201, 229>>
  iex> HMCrypto.Container.disclose_command(encrypted_data, Base.decode64!(private_key), Base.decode64!(access_cert), nonce)
  {:ok, <<0x00>>}
  """
  @spec enclose_command(
          binary,
          Crypto.private_key(),
          HMCrypto.AccessCertificate.access_certificate(),
          Container.nonce()
        ) :: binary
  def enclose_command(command, private_key, access_certificate, nonce) do
    session_key =
      private_key
      |> Crypto.compute_key(access_certificate)
      |> Crypto.hmac(nonce)

    command_with_padding = <<0x36, 0x01, byte_size(command)::integer-16>> <> command

    command_container_bytes =
      command_with_padding <> Crypto.hmac(session_key, command_with_padding)

    :aes_ecb
    |> :crypto.block_encrypt(encryption_key(session_key), encryption_iv(nonce))
    |> duplicate_cipher(byte_size(command_container_bytes))
    |> xor(command_container_bytes)
  end

  @doc """
  Discloses and decrypts container data into a command
  """
  @spec disclose_command(
          binary,
          Crypto.private_key(),
          HMCrypto.AccessCertificate.access_certificate(),
          Container.nonce()
        ) :: {:ok, binary} | {:error, disclose_error}
  def disclose_command(encrypted_command, private_key, access_certificate, nonce) do
    session_key =
      private_key
      |> Crypto.compute_key(access_certificate)
      |> Crypto.hmac(nonce)

    :aes_ecb
    |> :crypto.block_encrypt(encryption_key(session_key), encryption_iv(nonce))
    |> duplicate_cipher(byte_size(encrypted_command))
    |> xor(encrypted_command)
    |> validate_secure_command(session_key)
  end

  defp validate_secure_command(
         <<0x36, 0x1, cmd_size::integer-16, cmd::binary-size(cmd_size), hmac::binary-size(32)>>,
         session_key
       ) do
    if Crypto.hmac(session_key, <<0x36, 0x01, cmd_size::integer-16>> <> cmd) == hmac do
      {:ok, cmd}
    else
      {:error, :invalid_hmac}
    end
  end

  defp validate_secure_command(<<0x36, 0x0, cmd_size::integer-16, cmd::binary-size(cmd_size)>>, _) do
    {:ok, cmd}
  end

  defp validate_secure_command(_, _) do
    {:error, :invalid_secure_command}
  end

  defp encryption_iv(iv) do
    <<sub_iv::binary-size(7), _::binary>> = iv
    sub_iv <> iv
  end

  defp encryption_key(key) do
    <<sub_key::binary-size(16), _::binary>> = key
    sub_key
  end

  defp duplicate_cipher(cipher, len) do
    times = round(Float.ceil(len / byte_size(cipher)))
    cipher = :binary.copy(cipher, times)
    <<cipher::binary-size(len), _::binary>> = cipher
    cipher
  end

  defp xor(first_bin, second_bin) do
    first_bin
    |> :binary.bin_to_list()
    |> Enum.zip(:binary.bin_to_list(second_bin))
    |> Enum.map(fn {x, y} -> :erlang.bxor(x, y) end)
    |> :binary.list_to_bin()
  end
end
