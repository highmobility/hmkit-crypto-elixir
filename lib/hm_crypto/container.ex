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
defmodule HmCrypto.Container do
  @moduledoc """
  Enclose / Disclose a commands
  """

  alias HmCrypto.{Crypto, EncryptedContainer, ErrorContainer, ContentType}
  import HmCrypto.ContainerHelper

  defstruct target_serial: <<>>,
            sender_serial: <<>>,
            version: 1,
            request_id: <<>>,
            nonce: <<>>,
            command: <<>>,
            encrypted_flag: 0,
            content_type: :unknown

  @type t :: %__MODULE__{
          target_serial: <<_::72>>,
          nonce: <<_::72>>,
          command: binary,
          encrypted_flag: integer,
          content_type: ContentType.t()
        }

  @type container_parser_error ::
          :short_container
          | :invalid_container_wrapper
          | :invalid_container_property

  @type disclose_error ::
          :invalid_hmac
          | :invalid_secure_command
          | :unencrypted_command
          | :internal_error
          | :invalid_data
          | :timeout
  @type nonce :: <<_::72>>
  @type command :: binary
  @type data :: binary
  @type secure_command :: binary
  @type unsecure_command :: binary
  @type serial_number :: <<_::72>>

  @errror_internal_error <<0x00, 0x01>>
  @error_invalid_data <<0x01, 0x04>>
  @error_timeout <<0x00, 0x09>>
  @error_invalid_hmac <<0x36, 0x08>>

  @doc """
  Create new empty Container struct
  """
  @spec new(map) :: t
  def new(params \\ %{version: 2}) do
    struct(__MODULE__, params)
  end

  @doc """
  Encrypts/Decrypts the data
  """
  @spec encrypt_decrypt(data, Crypto.private_key(), Crypto.public_key(), nonce) :: binary
  def encrypt_decrypt(data, my_private_key, other_public_key, nonce) do
    session_key = session_key(my_private_key, other_public_key, nonce)

    :aes_ecb
    |> erl_crypto_encrypt_decrypt(encryption_key(session_key), encryption_iv(nonce))
    |> duplicate_cipher(byte_size(data))
    |> xor(data)
  end

  @doc """
  Creates a secure container command. It also escapes [0x00, 0xFE, 0xFF] with [orignal, 0xFE].

  When a party with this given serial_number and private_key want's to make HM container binary for other
  party using provided access_certificate

      iex> serial_number = <<93, 151, 197, 254, 242, 65, 186, 175, 170>>
      iex> private_key = "9JFamPU0SF35y3c4TOt1frNwamZUQcUSD5dvOOu7xpw="
      iex> access_cert = "985tN4j0KNRqnpm0SD3UekJJLTS8nu5TBKUmcqDwjolao1UgGntXgs5hxdZIXu77up96IpwKUIyDVWjtamZwyaqk6AGdDC9SARqs41rSMcXruBEIAws1EQkCCzUHEAf//f/v/6+MpCSOvbhpyQpDnRYi89It6XqEm9TAevyFu3GrCLIbBWNk1rwuRmOL4KRhfSnMCNkhsHXCUvkEBU4SzUgcEvg="
      iex> nonce = <<0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08>>
      iex> contained_msg = HmCrypto.Container.enclose(<<0x00>>, serial_number, Base.decode64!(private_key), Base.decode64!(access_cert), nonce, :v1)
      <<0x0, 0x5D, 0x97, 0xC5, 0xFE, 0xFE, 0xF2, 0x41, 0xBA, 0xAF, 0xAA, 0xFE, 0x0, \
      0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x1, 0xBC, 0xF5, 0x77, 0x41, 0xE9, \
      0xDD, 0x8F, 0x53, 0xD2, 0xFA, 0x2E, 0x19, 0xEE, 0x7A, 0xAF, 0x31, 0x5F, 0xB3, \
      0x11, 0xC7, 0xA0, 0xE9, 0x54, 0x2B, 0x2D, 0x25, 0x1F, 0x6F, 0xD, 0x7D, 0x45, \
      0xA4, 0x6C, 0x92, 0xEC, 0xC9, 0xE5, 0xFF>>
      iex> HmCrypto.Container.disclose(contained_msg, Base.decode64!(private_key), Base.decode64!(access_cert), :v1)
      {:ok, <<0x00>>}
  """
  @spec enclose(
          command,
          serial_number,
          Crypto.private_key(),
          HmCrypto.AccessCertificate.access_certificate_binary() | Crypto.public_key(),
          nonce,
          :v1
        ) :: secure_command
  def enclose(command, serial_number, private_key, access_certificate, nonce, :v1) do
    session_key = session_key(private_key, access_certificate, nonce)

    command_with_padding = <<0x36, 0x01, byte_size(command)::integer-16>> <> command

    command_container_bytes =
      command_with_padding <> Crypto.hmac(session_key, command_with_padding)

    data = encrypt_decrypt(command_container_bytes, private_key, access_certificate, nonce)

    <<0x00>> <> add_paddings(serial_number <> nonce <> <<0x01>> <> data) <> <<0xFF>>
  end

  @spec enclose(
          t,
          Crypto.private_key(),
          HmCrypto.AccessCertificate.access_certificate_binary() | Crypto.public_key()
        ) :: secure_command
  def enclose(container, private_key, public_key) do
    session_key = session_key(private_key, public_key, container.nonce)

    data = encrypt_decrypt(container.command, private_key, public_key, container.nonce)

    container = %EncryptedContainer{
      target_serial: container.target_serial,
      sender_serial: container.sender_serial,
      encrypted_flag: 0x01,
      nonce: container.nonce,
      encrypted_data: data,
      request_id: container.request_id,
      content_type: container.content_type,
      version: container.version
    }

    EncryptedContainer.to_bin(container, session_key)
  end

  @doc """
  Create an Error container.

      iex> error_cmd = <<0x02, 0x36, 0x08>>
      iex> serial_number = <<93, 151, 197, 254, 242, 65, 186, 175, 170>>
      iex> nonce = <<0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08>>
      iex> error_container = HmCrypto.Container.enclose_error(error_cmd, serial_number, nonce)
      iex> HmCrypto.Container.disclose_error(error_container)
      {:ok, <<0x02,0x36, 0x08>>}
  """
  @spec enclose_error(
          command | disclose_error,
          serial_number,
          nonce,
          :v1
        ) :: unsecure_command
  def enclose_error(command, serial_number, nonce, :v1) when is_binary(command) do
    <<0x00>> <> add_paddings(serial_number <> nonce <> <<0x00>> <> command) <> <<0xFF>>
  end

  def enclose_error(:internal_error, serial_number, nonce, version) do
    enclose_error(<<0x02>> <> @errror_internal_error, serial_number, nonce, version)
  end

  def enclose_error(:timeout, serial_number, nonce, version) do
    enclose_error(<<0x02>> <> @error_timeout, serial_number, nonce, version)
  end

  def enclose_error(error_atom, serial_number, nonce, version)
      when error_atom in [:invalid_data, :unencrypted_command] do
    enclose_error(<<0x02>> <> @error_invalid_data, serial_number, nonce, version)
  end

  def enclose_error(error_atom, serial_number, nonce, version)
      when error_atom in [:invalid_hmac, :invalid_secure_command] do
    enclose_error(<<0x02>> <> @error_invalid_hmac, serial_number, nonce, version)
  end

  def enclose_error(error_container) do
    ErrorContainer.to_bin(error_container)
  end

  @doc """
  Parses a secure_command and return the raw command unencrypted.

  Returns {:error, reason} if the provided command has encrypted_flag off or the data is not acceptable.

      iex> unencrypted_command = <<0x0, 0x5D, 0x97, 0xC5, 0xFE, 0xFE, 0xF2, 0x41, 0xBA, 0xAF, 0xAA, 0xFE, 0x0,\
                                  0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, \
                                  0xFE, 0x0, 0xFE, 0x0, 0x2, 0xFE, 0x0, 0xFE, 0x0, 0xFF>>
      iex> HmCrypto.Container.disclose(unencrypted_command, <<0x67, 0x61, 0x72, 0x62, 0x61, 0x67, 0x65>>, <<0x67, 0x61, 0x72, 0x62, 0x61, 0x67, 0x65>>, :v1)
      {:error, :unencrypted_command}
  """

  @spec disclose(
          secure_command,
          Crypto.private_key(),
          HmCrypto.AccessCertificate.access_certificate_binary() | HmCrypto.Crypto.public_key()
        ) :: {:ok, command} | {:error, disclose_error} | {:error, container_parser_error}
  def disclose(secure_command, private_key, public_key) do
    disclose(secure_command, private_key, public_key, :v2)
  end

  def disclose(container_data, private_key, access_certificate, :v1) do
    with {:ok, container} <- destruct_container(container_data),
         {:ok, :encrypted} <- encrypted?(container.encrypted_flag) do
      disclose_command(container.encrypted_data, private_key, access_certificate, container.nonce)
    else
      {:ok, :not_encrypted} ->
        {:error, :unencrypted_command}

      error ->
        error
    end
  end

  def disclose(secure_command, private_key, public_key, :v2) do
    with {:ok, encrypted_container} <- EncryptedContainer.from_bin(secure_command) do
      disclose_encrypted_container(encrypted_container, private_key, public_key)
    end
  end

  def disclose_encrypted_container(encrypted_container, private_key, public_key) do
    with {:ok, :encrypted} <- encrypted?(encrypted_container.encrypted_flag),
         :ok <-
           EncryptedContainer.validate_hmac(
             encrypted_container,
             private_key,
             public_key
           ) do
      {:ok,
       encrypt_decrypt(
         encrypted_container.encrypted_data,
         private_key,
         public_key,
         encrypted_container.nonce
       )}
    else
      {:ok, :not_encrypted} ->
        {:error, :unencrypted_command}

      error ->
        error
    end
  end

  @doc """
  Parses an Error command.

  When `disclose` command returns {:error, :unencrypted_command}, the only acceptable command is when it's an error message.

  This function removes the paddings and container from the `container_data` and returns the raw command

      iex> unencrypted_command = <<0x0, 0x5D, 0x97, 0xC5, 0xFE, 0xFE, 0xF2, 0x41, 0xBA, 0xAF, 0xAA, 0xFE, 0x0,\
                                  0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, 0xFE, 0x0, \
                                  0xFE, 0x0, 0xFE, 0x0, 0x2, 0xFE, 0x0, 0xFE, 0x0, 0xFF>>
      iex> HmCrypto.Container.disclose_error(unencrypted_command)
      {:ok, <<0x02, 0x00, 0x00>>}
  """
  @spec disclose_error(binary) ::
          {:error, :error_message_is_encrypted} | {:error, container_parser_error}
  def disclose_error(error_container_binary) do
    with {:ok, %{encrypted_flag: encrypted_flag} = error_container} <-
           ErrorContainer.from_bin(error_container_binary),
         {:ok, :not_encrypted} <- encrypted?(encrypted_flag) do
      {:ok, error_container.command_binary}
    else
      {:ok, :encrypted} -> {:error, :error_message_is_encrypted}
      error -> error
    end
  end

  @doc """
  Destruct container binary to `%Container{}`

      iex> serial_number = <<93, 151, 197, 254, 242, 65, 186, 175, 170>>
      iex> private_key = "9JFamPU0SF35y3c4TOt1frNwamZUQcUSD5dvOOu7xpw="
      iex> access_cert = "985tN4j0KNRqnpm0SD3UekJJLTS8nu5TBKUmcqDwjolao1UgGntXgs5hxdZIXu77up96IpwKUIyDVWjtamZwyaqk6AGdDC9SARqs41rSMcXruBEIAws1EQkCCzUHEAf//f/v/6+MpCSOvbhpyQpDnRYi89It6XqEm9TAevyFu3GrCLIbBWNk1rwuRmOL4KRhfSnMCNkhsHXCUvkEBU4SzUgcEvg="
      iex> nonce = :crypto.strong_rand_bytes(9)
      iex> contained_msg = HmCrypto.Container.enclose(<<0x00>>, serial_number, Base.decode64!(private_key), Base.decode64!(access_cert), nonce, :v1)
      iex> {:ok, container} = HmCrypto.Container.destruct_container(contained_msg)
      iex> container.nonce == nonce
      true
      iex> container.encrypted_flag == 1
      true
      iex> container.sender_serial == serial_number
      true
  """
  @spec destruct_container(binary) :: {:ok, map} | {:error, container_parser_error}
  def destruct_container(container_data) when byte_size(container_data) > 21 do
    EncryptedContainer.from_bin(container_data)
  end

  def destruct_container(_) do
    {:error, :short_container}
  end

  @doc """
  Discloses and decrypts container data into a command
  """
  @spec disclose_command(
          binary,
          Crypto.private_key(),
          HmCrypto.AccessCertificate.access_certificate_binary() | Crypto.public_key(),
          nonce()
        ) :: {:ok, binary} | {:error, disclose_error}
  def disclose_command(encrypted_command, private_key, access_certificate, nonce) do
    session_key =
      private_key
      |> Crypto.compute_key(access_certificate)
      |> Crypto.hmac(nonce)

    encrypted_command
    |> encrypt_decrypt(private_key, access_certificate, nonce)
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

  defp encrypted?(0x00), do: {:ok, :not_encrypted}
  defp encrypted?(_), do: {:ok, :encrypted}

  if String.to_integer(to_string(:erlang.system_info(:otp_release))) >= 24 do
    defp erl_crypto_encrypt_decrypt(cipher, key, iv) do
      :crypto.crypto_one_time(cipher, key, iv, [])
    end
  else
    defp erl_crypto_encrypt_decrypt(cipher, key, iv) do
      :crypto.block_encrypt(cipher, key, iv)
    end
  end
end
