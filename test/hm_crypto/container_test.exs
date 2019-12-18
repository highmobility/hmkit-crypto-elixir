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

defmodule HmCrypto.ContainerTest do
  use ExUnit.Case
  use PropCheck
  # doctest HmCrypto.Container
  alias HmCrypto.{Container, Crypto, EncryptedContainer, ErrorContainer}

  @target_serial <<0xFF, 151, 197, 254, 242, 65, 186, 175, 0x00>>
  @serial_number <<93, 151, 197, 254, 242, 65, 186, 175, 170>>
  @nonce <<0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08>>

  describe "error container v1" do
    test "internal_error" do
      container_error = Container.enclose_error(:internal_error, @serial_number, @nonce, :v1)

      assert Container.disclose_error(container_error) == {:ok, <<0x2, 0x00, 0x01>>}
    end

    test "timeout" do
      container_error = Container.enclose_error(:timeout, @serial_number, @nonce, :v1)

      assert Container.disclose_error(container_error) == {:ok, <<0x2, 0x00, 0x09>>}
    end

    test "invalid_data" do
      container_error = Container.enclose_error(:invalid_data, @serial_number, @nonce, :v1)

      assert Container.disclose_error(container_error) == {:ok, <<0x2, 0x01, 0x04>>}
    end

    test "invalid_hmac" do
      container_error = Container.enclose_error(:invalid_hmac, @serial_number, @nonce, :v1)

      assert Container.disclose_error(container_error) == {:ok, <<0x2, 0x36, 0x08>>}
    end

    test "disclose an error" do
      serial_number = <<0x0, 0xFF, 197, 254, 242, 65, 186, 175, 170>>
      container_error = Container.enclose_error(:invalid_hmac, serial_number, @nonce, :v1)

      assert {:ok, _} = Container.destruct_container(container_error)

      assert Container.disclose_error(container_error) == {:ok, <<0x2, 0x36, 0x08>>}
    end

    test "returns error when Error container is encrypted" do
      encrypted_flag = 1

      container_error =
        <<0, 93, 151, 197, 254, 254, 242, 65, 186, 175, 170, 254, 0, 1, 2, 3, 4, 5, 6, 7, 8, 254,
          encrypted_flag, 2, 54, 8, 255>>

      assert Container.disclose_error(container_error) == {:error, :error_message_is_encrypted}
    end
  end

  describe "error container v2" do
    test "internal_error" do
      error_container_orginal = %ErrorContainer{
        sender_serial: @serial_number,
        target_serial: @target_serial,
        nonce: @nonce,
        version: 2,
        command: :internal_error,
        content_type: :unknown
      }

      error_container_bin = Container.enclose_error(error_container_orginal)

      assert {:ok, <<0x2, 0x00, 0x01>>} == Container.disclose_error(error_container_bin)
    end
  end

  describe "destruct_container/1" do
    test "returns error when container is short" do
      assert Container.destruct_container(<<>>) == {:error, :short_container}
    end

    test "returns error when container is invalid" do
      invalid_container = String.duplicate(<<0x00>>, 30)

      assert Container.destruct_container(invalid_container) ==
               {:error, :invalid_container_wrapper}
    end

    test "returns error when inside data of container is invalid" do
      serial_number = String.duplicate(<<0xFE>>, 18)
      nonce = String.duplicate(<<0x01>>, 9)

      invalid_container = <<0x0, serial_number::binary, nonce::binary, 0xFF>>

      assert Container.destruct_container(invalid_container) ==
               {:error, :invalid_container_property}
    end
  end

  describe "enclose/8 v2" do
    test "enclose a command in Telematics Container" do
      {_, alice_private_key} = Crypto.generate_key()
      {bob_public_key, _} = Crypto.generate_key()
      command = :crypto.strong_rand_bytes(20)
      nonce = :crypto.strong_rand_bytes(9)
      sender_serial = :crypto.strong_rand_bytes(9)
      target_serial = :crypto.strong_rand_bytes(9)
      request_id = :crypto.strong_rand_bytes(12)

      container =
        Container.new(%{
          version: 2,
          target_serial: target_serial,
          sender_serial: sender_serial,
          nonce: nonce,
          content_type: :unknown,
          command: command,
          request_id: request_id
        })

      telematics_container_bin =
        Container.enclose(
          container,
          alice_private_key,
          bob_public_key
        )

      assert {:ok, encrypted_container} = EncryptedContainer.from_bin(telematics_container_bin)
      assert encrypted_container.version == 2
      assert encrypted_container.sender_serial == sender_serial
      assert encrypted_container.target_serial == target_serial
      assert encrypted_container.request_id == request_id
      assert encrypted_container.nonce == nonce
      assert encrypted_container.content_type == :unknown

      assert :ok ==
               EncryptedContainer.validate_hmac(
                 encrypted_container,
                 alice_private_key,
                 bob_public_key
               )
    end
  end

  describe "encrypt_decrypt/3" do
    property "symmetric encrypt_decrypt a binary data" do
      forall data <- [
               alice_key_pair: key_pair(),
               bob_key_pair: key_pair(),
               nonce: serial_number(),
               raw_data: binary()
             ] do
        private_key = elem(data[:alice_key_pair], 1)

        public_key = elem(data[:bob_key_pair], 0)

        nonce = data[:nonce]
        raw_data = data[:raw_data]

        encrypted_data =
          HmCrypto.Container.encrypt_decrypt(
            raw_data,
            private_key,
            public_key,
            nonce
          )

        decrypted_data =
          HmCrypto.Container.encrypt_decrypt(
            encrypted_data,
            private_key,
            public_key,
            nonce
          )

        assert decrypted_data == raw_data
      end
    end
  end

  property "enclose v1 container" do
    forall data <- [
             device_serial: serial_number(),
             device_key_pair: key_pair(),
             nonce: serial_number(),
             command: binary()
           ] do
      private_key = elem(data[:device_key_pair], 1)

      contained_msg =
        HmCrypto.Container.enclose(
          data[:command],
          data[:device_serial],
          private_key,
          sample_access_cert(),
          data[:nonce],
          :v1
        )

      {:ok, encrypted_container} = EncryptedContainer.from_bin(contained_msg)
      assert encrypted_container.version == 1
      assert encrypted_container.sender_serial == data[:device_serial]
      assert encrypted_container.nonce == data[:nonce]
      assert encrypted_container.encrypted_flag == 1
    end
  end

  property "symmetric enclosing/disclosing a command" do
    forall data <- [
             device_serial: serial_number(),
             device_key_pair: key_pair(),
             nonce: serial_number(),
             command: binary()
           ] do
      private_key = elem(data[:device_key_pair], 1)

      contained_msg =
        HmCrypto.Container.enclose(
          data[:command],
          data[:device_serial],
          private_key,
          sample_access_cert(),
          data[:nonce],
          :v1
        )

      case HmCrypto.Container.disclose(contained_msg, private_key, sample_access_cert(), :v1) do
        {:ok, cmd} -> cmd == data[:command]
        _ -> false
      end
    end
  end

  property "symmetric enclosing/disclosing a command with public key" do
    forall data <- [
             device_serial: serial_number(),
             device_key_pair: key_pair(),
             nonce: serial_number(),
             command: binary()
           ] do
      private_key = elem(data[:device_key_pair], 1)

      contained_msg =
        HmCrypto.Container.enclose(
          data[:command],
          data[:device_serial],
          private_key,
          sample_public_key(),
          data[:nonce],
          :v1
        )

      case HmCrypto.Container.disclose(contained_msg, private_key, sample_public_key(), :v1) do
        {:ok, cmd} -> cmd == data[:command]
        _ -> false
      end
    end
  end

  describe "Container V2" do
    property "symmetric enclosing/disclosing a command with public key" do
      forall data <- [
               vehicle_serial: serial_number(),
               device_serial: serial_number(),
               device_key_pair: key_pair(),
               nonce: serial_number(),
               request_id: serial_number(),
               raw_data: binary()
             ] do
        private_key = elem(data[:device_key_pair], 1)

        container =
          Container.new(%{
            version: 2,
            target_serial: data[:device_serial],
            sender_serial: data[:vehicle_serial],
            nonce: data[:nonce],
            content_type: :auto_api,
            command: data[:raw_data],
            request_id: data[:request_id]
          })

        telematics_container_bin = Container.enclose(container, private_key, sample_public_key())

        case Container.disclose(
               telematics_container_bin,
               private_key,
               sample_public_key(),
               :v2
             ) do
          {:ok, raw_data} ->
            assert raw_data == data[:raw_data]

          _ ->
            false
        end
      end
    end

    test "fails to disclose not encrypted secure container" do
      invalid_data =
        <<0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 35, 96, 57, 137, 73, 93, 16, 219, 0, 181, 233, 8, 6,
          152, 161, 96, 125, 13, 44, 73, 42, 141, 244, 227, 154, 42, 177, 71, 37, 72, 202, 25,
          164, 153, 0, 28, 111, 145, 105, 87, 150, 238, 225, 92, 123, 111, 216, 8, 175, 32, 251,
          191, 252, 37, 104, 252, 40, 6, 105, 91, 166, 87, 50, 32, 55, 68, 159, 241, 56, 143, 35,
          191, 122, 45, 225, 26, 27, 196, 26, 93, 214, 37, 197, 38, 2, 76, 167, 45, 136, 255>>

      {_, alice_private_key} = Crypto.generate_key()
      {bob_public_key, _} = Crypto.generate_key()

      assert {:error, :unencrypted_command} =
               Container.disclose(
                 invalid_data,
                 alice_private_key,
                 bob_public_key
               )
    end

    test "decrypts all hardcoded example" do
      secure_container =
        <<0, 2, 14, 115, 145, 244, 96, 219, 211, 184, 51, 238, 74, 103, 237, 75, 106, 75, 218, 40,
          123, 199, 32, 242, 9, 60, 13, 115, 171, 254, 0, 254, 0, 1, 1, 254, 0, 254, 0, 254, 0, 4,
          90, 169, 20, 221, 155, 14, 192, 40, 100, 207, 40, 123, 104, 204, 193, 190, 208, 195,
          190, 147, 23, 105, 151, 184, 91, 167, 183, 71, 12, 111, 213, 254, 0, 178, 66, 151, 218,
          255>>

      vehicle_private_key =
        <<252, 90, 189, 47, 229, 16, 118, 234, 166, 180, 82, 56, 205, 236, 217, 219, 235, 184,
          114, 192, 28, 152, 251, 235, 210, 95, 30, 71, 18, 29, 166, 78>>

      vehicle_device_access_cert =
        <<1, 116, 109, 99, 115, 238, 74, 103, 237, 75, 106, 75, 218, 40, 14, 115, 145, 244, 96,
          219, 211, 184, 51, 59, 124, 2, 113, 175, 63, 184, 193, 161, 1, 50, 170, 28, 237, 186,
          133, 210, 45, 93, 245, 27, 73, 135, 255, 206, 165, 89, 1, 128, 170, 44, 74, 202, 119,
          158, 132, 15, 27, 12, 27, 100, 77, 91, 245, 130, 225, 81, 19, 242, 190, 68, 176, 124,
          88, 81, 0, 141, 72, 155, 68, 73, 40, 101, 77, 19, 12, 18, 3, 18, 24, 12, 18, 3, 18, 16,
          16, 7, 255, 253, 255, 239, 255, 255, 255, 255, 31, 0, 0, 0, 0, 0, 140, 239, 63, 134,
          115, 84, 180, 187, 4, 145, 86, 12, 191, 255, 85, 99, 234, 182, 204, 15, 169, 110, 159,
          172, 243, 124, 205, 48, 11, 251, 187, 205, 72, 6, 250, 170, 241, 255, 235, 33, 163, 177,
          33, 115, 101, 66, 14, 13, 202, 163, 205, 133, 181, 197, 210, 244, 70, 102, 13, 191, 33,
          214, 144, 156>>

      assert {:ok, encrypted_container} = EncryptedContainer.from_bin(secure_container)

      assert Container.disclose_encrypted_container(
               encrypted_container,
               vehicle_private_key,
               vehicle_device_access_cert
             ) == {:ok, <<11, 0, 17, 0>>}
    end
  end

  def serial_number do
    let _ <- any() do
      :crypto.strong_rand_bytes(9)
    end
  end

  def key_pair do
    let _ <- any() do
      HmCrypto.Crypto.generate_key()
    end
  end

  def sample_public_key do
    Base.decode64!(
      "npm0SD3UekJJLTS8nu5TBKUmcqDwjolao1UgGntXgs5hxdZIXu77up96IpwKUIyDVWjtamZwyaqk6AGdDC9SAQ=="
    )
  end

  def sample_access_cert do
    # TODO: improve AccessCertificate model to create them on the fly
    Base.decode64!(
      "985tN4j0KNRqnpm0SD3UekJJLTS8nu5TBKUmcqDwjolao1UgGntXgs5hxdZIXu77up96IpwKUIyDVWjtamZwyaqk6AGdDC9SARqs41rSMcXruBEIAws1EQkCCzUHEAf//f/v/6+MpCSOvbhpyQpDnRYi89It6XqEm9TAevyFu3GrCLIbBWNk1rwuRmOL4KRhfSnMCNkhsHXCUvkEBU4SzUgcEvg="
    )
  end
end
