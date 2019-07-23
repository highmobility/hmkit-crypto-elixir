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
  doctest HmCrypto.Container
  alias HmCrypto.Container

  @serial_number <<93, 151, 197, 254, 242, 65, 186, 175, 170>>
  @nonce <<0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08>>

  describe "error container" do
    test "internal_error" do
      container_error = Container.enclose_error(:internal_error, @serial_number, @nonce)

      assert Container.disclose_error(container_error) == {:ok, <<0x2, 0x00, 0x01>>}
    end

    test "timeout" do
      container_error = Container.enclose_error(:timeout, @serial_number, @nonce)

      assert Container.disclose_error(container_error) == {:ok, <<0x2, 0x00, 0x09>>}
    end

    test "invalid_data" do
      container_error = Container.enclose_error(:invalid_data, @serial_number, @nonce)

      assert Container.disclose_error(container_error) == {:ok, <<0x2, 0x01, 0x04>>}
    end

    test "invalid_hmac" do
      container_error = Container.enclose_error(:invalid_hmac, @serial_number, @nonce)

      assert Container.disclose_error(container_error) == {:ok, <<0x2, 0x36, 0x08>>}
    end

    test "disclose an error" do
      serial_number = <<0x0, 0xFF, 197, 254, 242, 65, 186, 175, 170>>
      container_error = Container.enclose_error(:invalid_hmac, serial_number, @nonce)

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
          data[:nonce]
        )

      case HmCrypto.Container.disclose(contained_msg, private_key, sample_access_cert()) do
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
          data[:nonce]
        )

      case HmCrypto.Container.disclose(contained_msg, private_key, sample_public_key()) do
        {:ok, cmd} -> cmd == data[:command]
        _ -> false
      end
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
