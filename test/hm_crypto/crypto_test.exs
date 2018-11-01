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

defmodule HmCrypto.CryptoTest do
  use ExUnit.Case
  doctest HmCrypto.Crypto
  alias HmCrypto.Crypto

  @private_key_pem "-----BEGIN PRIVATE KEY-----\nMEYCAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcELDAqAgEBBCCzSWRx8hp7/r7GhTFu\nR/OQBVaAAWT5vyb2tIPN/hnB/KEDAwEA\n-----END PRIVATE KEY-----\n\n"

  @private_key_binary <<179, 73, 100, 113, 242, 26, 123, 254, 190, 198, 133, 49, 110, 71, 243,
                        144, 5, 86, 128, 1, 100, 249, 191, 38, 246, 180, 131, 205, 254, 25, 193,
                        252>>

  @public_key_binary <<134, 137, 240, 89, 153, 200, 168, 69, 241, 78, 123, 101, 246, 137, 86, 38,
                       212, 82, 171, 95, 195, 172, 11, 228, 242, 187, 38, 103, 215, 197, 150, 113,
                       83, 46, 73, 215, 5, 248, 14, 221, 22, 146, 30, 204, 26, 80, 134, 72, 158,
                       180, 236, 177, 184, 141, 241, 104, 82, 157, 151, 62, 152, 246, 237, 80>>

  @public_key_pem "-----BEGIN PUBLIC KEY-----\nMFowEwYHKoZIzj0CAQYIKoZIzj0DAQcDQwAEBIaJ8FmZyKhF8U57ZfaJVibUUqtf\nw6wL5PK7JmfXxZZxUy5J1wX4Dt0Wkh7MGlCGSJ607LG4jfFoUp2XPpj27VA=\n-----END PUBLIC KEY-----\n\n"

  describe "to_pem" do
    test "converts binary private key to pem" do
      assert {:ok, pem} = Crypto.to_pem(@private_key_binary)

      assert @private_key_pem == pem
    end

    test "converts binary public key to pem" do
      assert {:ok, pem} = Crypto.to_pem(@public_key_binary)
      assert @public_key_pem == pem
    end
  end

  describe "from_pem" do
    test "converts private key pem to binary" do
      assert {:ok, binary_key} = Crypto.from_pem(@private_key_pem)
      assert @private_key_binary == binary_key
    end

    test "converts public key pem to binary" do
      assert {:ok, binary_key} = Crypto.from_pem(@public_key_pem)
      assert @public_key_binary == binary_key
    end
  end

  describe "symmetric" do
    test "converts public key from bin to pem and reverse" do
      {public_key_binary, _} = Crypto.generate_key()
      assert {:ok, pem_key} = Crypto.to_pem(public_key_binary)
      assert {:ok, binary_key} = Crypto.from_pem(pem_key)
      assert public_key_binary == binary_key
    end

    test "converts private key from bin to pem and reverse" do
      {_, private_key_binary} = Crypto.generate_key()
      assert {:ok, pem_key} = Crypto.to_pem(private_key_binary)
      assert {:ok, binary_key} = Crypto.from_pem(pem_key)
      assert private_key_binary == binary_key
    end
  end
end
