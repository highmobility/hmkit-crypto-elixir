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
  use PropCheck
  doctest HmCrypto.Crypto
  alias HmCrypto.Crypto

  @private_key_pem "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgs0lkcfIae/6+xoUx\nbkfzkAVWgAFk+b8m9rSDzf4ZwfyhRANCAAQz3HvOSI5mVfHvZ5THhbJLN+jj0oMd\nqz55J3bwxXb9yyqYsAubxrTh+nnsqmBQE9/XakF8r4cINscGdFCbcOtX\n-----END PRIVATE KEY-----\n\n"

  @private_key_binary <<179, 73, 100, 113, 242, 26, 123, 254, 190, 198, 133, 49, 110, 71, 243,
                        144, 5, 86, 128, 1, 100, 249, 191, 38, 246, 180, 131, 205, 254, 25, 193,
                        252>>

  @public_key_binary <<51, 220, 123, 206, 72, 142, 102, 85, 241, 239, 103, 148, 199, 133, 178, 75,
                       55, 232, 227, 210, 131, 29, 171, 62, 121, 39, 118, 240, 197, 118, 253, 203,
                       42, 152, 176, 11, 155, 198, 180, 225, 250, 121, 236, 170, 96, 80, 19, 223,
                       215, 106, 65, 124, 175, 135, 8, 54, 199, 6, 116, 80, 155, 112, 235, 87>>

  @public_key_pem "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM9x7zkiOZlXx72eUx4WySzfo49KD\nHas+eSd28MV2/csqmLALm8a04fp57KpgUBPf12pBfK+HCDbHBnRQm3DrVw==\n-----END PUBLIC KEY-----\n\n"

  describe "to_pem" do
    test "converts binary private key to pem" do
      assert {:ok, pem} = Crypto.to_pem(@private_key_binary, @public_key_binary)

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
      {public_key_binary, private_key_binary} = Crypto.generate_key()
      assert {:ok, pem_key} = Crypto.to_pem(private_key_binary, public_key_binary)
      assert {:ok, binary_key} = Crypto.from_pem(pem_key)
      assert private_key_binary == binary_key
    end
  end

  property "generate_key/0" do
    forall data <- [key: key_pair()] do
      {public_key, private_key} = data[:key]

      assert byte_size(public_key) == 64
      assert byte_size(private_key) == 32
    end
  end

  def key_pair do
    let _ <- any() do
      HmCrypto.Crypto.generate_key()
    end
  end
end
