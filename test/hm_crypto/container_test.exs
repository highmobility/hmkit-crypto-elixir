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
