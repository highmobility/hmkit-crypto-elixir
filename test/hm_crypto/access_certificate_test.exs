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

defmodule HmAccessCertificateTest do
  use ExUnit.Case
  alias HmCrypto.{AccessCertificate, Issuer}

  @gaining_public_key Base.decode64!(
                        "K6wjT9+NY3vJjYFgI4H9ySFQBrOL0QXdixh5M9ZVcCiL1pGvr6SWs3G4cfCP5Z8jkdqRJQeOAohkU240ED57Mg=="
                      )
  @gaining_serial <<222, 144, 106, 246, 45, 114, 168, 80, 74>>
  @providing_serial <<1, 203, 202, 102, 243, 221, 30, 206, 82>>
  @permissions <<0x10, 0x07, 0xBF, 0xBF, 0x07>>
  @start_date "2018-09-17T07:28:11.191824Z"
  @end_date "2018-09-17T17:28:11.191824Z"
  @start_date_bin <<0x12, 0x09, 0x11, 0x07, 0x1C>>
  @end_date_bin <<0x12, 0x09, 0x11, 0x11, 0x1C>>

  @issuer_private_key Base.decode64!("dVcNF5Dt3anEnBNK8YVY5S/GYjD+0NoqditZ4TuSURM=")
  @issuer_public_key Base.decode64!(
                       "atCm1u2LiFWP4AW/gcUyopARRC4HtYTmnisiMcpcfp76KSpHtVUBGsO8lXfGuHjVtvck3CMEMpzsgMKjB1WeWg=="
                     )
  @issuer_identifier <<0x0, 0x0, 0x3, 0x4>>

  describe "Access Certificate payload" do
    setup [:dates]

    test "validate date conversion", %{start_date: start_date, end_date: end_date} do
      access_cert =
        AccessCertificate.new(
          @providing_serial,
          @gaining_serial,
          @gaining_public_key,
          start_date,
          end_date,
          @permissions
        )

      assert access_cert.start_date == @start_date_bin
      assert access_cert.end_date == @end_date_bin
    end

    test "create v1 payload", %{start_date: start_date, end_date: end_date} do
      access_cert =
        AccessCertificate.new(
          @providing_serial,
          @gaining_serial,
          @gaining_public_key,
          start_date,
          end_date,
          @permissions
        )

      assert cert_payload =
               AccessCertificate.payload(access_cert, %Issuer{name: @issuer_identifier})

      <<version, issuer_name::binary-4, providing_serial::binary-9, gaining_serial::binary-9,
        public_key::binary-64, dates::binary-10, perm_len, permissions::binary-5>> = cert_payload

      assert version == 1
      assert issuer_name == @issuer_identifier
      assert @providing_serial == providing_serial
      assert @gaining_serial == gaining_serial
      assert @gaining_public_key == public_key
      assert dates == @start_date_bin <> @end_date_bin
      assert perm_len == 5
      assert @permissions == permissions

      assert byte_size(cert_payload) == 103
      refute access_cert.signature
    end

    test "create v0 payload", %{start_date: start_date, end_date: end_date} do
      access_cert =
        AccessCertificate.new_with_version(
          :v0,
          @providing_serial,
          @gaining_serial,
          @gaining_public_key,
          start_date,
          end_date,
          @permissions
        )

      assert cert_payload =
               AccessCertificate.payload(access_cert, %Issuer{name: @issuer_identifier})

      <<gaining_serial::binary-9, _::binary>> = cert_payload
      assert @gaining_serial == gaining_serial

      refute access_cert.signature
    end
  end

  describe "sign Access Certificate" do
    setup [:dates]

    test "signs AccessCertificate v1", %{start_date: start_date, end_date: end_date} do
      access_cert =
        AccessCertificate.new(
          @gaining_serial,
          @gaining_public_key,
          @providing_serial,
          start_date,
          end_date,
          @permissions
        )

      issuer = %Issuer{name: @issuer_identifier, private_key: @issuer_private_key}
      payload = AccessCertificate.payload(access_cert, issuer)

      assert access_cert = AccessCertificate.sign(access_cert, issuer)

      assert HmCrypto.Crypto.verify(payload, access_cert.signature, @issuer_public_key)
    end

    test "payload shouldn't include the signature", %{start_date: start_date, end_date: end_date} do
      access_cert =
        AccessCertificate.new(
          @gaining_serial,
          @gaining_public_key,
          @providing_serial,
          start_date,
          end_date,
          @permissions
        )

      issuer = %Issuer{name: @issuer_identifier, private_key: @issuer_private_key}
      payload = AccessCertificate.payload(access_cert, issuer)

      assert access_cert = AccessCertificate.sign(access_cert, issuer)
      assert payload == AccessCertificate.payload(access_cert, issuer)

      assert HmCrypto.Crypto.verify(payload, access_cert.signature, @issuer_public_key)
    end
  end

  def dates(_) do
    {:ok, start_date, _} = DateTime.from_iso8601(@start_date)
    {:ok, end_date, _} = DateTime.from_iso8601(@end_date)
    %{start_date: start_date, end_date: end_date}
  end
end
