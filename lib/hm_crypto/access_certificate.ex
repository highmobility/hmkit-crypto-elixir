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

defmodule HmCrypto.AccessCertificate do
  @moduledoc false
  @type access_certificate_binary :: <<_::1312>>

  alias __MODULE__
  alias HmCrypto.{Issuer, Crypto}

  defstruct version: :v0,
            gaining_serial: nil,
            gaining_public_key: nil,
            providing_serial: nil,
            start_date: nil,
            end_date: nil,
            permissions: nil,
            signature: nil,
            issuer: nil

  @type serial_number :: <<_::72>>
  @type version :: :v0 | :v1
  @type t :: %HmCrypto.AccessCertificate{
          version: version,
          gaining_serial: serial_number,
          gaining_public_key: Crypto.public_key(),
          providing_serial: serial_number,
          start_date: binary,
          end_date: binary,
          permissions: binary,
          signature: nil | binary,
          issuer: nil | Issuer.name()
        }

  @doc """
  Creates a new Access Certificate struct
  """
  @spec new(serial_number, Crypto.public_key(), serial_number, DateTime.t(), DateTime.t(), binary) ::
          t
  def new(
        providing_serial,
        gaining_serial,
        gaining_public_key,
        start_date,
        end_date,
        permissions
      ) do
    new_with_version(
      :v1,
      providing_serial,
      gaining_serial,
      gaining_public_key,
      start_date,
      end_date,
      permissions
    )
  end

  @doc """
  Creates a new Access Certificate struct with version
  """

  @spec new_with_version(
          version,
          serial_number,
          Crypto.public_key(),
          serial_number,
          DateTime.t(),
          DateTime.t(),
          binary
        ) :: t
  def new_with_version(
        version,
        providing_serial,
        gaining_serial,
        gaining_public_key,
        start_date,
        end_date,
        permissions
      ) do
    %AccessCertificate{
      version: version,
      gaining_serial: gaining_serial,
      providing_serial: providing_serial,
      gaining_public_key: gaining_public_key,
      start_date: encode_date(start_date),
      end_date: encode_date(end_date),
      permissions: permissions
    }
  end

  @doc """
  Signs AccessCertificate using issuer detail
  """
  @spec sign(t, Issuer.t()) :: t
  def sign(access_certificate, issuer) do
    access_certificate = %AccessCertificate{access_certificate | issuer: issuer.name}
    signature = HmCrypto.Crypto.sign(compact(access_certificate), issuer.private_key)

    %AccessCertificate{access_certificate | signature: signature}
  end

  @doc """
  Returns payload of AccessCertificate
  """
  @spec payload(t, Issuer.t()) :: binary
  def payload(access_certificate, issuer) do
    access_certificate
    |> Map.put(:issuer, issuer.name)
    |> compact()
  end

  defp compact(%AccessCertificate{issuer: nil_value, signature: nil_value})
       when is_nil(nil_value),
       do: raise(ArgumentError)

  defp compact(%AccessCertificate{version: :v0} = certificate) do
    permissions = certificate.permissions

    result =
      certificate.gaining_serial <>
        certificate.gaining_public_key <>
        certificate.providing_serial <>
        certificate.start_date <>
        certificate.end_date <> <<byte_size(permissions)::8>> <> permissions

    if is_nil(certificate.signature) do
      result
    else
      result <> certificate.signature
    end
  end

  defp compact(%AccessCertificate{version: :v1} = certificate) do
    permissions = certificate.permissions

    result =
      <<0x01>> <>
        certificate.issuer <>
        certificate.providing_serial <>
        certificate.gaining_serial <>
        certificate.gaining_public_key <>
        certificate.start_date <>
        certificate.end_date <> <<byte_size(permissions)::8>> <> permissions

    if is_nil(certificate.signature) do
      result
    else
      result <> certificate.signature
    end
  end

  defp encode_date(date) do
    date
    |> Timex.Timezone.convert("Etc/UTC")
    |> Timex.format!("%y,%m,%d,%H,%M", :strftime)
    |> String.split(",")
    |> Enum.map(&String.to_integer/1)
    |> :binary.list_to_bin()
  end
end
