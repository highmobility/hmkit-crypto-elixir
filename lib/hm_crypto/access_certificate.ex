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
  @spec payload(t, Issuer.t() | Issuer.name()) :: binary
  def payload(access_certificate, %Issuer{} = issuer) do
    payload(access_certificate, issuer.name)
  end

  def payload(access_certificate, issuer_name) do
    access_certificate
    |> Map.put(:issuer, issuer_name)
    |> compact()
  end

  @doc """
  converts AccessCertificate to binary value. The AccessCertificate should
  contain the signature when this function is called. You may use `payload/2`
  if only want the payload of AccessCertificate in binary
  """
  @spec to_bin(t) :: binary | no_return
  def to_bin(%AccessCertificate{issuer: nil}), do: raise(ArgumentError)
  def to_bin(%AccessCertificate{signature: nil}), do: raise(ArgumentError)

  def to_bin(%AccessCertificate{} = access_certificate) do
    compact(access_certificate) <> access_certificate.signature
  end

  defp compact(%AccessCertificate{version: :v0} = certificate) do
    permissions = certificate.permissions

    result =
      certificate.gaining_serial <>
        certificate.gaining_public_key <>
        certificate.providing_serial <>
        certificate.start_date <>
        certificate.end_date <> <<byte_size(permissions)::8>> <> permissions

    result
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

    result
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
