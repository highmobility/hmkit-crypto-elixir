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
defmodule HmCrypto.Crypto do
  @signed_curve :secp256r1

  @type private_key :: <<_::256>>
  @type public_key :: <<_::512>>
  @type version :: :v1 | :v2
  @doc """
  Generates Key pair using public key ecdh algorithm and secp256r1 curve.

  It returns compact version of public key which is leading 0x4 is removed

      iex> {public_key, private_key} = HmCrypto.Crypto.generate_key
      iex> byte_size(public_key)
      64
      iex> byte_size(private_key)
      32

  """
  @spec generate_key() :: {public_key, private_key}
  def generate_key do
    {public_key, private_key} = :crypto.generate_key(:ecdh, :secp256r1)

    if byte_size(private_key) == 32 do
      <<0x4, public_key::binary>> = public_key
      {public_key, private_key}
    else
      <<0x4, public_key::binary>> = public_key
      {public_key, <<0x00>> <> private_key}
    end
  end

  @doc """
  Computes a HMAC of sha256 from message using key as the authentication key.

      iex> key = <<115, 228, 83, 59, 244, 133, 161, 194, 199, 241, 63, 123, 104, 1, 218, 147, 81, 95, 75, 191, 203, 174, 87, 44, 223, 32, 113, 121, 205, 50, 151, 177>>
      iex> message = <<40, 175, 134, 252, 218, 233, 81, 240, 96>>
      iex> HmCrypto.Crypto.hmac(key, message, :v1)
      <<165, 117, 127, 113, 199, 48, 40, 92, 16, 83, 172, 172, 120, 31, 145, 194, 252, 28, 21, 86, 108, 83, 131, 77, 160, 243, 233, 188, 211, 56, 0, 186>>

      iex> key = <<115, 228, 83, 59, 244, 133, 161, 194, 199, 241, 63, 123, 104, 1, 218, 147, 81, 95, 75, 191, 203, 174, 87, 44, 223, 32, 113, 121, 205, 50, 151, 177>>
      iex> message = <<40, 175, 134, 252, 218, 233, 81, 240, 96>>
      iex> HmCrypto.Crypto.hmac(key, message, :v2)
      <<185, 190, 231, 253, 176, 49, 208, 104, 185, 136, 191, 50, 64, 151, 1, 163, 172, 2, 184, 146, 234, 32, 241, 103, 193, 98, 79, 87, 17, 12, 169, 142>>
      iex> message = String.duplicate(<<0x01>>, 65)
      iex> HmCrypto.Crypto.hmac(key, message, :v2)
      <<83, 125, 18, 189, 5, 102, 116, 117, 160, 193, 19, 130, 164, 85, 201, 143, 175, 106, 15, 143, 156, 169, 7, 247, 175, 155, 98, 160, 196, 148, 39, 129>>

  """
  @spec hmac(binary, binary) :: binary
  def hmac(key, message) do
    hmac(key, message, :v2)
  end

  @spec hmac(binary, binary, version) :: binary
  def hmac(key, message, :v1) do
    message = expand_to_256(message)
    erl_crypto_hamc_func(key, message)
  end

  def hmac(key, message, :v2) do
    message = expand_to_64_blocks(message)
    erl_crypto_hamc_func(key, message)
  end

  @doc """
  Computes shared secret.

      iex> private_key = "9JFamPU0SF35y3c4TOt1frNwamZUQcUSD5dvOOu7xpw="
      iex> access_cert_v0 = "985tN4j0KNRqnpm0SD3UekJJLTS8nu5TBKUmcqDwjolao1UgGntXgs5hxdZIXu77up96IpwKUIyDVWjtamZwyaqk6AGdDC9SARqs41rSMcXruBEIAws1EQkCCzUHEAf//f/v/6+MpCSOvbhpyQpDnRYi89It6XqEm9TAevyFu3GrCLIbBWNk1rwuRmOL4KRhfSnMCNkhsHXCUvkEBU4SzUgcEvg="
      iex> HmCrypto.Crypto.compute_key(Base.decode64!(private_key), Base.decode64!(access_cert_v0)) |> Base.encode64
      "c+RTO/SFocLH8T97aAHak1FfS7/Lrlcs3yBxec0yl7E="
      iex> access_cert_v1 = "AXRtY3NOhYW633ctVZmRq+gXlHUSQ/a55N3sUZGUfAGaOfw+/C5DIhGelCWmClEWJEzLkmD5CzTbeHJTFBZ9Qh73mGX3XBhHFnFEc3DwETCyEW5YO0KGEQsdCRERDB0JEQcQB//9/+//KCBMF36Nt73aPCydO2Nt9+shOHtbHFSAIZSy/FRmIcH0z1d0PJRkwvPD2fLXicH2HYjDlYTaOhpTz0CpSoWfGg=="
      iex> HmCrypto.Crypto.compute_key(Base.decode64!(private_key), Base.decode64!(access_cert_v1)) |> Base.encode64
      "gPK2rZLowBWK1TE+Vm1JJZanwg42yynT3wOH9uX2av8="
  """
  @spec compute_key(
          private_key,
          HmCrypto.AccessCertificate.access_certificate_binary() | HmCrypto.Crypto.public_key()
        ) :: binary
  def compute_key(private_key, public_key) when byte_size(public_key) == 64 do
    private_key = private_key_record(private_key, <<>>)
    public_key = <<0x04>> <> public_key
    :public_key.compute_key({:ECPoint, public_key}, private_key)
  end

  def compute_key(private_key, access_cert) do
    pub =
      case access_cert do
        <<0x01, _beginning::binary-size(22), public_key::binary-size(64), _dates::binary-size(10),
          permissions_size, _permissions::binary-size(permissions_size),
          _signature::binary-size(64)>> ->
          public_key

        <<_::binary-size(9), public_key::binary-size(64), _::binary>> ->
          public_key
      end

    compute_key(private_key, pub)
  end

  @doc """
  Generates a signature for a message using elrang crypto

      iex> {public_key, private_key} = HmCrypto.Crypto.generate_key
      iex> signed_msg = HmCrypto.Crypto.sign("Blah Blah", private_key, :v2)
      iex> HmCrypto.Crypto.verify("Blah Blah", signed_msg, public_key, :v2)
      true

  read more at https://crypto.stackexchange.com/questions/1795/how-can-i-convert-a-der-ecdsa-signature-to-asn-1/1797#1797
  """
  @spec sign(binary, private_key) :: binary
  def sign(message, private_key) do
    sign(message, private_key, :v1)
  end

  @spec sign(binary, private_key, version) :: binary
  def sign(message, private_key, :v1) do
    message = expand_to_256(message)

    :ecdsa
    |> :crypto.sign(:sha256, message, [private_key, @signed_curve])
    |> strip_signature
  end

  def sign(message, private_key, :v2) do
    message = expand_to_64_blocks(message)

    :ecdsa
    |> :crypto.sign(:sha256, message, [private_key, @signed_curve])
    |> strip_signature
  end

  defp strip_signature(signature) do
    <<0x30, _b1, 0x02, b2, vr::binary-size(b2), 0x02, b3, vs::binary-size(b3)>> = signature
    sec_vr = String.trim_leading(vr, <<0x00>>)
    sec_vs = String.trim_leading(vs, <<0x00>>)

    (:binary.copy(<<0x00>>, 32 - byte_size(sec_vr)) <> sec_vr) <>
      :binary.copy(<<0x00>>, 32 - byte_size(sec_vs)) <> sec_vs
  end

  @doc """
  Generates a signature for a message using elrang crypto

      iex> {public_key, private_key} = HmCrypto.Crypto.generate_key
      iex> signed_msg = HmCrypto.Crypto.sign("Blah Blah", private_key, :v1)
      iex> HmCrypto.Crypto.verify("Blah Blah", signed_msg, public_key, :v1)
      true

  [Read more](https://crypto.stackexchange.com/questions/1795/how-can-i-convert-a-der-ecdsa-signature-to-asn-1/1797#1797)
  about converting ecdsa signature to asn
  """
  @spec verify(binary, binary, public_key) :: boolean
  def verify(message, signature, public_key) do
    verify(message, signature, public_key, :v1)
  end

  @spec verify(binary, binary, public_key, version) :: boolean
  def verify(message, signature, public_key, :v1) do
    message = expand_to_256(message)
    public_key = <<0x4>> <> public_key
    signature = signature

    :crypto.verify(:ecdsa, :sha256, message, fill_signature(signature), [
      public_key,
      @signed_curve
    ])
  end

  def verify(message, signature, public_key, :v2) do
    message = expand_to_64_blocks(message)
    public_key = <<0x4>> <> public_key
    signature = signature

    :crypto.verify(:ecdsa, :sha256, message, fill_signature(signature), [
      public_key,
      @signed_curve
    ])
  end

  @doc """
  Converts pair of keys or public key to pem

      {public_key, private_key} = Crypto.generate_key()
      Crypto.to_pem(public_key_binary)
      Crypto.to_pem(private_key, public_key_binary)
  """
  @spec to_pem(public_key) :: {:ok, String.t()} | {:error, atom}
  def to_pem(public_key) when byte_size(public_key) == 64 do
    public_key
    |> extended_public_key
    |> to_pem
  end

  def to_pem(public_key) when byte_size(public_key) == 65 do
    pem_entry =
      :public_key.pem_entry_encode(
        :SubjectPublicKeyInfo,
        {{:ECPoint, public_key}, {:namedCurve, :pubkey_cert_records.namedCurves(:secp256r1)}}
      )

    {:ok, :public_key.pem_encode([pem_entry])}
  end

  def to_pem(private_key, public_key)
      when byte_size(private_key) == 32 and byte_size(public_key) == 64 do
    to_pem(private_key, <<0x04>> <> public_key)
  end

  def to_pem(private_key, public_key)
      when byte_size(private_key) == 32 and byte_size(public_key) == 65 do
    pem_entry =
      :public_key.pem_entry_encode(
        :PrivateKeyInfo,
        private_key_record(private_key, public_key)
      )

    {:ok, :public_key.pem_encode([pem_entry])}
  end

  @doc """
  Converts public key or private key pem to its binary value
  """
  @spec from_pem(String.t()) :: {:ok, private_key | public_key} | {:error, atom}
  def from_pem(pem) do
    with [pem_decoded] <- :public_key.pem_decode(pem),
         {:ok, binary_key} <- extract_binary_from_pem(:public_key.pem_entry_decode(pem_decoded)) do
      {:ok, binary_key}
    else
      _ ->
        {:error, :invalid_pem}
    end
  end

  defp extended_public_key(public_key) do
    <<0x04>> <> public_key
  end

  defp extract_binary_from_pem({:ECPrivateKey, _, private_key, _, _}) do
    # Support OTP 23 and older
    {:ok, private_key}
  end

  defp extract_binary_from_pem({:ECPrivateKey, _, private_key, _, _, _}) do
    {:ok, private_key}
  end

  defp extract_binary_from_pem({{:ECPoint, <<0x04, public_key::binary-size(64)>>}, _}) do
    {:ok, public_key}
  end

  defp extract_binary_from_pem(_) do
    {:error, :unknown_key}
  end

  defp fill_signature(<<vr::binary-size(32), vs::binary-size(32)>>) do
    vr = String.trim_leading(vr, <<0x00>>)
    vs = String.trim_leading(vs, <<0x00>>)
    vr = prepand_zero_if_needed(vr)
    vs = prepand_zero_if_needed(vs)
    b2 = byte_size(vr)
    b3 = byte_size(vs)
    b1 = 4 + b2 + b3
    <<0x30, b1, 0x02, b2>> <> vr <> <<0x02, b3>> <> vs
  end

  defp fill_signature(_) do
    <<>>
  end

  defp prepand_zero_if_needed(<<1::size(1), _::size(7), _::binary>> = bytes) do
    <<0x00>> <> bytes
  end

  defp prepand_zero_if_needed(bytes), do: bytes

  defp expand_to_256(message) do
    message <> :binary.copy(<<0x00>>, 256 - byte_size(message))
  end

  defp expand_to_64_blocks(message)
       when byte_size(message) / 64 == round(byte_size(message) / 64) do
    message
  end

  defp expand_to_64_blocks(message) do
    message
    |> split_to_64_bytes
    |> Enum.map(fn
      b when byte_size(b) == 64 -> b
      b -> padding(b, 64)
    end)
    |> Enum.reduce(<<>>, fn x, acc -> acc <> x end)
  end

  defp split_to_64_bytes(<<>>), do: []

  defp split_to_64_bytes(data) when byte_size(data) <= 64 do
    [data]
  end

  defp split_to_64_bytes(data) when byte_size(data) > 64 do
    {chunk, rest} = :erlang.split_binary(data, 64)
    [chunk | split_to_64_bytes(rest)]
  end

  defp padding(message, size) do
    message <> :binary.copy(<<0x00>>, size - byte_size(message))
  end

  if String.to_integer(to_string(:erlang.system_info(:otp_release))) >= 24 do
    defp erl_crypto_hamc_func(key, message) do
      :crypto.mac(:hmac, :sha256, key, message)
    end

    defp private_key_record(private_key, public_key) do
      {:ECPrivateKey, 1, private_key, {:namedCurve, :pubkey_cert_records.namedCurves(:secp256r1)},
       public_key, :asn1_NOVALUE}
    end
  else
    defp erl_crypto_hamc_func(key, message) do
      :crypto.hmac(:sha256, key, message)
    end

    defp private_key_record(private_key, public_key) do
      {:ECPrivateKey, 1, private_key, {:namedCurve, :pubkey_cert_records.namedCurves(:secp256r1)},
       public_key}
    end
  end
end
