# HmKitCrypto

[![Build Status](https://github.com/highmobility/hmkit-crypto-elixir/workflows/CI/badge.svg)](https://github.com/highmobility/hmkit-crypto-elixir/actions)

HmCrypto is securing communication between two parties using public key infrastructure.

## Installation

# HmCrypto Elixir

Table of contents
=================
   * [Features](#features)
   * [Installation](#installation)
   * [Requirements](#requirements)
   * [Getting Started](#getting-started)
   * [Contributing](#contributing)
   * [License](#license)


## Features


**ECC**: Uses well established *Elliptic Curve Cryptography*'s curve *p256* (that is as secure as RSA, while having a smaller footprint).

**De-/Encrypt**: Enables simple encryption and decryption with *AES128*.

**Keys**: Perform *Diffie-Hellman*'s key exchange using *X9.63 SHA256* algorithm. Additionally
convert keys back and forth between bytes and Apple's `SecKey` format.

**Random**: Create pseudo-random bytes for cryptographic functions or as unique IDs.

**Signatures**: Create and verify *Elliptic Curve Digital Signature Algorithm* (ECDSA) *X9.62 SHA256* or *HMAC* signatures.


## Installation

The package can be installed
by adding `hm_crypto` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:hm_crypto, github: "highmobility/hmkit-crypto-elixir", tag: "v2.0.0"}
  ]
end
```

## Requirements

HmCrypto Elixir requires Elixir 1.8 or later and is compatible with apps targeting Erlang 21.0 or above.



## Getting Started

Get an overview by reading the security documentation [browse the documentation](https://high-mobility.com/learn/documentation/security/overview/).


## Contributing

We would love to accept your patches and contributions to this project. Before getting to work, please first discuss the changes that you wish to make with us via GitHub Issues, [Spectrum](https://spectrum.chat/high-mobility/) or [Slack](https://slack.high-mobility.com/).

See more in [CONTRIBUTING.md](CONTRIBUTING.md)


## License

This repository is using MIT license. See more in [LICENSE](LICENSE)
