# ECIES - Elliptical Curve Integrated Encryption System

[![Build Status](https://travis-ci.org/jamoes/ecies.svg?branch=master)](https://travis-ci.org/jamoes/ecies)
[![Gem Version](https://badge.fury.io/rb/ecies.svg)](https://badge.fury.io/rb/ecies)

## Description

This library implements Elliptical Curve Integrated Encryption System (ECIES), as specified by [SEC 1: Elliptic Curve Cryptography, Version 2.0](http://www.secg.org/sec1-v2.pdf).

ECIES is a public-key encryption scheme based on ECC. It is designed to be semantically secure in the presence of an adversary capable of launching chosen-plaintext and chosen-ciphertext attacks.

ECIES can be used to encrypt messages to bitcoin addresses with keys published on the blockchain, and subsequently to decrypt messages by the holders of the address's private key.

## Installation

This library is distributed as a gem named [ecies](https://rubygems.org/gems/ecies) at RubyGems.org.  To install it, run:

    gem install ecies

## Usage

First, require the gem:

```ruby
require 'ecies'
```

Intitlialize a key and a `Crypt` object.

```ruby
key = OpenSSL::PKey::EC.new('secp256k1').generate_key
crypt = ECIES::Crypt.new
```

Next, we'll encrypt a message. Although in this example our key contains both the private and public components, you only need the key to contain the public component to encrypt a message.

```ruby
encrypted = crypt.encrypt(key, 'secret message')
```

Finally, decrypt the message. In order to decrypt, the key must contain the private component.

```ruby
crypt.decrypt(key, encrypted) # => "secret message"
```

### Encrypting a message to a Bitcoin address

Bitcoin P2PKH addresses themselves contain only *hashes* of public keys (hence the name, pay-to-public-key-hash). However, any time a P2PKH output is spent, the public key associated with the address is published on the blockchain in the transaction's scriptSig. This allows you to encrypt a message to any bitcoin address that has sent a transaction (or published its public key in other ways). To demonstrate this, we'll encrypt a message to Satoshi's public key from Bitcoin's genesis block:

```ruby
public_key = ECIES::Crypt.public_key_from_hex(
    "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb"\
    "649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")
encrypted = ECIES::Crypt.new.encrypt(public_key, 'you rock!')
```

To decrypt this message, Satoshi would follow these steps:

```ruby
private_key = ECIES::Crypt.private_key_from_hex("<satoshi's private key>")
ECIES::Crypt.new.decrypt(private_key, encrypted) # => "you rock!"
```

### Default parameters

By default, when constructing a new `ECIES::Crypt` object, it will use the following parameters for ECIES:

 - KDF: ANSI-X9.63-KDF with SHA256
 - MAC: HMAC-SHA-256-128
 - Cipher: AES-256-CTR
 - EC Group: secp256k1

These defaults work well for encrypting messages to bitcoin keys. This library also supports alternate algorithms as described in the below 'Compatibility' section. In order to utilize these other algorithms, initialize an `ECIES::Crypt` object with alternate parameters (see the `ECIES::Crypt.new` documentation for details). The `Crypt` object must be initialized with the same parameters when encrypting and decrypting messages.

## Compatibility

The sec1-v2 document allows for many combinations of various algorithms for ECIES. This library only supports a subset of the allowable algorithms:
  - Key Derivation Functions
    - Supported:
      - ANSI-X9.63-KDF
    - Not supported:
      - IKEv2-KDF
      - TLS-KDF
      - NIST-800-56-Concatenation-KDF
  - Hash Functions
    - Supported:
      - SHA-224
      - SHA-256
      - SHA-384
      - SHA-512
    - Not supported:
      - SHA-1
  - MAC Schemes
    - Supported:
      - HMAC-SHA-224-112
      - HMAC-SHA-224-224
      - HMAC-SHA-256-128
      - HMAC-SHA-256-256
      - HMAC-SHA-384-192
      - HMAC-SHA-384-384 (I believe sec1-v2 has a typo here, they state "HMAC-SHA-384-284". 284 bits would be 35.5 bytes, which is nonsensical)
      - HMAC-SHA-512-256
      - HMAC-SHA-512-512
    - Not supported:
      - HMAC-SHA-1-160
      - HMAC-SHA-1-80
      - CMAC-AES-128
      - CMAC-AES-192
      - CMAC-AES-256
  - Symmetric Encryption Schemes
    - Supported:
      - AES-128-CBC
      - AES-192-CBC
      - AES-256-CBC
      - AES-128-CTR
      - AES-192-CTR
      - AES-256-CTR
    - Not supported:
      - 3-key TDES in CBC mode
      - XOR encryption scheme

In addition, the following options have been chosen:
  - Elliptical curve points are represented in compressed form.
  - Benign malleability is prevented by including the ephemeral public key as an input to the KDF (sec1-v2 p97).

## Supported platforms

Ruby 2.0 and above.

## Contributing

Bug reports and pull requests welcome! I happily accept any feedback that can improve this library's security.

## Disclaimer

While I have taken every effort to make this library as secure as possible, it is still an early version and has not yet been reviewed by a wide audience. Use at your own risk.

## Documentation

For complete documentation, see the [ECIES page on RubyDoc.info](http://rubydoc.info/gems/ecies).
