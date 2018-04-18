# ECIES - Elliptical Curve Integrated Encryption System

[![Build Status](https://travis-ci.org/jamoes/ecies.svg?branch=master)](https://travis-ci.org/jamoes/ecies)

## Description

This library implements Elliptical Curve Integrated Encryption System (ECIES), as specified by [SEC 1: Elliptic Curve Cryptography, Version 2.0](http://www.secg.org/sec1-v2.pdf).

ECIES is a public-key encryption scheme based on ECC. It is designed to be semantically secure in the presence of an adversary capable of launching chosen-plaintext and chosen-ciphertext attacks.

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
key = OpenSSL::PKey::EC.new('secp256k1').generate_key!
crypt = ECIES::Crypt.new
```

Next, we'll encrypt a message. Although in this example our key contains both the private and public components, you only need the key to contain the public component to encrypt a message.

```ruby
encrypted = crypt.encrypt(key, 'secret message')
```

Finally, decrypt the message. In order to decrypt, the key must contain the private component.

```ruby
crypt.decrypt(key, encrypted) # => 'secret message'
```

When constructing a `Crypt` object, the default hash digest function is 'SHA256', and the default cipher algorithm is 'AES-256-CTR'. You can also specify alternative cipher or digest algorithms. For example:

```ruby
crypt = ECIES::Crypt.new(cipher: 'AES-256-CBC', digest: 'SHA512')
```

The `Crypt` object must be initialized with the same parameters when encrypting and decrypting messages.

## Compatibility

The sec1-v2 document allows for a many combinations of various algorithms for ECIES. This library only supports a subset of the allowable algorithms.

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
      - HMAC-SHA-384-384 (I believe sec1-v2 has a typo here, they state "HMAC-SHA-384-284". 284 bits would be 35.5 bytes, which is non-sensical)
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

## Supported platforms

Ruby 2.0 and above, including jruby.

## Documentation

For complete documentation, see the [ECIES page on RubyDoc.info](http://rubydoc.info/gems/ecies).
