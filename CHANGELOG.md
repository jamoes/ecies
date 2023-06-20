Change log
====

This gem follows [Semantic Versioning 2.0.0](http://semver.org/spec/v2.0.0.html).
All classes and public methods are part of the public API.

0.4.0
---
Released on 2023-06-20

- Add support for OpenSSL 3.0.
- Remove `Crypt.private_key_from_hex` method.
  - Users can still utilize `OpenSSL::PKey::EC.new` to construct a PKey.
- `Crypt.public_key_from_hex` now raises `ArgumentError` on an invalid key, rather than an `OpenSSL::PKey::EC::Point::Error`.
- Explicitly require 'stringio' (thanks thekuwayama!).

0.3.0
---
Released on 2018-04-22

- Prevent benign malleability, as suggested in sec1-v2 page 97.
  - The ECIES process is modified to prevent benign malleability by including the ephemeral public key as an input to the KDF.
  - All encrypted output generated with previous versions cannot be decrypted with this version, and older versions cannot decrypt output generated with this version.
  - The choice was made to simply break compatibility early in this library's life, rather than add an extra configuration parameter that should almost always be unused.
- Add `Crypt.public_key_from_hex` method.
- Add `Crypt.private_key_from_hex` method.
- Remove support for hex-encoded keys in `Crypt#encrypt` and `Crypt#decrypt` methods. The above `*_from_hex` helper methods can be used instead.
- Remove `ec_group` option from `Crypt` constructor.
- Add `Crypt#to_s` method.

0.2.0
---
Released on 2018-04-19

- Add support for hex-encoded keys in `Crypt#encrypt` and `Crypt#decrypt` methods.
- Add new option `ec_group` in `Crypt` constructor.

0.1.0
----
Released on 2018-04-18

All core functionality is implemented:

- `ECIES::Crypt` class:
  - `encrypt` method
  - `decrypt` method
  - `kdf` method
  - `DIGESTS` constant
  - `CIPHERS` constant
  - `IV` constant
