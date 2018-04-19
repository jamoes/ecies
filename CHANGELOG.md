Change log
====

This gem follows [Semantic Versioning 2.0.0](http://semver.org/spec/v2.0.0.html).
All classes and public methods are part of the public API.

0.2.0
---
Release 2018-04-19

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
