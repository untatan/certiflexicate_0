# Certiflexicate

The idea is to use certiflexicates as a flexible structure
for digital signed data.

---

## Overview

Thanks to the power of [serde](https://serde.rs), it is not tied to a
specific file format.

For cryptographic operations it currently relies on what
[ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
provides.


Usually a `Certiflexicate` includes

  * version information,
  * a public key in a `PublicKeyInfo` object,
  * optional content data and
  * one or more `SignatureData` structures, which contains a signature,
    possibly an accept signature and optional other constraints.

How [Certiflexicates](./certiflexicates) may appear.
    
---

## Current state

[flexicate-core](./crates/flexicate-core) has some experimental
Rust code in order to discover flaws in the design and implementation.

**Do not use it for anything serious!**

---
---
