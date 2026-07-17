# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

Report any vulnerabilities by either emailing dwg@linuxprogrammer.org or
redmike7@gmail.com. DO NOT file public issues in this repo.

## std-only Status

This crate is **std-only**. It depends on `std::collections::BTreeMap`,
`std::fmt`, and `unsigned-varint` with the `std` feature. The crypto
dependency stack (RSA, SSH, BLS, hybrid KEMs, post-quantum signature
schemes) all require std. A full `no_std` conversion is infeasible given
the crypto dependency stack; this decision is final for the foreseeable
future.

## Release-Candidate Dependencies

This crate depends on the following release-candidate (RC) crates:

- `rsa = "0.10.0-rc.18"` — RSA signature scheme
- `slh-dsa = "0.2.0-rc.5"` — SLH-DSA post-quantum signatures
- `vsss-rs = "6.0.0-rc2"` — verifiable secret sharing (transitive via
  `blsful`)
- `blsful = "4.0.0-rc1"` — BLS12-381 signature implementation
- `ssh-key = "0.7.0-rc.11"` — SSH key/signature encoding

These are pinned to RC versions because stable releases are not yet
available. This is a **tracked acceptance**: the RC versions are reviewed
on each release and will be upgraded to stable when available. Consumers
should be aware that RC APIs may change before stabilisation. Coordinate
with `multi-sig` (which depends on the same `blsful` and `ssh-key`
versions) when upgrading.

## Comment Field Zeroization (R6)

The `Multikey` comment field is stored as a plain `String` and is **not**
zeroized on drop. This is a deliberate design decision:

- **Rationale:** The comment is non-sensitive metadata (e.g. a key label
  or human-readable description). Wrapping it in `Zeroizing<String>` would
  require deref-coercion shims across ~120 call sites that read the
  comment, adding complexity and friction for no security benefit when the
  comment does not contain sensitive material.
- **Key material is zeroized:** The actual key material in `attributes` is
  wrapped in `Zeroizing<Vec<u8>>` and is zeroized on drop.
- **Caller responsibility:** If a caller places sensitive material in the
  comment field, they must zeroize that material themselves before it
  leaves scope. The crate does not assume the comment is sensitive.

## Decoded-Size Caps

The decoder enforces the following caps on untrusted wire data to mitigate
CWE-400 (Uncontrolled Resource Consumption):

- **`MAX_ATTRIBUTES = 256`** — maximum number of attributes per
  `Multikey`.
- **`MAX_DECODED_SIZE = 16 MiB`** — maximum total decoded bytes per
  `Multikey`. Tracked across the attribute decode loop.
- Per-attribute `Varbytes` payloads are individually capped by
  `multi_util::varbytes::MAX_DECODED_SIZE` (16 MiB).

Exceeding any cap returns a clean `Err` (`Error::TooManyAttributes` or
`Error::InputTooLarge`); the decoder never panics on oversized input.

## Memory Safety

- **No unsafe code**: `#![deny(unsafe_code)]` is enforced at compile time.
- **Key material zeroization**: Private key bytes are wrapped in
  `Zeroizing<Vec<u8>>` and zeroized on drop.
- **Constant-time comparison**: `impl ConstantTimeEq for Multikey` compares
  the canonical wire encoding in constant time. Use `mk.ct_eq(&other)` in
  timing-sensitive contexts instead of `PartialEq`.