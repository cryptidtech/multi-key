# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

Report any vulnerabilities by emailing dwg@linuxprogrammer.org or redmike7@gmail.com. Do not file public issues in this repo.

## std-only Status

This crate is std-only. It depends on `std::collections::BTreeMap`, `std::fmt`, and `unsigned-varint` with the `std` feature. The crypto dependency stack (RSA, SSH, BLS, hybrid KEMs, post-quantum signature schemes) all require std. A full `no_std` conversion is infeasible given the crypto dependency stack. This decision is final for the foreseeable future.

## Release-Candidate Dependencies

This crate depends on the following release-candidate (RC) crates:

- `slh-dsa = "0.2.0-rc.5"` — SLH-DSA post-quantum signatures
- `ssh-key = "0.7.0-rc.11"` — SSH key and signature encoding

The `blsful` dependency is now on a stable release (`4.0.0`). The `vsss-rs` dependency is now on a stable release (`6.0.1`).

The `slh-dsa` and `ssh-key` crates are on RC versions. No stable releases exist at the time of writing. The crate keeps them on RC for three reasons:

1. No stable releases exist. The upstream maintainers of `slh-dsa` and `ssh-key` have not published a stable (non-RC) release. The only alternatives are to vendor a fork (duplicating unaudited code) or to forgo the functionality. Neither is acceptable for this crate.
2. RC is the actively-maintained line. The RC versions receive bug fixes, security patches, and API feedback. Staying on the latest RC keeps this crate current with upstream corrections, including vulnerability fixes. It does not freeze on an older, unpatched revision.
3. The RC APIs this crate depends on are stable in practice. The surface area consumed (SLH-DSA signing and verification, SSH key encoding) has not changed across the RC bumps this crate has tracked. Breaking changes are absorbed as part of routine maintenance.

This is a tracked acceptance. The RC versions are reviewed on each upstream release. The crate is upgraded to the latest RC as they become available. It will migrate to stable when the upstreams publish one. Consumers should be aware that RC APIs may change before stabilisation. Coordinate with `multi-sig` (which depends on the same `ssh-key` version) when upgrading.

## RSA Implementation: `sad-rsa` (Marvin Attack Mitigation)

This crate uses [`sad-rsa`](https://crates.io/crates/sad-rsa) (`0.2.3`) instead of the upstream `rsa` crate. This mitigates RUSTSEC-2023-0071 (Marvin Attack: potential key recovery through timing side channels).

`sad-rsa` is a hardened fork of `rsa`. It implements implicit rejection for PKCS#1 v1.5 decryption. This makes valid and invalid ciphertexts indistinguishable to attackers. The API is fully compatible with `rsa`.

This crate uses RSA for:
- RSA key generation (`RsaPrivateKey::new` for 2048/3072/4096-bit keys)
- PKCS#1 encoding (`pkcs1::EncodeRsaPrivateKey`)
- RSA-PSS signing and verification (`pss::SigningKey`, `pss::VerifyingKey`)
- RSA-OAEP encryption and decryption for hybrid key encapsulation

RSA key material is wrapped in `Zeroizing<Vec<u8>>` and zeroized on drop.

## Comment Field Zeroization (R6)

The `Multikey` comment field is stored as a plain `String`. It is not zeroized on drop. This is a deliberate design decision:

- Rationale. The comment is non-sensitive metadata, for example a key label or human-readable description. Wrapping it in `Zeroizing<String>` would require deref-coercion shims across approximately 120 call sites that read the comment. This adds complexity and friction for no security benefit when the comment does not contain sensitive material.
- Key material is zeroized. The actual key material in `attributes` is wrapped in `Zeroizing<Vec<u8>>` and is zeroized on drop.
- Caller responsibility. If a caller places sensitive material in the comment field, they must zeroize that material themselves before it leaves scope. The crate does not assume the comment is sensitive.

## Hybrid KEM Combiner Hash (M3)

The AEAD-key KDF is unified across all four hybrid KEMs. It uses HKDF-SHA512 via the shared `aead::derive_aead_key` helper. The secret-combiner hash is not unified. `x25519_mlkem768` uses SHA-512. The other three hybrid KEMs (`x25519_sntrup761`, `x25519_frodokem640`, `x25519_mceliece348864`) use BLAKE3. Both constructions are cryptographically sound. The split is accepted. The combiner hash feeds into HKDF-SHA512, which accepts arbitrary input length.

## Decoded-Size Caps

The decoder enforces these caps on untrusted wire data to mitigate CWE-400 (Uncontrolled Resource Consumption):

- `MAX_ATTRIBUTES = 256` — maximum number of attributes per `Multikey`.
- `MAX_DECODED_SIZE = 16 MiB` — maximum total decoded bytes per `Multikey`. Tracked across the attribute decode loop.
- Per-attribute `Varbytes` payloads are individually capped by `multi_util` (16 MiB).

Exceeding any cap returns a clean `Err` (`Error::TooManyAttributes` or `Error::InputTooLarge`). The decoder never panics on oversized input.

## Memory Safety

- No unsafe code. `#![deny(unsafe_code)]` is enforced at compile time.
- Key material zeroization. Private key bytes are wrapped in `Zeroizing<Vec<u8>>` and zeroized on drop.
- Constant-time comparison. `impl ConstantTimeEq for Multikey` compares the canonical wire encoding in constant time. Use `mk.ct_eq(&other)` in timing-sensitive contexts instead of `PartialEq`.