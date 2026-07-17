# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.8] - 2026-07-17

### Security
- Replaced the vulnerable `rsa = "0.10.0-rc.18"` crate (RUSTSEC-2023-0071,
  Marvin Attack: timing side-channel key recovery) with
  `sad-rsa = "0.2.3"`, a hardened fork that implements implicit rejection
  to mitigate the Marvin Attack. `sad-rsa` is API-compatible with `rsa`.
  All `::rsa::` references updated to `::sad_rsa::` in `src/views/rsa.rs`
  and `src/mk.rs`.
- Removed unmaintained `serde_cbor` dependency (RUSTSEC-2021-0127). Replaced
  with `ciborium` in both production code (`src/keysplit.rs`,
  `src/views/threshold_marker.rs`) and test code (`src/serde/mod.rs`).
- Dropped `ssh-key` `crypto` feature on native target (was
  `["alloc", "crypto", "ed25519"]`, now
  `["alloc", "ecdsa", "ed25519", "p256", "p384", "p521"]` — matching the
  wasm target). This removed the transitive `rsa` dependency via `ssh-key`;
  `rsa`/`sad-rsa` is now only a direct dependency.
- Added `ByteBufVisitor` to `src/serde/de.rs` — `Nonce` and `Multikey`
  non-human-readable `Deserialize` paths now use `deserialize_byte_buf`
  with a visitor that accepts borrowed and owned bytes (compatible with
  `serde_test`, `serde_cbor`, and `ciborium`).
- Updated `src/views/bls12381.rs` to use `new_from_bls_signature_with_codec`/
  `new_from_bls_signature_share_with_codec` (fixing deprecation warnings from
  `multi-sig`'s deprecated constructors).

### Changed
- `src/keysplit.rs`: Added `cbor_to_vec`/`cbor_from_slice` helpers; replaced
  `serde_cbor::` calls with `ciborium` equivalents.
- `src/views/threshold_marker.rs`: Replaced `serde_cbor::` calls with
  `ciborium::from_reader`/`into_writer`.

### Dependencies
- `rsa = "0.10.0-rc.18"` → `sad-rsa = "0.2.3"` (both with `features = ["sha2"]`)
- Removed `serde_cbor = "0.11"` from `[dependencies]` and `[dev-dependencies]`
- Added `ciborium = "0.2"` to `[dependencies]`
- `ssh-key` (native target): dropped `crypto` feature, added `p256`/`p384`/`p521`

### Documentation
- Updated `SECURITY.md`: removed "Known Vulnerability: `rsa`" section, added
  "RSA Implementation: `sad-rsa`" section documenting the Marvin Attack
  mitigation. Removed `rsa` from RC dependencies list.

## [1.0.7] - 2026-07-16

### Security
- Added `MAX_DECODED_SIZE = 16 MiB` total decoded-size cap to
  `Multikey::try_decode_from` (tracks consumed bytes across the attribute
  decode loop, returns `Error::InputTooLarge`). Per-attribute payloads are
  also individually capped by `Varbytes::MAX_DECODED_SIZE` via `multi_util`.
  Mitigates CWE-400.
- Added `impl ConstantTimeEq for Multikey` — compares the canonical wire
  encoding in constant time. Use `mk.ct_eq(&other)` in timing-sensitive
  contexts instead of `PartialEq`.
- Documented comment field zeroization decision (R6): the `comment` field is
  a plain `String` (not zeroized); key material in `attributes` is wrapped in
  `Zeroizing<Vec<u8>>`.

### Changed
- Upgraded to Edition 2024 (`edition = "2024"`, `rust-version = "1.85"`).
- Renamed test helper `gen` → `gen_key` in `src/keysplit.rs` (12 call sites)
  to avoid the `gen` reserved keyword in Edition 2024.
- Added `[lints.clippy]` (pedantic/nursery/cargo at warn) and
  `[lints.rust] unsafe_code = "deny"` with targeted `#![allow(...)]` for
  stylistic lints.
- Added `Error::InputTooLarge { claimed, max }` error variant.
- Exported `MAX_DECODED_SIZE` from crate root.
- Major dependency upgrades: `aes-gcm` 0.10→0.11, `bcrypt-pbkdf` 0.10→0.11,
  `chacha20` 0.9→0.10, `chacha20poly1305` 0.10→0.11, `hkdf` 0.12→0.13,
  `ml-kem` 0.2→0.3, `poly1305` 0.8→0.9, `sha2` 0.10→0.11.
- Fixed AEAD fallback for legacy ChaCha20-encrypted keys.
- Added `AlgorithmName`/`KeyType` attributes and fixed builder
  `try_from_multikey`.

### CI
- Expanded CI from build+test to include: fmt check, clippy `-D warnings`,
  MSRV (1.85) check, and cargo audit job. Updated MSRV from 1.73.0 to 1.85.0.

### Documentation
- Added `SECURITY.md` documenting std-only status, RC dependencies, comment
  zeroization, decoded-size caps, and constant-time comparison.

### Tests
- Added `test_too_many_attributes_rejected` and `test_valid_roundtrip_with_caps`.

## [1.0.6] - 2026-07-14

### Fixed
- Fixed AEAD fallback for legacy ChaCha20-encrypted keys (added
  `legacy_chacha20_fallback` feature, disabled by default — AEAD failure is
  a hard error so unauthenticated ciphertext is never returned as valid).
- Added security tests for AEAD fallback behavior.

## [1.0.5] - 2026-07-14

### Added
- Added `AlgorithmName`/`KeyType` attributes to `AttrId`.
- Fixed builder `try_from_multikey` and added algorithm name/key type
  attribute support.

### Fixed
- Fixed builder `try_from_multikey` conversion.

## [1.0.4] - 2026-07-14

### Fixed
- Fixed codec values in signature views.

## [1.0.3] - 2026-07-14

### Added
- Added threshold hardening: `ThresholdKeyView` trait, DKG metadata support,
  threshold marker module (`threshold_meta.rs`), encrypted threshold
  parameters with ChaCha20-Poly1305 AEAD.
- Added `AttrId` variants for threshold disclosure and metadata.
- Updated `README.md` with comprehensive documentation.

### Changed
- Bumped version for threshold hardening release.

## [1.0.2] - 2026-07-13

### Changed
- Updated dependencies to published crates.io versions.

## [1.0.1] - 2026-07-13

### Fixed
- Fixed codec name references after multicodec table sync.
- Bumped `p521` dependency.

## [1.0.0] - 2026-07-13

### Changed
- Synced from bettersign workspace (bs-multikey 0.7.0)
- Renamed crate from `bs-multikey` to `multi-key`
- Added PQC key views: ML-DSA, ML-KEM, SLH-DSA, FN-DSA, MAYO, SNTRUP, FrodoKEM, Classic McEliece
- Added NIST curve views: P-256, P-384, P-521
- Added RSA views: RSA-2048, RSA-3072, RSA-4096
- Added X25519 views and hybrid KEMs: X25519+SNTRUP761, X25519+ML-KEM-768, X25519+FrodoKEM-640, X25519+McEliece
- Added hybrid signature views: Ed25519+MAYO2, Ed25519+ML-DSA-65, Ed25519+FN-DSA-512, BLS12-381-G1+ML-DSA-65, +FN-DSA-512, +MAYO1, +MAYO2
- Added `SealView`/`OpenView` traits for KEM-based encryption
- Added `ThresholdKeyView` trait for DKG metadata
- Added `keysplit.rs` module for verifiable threshold key splitting (Feldman VSS, gf256, dual)
- Added `types.rs` module with type-safe wrappers (`PublicKeyBytes`, `PrivateKeyBytes`, `KeyScheme`)
- Added `frodokem_helper.rs` module (inlined from former bs-frodokem wrapper)
- Added comprehensive test suite (edge cases, proptest, security)
- Major dependency updates: ed25519-dalek 3, blsful 4, elliptic-curve 0.14, vsss-rs 6, ssh-key 0.7
- Initial published release on crates.io as `multi-key`

[1.0.8]: https://github.com/cryptidtech/multi-key/compare/v1.0.7...v1.0.8
[1.0.7]: https://github.com/cryptidtech/multi-key/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/cryptidtech/multi-key/releases/tag/v1.0.6
[1.0.5]: https://github.com/cryptidtech/multi-key/releases/tag/v1.0.5
[1.0.4]: https://github.com/cryptidtech/multi-key/releases/tag/v1.0.4
[1.0.3]: https://github.com/cryptidtech/multi-key/releases/tag/v1.0.3
[1.0.2]: https://github.com/cryptidtech/multi-key/releases/tag/v1.0.2
[1.0.1]: https://github.com/cryptidtech/multi-key/releases/tag/v1.0.1
[1.0.0]: https://github.com/cryptidtech/multi-key/releases/tag/v1.0.0