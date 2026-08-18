# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-08-18

### Fixed

- Completed the Lamport and XMSS codec dispatch arms in `sign_view`, `verify_view`, `conv_view`, `data_view`, `attr_view`, and `fingerprint_view` in `src/mk.rs`. The `1.1.0` commit added these arms only to a subset of the view dispatch tables; the remaining match blocks returned `UnsupportedCodec` for Lamport/XMSS codecs. All six view functions now route Lamport and XMSS codecs to their views.

### Changed

- Switched the `multi-*` dependencies from the `bs-*` workspace path deps back to the published crates.io versions: `multi-base` 1.0, `multi-codec` 1.2, `multi-hash` 1.1, `multi-sig` 1.2, `multi-trait` 1.0, `multi-util` 1.1. The `multi-codec 1.2` release publishes the expanded codec table (Lamport and XMSS variants) and the `SlhDsa`/`MlDsa` casing that `1.1.0` consumed via the `bs-multicodec` path dep.
- Bumped `pq-mayo` from `0.5.0` to `0.6.0`.
- Bumped `sntrup` from `0.3.0` to `0.4.0`.
- Version bumped from `1.1.0` to `1.1.1` (patch: feature completion and dependency finalization, no breaking change).

### CI

- Restructured the `rust.yml` workflow. Removed the cross-platform build matrix (i686, macOS, Windows) and the `wasm_builds` and `test` matrix jobs. The `build` job now runs on `ubuntu-latest` with fmt check, clippy `-D warnings`, build, and test. Added a `coverage` job using `cargo-llvm-cov` with Codecov upload. Switched push and pull-request branch targets from `main` to `master`.

## [1.1.0] - 2026-08-13

### Added

- `lamport` cargo feature (default-enabled). Adds Lamport one-time hash-based key support for all 11 digest variants (SHA3-256/384/512, SHA2-256/384/512, BLAKE2b-512, BLAKE2s-256, BLAKE3-256, SHAKE-128/256). Each variant has `Priv`, `Pub`, and `PrivShare` codec entries. The view implements `AttrView`, `DataView`, `ConvView`, `FingerprintView`, `SignView`, `VerifyView`, and `ThresholdView` (with `split_with_disclosure`, `add_share_with_meta`, `combine_with_meta` delegating to base methods). `new_from_random_bytes` now supports all Lamport private key codecs.
- `xmss` cargo feature (default-enabled). Adds XMSS-SHA2_10/16/20_256 (RFC 8391) stateful hash-based key support. The view implements `AttrView`, `DataView`, `ConvView`, `FingerprintView`, `SignView`, and `VerifyView`. `new_from_random_bytes` now supports all XMSS private key codecs. The `sign_advance` function returns both the signature and the advanced secret key (with incremented leaf index).
- `lamport_signature_plus = "0.5.0-rc2"`, `sha3 = "0.12"`, `blake2 = "0.11.0-rc.6"`, `shake = "0.1"` as optional dependencies gated by the `lamport` feature.
- `xmss = "0.1.0-pre.0"` as an optional dependency gated by the `xmss` feature.
- `blake3` upgraded from `1.5.1` to `1.8`.
- Lamport and XMSS codec dispatch arms added to `sign_view`, `verify_view`, `conv_view`, `data_view`, `attr_view`, `fingerprint_view`, and `new_from_random_bytes` in `mk.rs`.
- `lamport` and `xmss` modules added to `views.rs`.
- `SigIndex` attribute ID added to `multi-sig` (for XMSS leaf index tracking).
- `with_sig_index()` builder method and `sig_index()` accessor added to `multi-sig` `Multisig`/`Builder`.

### Changed

- Version bumped from `1.0.9` to `1.1.0` (minor: new feature, no breaking change).
- The `default` feature now includes `lamport` and `xmss` in addition to `serde`.
- `multi-sig` repointed to the local `multi-sig` path dep (Phase 8) instead of crates.io `1.1.0`.
- `multi-codec`, `multi-hash`, `multi-trait`, `multi-util`, `multi-base` repointed to `bs-*` workspace path deps via `package` rename (to match the `bs-multicodec` codec variant names and the `bs-multisig` API).
- `Codec` variant names updated to match `bs-multicodec` generated names: `SlhdsaSha*` → `SlhDsaSha*`, `Mldsa*` → `MlDsa*` (the standalone `multi-codec` and `bs-multicodec` use different casing in the generated enum).

### Notes

- The `bs-lamport` wrapper logic is inlined into `src/views/lamport.rs` as a private `lamport_wrapper` module. The `bs-xmss` wrapper logic is inlined into `src/views/xmss.rs` as a private `xmss_wrapper` module.
- The `multi-codec`, `multi-hash`, `multi-trait`, `multi-util`, and `multi-base` dependencies currently point at the `bs-*` workspace path deps in `bettersign/crates/` via `package` rename. When the standalone crates publish the expanded codec table and Lamport/XMSS support to crates.io, the path deps will switch to the crates.io versions.
- The `--no-default-features` build fails because `threshold_meta` always uses `serde` (the `serde` feature controls only the optional `serde` dep, but `threshold_meta` imports it unconditionally). This is a pre-existing issue from `multi-key 1.0.9`. The `default` feature includes `serde`, so the default build works.

## [1.0.9] - 2026-08-04

### Changed

- Bumped the `multi-codec` pin from `1.0` to `1.1`, the `multi-util` pin from `1.0` to `1.1`, the `multi-hash` pin from `1.0` to `1.0.7`, and the `multi-sig` pin from `1.0` to `1.1.0` for traceability. The `multi-codec 1.1.0` release rejects trailing bytes in `TryFrom<&[u8]>`. All 15 `Codec::try_from(...as_slice())` call sites in this crate read discrete single-codec attribute `Vec<u8>` values. The two sites flagged in the prior plan (`src/mk.rs:480,630`) are attribute reads, not stream decodes. The stream decoder at `src/mk.rs:254-264` uses `Codec::try_decode_from`. No source change was required for M6.
- Bumped `blsful` from `4.0.0-rc4` to `4.0.0` (stable) on both native and wasm targets. The `blsful 4.0.0` release changed `From<&TimeCryptCiphertext>` to `TryFrom<&TimeCryptCiphertext>` (it now returns `BlsResult`). Fixed `src/views/bls12381.rs:1469,1480` to use `Vec::try_from(&ct).map_err(...)?` instead of `Vec::from(&ct)`.
- Bumped `vsss-rs` from `6.0.0-rc9` to `6.0` (stable, resolved to `6.0.1`).
- Bumped `frodo-kem-rs` from `0.7` to `0.9`.
- Bumped `fn-dsa` from `0.3` to `0.4`.
- Bumped the MSRV from `1.85` to `1.87` to support `blsful 4.0.0` and `blstrs_plus 0.9.0`.
- Added a `getrandom_02` wasm-specific dependency with the `js` feature. The `getrandom 0.2` crate is pulled transitively by `rand_core 0.6` (used by `bls12_381_plus` and the PQC crates). On `wasm32` it needs the `js` feature to compile.
- Rewrote `README.md`, `SECURITY.md`, and `CHANGELOG.md` in ASD-STE100 strict mode. Removed marketing language, passive voice, and long sentences.

### Security

- Rewrote `SECURITY.md` with an updated RC-dependency rationale. The `blsful` dependency is now on a stable release (`4.0.0`). The `vsss-rs` dependency is now on a stable release (`6.0.1`). The `ssh-key` and `slh-dsa` dependencies remain on RC versions.

### Notes

- M6 (`multi-codec 1.1.0` `TrailingData` rejection). All 15 `Codec::try_from(...as_slice())` call sites read discrete single-codec attribute `Vec<u8>` values (`AttrId::CipherCodec`, `AttrId::KdfCodec`, `AttrId::PayloadEncoding`). The two sites flagged in the prior plan (`src/mk.rs:480,630`) are attribute reads, not stream decodes. The stream decoder at `src/mk.rs:254-264` uses `Codec::try_decode_from`. No source change was required.
- M3 (hybrid KEM combiner hash split). The AEAD-key KDF is unified via HKDF-SHA512. The secret-combiner hash stays split. `x25519_mlkem768` uses SHA-512. The other three hybrid KEMs use BLAKE3. Accepted as cryptographically sound. `SECURITY.md` documents this decision.
- R6 (comment field zeroization). The `comment: String` field is not zeroized on drop. Key material in `attributes` is `Zeroizing<Vec<u8>>` and is zeroized. `SECURITY.md` documents the rationale and caller responsibility.

## [1.0.8] - 2026-07-17

### Security

- Replaced the vulnerable `rsa = "0.10.0-rc.18"` crate (RUSTSEC-2023-0071, Marvin Attack) with `sad-rsa = "0.2.3"`. This is a hardened fork that implements implicit rejection to mitigate the Marvin Attack. `sad-rsa` is API-compatible with `rsa`. All `::rsa::` references were updated to `::sad_rsa::` in `src/views/rsa.rs` and `src/mk.rs`.
- Removed the unmaintained `serde_cbor` dependency (RUSTSEC-2021-0127). Replaced it with `ciborium` in both production code (`src/keysplit.rs`, `src/views/threshold_marker.rs`) and test code (`src/serde/mod.rs`).
- Dropped the `ssh-key` `crypto` feature on native target. The old config was `["alloc", "crypto", "ed25519"]`. The new config is `["alloc", "ecdsa", "ed25519", "p256", "p384", "p521"]`. This matches the wasm target. This removed the transitive `rsa` dependency via `ssh-key`. `rsa` and `sad-rsa` are now only direct dependencies.
- Added `ByteBufVisitor` to `src/serde/de.rs`. `Nonce` and `Multikey` non-human-readable `Deserialize` paths now use `deserialize_byte_buf` with a visitor that accepts borrowed and owned bytes. It is compatible with `serde_test`, `serde_cbor`, and `ciborium`.
- Updated `src/views/bls12381.rs` to use `new_from_bls_signature_with_codec` and `new_from_bls_signature_share_with_codec`. This fixes deprecation warnings from `multi-sig` deprecated constructors.

### Changed

- `src/keysplit.rs`. Added `cbor_to_vec` and `cbor_from_slice` helpers. Replaced `serde_cbor::` calls with `ciborium` equivalents.
- `src/views/threshold_marker.rs`. Replaced `serde_cbor::` calls with `ciborium::from_reader` and `ciborium::into_writer`.

### Dependencies

- `rsa = "0.10.0-rc.18"` changed to `sad-rsa = "0.2.3"` (both with `features = ["sha2"]`).
- Removed `serde_cbor = "0.11"` from `[dependencies]` and `[dev-dependencies]`.
- Added `ciborium = "0.2"` to `[dependencies]`.
- `ssh-key` (native target). Dropped the `crypto` feature. Added `p256`, `p384`, and `p521`.

### Documentation

- Updated `SECURITY.md`. Removed the "Known Vulnerability: `rsa`" section. Added an "RSA Implementation: `sad-rsa`" section that documents the Marvin Attack mitigation. Removed `rsa` from the RC dependencies list.

## [1.0.7] - 2026-07-16

### Security

- Added `MAX_DECODED_SIZE = 16 MiB` total decoded-size cap to `Multikey::try_decode_from`. It tracks consumed bytes across the attribute decode loop and returns `Error::InputTooLarge`. Per-attribute payloads are also individually capped by `Varbytes` in `multi_util`. This mitigates CWE-400.
- Added `impl ConstantTimeEq for Multikey`. It compares the canonical wire encoding in constant time. Use `mk.ct_eq(&other)` in timing-sensitive contexts instead of `PartialEq`.
- Documented the comment field zeroization decision (R6). The `comment` field is a plain `String` (not zeroized). Key material in `attributes` is wrapped in `Zeroizing<Vec<u8>>`.

### Changed

- Upgraded to Edition 2024. Set `edition = "2024"` and `rust-version = "1.85"`.
- Renamed the test helper `gen` to `gen_key` in `src/keysplit.rs` (12 call sites). This avoids the `gen` reserved keyword in Edition 2024.
- Added `[lints.clippy]` with `pedantic`, `nursery`, and `cargo` at `warn`. Added `[lints.rust] unsafe_code = "deny"` with targeted `#![allow(...)]` for stylistic lints.
- Added `Error::InputTooLarge { claimed, max }` error variant.
- Exported `MAX_DECODED_SIZE` from the crate root.
- Major dependency upgrades. `aes-gcm` 0.10 to 0.11. `bcrypt-pbkdf` 0.10 to 0.11. `chacha20` 0.9 to 0.10. `chacha20poly1305` 0.10 to 0.11. `hkdf` 0.12 to 0.13. `ml-kem` 0.2 to 0.3. `poly1305` 0.8 to 0.9. `sha2` 0.10 to 0.11.
- Fixed the AEAD fallback for legacy ChaCha20-encrypted keys.
- Added `AlgorithmName` and `KeyType` attributes. Fixed the builder `try_from_multikey`.

### CI

- Expanded CI from build and test to include fmt check, clippy `-D warnings`, MSRV (1.85) check, and a cargo audit job. Updated the MSRV from 1.73.0 to 1.85.0.

### Documentation

- Added `SECURITY.md`. It documents std-only status, RC dependencies, comment zeroization, decoded-size caps, and constant-time comparison.

### Tests

- Added `test_too_many_attributes_rejected` and `test_valid_roundtrip_with_caps`.

## [1.0.6] - 2026-07-14

### Fixed

- Fixed the AEAD fallback for legacy ChaCha20-encrypted keys. Added the `legacy_chacha20_fallback` feature, disabled by default. AEAD failure is a hard error. Unauthenticated ciphertext is never returned as valid.
- Added security tests for the AEAD fallback behavior.

## [1.0.5] - 2026-07-14

### Added

- Added `AlgorithmName` and `KeyType` attributes to `AttrId`.
- Fixed the builder `try_from_multikey` and added algorithm name and key type attribute support.

### Fixed

- Fixed the builder `try_from_multikey` conversion.

## [1.0.4] - 2026-07-14

### Fixed

- Fixed codec values in signature views.

## [1.0.3] - 2026-07-14

### Added

- Added threshold hardening. The `ThresholdKeyView` trait, DKG metadata support, the threshold marker module (`threshold_meta.rs`), and encrypted threshold parameters with ChaCha20-Poly1305 AEAD.
- Added `AttrId` variants for threshold disclosure and metadata.
- Updated `README.md` with comprehensive documentation.

### Changed

- Bumped the version for the threshold hardening release.

## [1.0.2] - 2026-07-13

### Changed

- Updated dependencies to published crates.io versions.

## [1.0.1] - 2026-07-13

### Fixed

- Fixed codec name references after the multicodec table sync.
- Bumped the `p521` dependency.

## [1.0.0] - 2026-07-13

### Changed

- Synced from the bettersign workspace (`bs-multikey` 0.7.0).
- Renamed the crate from `bs-multikey` to `multi-key`.
- Added PQC key views: ML-DSA, ML-KEM, SLH-DSA, FN-DSA, MAYO, SNTRUP, FrodoKEM, Classic McEliece.
- Added NIST curve views: P-256, P-384, P-521.
- Added RSA views: RSA-2048, RSA-3072, RSA-4096.
- Added X25519 views and hybrid KEMs: X25519+SNTRUP761, X25519+ML-KEM-768, X25519+FrodoKEM-640, X25519+McEliece.
- Added hybrid signature views: Ed25519+MAYO2, Ed25519+ML-DSA-65, Ed25519+FN-DSA-512, BLS12-381-G1+ML-DSA-65, +FN-DSA-512, +MAYO1, +MAYO2.
- Added `SealView` and `OpenView` traits for KEM-based encryption.
- Added the `ThresholdKeyView` trait for DKG metadata.
- Added the `keysplit.rs` module for verifiable threshold key splitting (Feldman VSS, gf256, dual).
- Added the `types.rs` module with type-safe wrappers (`PublicKeyBytes`, `PrivateKeyBytes`, `KeyScheme`).
- Added the `frodokem_helper.rs` module (inlined from the former `bs-frodokem` wrapper).
- Added a comprehensive test suite for edge cases, proptests, and security.
- Major dependency updates: ed25519-dalek 3, blsful 4, elliptic-curve 0.14, vsss-rs 6, ssh-key 0.7.
- Initial published release on crates.io as `multi-key`.

[1.1.1]: https://github.com/cryptidtech/multi-key/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/cryptidtech/multi-key/compare/v1.0.9...v1.1.0
[1.0.9]: https://github.com/cryptidtech/multi-key/compare/v1.0.8...v1.0.9
[1.0.8]: https://github.com/cryptidtech/multi-key/compare/v1.0.7...v1.0.8
[1.0.7]: https://github.com/cryptidtech/multi-key/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/cryptidtech/multi-key/releases/tag/v1.0.6
[1.0.5]: https://github.com/cryptidtech/multi-key/releases/tag/v1.0.5
[1.0.4]: https://github.com/cryptidtech/multi-key/releases/tag/v1.0.4
[1.0.3]: https://github.com/cryptidtech/multi-key/releases/tag/v1.0.3
[1.0.2]: https://github.com/cryptidtech/multi-key/releases/tag/v1.0.2
[1.0.1]: https://github.com/cryptidtech/multi-key/releases/tag/v1.0.1
[1.0.0]: https://github.com/cryptidtech/multi-key/releases/tag/v1.0.0