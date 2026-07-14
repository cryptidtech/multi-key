# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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