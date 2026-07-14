[![](https://img.shields.io/badge/made%20by-Cryptid%20Technologies-gold.svg?style=flat-square)][CRYPTID]
[![](https://img.shields.io/badge/project-provenance-purple.svg?style=flat-square)][PROVENANCE]
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)][MULTIFORMATS]
![](https://github.com/cryptidtech/multi-key/actions/workflows/rust.yml/badge.svg)

# Multi-Key

A Rust implementation of the [multiformats][MULTIFORMATS] [multikey specification][MULTIKEY] and
[nonce specification][NONCE]. The published crate is **`multi-key`** (depend on it as
`multi-key = "1.0"` in `Cargo.toml` and import it as `multi_key` in Rust, e.g.
`use multi_key::Builder;`).

## Current Status

This implementation of the multikey specification supports an extensive set of public key
and secret key cryptography keys spanning classical, post-quantum, and hybrid schemes:

- **Classical signing** — Ed25519, secp256k1, NIST P-256/P-384/P-521, RSA-2048/3072/4096,
  and BLS12-381 G1/G2.
- **Post-quantum signing** — FN-DSA, ML-DSA, MAYO, and SLH-DSA (all parameter sets).
- **Key encapsulation / key agreement** — X25519, ML-KEM, sntrup, Classic McEliece,
  FrodoKEM, and the BLS12-381 TimeCrypt pairing-based KEM.
- **Hybrid signing** — combinations of Ed25519 or BLS12-381 G1 with a PQ signing scheme.
- **Hybrid KEMs** — combinations of X25519 with a PQ KEM.
- **Secret-key / symmetric** — ChaCha20-Poly1305 keys.

See the [Supported Key Formats](#supported-key-formats) section below for the exhaustive
list of codecs.

This implementation supports encrypting and decrypting keys at rest using
ChaCha20-Poly1305 AEAD with keys derived via the bcrypt PBKDF from a preimage. A legacy
bare-ChaCha20 fallback is honored on decrypt so older keystores continue to work;
re-encrypting upgrades them to the authenticated AEAD format.

KEM-based message encryption uses `SealView`/`OpenView` with a choice of four AEAD codecs
(ChaCha20-Poly1305, XChaCha20-Poly1305, AES-GCM-128, AES-GCM-256) and HKDF-SHA512 to derive
the AEAD key from the KEM shared secret.

For threshold cryptography, this implementation supports three mechanisms:

1. **BLS12-381 Shamir splitting** of G1/G2 keys, including threshold signing and verifying.
2. **Distributed Key Generation (DKG)** threshold shares for Ed25519, P-256, P-384,
   secp256k1, BLS12-381, and Ed448, with an authenticated threshold marker bundle (TSIG-1).
3. A generic **`keysplit`** module providing verifiable Feldman VSS for ECC keys, gf256
   byte-sharing for RSA and all PQ/hybrid keys, and a dual mode (gf256 + Feldman) for
   Ed25519/X25519.

This crate also supports converting to and from SSH format keys using the
[`ssh-key`][SSHKEY] crate, giving full OpenSSH compatibility for reading OpenSSH serialized
keys and converting them to Multi-Key format. This includes non-standard SSH key protocols
such as secp256k1 and BLS12-381 G1/G2 keys through the [RFC 4251][RFC4251] standard for
"additional algorithms" names using the `@multikey` domain suffix. See the
[SSH Key Conversions](#ssh-key-conversions) section for the full table.

For the technical details of the design of the multikey or nonce format, please refer to
the specifications linked above.

## Introduction

This is a Rust implementation of a multicodec format for cryptographic keys. The design of
the format is intentionally abstract to support any kind of cryptographic key in any state
(e.g. encrypted or unencrypted). This format is best thought of as a container of key
material with abstract, algorithm-specific views and a generic, self-describing data storage
format.

Every piece of data in the serialized Multi-Key object either has a known fixed size or a
self-describing variable size, such that software processing these objects does not need to
support all encryption algorithms to accurately calculate the size of the serialized object
and skip over it if needed.

## Supported Key Formats

The tables below enumerate every key codec supported by this crate. Each algorithm has
`Pub` (public key) and `Priv` (private key) variants unless otherwise noted. The codec
identifiers come from the [multicodec][MULTICODEC] registry and are surfaced as
`multi_codec::Codec` variants.

### Classical Signing

| Algorithm | Codecs | Notes |
|---|---|---|
| Ed25519 | `Ed25519Pub` / `Ed25519Priv` | Ed25519 signatures |
| secp256k1 | `Secp256K1Pub` / `Secp256K1Priv` | ECDSA over secp256k1 |
| NIST P-256 | `P256Pub` / `P256Priv` | ECDSA + ECDH |
| NIST P-384 | `P384Pub` / `P384Priv` | ECDSA + ECDH |
| NIST P-521 | `P521Pub` / `P521Priv` | ECDSA + ECDH |
| RSA-2048 | `Rsa2048Pub` / `Rsa2048Priv` | RSA-SHA256 signatures |
| RSA-3072 | `Rsa3072Pub` / `Rsa3072Priv` | RSA-SHA256 signatures |
| RSA-4096 | `Rsa4096Pub` / `Rsa4096Priv` | RSA-SHA256 signatures |
| BLS12-381 G1 | `Bls12381G1Pub` / `Bls12381G1Priv` | BLS signatures on G1; also a TimeCrypt KEM |
| BLS12-381 G2 | `Bls12381G2Pub` / `Bls12381G2Priv` | BLS signatures on G2; also a TimeCrypt KEM |

### Post-Quantum Signing

| Algorithm | Codecs | Parameter sets |
|---|---|---|
| FN-DSA | `FnDsa512Pub`/`Priv`, `FnDsa1024Pub`/`Priv` | 512, 1024 |
| ML-DSA | `Mldsa65Pub`/`Priv`, `Mldsa87Pub`/`Priv` | 65, 87 |
| MAYO | `Mayo1Pub`/`Priv`, `Mayo2Pub`/`Priv`, `Mayo3Pub`/`Priv`, `Mayo5Pub`/`Priv` | 1, 2, 3, 5 |
| SLH-DSA | `SlhdsaSha2128FPub`/`Priv`, `SlhdsaSha2128SPub`/`Priv`, `SlhdsaSha2192FPub`/`Priv`, `SlhdsaSha2192SPub`/`Priv`, `SlhdsaSha2256FPub`/`Priv`, `SlhdsaSha2256SPub`/`Priv`, `SlhdsaShake128FPub`/`Priv`, `SlhdsaShake128SPub`/`Priv`, `SlhdsaShake192FPub`/`Priv`, `SlhdsaShake192SPub`/`Priv`, `SlhdsaShake256FPub`/`Priv`, `SlhdsaShake256SPub`/`Priv` | 12 sets: SHA-2/SHAKE × 128/192/256 × F/S |

### KEMs / Key Agreement

| Algorithm | Codecs | Notes |
|---|---|---|
| X25519 | `X25519Pub` / `X25519Priv` | ECDH; returns ephemeral public key from `seal` |
| ML-KEM | `Mlkem768Pub`/`Priv`, `Mlkem1024Pub`/`Priv` | 768, 1024 |
| sntrup | `Sntrup761Pub`/`Priv`, `Sntrup857Pub`/`Priv`, `Sntrup953Pub`/`Priv`, `Sntrup1013Pub`/`Priv`, `Sntrup1277Pub`/`Priv` | 761, 857, 953, 1013, 1277 |
| Classic McEliece | `Mceliece348864Pub` / `Mceliece348864Priv` | 348864 |
| FrodoKEM | `FrodoKem640AesPub`/`Priv`, `FrodoKem976AesPub`/`Priv`, `FrodoKem1344AesPub`/`Priv`, `FrodoKem640ShakePub`/`Priv`, `FrodoKem976ShakePub`/`Priv`, `FrodoKem1344ShakePub`/`Priv` | 640/976/1344 × AES/SHAKE |
| BLS12-381 TimeCrypt | (uses the G1/G2 codecs above) | Pairing-based KEM built into the BLS views |

### Hybrid Signing (Classical + Post-Quantum)

| Hybrid | Codecs | Components |
|---|---|---|
| Ed25519-MAYO2 | `Ed25519Mayo2Pub` / `Ed25519Mayo2Priv` | Ed25519 + MAYO-2 |
| Ed25519-ML-DSA-65 | `Ed25519Mldsa65Pub` / `Ed25519Mldsa65Priv` | Ed25519 + ML-DSA-65 |
| Ed25519-FN-DSA-512 | `Ed25519Fndsa512Pub` / `Ed25519Fndsa512Priv` | Ed25519 + FN-DSA-512 |
| BLS12-381-G1-ML-DSA-65 | `Bls12381G1Mldsa65Pub` / `Bls12381G1Mldsa65Priv` | BLS G1 + ML-DSA-65 |
| BLS12-381-G1-FN-DSA-512 | `Bls12381G1Fndsa512Pub` / `Bls12381G1Fndsa512Priv` | BLS G1 + FN-DSA-512 |
| BLS12-381-G1-MAYO-1 | `Bls12381G1Mayo1Pub` / `Bls12381G1Mayo1Priv` | BLS G1 + MAYO-1 |
| BLS12-381-G1-MAYO-2 | `Bls12381G1Mayo2Pub` / `Bls12381G1Mayo2Priv` | BLS G1 + MAYO-2 |

### Hybrid KEMs (Classical + Post-Quantum)

| Hybrid | Codecs | Components |
|---|---|---|
| X25519-sntrup761 | `X25519Sntrup761Pub` / `X25519Sntrup761Priv` | X25519 + sntrup761 |
| X25519-ML-KEM-768 | `X25519Mlkem768Pub` / `X25519Mlkem768Priv` | X25519 + ML-KEM-768 |
| X25519-FrodoKEM-640 | `X25519Frodokem640AesPub`/`Priv`, `X25519Frodokem640ShakePub`/`Priv` | X25519 + FrodoKEM-640 (AES/SHAKE) |
| X25519-McEliece-348864 | `X25519Mceliece348864Pub` / `X25519Mceliece348864Priv` | X25519 + Classic McEliece 348864 |

### Threshold Key Shares

| Mechanism | Codecs | Notes |
|---|---|---|
| BLS12-381 Shamir shares | `Bls12381G1PubShare`/`PrivShare`, `Bls12381G2PubShare`/`PrivShare` | Split/combine via `ThresholdView`; threshold sign/verify |
| DKG threshold shares | `Ed25519ThreshPubShare`/`PrivShare`, `P256ThreshPubShare`/`PrivShare`, `P384ThreshPubShare`/`PrivShare`, `Secp256K1ThreshPubShare`/`PrivShare`, `Bls12381ThreshPubShare`/`PrivShare`, `Ed448ThreshPubShare`/`PrivShare` | DKG metadata via `ThresholdKeyView`; authenticated marker (TSIG-1) |
| Generic `keysplit` shares | `KeySplitShare` | Feldman VSS (ECC), gf256 byte-sharing (RSA + PQ + hybrids), dual mode (Ed25519/X25519) |

### Symmetric

| Algorithm | Codec | Notes |
|---|---|---|
| ChaCha20-Poly1305 | `Chacha20Poly1305` | Used both for at-rest Multi-Key encryption and as a symmetric key codec |

## Views on the Multi-Key Data

To provide an abstract interface to cryptographic keys for all algorithms, this crate
provides "views" on the Multi-Key data. These are read-only abstract interfaces to the
Multi-Key attributes with implementations for different supporting algorithms.

Currently the set of views provides generic access to the general attributes
(`multi_key::AttrView`) of the Multi-Key, the key data (`multi_key::DataView`), as well as
views on the KDF attributes (`multi_key::KdfAttrView`) and cipher attributes
(`multi_key::CipherAttrView`) for encrypted Multi-Keys. For algorithms that support
threshold operations there is a threshold attributes view
(`multi_key::ThresholdAttrView`) and a higher-level DKG metadata view
(`multi_key::ThresholdKeyView`).

For operations you can do with a Multi-Key, there is:

- a cipher view (`multi_key::CipherView`) for encrypting/decrypting a Multi-Key at rest,
- a conversion view (`multi_key::ConvView`) for converting the Multi-Key to other formats
  (e.g. to/from SSH key format, and secret keys to public keys),
- a fingerprint view (`multi_key::FingerprintView`) for getting a key fingerprint using a
  given hashing codec,
- a KDF view (`multi_key::KdfView`) for generating cipher keys for use by a cipher view to
  encrypt/decrypt the Multi-Key,
- a seal view (`multi_key::SealView`) and open view (`multi_key::OpenView`) for KEM-based
  message encryption/decryption,
- a threshold view (`multi_key::ThresholdView`) for key splitting and combining keys,
- a sign view (`multi_key::SignView`) and verify view (`multi_key::VerifyView`) for
  creating and verifying [`Multisig`][MULTISIG] digital signatures.

Two additional modules provide threshold functionality outside the view traits:

- `multi_key::keysplit` — generic verifiable threshold key splitting (Feldman VSS, gf256,
  dual) exposed as free `split`/`combine`/`verify_share` functions.
- `multi_key::threshold_marker` — DKG marker stamping/reading and TSIG-1 marker
  authentication, including the `MarkerView` trait and `threshold_kind`/`threshold_params`
  helpers.

It is important to note that the operations that seem to mutate the Multi-Key (e.g. encrypt,
decrypt, convert, etc.) in fact do a copy-on-write (CoW) operation and return a new
Multi-Key with the mutation applied.

## SSH Key Conversions

This crate converts to and from the SSH key format using the [`ssh-key`][SSHKEY] crate.
Standard SSH algorithms are handled natively; non-standard algorithms use the [RFC 4251][RFC4251]
"additional algorithms" mechanism with an `ssh_key::Algorithm::Other` opaque key and an
algorithm name ending in the literal `@multikey` suffix (this is a wire-format identifier,
distinct from the crate name).

### Native SSH algorithms (no `@multikey` suffix)

| Algorithm | SSH algorithm name |
|---|---|
| Ed25519 | `ssh-ed25519` |
| ECDSA P-256 | `ecdsa-sha2-nistp256` |
| ECDSA P-384 | `ecdsa-sha2-nistp384` |
| ECDSA P-521 | `ecdsa-sha2-nistp521` |

### Custom `@multikey` algorithms (opaque SSH keys)

| Algorithm | SSH algorithm name |
|---|---|
| secp256k1 | `secp256k1@multikey` |
| BLS12-381 G1 | `bls12_381-g1@multikey` |
| BLS12-381 G1 share | `bls12_381-g1-share@multikey` |
| BLS12-381 G2 | `bls12_381-g2@multikey` |
| BLS12-381 G2 share | `bls12_381-g2-share@multikey` |
| RSA-2048/3072/4096 | `rsa-sha256@multikey` |
| ML-DSA-65 | `ml-dsa-65@multikey` |
| ML-DSA-87 | `ml-dsa-87@multikey` |
| FN-DSA-512 | `fn-dsa-512@multikey` |
| FN-DSA-1024 | `fn-dsa-1024@multikey` |
| MAYO-1 | `mayo-1@multikey` |
| MAYO-2 | `mayo-2@multikey` |
| MAYO-3 | `mayo-3@multikey` |
| MAYO-5 | `mayo-5@multikey` |
| SLH-DSA SHA-2 128f | `slh-dsa-sha2-128f@multikey` |
| SLH-DSA SHA-2 128s | `slh-dsa-sha2-128s@multikey` |
| SLH-DSA SHA-2 192f | `slh-dsa-sha2-192f@multikey` |
| SLH-DSA SHA-2 192s | `slh-dsa-sha2-192s@multikey` |
| SLH-DSA SHA-2 256f | `slh-dsa-sha2-256f@multikey` |
| SLH-DSA SHA-2 256s | `slh-dsa-sha2-256s@multikey` |
| SLH-DSA SHAKE 128f | `slh-dsa-shake-128f@multikey` |
| SLH-DSA SHAKE 128s | `slh-dsa-shake-128s@multikey` |
| SLH-DSA SHAKE 192f | `slh-dsa-shake-192f@multikey` |
| SLH-DSA SHAKE 192s | `slh-dsa-shake-192s@multikey` |
| SLH-DSA SHAKE 256f | `slh-dsa-shake-256f@multikey` |
| SLH-DSA SHAKE 256s | `slh-dsa-shake-256s@multikey` |

The import direction (`Builder::new_from_ssh_public_key` /
`Builder::new_from_ssh_private_key`) supports all of the algorithms above.

### Key types that do not support SSH conversion

All KEM-only and hybrid key types explicitly reject SSH conversion and return
`UnsupportedAlgorithm`. These include: X25519, ML-KEM, all sntrup sizes, Classic McEliece,
all FrodoKEM variants, the BLS12-381 TimeCrypt KEM, and all hybrid signing and hybrid KEM
schemes.

## Threshold Operations

### BLS12-381 Shamir Splitting

`ThresholdView::split(threshold, limit)` splits a `Bls12381G1Priv` or `Bls12381G2Priv` into
`Bls12381G1PrivShare` / `Bls12381G2PrivShare` shares using `blsful`'s `SecretKey::split`.
Shares are recombined with `combine`, and threshold signing/verifying is supported on the
share codecs. Requires `2 <= threshold <= limit <= 255`.

### DKG Threshold Shares

The DKG share codecs (`Ed25519Thresh*`, `P256Thresh*`, `P384Thresh*`, `Secp256K1Thresh*`,
`Bls12381Thresh*`, `Ed448Thresh*`) carry DKG metadata attributes (`DkgThreshold`, `DkgLimit`,
`DkgIdentifier`, `DkgGroupPublicKey`, `DkgOwnerId`). The `ThresholdKeyView` trait exposes
`group_pubkey()`, `is_threshold_key()`, `participant_count()`, `threshold()`, and
`owner_vlad()`. The `threshold_marker` module stamps and authenticates a marker bundle
(TSIG-1) with a controller signing key via `sign_marker` / `verify_marker`.

### Generic `keysplit` Module

`multi_key::keysplit` provides scheme-aware verifiable threshold splitting for any key type
as free functions (`split`, `combine`, `verify_share`) producing `KeySplitShare` Multi-Keys:

- **Feldman VSS** — secp256k1, P-256/P-384/P-521, BLS12-381 G1/G2 (verifiable, with
  commitments).
- **gf256 byte-sharing** — RSA and all PQ families (ML-DSA, ML-KEM, SLH-DSA, FN-DSA, MAYO,
  sntrup, FrodoKEM, Classic McEliece) and all hybrids.
- **Dual mode** — Ed25519 and X25519: a gf256 share of the 32-byte seed (exact restore)
  plus a Feldman scalar share (threshold-signing-ready).

## Encryption

### At-Rest Multi-Key Encryption

Multi-Keys can be encrypted at rest using **ChaCha20-Poly1305** AEAD (`CipherView`) with the
cipher key derived from a preimage via the **bcrypt PBKDF** (`KdfView`, 32-byte salt,
configurable rounds). A legacy bare-ChaCha20 fallback is honored on decrypt so keystores
encrypted before AEAD was added continue to work; re-encrypting upgrades them to the
authenticated format.

### KEM Seal / Open

KEM-based message encryption uses `SealView` / `OpenView`. The KEM shared secret is
expanded into an AEAD key via **HKDF-SHA512**, then one of four AEAD codecs may be used:

| AEAD codec | Key size | Nonce size |
|---|---|---|
| `Chacha20Poly1305` | 32 bytes | 12 bytes |
| `Xchacha20Poly1305` | 32 bytes | 24 bytes |
| `AesGcm128` | 16 bytes | 12 bytes |
| `AesGcm256` | 32 bytes | 12 bytes |

Individual KEM views may restrict the allowed AEAD codec (e.g. X25519-ML-KEM-768 only
permits `Chacha20Poly1305` per its specification).

## Cargo Features

| Feature | Default | Description |
|---|---|---|
| `serde` | yes | Serde serialization for `Multikey`, `KeyShare`, `SharePayload`, `ThresholdParticipant` |
| `wasm` | no | WebAssembly support via `getrandom/wasm_js`; switches `blsful` to the `rust` backend and `ssh-key` to `ecdsa`/`ed25519`/`p256`/`p384`/`p521` features on `wasm32` |

## Security

- Private keys are wrapped in `Zeroizing` buffers and automatically zeroized on drop.
- `Debug` output for private key material is redacted.
- All views are thread-safe (`Send` + `Sync`) for concurrent operations.
- Mutation operations use copy-on-write semantics, returning a new `Multi-Key` rather than
  mutating in place.

## Links

- [Cryptid Technologies][CRYPTID]
- [Provenance Specifications][PROVENANCE]
- [Multiformats][MULTIFORMATS]
- [Multikey Specification][MULTIKEY]
- [Nonce Specification][NONCE]
- [Multisig][MULTISIG]
- [`ssh-key` crate][SSHKEY]
- [RFC 4251][RFC4251]

[CRYPTID]: https://cryptid.tech
[PROVENANCE]: https://github.com/cryptidtech/provenance-specifications/
[MULTIFORMATS]: https://github.com/multiformats/multiformats
[MULTIKEY]: https://github.com/cryptidtech/provenance-specifications/blob/main/specifications/multikey.md
[NONCE]: https://github.com/cryptidtech/provenance-specifications/blob/main/specifications/nonce.md
[MULTICODEC]: https://github.com/multiformats/multicodec
[SSHKEY]: https://crates.io/crates/ssh-key
[RFC4251]: https://www.rfc-editor.org/rfc/rfc4251.html#page-11
[MULTISIG]: https://github.com/cryptidtech/provenance-specifications/blob/main/specifications/multisig.md