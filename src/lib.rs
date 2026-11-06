// SPDX-License-Identifier: Apache-2.0
//! # multi-key
//!
//! Self-describing cryptographic key implementation supporting multiple key types
//! and formats including public keys, private keys, encrypted keys, and threshold keys.
//!
//! ## Overview
//!
//! This crate provides multikey functionality for creating and managing self-describing
//! cryptographic keys with support for:
//! - Ed25519, Secp256k1, and BLS12-381 key schemes
//! - Public and private key pairs
//! - Key encryption and decryption
//! - Threshold key sharing (Shamir Secret Sharing)
//! - SSH key format conversion
//! - View creation through the fluent `ViewBuilder`, including
//!   local-codec factories for custom protocol keys
//! - Nonce generation
//!
//! ## Quick Start
//!
//! ### Generating a Key Pair
//!
//! ```rust
//! # #[cfg(feature = "curve25519")] {
//! use multi_key::Builder;
//! use multi_codec::Codec;
//!
//! let mut rng = rand::rng();
//! let multikey = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
//!     .unwrap()
//!     .try_build()
//!     .unwrap();
//! # }
//! ```
//!
//! ### Encoding and Decoding
//!
//! ```rust
//! # #[cfg(feature = "curve25519")] {
//! use multi_key::{Builder, Multikey};
//! use multi_codec::Codec;
//!
//! let mut rng = rand::rng();
//! let mk1 = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
//!     .unwrap()
//!     .try_build()
//!     .unwrap();
//!
//! // Encode to bytes
//! let bytes = Vec::<u8>::from(&mk1);
//!
//! // Decode from bytes
//! let mk2 = Multikey::try_from(bytes.as_ref()).unwrap();
//! assert_eq!(mk1, mk2);
//! # }
//! ```
//!
//! ### Creating Views
//!
//! Views are created with [`ViewBuilder`]: select one view kind with a
//! fluent selector, then build it. Standard codecs dispatch to the built-in
//! views; custom protocol keys (the `Codec::Identity` codec carrying the
//! `AlgorithmName`/`KeyType` attributes) have no built-in views and
//! dispatch to caller-supplied local-codec factories registered with
//! `with_local_codec`. The `cipher` and `kdf` kinds additionally attach the
//! second key, for example
//! `ViewBuilder::new(&mk).cipher(&cipher_key).build()`.
//!
//! ```rust
//! # #[cfg(feature = "curve25519")] {
//! use multi_key::{Builder, ViewBuilder};
//! use multi_codec::Codec;
//!
//! let mut rng = rand::rng();
//! let mk = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
//!     .unwrap()
//!     .try_build()
//!     .unwrap();
//!
//! let signer = ViewBuilder::new(&mk).sign().build().unwrap();
//! let sig = signer.sign(b"message", false, None).unwrap();
//!
//! let verifier = ViewBuilder::new(&mk).verify().build().unwrap();
//! verifier.verify(&sig, Some(b"message")).unwrap();
//! # }
//! ```
//!
//! ## Features
//!
//! Each algorithm and curve is its own feature: `bcrypt`, `bls12-381`,
//! `chacha20`, `curve25519` (Ed25519, X25519, XEdDSA), `fn-dsa`, `frodokem`,
//! `lamport`, `mayo`, `ml-dsa`, `ml-kem`, `p256`, `p384`, `p521`, `rsa`,
//! `secp256k1`, `slh-dsa`, `sntrup`, and `xmss`, all enabled by default.
//! `threshold` (default) adds key splitting and the threshold marker
//! attributes. A hybrid key type compiles when every feature it combines is
//! enabled, e.g. Ed25519-ML-DSA-65 needs `curve25519` and `ml-dsa`. With
//! `default-features = false` the crate provides only the [`Multikey`] data
//! type, its attributes, the view traits, and the [`ViewBuilder`].
//!
//! - **`serde`** (default): Enables serde serialization
//! - **`wasm`**: Enables WebAssembly support with getrandom/js
//! - **`legacy_chacha20_fallback`** (default off): Enables the legacy bare-ChaCha20
//!   fallback on ChaCha20Poly1305 decryption failure for keys encrypted before
//!   AEAD was added. Disabled by default — AEAD failure is a hard error so
//!   unauthenticated ciphertext is never returned as if it were valid. Enable
//!   only to migrate pre-AEAD keystores; a warning is emitted on every fallback.
//! - **`deprecated`** (default off): Enables the deprecated Classic McEliece
//!   support (see the Deprecations section below).
//!
//! ## Deprecations
//!
//! Classic McEliece (the `Mceliece348864Pub`/`Priv` codecs and the
//! `X25519-McEliece-348864` hybrid) is deprecated; use ML-KEM, FrodoKEM, or
//! their X25519 hybrids instead. During 2026 structural attacks on binary
//! Goppa codes cut the estimated key-recovery cost from over 2^3000 to as low
//! as a claimed 2^99 to 2^102 operations:
//!
//! - Hemmert and Wiemers (BSI), higher-order-vanishing distinguisher
//!   (CRYPTO 2026), and Hemmert's key recovery,
//!   <https://eprint.iacr.org/2026/1339>
//! - Ghoshal, Ishai, Jain, and Sun, quasi-polynomial distinguisher,
//!   <https://eprint.iacr.org/2026/1630>
//! - Weis, improved key recovery, <https://eprint.iacr.org/2026/1984>
//! - Saarinen, recovered TII McEliece challenge keys,
//!   <https://eprint.iacr.org/2026/1778>, <https://eprint.iacr.org/2026/1986>,
//!   <https://github.com/mjosaarinen/tii-solved>
//!
//! On 29 September 2026 Germany's BSI advised against Classic McEliece in new
//! developments: <https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Crypto/Notes_Classic_McEliece.pdf>.
//! Most of these results are still preprints, and BSI reports no practical
//! attack yet on the parameter sets it recommends.
//!
//! The McEliece views compile only with the `deprecated` feature. Stored
//! McEliece multikeys still decode in default builds, but key generation
//! fails with `UnsupportedCodec`.
//!
//! ## Security
//!
//! - Private keys are automatically zeroized on drop
//! - Debug output redacts sensitive key material
//! - Thread-safe for concurrent operations
//!
//! ## Supported Key Types
//!
//! See [`KEY_CODECS`] for the complete list of supported key algorithms.

/// Errors produced by this library
pub mod error;
pub use error::Error;

/// Multikey attribute IDs
pub mod attrid;
pub use attrid::AttrId;

/// Cipher function builder
pub mod cipher;

/// Key derivation function builder
pub mod kdf;

/// Key views
pub mod views;
pub use views::builder::{
    AttrKind, CipherAttrKind, CipherKind, ConvKind, DataKind, DisclosureKind, FingerprintKind,
    KdfAttrKind, KdfKind, MerkleStateKind, OpenKind, SealKind, SignKind, ThresholdAttrKind,
    ThresholdKeyKind, ThresholdKind, Unselected, VerifyKind, ViewBuilder, ViewKind,
};
#[cfg(feature = "threshold")]
pub use views::threshold_marker::{
    self, MarkerView, ThresholdParticipant, ThresholdScheme, group_public_key, participants,
    set_group_public_key, set_participants, threshold_kind, threshold_params,
};
pub use views::threshold_meta::{
    self, DisclosureView, ThresholdDisclosure, ThresholdMetaCipher, ThresholdMetadata,
    read_threshold_params, stamp_disclosure_attrs,
};
#[cfg(feature = "chacha20")]
pub use views::threshold_meta::{
    decrypt_threshold_meta, encrypt_threshold_meta, generate_meta_key,
};
pub use views::{
    AttrView, CipherAttrView, CipherView, ConvView, DataView, FingerprintView, KdfAttrView,
    KdfView, MerkleStateView, OpenView, SealView, SignView, ThresholdAttrView,
    ThresholdDisclosureView, ThresholdKeyView, ThresholdView, VerifyView,
};

/// Key splitting / recombination (verifiable threshold shares)
#[cfg(feature = "threshold")]
pub mod keysplit;

/// Multikey type and functions
pub mod mk;
pub use mk::{
    Builder, EncodedMultikey, FN_DSA_KEY_CODECS, KEY_CODECS, KEY_SHARE_CODECS, MAX_ATTRIBUTES,
    MAX_DECODED_SIZE, ML_DSA_KEY_CODECS, ML_KEM_KEY_CODECS, Multikey, SLH_DSA_KEY_CODECS,
    X25519_KEY_CODECS,
};
#[cfg(feature = "lamport")]
pub use mk::{LAMPORT_MERKLE_KEY_CODECS, LAMPORT_MERKLE_KEY_SHARE_CODECS};

/// Nonce type
pub mod nonce;
pub use nonce::{EncodedNonce, Nonce};

// Re-export EncodingInfo for consumers of Nonce who need the encoding() method
pub use multi_util::EncodingInfo;

/// Type-safe wrappers for key components
pub mod types;
pub use types::{KeyScheme, PrivateKeyBytes, PublicKeyBytes};

/// Serde serialization
#[cfg(feature = "serde")]
pub mod serde;

/// Commonly used items
///
/// ```
/// # #[cfg(feature = "curve25519")] {
/// use multi_key::prelude::*;
///
/// let mut rng = rand::rng();
/// let mk = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
///     .unwrap()
///     .try_build()
///     .unwrap();
/// # }
/// ```
pub mod prelude {
    pub use super::*;
    /// re-exports
    pub use multi_base::Base;
    pub use multi_codec::Codec;
    pub use multi_util::BaseEncoded;
}
