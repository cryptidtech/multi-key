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
//! - Nonce generation
//!
//! ## Quick Start
//!
//! ### Generating a Key Pair
//!
//! ```rust
//! use multi_key::Builder;
//! use multi_codec::Codec;
//!
//! let mut rng = rand::rng();
//! let multikey = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
//!     .unwrap()
//!     .try_build()
//!     .unwrap();
//! ```
//!
//! ### Encoding and Decoding
//!
//! ```rust
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
//! let bytes: Vec<u8> = mk1.clone().into();
//!
//! // Decode from bytes
//! let mk2 = Multikey::try_from(bytes.as_ref()).unwrap();
//! assert_eq!(mk1, mk2);
//! ```
//!
//! ## Features
//!
//! - **`serde`** (default): Enables serde serialization
//! - **`wasm`**: Enables WebAssembly support with getrandom/js
//! - **`legacy_chacha20_fallback`** (default off): Enables the legacy bare-ChaCha20
//!   fallback on ChaCha20Poly1305 decryption failure for keys encrypted before
//!   AEAD was added. Disabled by default — AEAD failure is a hard error so
//!   unauthenticated ciphertext is never returned as if it were valid. Enable
//!   only to migrate pre-AEAD keystores; a warning is emitted on every fallback.
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

#![warn(missing_docs)]
#![deny(
    unsafe_code,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]
// Pedantic/nursery lints are enabled at the workspace level via
// `[lints.clippy]` in Cargo.toml. The following allows suppress stylistic
// lints that would require large-scale churn for minimal security benefit.
#![allow(
    clippy::doc_markdown,
    clippy::elidable_lifetime_names,
    clippy::use_self,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::return_self_not_must_use,
    clippy::semicolon_if_nothing_returned,
    clippy::or_fun_call,
    clippy::missing_const_for_fn,
    clippy::multiple_crate_versions,
    clippy::too_many_lines,
    clippy::option_if_let_else,
    clippy::single_match_else,
    clippy::uninlined_format_args,
    clippy::cast_possible_truncation,
    clippy::redundant_pub_crate,
    clippy::redundant_clone,
    clippy::items_after_statements,
    clippy::if_not_else,
    clippy::explicit_iter_loop,
    clippy::enum_glob_use,
    clippy::branches_sharing_code,
    clippy::too_long_first_doc_paragraph,
    clippy::useless_let_if_seq,
    clippy::large_stack_frames,
    clippy::match_same_arms,
    clippy::similar_names,
    clippy::single_char_pattern,
    clippy::needless_pass_by_value
)]

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
pub use views::threshold_marker::{
    self, MarkerView, ThresholdParticipant, ThresholdScheme, group_public_key, participants,
    set_group_public_key, set_participants, threshold_kind, threshold_params,
};
pub use views::threshold_meta::{
    self, DisclosureView, ThresholdDisclosure, ThresholdMetaCipher, ThresholdMetadata,
    decrypt_threshold_meta, encrypt_threshold_meta, generate_meta_key, read_threshold_params,
    stamp_disclosure_attrs,
};
pub use views::{
    AttrView, CipherAttrView, CipherView, ConvView, DataView, FingerprintView, KdfAttrView,
    KdfView, OpenView, SealView, SignView, ThresholdAttrView, ThresholdDisclosureView,
    ThresholdKeyView, ThresholdView, VerifyView, Views,
};

/// Key splitting / recombination (verifiable threshold shares)
pub mod keysplit;

/// Multikey type and functions
pub mod mk;
pub use mk::{
    Builder, EncodedMultikey, FN_DSA_KEY_CODECS, KEY_CODECS, KEY_SHARE_CODECS, MAX_ATTRIBUTES,
    MAX_DECODED_SIZE, ML_DSA_KEY_CODECS, ML_KEM_KEY_CODECS, Multikey, SLH_DSA_KEY_CODECS,
    X25519_KEY_CODECS,
};

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
/// use multi_key::prelude::*;
///
/// let mut rng = rand::rng();
/// let mk = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
///     .unwrap()
///     .try_build()
///     .unwrap();
/// ```
pub mod prelude {
    pub use super::*;
    /// re-exports
    pub use multi_base::Base;
    pub use multi_codec::Codec;
    pub use multi_util::BaseEncoded;
}
