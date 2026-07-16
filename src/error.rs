// SPDX-License-Identifier: Apache-2.0
/// Errors created by this library
#[must_use]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Attributes error
    #[error(transparent)]
    Attributes(#[from] AttributesError),
    /// Conversions error
    #[error(transparent)]
    Conversions(#[from] ConversionsError),
    /// Cipher error
    #[error(transparent)]
    Cipher(#[from] CipherError),
    /// Kdf error
    #[error(transparent)]
    Kdf(#[from] KdfError),
    /// Nonce error
    #[error(transparent)]
    Nonce(#[from] NonceError),
    /// Seal error
    #[error(transparent)]
    Seal(#[from] SealError),
    /// Sign error
    #[error(transparent)]
    Sign(#[from] SignError),
    /// Threshold error
    #[error(transparent)]
    Threshold(#[from] ThresholdError),
    /// Verify error
    #[error(transparent)]
    Verify(#[from] VerifyError),
    /// Key split/combine error
    #[error("key split error: {0}")]
    KeySplit(String),

    /// Multibase conversion error
    #[error(transparent)]
    Multibase(#[from] multi_base::Error),
    /// Multicodec decoding error
    #[error(transparent)]
    Multicodec(#[from] multi_codec::Error),
    /// Multiutil error
    #[error(transparent)]
    Multiutil(#[from] multi_util::Error),
    /// Multisig error
    #[error(transparent)]
    Multisig(#[from] multi_sig::Error),
    /// Multitrait error
    #[error(transparent)]
    Multitrait(#[from] multi_trait::Error),
    /// Multihash error
    #[error(transparent)]
    Multihash(#[from] multi_hash::Error),

    /// Utf8 error
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
    /// Duplicate attribute error
    #[error("Duplicate Multikey attribute: {0}")]
    DuplicateAttribute(u8),
    /// Attribute count exceeds the configured maximum
    ///
    /// Returned by [`crate::mk::Multikey::try_decode_from`] when the number of
    /// attributes declared in the wire data exceeds
    /// [`crate::mk::MAX_ATTRIBUTES`]. Bounds the work a crafted input can
    /// force the decoder to perform and mitigates CWE-400.
    #[error("attribute count {0} exceeds maximum {1}")]
    TooManyAttributes(usize, usize),
    /// Incorrect Multikey sigil
    #[error("Missing Multikey sigil")]
    MissingSigil,
    /// Unsupported key algorithm
    #[error("Unsupported key algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// Attributes errors created by this library
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttributesError {
    /// Error with the key codec
    #[error("Unsupported key codec: {0}")]
    UnsupportedCodec(multi_codec::Codec),
    /// No key data attribute
    #[error("Key data unit missing")]
    MissingKey,
    /// Not a secret key
    #[error("Not a secret key {0}")]
    NotSecretKey(multi_codec::codec::Codec),
    /// Key is encrypted
    #[error("Key is encrypted")]
    EncryptedKey,
    /// Invalid attribute name
    #[error("Invalid attribute name {0}")]
    InvalidAttributeName(String),
    /// Invalid attribute value
    #[error("Invalid attribute value {0}")]
    InvalidAttributeValue(u8),
    /// No threshold
    #[error("Missing threshold")]
    MissingThreshold,
    /// No limit
    #[error("Missing limit")]
    MissingLimit,
    /// No key share identifier
    #[error("Missing share identifier")]
    MissingShareIdentifier,
    /// No threshold data
    #[error("Missing threshold data")]
    MissingThresholdData,
    /// No group public key
    #[error("Missing group public key")]
    MissingGroupPublicKey,
    /// No participant map
    #[error("Missing threshold participants")]
    MissingThresholdParticipants,
    /// CBOR (de)serialization error for a threshold marker attribute
    #[error("Threshold marker CBOR error: {0}")]
    ThresholdMarkerCbor(String),
    /// The threshold marker bundle carries no authenticating signature.
    #[error("Missing threshold marker signature")]
    MissingThresholdMarkerSig,
    /// The threshold marker signature failed verification (tampered marker).
    #[error("Threshold marker signature verification failed")]
    ThresholdMarkerSigInvalid,
}

/// Conversions errors created by this library
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConversionsError {
    /// Ssh key error
    #[error(transparent)]
    Ssh(#[from] SshErrors),
    /// Public key operation failure
    #[error("Public key error: {0}")]
    PublicKeyFailure(String),
    /// Secret key operation failure
    #[error("Secret key error: {0}")]
    SecretKeyFailure(String),
    /// Error converting from ssh keys
    #[error("Unsupported SSH key algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// Error with the key codec
    #[error("Unsupported key codec: {0}")]
    UnsupportedCodec(multi_codec::Codec),
}

/// SSH Encoding Errors that cannot be handled by thiserror since they may not use the std feature
/// in the case of wasm32 target.
#[derive(Debug)]
pub enum SshErrors {
    /// Error from [ssh_key::Error]
    Key(ssh_key::Error),
    /// Invalid label from [ssh_encoding::LabelError]
    KeyLabel(ssh_encoding::LabelError),
    /// Unexpected trailing data at end of message from [ssh_encoding::Error]
    Encoding(ssh_encoding::Error),
}

/// Impl Display for EncodingError
impl std::fmt::Display for SshErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshErrors::Key(err) => write!(f, "{}", err),
            SshErrors::KeyLabel(err) => write!(f, "{}", err),
            SshErrors::Encoding(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for SshErrors {}

impl From<ssh_encoding::Error> for SshErrors {
    fn from(err: ssh_encoding::Error) -> Self {
        SshErrors::Encoding(err)
    }
}

impl From<ssh_key::Error> for SshErrors {
    fn from(err: ssh_key::Error) -> Self {
        SshErrors::Key(err)
    }
}

impl From<ssh_encoding::LabelError> for SshErrors {
    fn from(err: ssh_encoding::LabelError) -> Self {
        SshErrors::KeyLabel(err)
    }
}

/// Cipher errors created by this library
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CipherError {
    /// Error with the cipher codec
    #[error("Unsupported cipher codec: {0}")]
    UnsupportedCodec(multi_codec::Codec),
    /// Missing codec
    #[error("Missing cipher codec")]
    MissingCodec,
    /// Missing nonce error
    #[error("Missing cipher nonce")]
    MissingNonce,
    /// Missing nonce length error
    #[error("Invalid cipher nonce length")]
    InvalidNonceLen,
    /// Invalid nonce error
    #[error("Invalid cipher nonce")]
    InvalidNonce,
    /// Missing key error
    #[error("Missing cipher key")]
    MissingKey,
    /// Missing key length error
    #[error("Missing cipher key length")]
    MissingKeyLen,
    /// Invalid key error
    #[error("Invalid cipher key")]
    InvalidKey,
    /// Encryption error
    #[error("Encryption error: {0}")]
    EncryptionFailed(String),
    /// Decryption error
    #[error("Decryption failed")]
    DecryptionFailed,
}

/// Kdf errors created by this library
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KdfError {
    /// Bcrypt PBKDF error
    #[error(transparent)]
    Bcrypt(#[from] bcrypt_pbkdf::Error),
    /// Error with the KDF codec
    #[error("Unsupported KDF codec: {0}")]
    UnsupportedCodec(multi_codec::Codec),
    /// Missing codec
    #[error("Missing KDF codec")]
    MissingCodec,
    /// Missing salt error
    #[error("Missing KDF salt")]
    MissingSalt,
    /// Invalid salt length error
    #[error("Invalid KDF salt length")]
    InvalidSaltLen,
    /// Missing rounds error
    #[error("Missing KDF rounds")]
    MissingRounds,
}

/// Nonce errors created by this library
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NonceError {
    /// Missing sigil
    #[error("Missing Nonce codec")]
    MissingSigil,
    /// Missing bytes
    #[error("Missing Nonce bytes")]
    MissingBytes,
}

/// Seal/Open (encryption) errors created by this library
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SealError {
    /// Not an encryption key
    #[error("Not an encryption key")]
    NotEncryptionKey,
    /// Not a decapsulation (private) key
    #[error("Not a decapsulation key")]
    NotDecapsulationKey,
    /// Not an encapsulation (public) key
    #[error("Not an encapsulation key")]
    NotEncapsulationKey,
    /// Unsupported AEAD codec
    #[error("Unsupported AEAD codec: {0}")]
    UnsupportedAeadCodec(multi_codec::Codec),
    /// Encapsulation failed
    #[error("Encapsulation failed: {0}")]
    EncapsulationFailed(String),
    /// Decapsulation failed
    #[error("Decapsulation failed: {0}")]
    DecapsulationFailed(String),
    /// AEAD seal failed
    #[error("AEAD seal failed: {0}")]
    AeadSealFailed(String),
    /// AEAD open failed
    #[error("AEAD open failed")]
    AeadOpenFailed,
    /// Invalid format
    #[error("Invalid sealed message format: {0}")]
    InvalidFormat(String),
    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    /// RNG failure during sealing
    ///
    /// Returned when the OS RNG (`getrandom`) fails to produce randomness
    /// (e.g. on constrained targets without entropy). Propagated from the
    /// sealing path instead of panicking.
    #[error("RNG failure: {0}")]
    RngFailure(String),
}

/// Sign errors created by this library
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
    /// Not a signing key
    #[error("Not a signing key")]
    NotSigningKey,
    /// Signing failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    /// Missing scheme
    #[error("Missing signature scheme")]
    MissingScheme,
    /// RNG failure during signing
    ///
    /// Returned when the OS RNG (`getrandom`) fails to produce randomness
    /// (e.g. on constrained targets without entropy). Propagated from the
    /// signing path instead of panicking.
    #[error("RNG failure: {0}")]
    RngFailure(String),
}

/// Threshold errors created by this library
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ThresholdError {
    /// Bls error
    #[error(transparent)]
    Bls(#[from] blsful::BlsError),
    /// Invalid threshold and limit
    #[error("Invalid threshold ({0}) and limit ({1}). Limit must be greater than threshold")]
    InvalidThresholdLimit(usize, usize),
    /// Not a secret key
    #[error("Not a secret key; only secret keys may be split and combined")]
    NotASecretKey,
    /// Is a key share when we expect a key
    #[error("Is a key share when we expect a key")]
    IsAKeyShare,
    /// Not enough shares
    #[error("Not enough shares to combine")]
    NotEnoughShares,
    /// Share combine failed
    #[error("Combining secret key shares failed: {0}")]
    ShareCombineFailed(String),
    /// Threshold metadata encryption/decryption error
    #[error("Threshold metadata error: {0}")]
    MetaEncryption(String),
    /// Missing threshold metadata key for decrypting t/n
    #[error("Missing threshold metadata key")]
    MissingMetaKey,
    /// Threshold disclosure mode mismatch between shares
    #[error("Threshold disclosure mode mismatch: expected {expected}, found {found}")]
    DisclosureMismatch {
        /// Expected disclosure mode code
        expected: u8,
        /// Found disclosure mode code
        found: u8,
    },
    /// Duplicate share identifier in threshold data
    #[error("Duplicate share identifier")]
    DuplicateShare,
}

/// Verify errors created by this library
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// Missing signature
    #[error("Missing signature")]
    MissingSignature,
    /// Missing message
    #[error("Missing message")]
    MissingMessage,
    /// Bad signature
    #[error("Bad signature: {0}")]
    BadSignature(String),
}

impl Error {
    /// Get the error kind as a string
    #[must_use]
    pub fn kind(&self) -> &str {
        match self {
            Self::Attributes(_) => "Attributes",
            Self::Conversions(_) => "Conversions",
            Self::Cipher(_) => "Cipher",
            Self::Kdf(_) => "Kdf",
            Self::Nonce(_) => "Nonce",
            Self::Seal(_) => "Seal",
            Self::Sign(_) => "Sign",
            Self::Threshold(_) => "Threshold",
            Self::Verify(_) => "Verify",
            Self::KeySplit(_) => "KeySplit",
            Self::Multibase(_) => "Multibase",
            Self::Multicodec(_) => "Multicodec",
            Self::Multiutil(_) => "Multiutil",
            Self::Multisig(_) => "Multisig",
            Self::Multitrait(_) => "Multitrait",
            Self::Multihash(_) => "Multihash",
            Self::Utf8(_) => "Utf8",
            Self::DuplicateAttribute(_) => "DuplicateAttribute",
            Self::TooManyAttributes(_, _) => "TooManyAttributes",
            Self::MissingSigil => "MissingSigil",
            Self::UnsupportedAlgorithm(_) => "UnsupportedAlgorithm",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_kind() {
        let err = Error::MissingSigil;
        assert_eq!(err.kind(), "MissingSigil");
    }

    #[test]
    fn test_error_display() {
        let err = Error::MissingSigil;
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn test_error_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<Error>();
        assert_sync::<Error>();
    }
}
