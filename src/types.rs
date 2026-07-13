// SPDX-License-Identifier: Apache-2.0
//! Type-safe wrappers for cryptographic key components

use multi_codec::Codec;
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Public key bytes
///
/// Type-safe wrapper for public key data.
///
/// # Examples
///
/// ```
/// use multi_key::types::PublicKeyBytes;
///
/// let pubkey = PublicKeyBytes::new(vec![0u8; 32]);
/// assert_eq!(pubkey.len(), 32);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyBytes(Vec<u8>);

impl PublicKeyBytes {
    /// Create new PublicKeyBytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get length
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Convert to inner bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for PublicKeyBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PublicKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Private key bytes with automatic zeroization
///
/// Sensitive key material that is automatically zeroized on drop.
///
/// # Examples
///
/// ```
/// use multi_key::types::PrivateKeyBytes;
///
/// let privkey = PrivateKeyBytes::new(vec![0u8; 32]);
/// assert_eq!(privkey.len(), 32);
/// // Automatically zeroized when dropped
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKeyBytes(Vec<u8>);

impl PrivateKeyBytes {
    /// Create new PrivateKeyBytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get bytes (careful - exposes sensitive data)
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get length
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get a copy of the bytes (careful - caller must handle zeroization)
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl From<Vec<u8>> for PrivateKeyBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PrivateKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PrivateKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKeyBytes([REDACTED {} bytes])", self.0.len())
    }
}

/// Key scheme identifier
///
/// Type-safe wrapper for key algorithm codecs.
///
/// # Examples
///
/// ```
/// use multi_key::types::KeyScheme;
/// use multi_codec::Codec;
///
/// let scheme = KeyScheme::new(Codec::Ed25519Pub);
/// assert_eq!(scheme.codec(), Codec::Ed25519Pub);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyScheme(Codec);

impl KeyScheme {
    /// Create new KeyScheme
    pub const fn new(codec: Codec) -> Self {
        Self(codec)
    }

    /// Get codec
    pub const fn codec(self) -> Codec {
        self.0
    }

    /// Get name
    pub fn name(self) -> &'static str {
        self.0.into()
    }

    /// Get code
    pub fn code(self) -> u64 {
        self.0.code()
    }
}

impl From<Codec> for KeyScheme {
    fn from(codec: Codec) -> Self {
        Self(codec)
    }
}

impl From<KeyScheme> for Codec {
    fn from(scheme: KeyScheme) -> Codec {
        scheme.0
    }
}

impl fmt::Display for KeyScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_bytes() {
        let pubkey = PublicKeyBytes::new(vec![1, 2, 3]);
        assert_eq!(pubkey.len(), 3);
        assert_eq!(pubkey.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn test_private_key_bytes_zeroization() {
        let privkey = PrivateKeyBytes::new(vec![1, 2, 3]);
        assert_eq!(privkey.len(), 3);
        // Automatically zeroized on drop
    }

    #[test]
    fn test_private_key_debug_redacted() {
        let privkey = PrivateKeyBytes::new(vec![1, 2, 3]);
        let debug = format!("{:?}", privkey);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("1"));
    }

    #[test]
    fn test_key_scheme() {
        let scheme = KeyScheme::new(Codec::Ed25519Pub);
        assert_eq!(scheme.codec(), Codec::Ed25519Pub);
        assert_eq!(scheme.name(), "ed25519-pub");
    }

    #[test]
    fn test_newtypes_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<PublicKeyBytes>();
        assert_sync::<PublicKeyBytes>();
        assert_send::<PrivateKeyBytes>();
        assert_sync::<PrivateKeyBytes>();
        assert_send::<KeyScheme>();
        assert_sync::<KeyScheme>();
    }
}
