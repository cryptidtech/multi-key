// SPDX-License-Identifier: Apache-2.0
//! Threshold disclosure modes and encrypted metadata helpers.
//!
//! This module provides the types and functions for configurable confidentiality
//! of threshold `t` and share-count `n` values on key shares.
//!
//! Three disclosure modes are supported:
//!
//! - **[`ThresholdDisclosure::Full`]** — t and n are plaintext attributes (default).
//! - **[`ThresholdDisclosure::Partial`]** — n is plaintext, t is encrypted.
//! - **[`ThresholdDisclosure::FullConfidentialial`]** — both t and n are encrypted.

use crate::{
    AttrId, Error, Multikey, Views,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use multi_codec::Codec;
use multi_trait::{EncodeInto, TryDecodeFrom};
use multi_util::Varuint;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Disclosure mode for threshold parameters (t and n).
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum ThresholdDisclosure {
    /// t and n are plaintext attributes (default, backward-compatible).
    #[default]
    Full = 0,
    /// n is plaintext, t is encrypted (auditable n, hidden t).
    Partial = 1,
    /// Both t and n are encrypted.
    FullConfidentialial = 2,
}

impl ThresholdDisclosure {
    /// Get the human-readable name for this mode.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
            Self::FullConfidentialial => "full-confidentialial",
        }
    }
}

impl core::fmt::Display for ThresholdDisclosure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<ThresholdDisclosure> for u8 {
    fn from(val: ThresholdDisclosure) -> Self {
        val as u8
    }
}

impl TryFrom<u8> for ThresholdDisclosure {
    type Error = Error;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            0 => Ok(Self::Full),
            1 => Ok(Self::Partial),
            2 => Ok(Self::FullConfidentialial),
            _ => Err(Error::Threshold(ThresholdError::MetaEncryption(
                format!("invalid disclosure mode: {code}"),
            ))),
        }
    }
}

impl EncodeInto for ThresholdDisclosure {
    fn encode_into(&self) -> Vec<u8> {
        let v: u8 = (*self).into();
        v.encode_into()
    }
}

impl<'a> TryDecodeFrom<'a> for ThresholdDisclosure {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (code, ptr) = u8::try_decode_from(bytes)
            .map_err(Error::Multitrait)?;
        let mode = Self::try_from(code)?;
        Ok((mode, ptr))
    }
}

impl Serialize for ThresholdDisclosure {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8((*self).into())
    }
}

impl<'de> Deserialize<'de> for ThresholdDisclosure {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let code = u8::deserialize(deserializer)?;
        Self::try_from(code).map_err(serde::de::Error::custom)
    }
}

/// The threshold parameters that may be encrypted.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThresholdMetadata {
    /// The threshold value `t`, or `None` if not stored in the encrypted blob.
    pub threshold: Option<u16>,
    /// The limit value `n`, or `None` if not stored in the encrypted blob.
    pub limit: Option<u16>,
}

impl ThresholdMetadata {
    /// Create metadata with both t and n.
    #[must_use]
    pub fn new(threshold: u16, limit: u16) -> Self {
        Self {
            threshold: Some(threshold),
            limit: Some(limit),
        }
    }

    /// Create metadata with only the threshold (for Partial mode).
    #[must_use]
    pub fn threshold_only(threshold: u16) -> Self {
        Self {
            threshold: Some(threshold),
            limit: None,
        }
    }

    /// Encode to CBOR bytes.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| Error::Threshold(ThresholdError::MetaEncryption(format!("CBOR encode: {e}"))))?;
        Ok(buf)
    }

    /// Decode from CBOR bytes.
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes)
            .map_err(|e| Error::Threshold(ThresholdError::MetaEncryption(format!("CBOR decode: {e}"))))
    }
}

/// Cipher parameters for decrypting [`ThresholdMetadata`].
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThresholdMetaCipher {
    /// The multicodec code of the AEAD cipher (e.g. `0x2000` for ChaCha20-Poly1305).
    pub cipher_codec: u64,
    /// The nonce bytes.
    pub nonce: Vec<u8>,
}

impl ThresholdMetaCipher {
    /// Create new cipher info from a codec and nonce.
    #[must_use]
    pub fn new(codec: Codec, nonce: Vec<u8>) -> Self {
        Self {
            cipher_codec: codec.into(),
            nonce,
        }
    }

    /// Get the codec as a [`Codec`].
    pub fn codec(&self) -> Result<Codec, Error> {
        Codec::try_from(self.cipher_codec)
            .map_err(|e| Error::Threshold(ThresholdError::MetaEncryption(format!("invalid codec: {e}"))))
    }

    /// Encode to CBOR bytes.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| Error::Threshold(ThresholdError::MetaEncryption(format!("CBOR encode cipher: {e}"))))?;
        Ok(buf)
    }

    /// Decode from CBOR bytes.
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes)
            .map_err(|e| Error::Threshold(ThresholdError::MetaEncryption(format!("CBOR decode cipher: {e}"))))
    }
}

/// Encrypt threshold metadata using ChaCha20-Poly1305 AEAD.
///
/// `key` must be 32 bytes. A random nonce is generated and returned in the
/// [`ThresholdMetaCipher`].
#[allow(deprecated)]
pub fn encrypt_threshold_meta(
    meta: &ThresholdMetadata,
    key: &[u8],
) -> Result<(Vec<u8>, ThresholdMetaCipher), Error> {
    if key.len() != 32 {
        return Err(Error::Threshold(ThresholdError::MetaEncryption(format!(
            "invalid key length: expected 32, got {}",
            key.len()
        ))));
    }

    let plaintext = meta.to_cbor_bytes()?;

    let mut nonce_bytes = vec![0u8; 12];
    getrandom::fill(&mut nonce_bytes).map_err(|e| {
        Error::Threshold(ThresholdError::MetaEncryption(format!("RNG failure: {e}")))
    })?;

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| Error::Threshold(ThresholdError::MetaEncryption(format!("AEAD key init: {e}"))))?;

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plaintext,
                aad: b"threshold-meta",
            },
        )
        .map_err(|e| Error::Threshold(ThresholdError::MetaEncryption(format!("AEAD seal: {e}"))))?;

    let cipher_info = ThresholdMetaCipher::new(Codec::Chacha20Poly1305, nonce_bytes);
    Ok((ciphertext, cipher_info))
}

/// Decrypt threshold metadata using ChaCha20-Poly1305 AEAD.
#[allow(deprecated)]
pub fn decrypt_threshold_meta(
    encrypted: &[u8],
    cipher_info: &ThresholdMetaCipher,
    key: &[u8],
) -> Result<ThresholdMetadata, Error> {
    if key.len() != 32 {
        return Err(Error::Threshold(ThresholdError::MetaEncryption(format!(
            "invalid key length: expected 32, got {}",
            key.len()
        ))));
    }

    let codec = cipher_info.codec()?;
    match codec {
        Codec::Chacha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| Error::Threshold(ThresholdError::MetaEncryption(format!("AEAD key init: {e}"))))?;

            let plaintext = cipher
                .decrypt(
                    Nonce::from_slice(&cipher_info.nonce),
                    Payload {
                        msg: encrypted,
                        aad: b"threshold-meta",
                    },
                )
                .map_err(|e| Error::Threshold(ThresholdError::MetaEncryption(format!("AEAD open: {e}"))))?;

            ThresholdMetadata::from_cbor_bytes(&plaintext)
        }
        _ => Err(Error::Threshold(ThresholdError::MetaEncryption(format!(
            "unsupported AEAD codec: {codec}"
        )))),
    }
}

/// Generate a random 32-byte ChaCha20-Poly1305 key.
pub fn generate_meta_key() -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(vec![0u8; 32]);
    getrandom::fill(key.as_mut_slice())
        .expect("getrandom failure during meta key generation");
    key
}

/// Read the raw 32-byte key from a `Multikey` that contains a symmetric
/// cipher key (e.g. a ChaCha20-Poly1305 key Multikey). This bridges the
/// `Multikey` at-rest encryption infrastructure to the threshold metadata
/// encryption.
fn extract_meta_key(meta_key: &Multikey) -> Result<Zeroizing<Vec<u8>>, Error> {
    let dv = meta_key.data_view()?;
    let key = dv.key_bytes()?;
    if key.len() != 32 {
        return Err(Error::Threshold(ThresholdError::MetaEncryption(format!(
            "meta key must be 32 bytes, got {}",
            key.len()
        ))));
    }
    Ok(key)
}

/// Read the disclosure mode from a Multikey. Returns [`ThresholdDisclosure::Full`]
/// if no `ThresholdDisclosure` attribute is present (backward compatible).
pub fn disclosure_mode(mk: &Multikey) -> Result<ThresholdDisclosure, Error> {
    match mk.attributes.get(&AttrId::ThresholdDisclosure) {
        Some(v) => {
            let (mode, _) = ThresholdDisclosure::try_decode_from(v.as_slice())?;
            Ok(mode)
        }
        None => Ok(ThresholdDisclosure::Full),
    }
}

/// Read t and n from a Multikey, decrypting if necessary.
///
/// In Full mode, reads plaintext `Threshold`/`Limit` attributes.
/// In Partial mode, reads `Limit` from plaintext and decrypts `Threshold`.
/// In FullConfidentialial mode, decrypts both from `EncryptedThresholdMeta`.
///
/// `meta_key` is required for Partial/FullConfidentialial modes.
pub fn read_threshold_params(
    mk: &Multikey,
    meta_key: Option<&Multikey>,
) -> Result<(usize, usize), Error> {
    let mode = disclosure_mode(mk)?;
    match mode {
        ThresholdDisclosure::Full => {
            let t = mk
                .attributes
                .get(&AttrId::Threshold)
                .ok_or(AttributesError::MissingThreshold)?;
            let n = mk
                .attributes
                .get(&AttrId::Limit)
                .ok_or(AttributesError::MissingLimit)?;
            let t = Varuint::<usize>::try_from(t.as_slice())?.to_inner();
            let n = Varuint::<usize>::try_from(n.as_slice())?.to_inner();
            Ok((t, n))
        }
        ThresholdDisclosure::Partial => {
            let n = mk
                .attributes
                .get(&AttrId::Limit)
                .ok_or(AttributesError::MissingLimit)?;
            let n = Varuint::<usize>::try_from(n.as_slice())?.to_inner();

            let encrypted = mk
                .attributes
                .get(&AttrId::EncryptedThresholdMeta)
                .ok_or(ThresholdError::MetaEncryption(
                    "missing EncryptedThresholdMeta".to_string(),
                ))?;
            let cipher_info_bytes = mk
                .attributes
                .get(&AttrId::ThresholdMetaCipher)
                .ok_or(ThresholdError::MetaEncryption(
                    "missing ThresholdMetaCipher".to_string(),
                ))?;
            let cipher_info = ThresholdMetaCipher::from_cbor_bytes(cipher_info_bytes)?;

            let meta_key = meta_key
                .ok_or(ThresholdError::MissingMetaKey)?;
            let key = extract_meta_key(meta_key)?;

            let meta = decrypt_threshold_meta(encrypted, &cipher_info, &key)?;
            let t = meta
                .threshold
                .ok_or(ThresholdError::MetaEncryption(
                    "threshold not in encrypted metadata".to_string(),
                ))? as usize;
            Ok((t, n))
        }
        ThresholdDisclosure::FullConfidentialial => {
            let encrypted = mk
                .attributes
                .get(&AttrId::EncryptedThresholdMeta)
                .ok_or(ThresholdError::MetaEncryption(
                    "missing EncryptedThresholdMeta".to_string(),
                ))?;
            let cipher_info_bytes = mk
                .attributes
                .get(&AttrId::ThresholdMetaCipher)
                .ok_or(ThresholdError::MetaEncryption(
                    "missing ThresholdMetaCipher".to_string(),
                ))?;
            let cipher_info = ThresholdMetaCipher::from_cbor_bytes(cipher_info_bytes)?;

            let meta_key = meta_key.ok_or(ThresholdError::MissingMetaKey)?;
            let key = extract_meta_key(meta_key)?;

            let meta = decrypt_threshold_meta(encrypted, &cipher_info, &key)?;
            let t = meta
                .threshold
                .ok_or(ThresholdError::MetaEncryption(
                    "threshold not in encrypted metadata".to_string(),
                ))? as usize;
            let n = meta
                .limit
                .ok_or(ThresholdError::MetaEncryption(
                    "limit not in encrypted metadata".to_string(),
                ))? as usize;
            Ok((t, n))
        }
    }
}

/// Stamp disclosure attributes onto a Multikey's attribute map.
///
/// This is the single place where the attribute-stamping logic lives, shared
/// between `Builder::with_disclosure()` and `to_disclosure()`.
pub fn stamp_disclosure_attrs(
    attributes: &mut crate::mk::Attributes,
    mode: ThresholdDisclosure,
    threshold: usize,
    limit: usize,
    meta_key: Option<&Multikey>,
) -> Result<(), Error> {
    use crate::error::ThresholdError;

    // remove old disclosure-related attributes
    attributes.remove(&AttrId::Threshold);
    attributes.remove(&AttrId::Limit);
    attributes.remove(&AttrId::EncryptedThresholdMeta);
    attributes.remove(&AttrId::ThresholdMetaCipher);
    attributes.remove(&AttrId::ThresholdDisclosure);

    match mode {
        ThresholdDisclosure::Full => {
            let t_bytes: Vec<u8> = Varuint(threshold).into();
            let n_bytes: Vec<u8> = Varuint(limit).into();
            attributes.insert(AttrId::Threshold, t_bytes.into());
            attributes.insert(AttrId::Limit, n_bytes.into());
            attributes.insert(
                AttrId::ThresholdDisclosure,
                Zeroizing::new(mode.encode_into()),
            );
        }
        ThresholdDisclosure::Partial => {
            let meta_key = meta_key.ok_or(ThresholdError::MissingMetaKey)?;
            let key = extract_meta_key(meta_key)?;

            // plaintext limit
            let n_bytes: Vec<u8> = Varuint(limit).into();
            attributes.insert(AttrId::Limit, n_bytes.into());

            // encrypted threshold only
            let meta = ThresholdMetadata::threshold_only(threshold as u16);
            let (ciphertext, cipher_info) = encrypt_threshold_meta(&meta, &key)?;
            attributes.insert(AttrId::EncryptedThresholdMeta, ciphertext.into());
            attributes.insert(
                AttrId::ThresholdMetaCipher,
                cipher_info.to_cbor_bytes()?.into(),
            );
            attributes.insert(
                AttrId::ThresholdDisclosure,
                Zeroizing::new(mode.encode_into()),
            );
        }
        ThresholdDisclosure::FullConfidentialial => {
            let meta_key = meta_key.ok_or(ThresholdError::MissingMetaKey)?;
            let key = extract_meta_key(meta_key)?;

            // encrypted both t and n
            let meta = ThresholdMetadata::new(threshold as u16, limit as u16);
            let (ciphertext, cipher_info) = encrypt_threshold_meta(&meta, &key)?;
            attributes.insert(AttrId::EncryptedThresholdMeta, ciphertext.into());
            attributes.insert(
                AttrId::ThresholdMetaCipher,
                cipher_info.to_cbor_bytes()?.into(),
            );
            attributes.insert(
                AttrId::ThresholdDisclosure,
                Zeroizing::new(mode.encode_into()),
            );
        }
    }
    Ok(())
}

/// The `ThresholdDisclosureView` trait for mode conversion and reading.
pub trait ThresholdDisclosureView {
    /// Get the current disclosure mode. Returns Full if no mode attribute is present.
    fn disclosure_mode(&self) -> Result<ThresholdDisclosure, Error>;

    /// Read t and n, decrypting if necessary. Requires `meta_key` for encrypted modes.
    fn read_threshold_params(
        &self,
        meta_key: Option<&Multikey>,
    ) -> Result<(usize, usize), Error>;

    /// Convert to a target disclosure mode.
    fn to_disclosure(
        &self,
        target: ThresholdDisclosure,
        meta_key: Option<&Multikey>,
        current_meta_key: Option<&Multikey>,
    ) -> Result<Multikey, Error>;
}

/// Concrete view implementation for any Multikey.
pub struct DisclosureView<'a> {
    mk: &'a Multikey,
}

impl<'a> DisclosureView<'a> {
    /// Create a disclosure view over a Multikey.
    pub fn new(mk: &'a Multikey) -> Self {
        Self { mk }
    }
}

impl<'a> TryFrom<&'a Multikey> for DisclosureView<'a> {
    type Error = Error;

    fn try_from(mk: &'a Multikey) -> Result<Self, Self::Error> {
        Ok(Self { mk })
    }
}

impl<'a> ThresholdDisclosureView for DisclosureView<'a> {
    fn disclosure_mode(&self) -> Result<ThresholdDisclosure, Error> {
        disclosure_mode(self.mk)
    }

    fn read_threshold_params(
        &self,
        meta_key: Option<&Multikey>,
    ) -> Result<(usize, usize), Error> {
        read_threshold_params(self.mk, meta_key)
    }

    fn to_disclosure(
        &self,
        target: ThresholdDisclosure,
        meta_key: Option<&Multikey>,
        current_meta_key: Option<&Multikey>,
    ) -> Result<Multikey, Error> {
        // read current t/n (decrypting if needed)
        let (t, n) = read_threshold_params(self.mk, current_meta_key)?;

        // clone and stamp new attrs
        let mut new_mk = self.mk.clone();
        stamp_disclosure_attrs(
            &mut new_mk.attributes,
            target,
            t,
            n,
            meta_key,
        )?;
        Ok(new_mk)
    }
}

use crate::error::{AttributesError, ThresholdError};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Builder;
    use multi_codec::Codec;

    fn make_meta_key() -> Multikey {
        let key = generate_meta_key();
        Builder::new(Codec::Chacha20Poly1305)
            .with_key_bytes(&key.as_slice())
            .try_build()
            .unwrap()
    }

    fn make_share(t: usize, n: usize) -> Multikey {
        Builder::new(Codec::Bls12381G1PrivShare)
            .with_threshold(t)
            .with_limit(n)
            .with_key_bytes(&vec![0u8; 32])
            .try_build()
            .unwrap()
    }

    #[test]
    fn test_disclosure_default() {
        assert_eq!(ThresholdDisclosure::default(), ThresholdDisclosure::Full);
    }

    #[test]
    fn test_disclosure_from_u8() {
        assert_eq!(
            ThresholdDisclosure::try_from(0u8).unwrap(),
            ThresholdDisclosure::Full
        );
        assert_eq!(
            ThresholdDisclosure::try_from(1u8).unwrap(),
            ThresholdDisclosure::Partial
        );
        assert_eq!(
            ThresholdDisclosure::try_from(2u8).unwrap(),
            ThresholdDisclosure::FullConfidentialial
        );
        assert!(ThresholdDisclosure::try_from(3u8).is_err());
    }

    #[test]
    fn test_disclosure_encode_decode_roundtrip() {
        for mode in [
            ThresholdDisclosure::Full,
            ThresholdDisclosure::Partial,
            ThresholdDisclosure::FullConfidentialial,
        ] {
            let encoded = mode.encode_into();
            let (decoded, rest) =
                ThresholdDisclosure::try_decode_from(&encoded).unwrap();
            assert_eq!(mode, decoded);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn test_metadata_cbor_roundtrip() {
        let meta = ThresholdMetadata::new(3, 5);
        let bytes = meta.to_cbor_bytes().unwrap();
        let decoded = ThresholdMetadata::from_cbor_bytes(&bytes).unwrap();
        assert_eq!(meta, decoded);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_meta_key();
        let meta = ThresholdMetadata::new(3, 5);
        let (ct, info) = encrypt_threshold_meta(&meta, &key).unwrap();
        let decrypted = decrypt_threshold_meta(&ct, &info, &key).unwrap();
        assert_eq!(meta, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_wrong_key() {
        let key1 = generate_meta_key();
        let key2 = generate_meta_key();
        let meta = ThresholdMetadata::new(3, 5);
        let (ct, info) = encrypt_threshold_meta(&meta, &key1).unwrap();
        assert!(decrypt_threshold_meta(&ct, &info, &key2).is_err());
    }

    #[test]
    fn test_encrypt_decrypt_tampered() {
        let key = generate_meta_key();
        let meta = ThresholdMetadata::new(3, 5);
        let (mut ct, info) = encrypt_threshold_meta(&meta, &key).unwrap();
        ct[0] ^= 0xFF;
        assert!(decrypt_threshold_meta(&ct, &info, &key).is_err());
    }

    #[test]
    fn test_read_full_mode() {
        let share = make_share(3, 5);
        let (t, n) = read_threshold_params(&share, None).unwrap();
        assert_eq!(t, 3);
        assert_eq!(n, 5);
    }

    #[test]
    fn test_convert_full_to_partial_and_back() {
        let share = make_share(3, 5);
        let meta_key = make_meta_key();

        // convert to Partial
        let partial = share
            .disclosure_view()
            .unwrap()
            .to_disclosure(ThresholdDisclosure::Partial, Some(&meta_key), None)
            .unwrap();
        assert_eq!(
            partial.disclosure_view().unwrap().disclosure_mode().unwrap(),
            ThresholdDisclosure::Partial
        );

        // read t/n from partial
        let (t, n) = read_threshold_params(&partial, Some(&meta_key)).unwrap();
        assert_eq!(t, 3);
        assert_eq!(n, 5);

        // convert back to Full
        let full = partial
            .disclosure_view()
            .unwrap()
            .to_disclosure(ThresholdDisclosure::Full, None, Some(&meta_key))
            .unwrap();
        assert_eq!(
            full.disclosure_view().unwrap().disclosure_mode().unwrap(),
            ThresholdDisclosure::Full
        );
        let (t, n) = read_threshold_params(&full, None).unwrap();
        assert_eq!(t, 3);
        assert_eq!(n, 5);
    }

    #[test]
    fn test_convert_full_to_full_confidentialial_and_back() {
        let share = make_share(3, 5);
        let meta_key = make_meta_key();

        // convert to FullConfidentialial
        let encrypted = share
            .disclosure_view()
            .unwrap()
            .to_disclosure(
                ThresholdDisclosure::FullConfidentialial,
                Some(&meta_key),
                None,
            )
            .unwrap();
        assert_eq!(
            encrypted
                .disclosure_view()
                .unwrap()
                .disclosure_mode()
                .unwrap(),
            ThresholdDisclosure::FullConfidentialial
        );

        // read t/n
        let (t, n) = read_threshold_params(&encrypted, Some(&meta_key)).unwrap();
        assert_eq!(t, 3);
        assert_eq!(n, 5);

        // convert back to Full
        let full = encrypted
            .disclosure_view()
            .unwrap()
            .to_disclosure(ThresholdDisclosure::Full, None, Some(&meta_key))
            .unwrap();
        let (t, n) = read_threshold_params(&full, None).unwrap();
        assert_eq!(t, 3);
        assert_eq!(n, 5);
    }

    #[test]
    fn test_read_encrypted_without_meta_key() {
        let share = make_share(3, 5);
        let meta_key = make_meta_key();
        let encrypted = share
            .disclosure_view()
            .unwrap()
            .to_disclosure(
                ThresholdDisclosure::FullConfidentialial,
                Some(&meta_key),
                None,
            )
            .unwrap();
        assert!(read_threshold_params(&encrypted, None).is_err());
    }

    #[test]
    fn test_convert_to_partial_without_meta_key() {
        let share = make_share(3, 5);
        let result = share
            .disclosure_view()
            .unwrap()
            .to_disclosure(ThresholdDisclosure::Partial, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_meta_key_is_32_bytes() {
        let key = generate_meta_key();
        assert_eq!(key.len(), 32);
    }
}