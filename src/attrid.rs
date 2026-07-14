// SPDX-License-Identifier: Apache-2.0
use crate::{error::AttributesError, Error};
use multi_trait::{EncodeInto, TryDecodeFrom};
use std::fmt;

/// enum of attribute identifiers. this is here to avoid collisions between
/// different codecs and encryption schemes. these are the common set of
/// attribute identifiers use in Multikeys
#[repr(u8)]
#[derive(Clone, Copy, Hash, Ord, PartialOrd, PartialEq, Eq)]
pub enum AttrId {
    /// bool attribute signaling if the key is encrypted
    KeyIsEncrypted,
    /// the key data
    KeyData,
    /// the cipher codec used to encrypt the key, if encrypted
    CipherCodec,
    /// the length of the cipher codec key in bytes, if encrypted
    CipherKeyLen,
    /// the nonce used to encrypt the key, if encrypted
    CipherNonce,
    /// the codec used to derive the encryption key, if encrypted
    KdfCodec,
    /// the salt used to derive the encryption key, if encrypted
    KdfSalt,
    /// the rounds used to derive the encryption key, if encrypted
    KdfRounds,
    /// the threshold key threshold
    Threshold,
    /// the threshold key limit
    Limit,
    /// the theshold key share identifier
    ShareIdentifier,
    /// codec-specific threshold key data
    ThresholdData,
    /// DKG: the VLAD bytes of the session owner
    DkgOwnerId,
    /// DKG: the CBOR-encoded list of participant VLADs
    DkgParticipants,
    /// DKG: the t-of-n threshold value (u16 little-endian)
    DkgThreshold,
    /// DKG: the t-of-n limit value (u16 little-endian)
    DkgLimit,
    /// DKG: the group public key bytes
    DkgGroupPublicKey,
    /// DKG: this participant's frost-dkg Identifier bytes
    DkgIdentifier,
    /// DKG: the session UUID bytes
    DkgSessionId,
    /// Feldman verifier commitment set for a verifiable key share (CBOR list of
    /// group-element byte strings). Present on Feldman shares of split keys.
    ShareVerifiers,
    /// Secondary dual share for seed-based keys (Ed25519/X25519): the CBOR
    /// encoding of the Feldman scalar share carried alongside the gf256 seed
    /// share. Lets these keys mirror the ECC shares without losing exact restore.
    ShareDual,
    /// Split (Shamir) threshold key: the group/combined BLS public key bytes.
    /// This is the split-key analogue of [`AttrId::DkgGroupPublicKey`]; it is
    /// stamped on a controller Multikey so that the combined threshold
    /// signature can be verified against the group public key.
    ThresholdGroupPublicKey,
    /// Split (Shamir) threshold key: a CBOR-encoded map from share-identifier
    /// bytes (the Shamir x-coordinate, exactly as stored in
    /// [`AttrId::ShareIdentifier`]) to a participant record carrying that
    /// participant's VLAD and its BLS public key share v_i bytes.
    ThresholdParticipants,
    /// Split (Shamir) threshold key: a `Multisig` (signature) over the canonical
    /// encoding of the marker bundle (group public key ‖ participants ‖ threshold
    /// ‖ limit), produced by the controller's signing key. Lets a verifier reject
    /// a tampered marker before trusting it (defeats TSIG-1 marker forgery).
    ThresholdMarkerSig,
    /// Threshold disclosure mode (varuint u8): 0=Full, 1=Partial, 2=FullConfidentialial.
    /// Absent means Full (legacy backward-compatible).
    ThresholdDisclosure,
    /// AEAD-encrypted `ThresholdMetadata` CBOR blob. Present in Partial and
    /// FullConfidentialial modes.
    EncryptedThresholdMeta,
    /// CBOR-encoded `ThresholdMetaCipher` (cipher codec + nonce) for decrypting
    /// `EncryptedThresholdMeta`.
    ThresholdMetaCipher,
}

impl AttrId {
    /// Get the code for the attribute id
    pub fn code(&self) -> u8 {
        (*self).into()
    }

    /// Convert the attribute id to &str
    pub fn as_str(&self) -> &str {
        match self {
            AttrId::KeyIsEncrypted => "key-is-encrypted",
            AttrId::KeyData => "key-data",
            AttrId::CipherCodec => "cipher-codec",
            AttrId::CipherKeyLen => "cipher-key-len",
            AttrId::CipherNonce => "cipher-nonce",
            AttrId::KdfCodec => "kdf-codec",
            AttrId::KdfSalt => "kdf-salt",
            AttrId::KdfRounds => "kdf-rounds",
            AttrId::Threshold => "threshold",
            AttrId::Limit => "limit",
            AttrId::ShareIdentifier => "share-identifier",
            AttrId::ThresholdData => "threshold-data",
            AttrId::DkgOwnerId => "dkg-owner-id",
            AttrId::DkgParticipants => "dkg-participants",
            AttrId::DkgThreshold => "dkg-threshold",
            AttrId::DkgLimit => "dkg-limit",
            AttrId::DkgGroupPublicKey => "dkg-group-public-key",
            AttrId::DkgIdentifier => "dkg-identifier",
            AttrId::DkgSessionId => "dkg-session-id",
            AttrId::ShareVerifiers => "share-verifiers",
            AttrId::ShareDual => "share-dual",
            AttrId::ThresholdGroupPublicKey => "threshold-group-public-key",
            AttrId::ThresholdParticipants => "threshold-participants",
            AttrId::ThresholdMarkerSig => "threshold-marker-sig",
            AttrId::ThresholdDisclosure => "threshold-disclosure",
            AttrId::EncryptedThresholdMeta => "encrypted-threshold-meta",
            AttrId::ThresholdMetaCipher => "threshold-meta-cipher",
        }
    }
}

impl From<AttrId> for u8 {
    fn from(val: AttrId) -> Self {
        val as u8
    }
}

impl TryFrom<u8> for AttrId {
    type Error = Error;

    fn try_from(c: u8) -> Result<Self, Self::Error> {
        match c {
            0 => Ok(AttrId::KeyIsEncrypted),
            1 => Ok(AttrId::KeyData),
            2 => Ok(AttrId::CipherCodec),
            3 => Ok(AttrId::CipherKeyLen),
            4 => Ok(AttrId::CipherNonce),
            5 => Ok(AttrId::KdfCodec),
            6 => Ok(AttrId::KdfSalt),
            7 => Ok(AttrId::KdfRounds),
            8 => Ok(AttrId::Threshold),
            9 => Ok(AttrId::Limit),
            10 => Ok(AttrId::ShareIdentifier),
            11 => Ok(AttrId::ThresholdData),
            12 => Ok(AttrId::DkgOwnerId),
            13 => Ok(AttrId::DkgParticipants),
            14 => Ok(AttrId::DkgThreshold),
            15 => Ok(AttrId::DkgLimit),
            16 => Ok(AttrId::DkgGroupPublicKey),
            17 => Ok(AttrId::DkgIdentifier),
            18 => Ok(AttrId::DkgSessionId),
            19 => Ok(AttrId::ShareVerifiers),
            20 => Ok(AttrId::ShareDual),
            21 => Ok(AttrId::ThresholdGroupPublicKey),
            22 => Ok(AttrId::ThresholdParticipants),
            23 => Ok(AttrId::ThresholdMarkerSig),
            24 => Ok(AttrId::ThresholdDisclosure),
            25 => Ok(AttrId::EncryptedThresholdMeta),
            26 => Ok(AttrId::ThresholdMetaCipher),
            _ => Err(AttributesError::InvalidAttributeValue(c).into()),
        }
    }
}

impl From<AttrId> for Vec<u8> {
    fn from(val: AttrId) -> Self {
        let v: u8 = val.into();
        v.encode_into()
    }
}

impl<'a> TryFrom<&'a [u8]> for AttrId {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (id, _) = Self::try_decode_from(bytes)?;
        Ok(id)
    }
}

impl<'a> TryDecodeFrom<'a> for AttrId {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (code, ptr) = u8::try_decode_from(bytes)?;
        Ok((AttrId::try_from(code)?, ptr))
    }
}

impl TryFrom<&str> for AttrId {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_ascii_lowercase().as_str() {
            "key-is-encrypted" => Ok(AttrId::KeyIsEncrypted),
            "key-data" => Ok(AttrId::KeyData),
            "cipher-codec" => Ok(AttrId::CipherCodec),
            "cipher-key-len" => Ok(AttrId::CipherKeyLen),
            "cipher-nonce" => Ok(AttrId::CipherNonce),
            "kdf-codec" => Ok(AttrId::KdfCodec),
            "kdf-salt" => Ok(AttrId::KdfSalt),
            "kdf-rounds" => Ok(AttrId::KdfRounds),
            "threshold" => Ok(AttrId::Threshold),
            "limit" => Ok(AttrId::Limit),
            "share-identifier" => Ok(AttrId::ShareIdentifier),
            "threshold-data" => Ok(AttrId::ThresholdData),
            "dkg-owner-id" => Ok(AttrId::DkgOwnerId),
            "dkg-participants" => Ok(AttrId::DkgParticipants),
            "dkg-threshold" => Ok(AttrId::DkgThreshold),
            "dkg-limit" => Ok(AttrId::DkgLimit),
            "dkg-group-public-key" => Ok(AttrId::DkgGroupPublicKey),
            "dkg-identifier" => Ok(AttrId::DkgIdentifier),
            "dkg-session-id" => Ok(AttrId::DkgSessionId),
            "share-verifiers" => Ok(AttrId::ShareVerifiers),
            "share-dual" => Ok(AttrId::ShareDual),
            "threshold-group-public-key" => Ok(AttrId::ThresholdGroupPublicKey),
            "threshold-participants" => Ok(AttrId::ThresholdParticipants),
            "threshold-marker-sig" => Ok(AttrId::ThresholdMarkerSig),
            "threshold-disclosure" => Ok(AttrId::ThresholdDisclosure),
            "encrypted-threshold-meta" => Ok(AttrId::EncryptedThresholdMeta),
            "threshold-meta-cipher" => Ok(AttrId::ThresholdMetaCipher),
            _ => Err(AttributesError::InvalidAttributeName(s.to_string()).into()),
        }
    }
}

impl fmt::Display for AttrId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
