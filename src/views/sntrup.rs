// SPDX-License-Identifier: Apache-2.0
//! Streamlined NTRU Prime multikey view; post-quantum KEM for all supported sizes.
//!
//! Supports sntrup761, sntrup857, sntrup953, sntrup1013, and sntrup1277.

use crate::{
    error::{AttributesError, ConversionsError, SealError},
    views::{aead, Views},
    AttrId, AttrView, Builder, ConvView, DataView, Error, FingerprintView, Multikey, OpenView,
    SealView,
};
use multi_codec::Codec;
use multi_hash::{mh, Multihash};
use multi_trait::TryDecodeFrom;
use multi_util::Varbytes;
use zeroize::Zeroizing;

const SNTRUP_SEED_LENGTH: usize = 32;

/// Compatibility wrapper: allows `rand 0.8` OsRng to satisfy `rand_core 0.10`
/// `CryptoRng` required by the `sntrup` crate.
struct OsRng010;

impl rand_core::TryRng for OsRng010 {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(rand_core::Rng::next_u32(&mut rand::rng()))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(rand_core::Rng::next_u64(&mut rand::rng()))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        rand_core::Rng::fill_bytes(&mut rand::rng(), dst);
        Ok(())
    }
}
impl rand_core::TryCryptoRng for OsRng010 {}

/// Decoded sealed message: (kem_ct, aead_codec, nonce, ciphertext+tag)
type SealedParts = (Vec<u8>, Codec, Vec<u8>, Vec<u8>);

fn is_sntrup_priv(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::Sntrup761Priv
            | Codec::Sntrup857Priv
            | Codec::Sntrup953Priv
            | Codec::Sntrup1013Priv
            | Codec::Sntrup1277Priv
    )
}

fn is_sntrup_pub(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::Sntrup761Pub
            | Codec::Sntrup857Pub
            | Codec::Sntrup953Pub
            | Codec::Sntrup1013Pub
            | Codec::Sntrup1277Pub
    )
}

/// SNTRUP AEAD codecs allowed (256-bit symmetric for PQ safety)
fn is_sntrup_aead_allowed(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::Xchacha20Poly1305 | Codec::Chacha20Poly1305 | Codec::AesGcm256
    )
}

/// Return the corresponding public codec for a private codec.
fn pub_codec(priv_codec: Codec) -> Result<Codec, Error> {
    match priv_codec {
        Codec::Sntrup761Priv => Ok(Codec::Sntrup761Pub),
        Codec::Sntrup857Priv => Ok(Codec::Sntrup857Pub),
        Codec::Sntrup953Priv => Ok(Codec::Sntrup953Pub),
        Codec::Sntrup1013Priv => Ok(Codec::Sntrup1013Pub),
        Codec::Sntrup1277Priv => Ok(Codec::Sntrup1277Pub),
        _ => Err(ConversionsError::SecretKeyFailure("not an sntrup private key".into()).into()),
    }
}

/// Return the HKDF info label for domain separation per size.
fn seal_info(codec: Codec) -> &'static [u8] {
    match codec {
        Codec::Sntrup761Pub | Codec::Sntrup761Priv => b"sntrup761-seal",
        Codec::Sntrup857Pub | Codec::Sntrup857Priv => b"sntrup857-seal",
        Codec::Sntrup953Pub | Codec::Sntrup953Priv => b"sntrup953-seal",
        Codec::Sntrup1013Pub | Codec::Sntrup1013Priv => b"sntrup1013-seal",
        Codec::Sntrup1277Pub | Codec::Sntrup1277Priv => b"sntrup1277-seal",
        _ => b"sntrup-seal",
    }
}

/// Generate a public key from a seed for the given private codec.
fn generate_public_key(priv_codec: Codec, seed: &[u8; 32]) -> Result<Vec<u8>, Error> {
    match priv_codec {
        Codec::Sntrup761Priv => {
            let (ek, _dk) = sntrup::sntrup761::generate_key_deterministic(seed);
            Ok(ek.as_ref().to_vec())
        }
        Codec::Sntrup857Priv => {
            let (ek, _dk) = sntrup::sntrup857::generate_key_deterministic(seed);
            Ok(ek.as_ref().to_vec())
        }
        Codec::Sntrup953Priv => {
            let (ek, _dk) = sntrup::sntrup953::generate_key_deterministic(seed);
            Ok(ek.as_ref().to_vec())
        }
        Codec::Sntrup1013Priv => {
            let (ek, _dk) = sntrup::sntrup1013::generate_key_deterministic(seed);
            Ok(ek.as_ref().to_vec())
        }
        Codec::Sntrup1277Priv => {
            let (ek, _dk) = sntrup::sntrup1277::generate_key_deterministic(seed);
            Ok(ek.as_ref().to_vec())
        }
        _ => Err(ConversionsError::SecretKeyFailure("not an sntrup private key".into()).into()),
    }
}

/// Encapsulate with a public key, returning (ciphertext_bytes, shared_secret_bytes).
fn kem_encapsulate(pub_codec: Codec, pub_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut rng = OsRng010;
    match pub_codec {
        Codec::Sntrup761Pub => {
            let ek = sntrup::sntrup761::EncapsulationKey::try_from(pub_bytes)
                .map_err(|_| SealError::EncapsulationFailed("invalid key size".into()))?;
            let (ct, ss) = ek.encapsulate(&mut rng);
            Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
        }
        Codec::Sntrup857Pub => {
            let ek = sntrup::sntrup857::EncapsulationKey::try_from(pub_bytes)
                .map_err(|_| SealError::EncapsulationFailed("invalid key size".into()))?;
            let (ct, ss) = ek.encapsulate(&mut rng);
            Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
        }
        Codec::Sntrup953Pub => {
            let ek = sntrup::sntrup953::EncapsulationKey::try_from(pub_bytes)
                .map_err(|_| SealError::EncapsulationFailed("invalid key size".into()))?;
            let (ct, ss) = ek.encapsulate(&mut rng);
            Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
        }
        Codec::Sntrup1013Pub => {
            let ek = sntrup::sntrup1013::EncapsulationKey::try_from(pub_bytes)
                .map_err(|_| SealError::EncapsulationFailed("invalid key size".into()))?;
            let (ct, ss) = ek.encapsulate(&mut rng);
            Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
        }
        Codec::Sntrup1277Pub => {
            let ek = sntrup::sntrup1277::EncapsulationKey::try_from(pub_bytes)
                .map_err(|_| SealError::EncapsulationFailed("invalid key size".into()))?;
            let (ct, ss) = ek.encapsulate(&mut rng);
            Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
        }
        _ => Err(SealError::NotEncapsulationKey.into()),
    }
}

/// Decapsulate with a private seed, returning shared_secret_bytes.
fn kem_decapsulate(priv_codec: Codec, seed: &[u8; 32], ct_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    match priv_codec {
        Codec::Sntrup761Priv => {
            let (_ek, dk) = sntrup::sntrup761::generate_key_deterministic(seed);
            let ct = sntrup::sntrup761::Ciphertext::try_from(ct_bytes)
                .map_err(|_| SealError::DecapsulationFailed("invalid ciphertext size".into()))?;
            let ss = dk.decapsulate(&ct);
            Ok(ss.as_ref().to_vec())
        }
        Codec::Sntrup857Priv => {
            let (_ek, dk) = sntrup::sntrup857::generate_key_deterministic(seed);
            let ct = sntrup::sntrup857::Ciphertext::try_from(ct_bytes)
                .map_err(|_| SealError::DecapsulationFailed("invalid ciphertext size".into()))?;
            let ss = dk.decapsulate(&ct);
            Ok(ss.as_ref().to_vec())
        }
        Codec::Sntrup953Priv => {
            let (_ek, dk) = sntrup::sntrup953::generate_key_deterministic(seed);
            let ct = sntrup::sntrup953::Ciphertext::try_from(ct_bytes)
                .map_err(|_| SealError::DecapsulationFailed("invalid ciphertext size".into()))?;
            let ss = dk.decapsulate(&ct);
            Ok(ss.as_ref().to_vec())
        }
        Codec::Sntrup1013Priv => {
            let (_ek, dk) = sntrup::sntrup1013::generate_key_deterministic(seed);
            let ct = sntrup::sntrup1013::Ciphertext::try_from(ct_bytes)
                .map_err(|_| SealError::DecapsulationFailed("invalid ciphertext size".into()))?;
            let ss = dk.decapsulate(&ct);
            Ok(ss.as_ref().to_vec())
        }
        Codec::Sntrup1277Priv => {
            let (_ek, dk) = sntrup::sntrup1277::generate_key_deterministic(seed);
            let ct = sntrup::sntrup1277::Ciphertext::try_from(ct_bytes)
                .map_err(|_| SealError::DecapsulationFailed("invalid ciphertext size".into()))?;
            let ss = dk.decapsulate(&ct);
            Ok(ss.as_ref().to_vec())
        }
        _ => Err(SealError::NotDecapsulationKey.into()),
    }
}

pub(crate) struct View<'a> {
    mk: &'a Multikey,
}

impl<'a> TryFrom<&'a Multikey> for View<'a> {
    type Error = Error;

    fn try_from(mk: &'a Multikey) -> Result<Self, Self::Error> {
        Ok(Self { mk })
    }
}

impl<'a> AttrView for View<'a> {
    fn is_encrypted(&self) -> bool {
        false
    }
    fn is_secret_key(&self) -> bool {
        is_sntrup_priv(self.mk.codec)
    }
    fn is_public_key(&self) -> bool {
        is_sntrup_pub(self.mk.codec)
    }
    fn is_secret_key_share(&self) -> bool {
        false
    }
}

impl<'a> DataView for View<'a> {
    fn key_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let key = self
            .mk
            .attributes
            .get(&AttrId::KeyData)
            .ok_or(AttributesError::MissingKey)?;
        Ok(key.clone())
    }
    fn secret_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        if !self.is_secret_key() {
            return Err(AttributesError::NotSecretKey(self.mk.codec).into());
        }
        self.key_bytes()
    }
}

impl<'a> ConvView for View<'a> {
    fn to_public_key(&self) -> Result<Multikey, Error> {
        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };

        if secret_bytes.len() != SNTRUP_SEED_LENGTH {
            return Err(ConversionsError::SecretKeyFailure("invalid seed length".into()).into());
        }

        let seed: [u8; 32] = secret_bytes[..32]
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("invalid seed".into()))?;

        let pub_bytes = generate_public_key(self.mk.codec, &seed)?;
        let codec = pub_codec(self.mk.codec)?;

        Builder::new(codec)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&pub_bytes)
            .try_build()
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        Err(
            ConversionsError::UnsupportedAlgorithm("sntrup not supported in SSH key format".into())
                .into(),
        )
    }
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        Err(
            ConversionsError::UnsupportedAlgorithm("sntrup not supported in SSH key format".into())
                .into(),
        )
    }
}

impl<'a> FingerprintView for View<'a> {
    fn fingerprint(&self, codec: Codec) -> Result<Multihash, Error> {
        let pub_bytes = if self.is_secret_key() {
            let pk = self.to_public_key()?;
            let dv = pk.data_view()?;
            dv.key_bytes()?
        } else {
            self.key_bytes()?
        };
        Ok(mh::Builder::new_from_bytes(codec, pub_bytes.as_slice())?.try_build()?)
    }
}

/// Encode a sealed message: [kem_ct Varbytes][aead_codec Codec][nonce Varbytes][ct+tag Varbytes]
fn encode_sealed(kem_ct: &[u8], aead_codec: Codec, nonce: &[u8], ct_tag: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.append(&mut Varbytes::new(kem_ct.to_vec()).into());
    out.append(&mut aead_codec.into());
    out.append(&mut Varbytes::new(nonce.to_vec()).into());
    out.append(&mut Varbytes::new(ct_tag.to_vec()).into());
    out
}

/// Decode a sealed message: [kem_ct Varbytes][aead_codec Codec][nonce Varbytes][ct+tag Varbytes]
fn decode_sealed(data: &[u8]) -> Result<SealedParts, SealError> {
    let (kem_ct, ptr) = Varbytes::try_decode_from(data)
        .map_err(|_| SealError::InvalidFormat("missing kem ciphertext".into()))?;
    let (aead_codec, ptr) = Codec::try_decode_from(ptr)
        .map_err(|_| SealError::InvalidFormat("missing aead codec".into()))?;
    let (nonce, ptr) = Varbytes::try_decode_from(ptr)
        .map_err(|_| SealError::InvalidFormat("missing nonce".into()))?;
    let (ct_tag, _) = Varbytes::try_decode_from(ptr)
        .map_err(|_| SealError::InvalidFormat("missing ciphertext".into()))?;
    Ok((
        kem_ct.to_inner(),
        aead_codec,
        nonce.to_inner(),
        ct_tag.to_inner(),
    ))
}

impl<'a> SealView for View<'a> {
    fn seal(
        &self,
        plaintext: &[u8],
        aead_codec: Codec,
        aad: &[u8],
    ) -> Result<(Vec<u8>, Option<Multikey>), Error> {
        if !self.is_public_key() {
            return Err(SealError::NotEncapsulationKey.into());
        }
        if !is_sntrup_aead_allowed(aead_codec) {
            return Err(SealError::UnsupportedAeadCodec(aead_codec).into());
        }

        let pub_bytes = self.key_bytes()?;

        let (kem_ct, shared_secret) = kem_encapsulate(self.mk.codec, &pub_bytes)?;

        // Derive AEAD key from shared secret via HKDF
        let key_len = aead::key_size(aead_codec)?;
        let info = seal_info(self.mk.codec);
        let aead_key = aead::derive_aead_key(&shared_secret, info, key_len)?;

        // Encrypt plaintext
        let (nonce, ct_tag) = aead::aead_seal(aead_codec, &aead_key, plaintext, aad)?;

        Ok((encode_sealed(&kem_ct, aead_codec, &nonce, &ct_tag), None))
    }
}

impl<'a> OpenView for View<'a> {
    fn open(
        &self,
        sealed_msg: &[u8],
        _ephemeral: Option<&Multikey>,
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if !self.is_secret_key() {
            return Err(SealError::NotDecapsulationKey.into());
        }

        let (kem_ct, aead_codec, nonce, ct_tag) = decode_sealed(sealed_msg)?;

        if !is_sntrup_aead_allowed(aead_codec) {
            return Err(SealError::UnsupportedAeadCodec(aead_codec).into());
        }

        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };

        if secret_bytes.len() != SNTRUP_SEED_LENGTH {
            return Err(ConversionsError::SecretKeyFailure("invalid seed length".into()).into());
        }

        let seed: [u8; 32] = secret_bytes[..32]
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("invalid seed".into()))?;

        let shared_secret = kem_decapsulate(self.mk.codec, &seed, &kem_ct)?;

        // Derive AEAD key from shared secret via HKDF
        let key_len = aead::key_size(aead_codec)?;
        let info = seal_info(self.mk.codec);
        let aead_key = aead::derive_aead_key(&shared_secret, info, key_len)?;

        // Decrypt ciphertext
        Ok(aead::aead_open(
            aead_codec, &aead_key, &nonce, &ct_tag, aad,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mk::SNTRUP_KEY_CODECS;
    use crate::views::Views;

    #[test]
    fn test_sntrup_key_gen_roundtrip() {
        for codec in SNTRUP_KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test kem key")
                .try_build()
                .unwrap();

            let attr = mk.attr_view().unwrap();
            assert!(attr.is_secret_key());
            assert!(!attr.is_public_key());

            let kd = mk.data_view().unwrap();
            assert!(kd.key_bytes().is_ok());
            assert!(kd.secret_bytes().is_ok());

            // serialize/deserialize roundtrip
            let bytes: Vec<u8> = mk.clone().into();
            let mk2 = Multikey::try_from(bytes.as_slice()).unwrap();
            assert_eq!(mk, mk2);
        }
    }

    #[test]
    fn test_sntrup_public_key_derivation() {
        for codec in SNTRUP_KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .try_build()
                .unwrap();

            let conv = mk.conv_view().unwrap();
            let pk = conv.to_public_key().unwrap();

            let attr = pk.attr_view().unwrap();
            assert!(attr.is_public_key());
            assert!(!attr.is_secret_key());

            // derive again and check same result
            let pk2 = conv.to_public_key().unwrap();
            assert_eq!(pk, pk2);
        }
    }

    #[test]
    fn test_sntrup_fingerprint() {
        for codec in SNTRUP_KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .try_build()
                .unwrap();

            let pk = mk.conv_view().unwrap().to_public_key().unwrap();
            let fp = pk
                .fingerprint_view()
                .unwrap()
                .fingerprint(Codec::Sha3256)
                .unwrap();
            let fp_bytes: Vec<u8> = fp.into();
            assert!(!fp_bytes.is_empty());
        }
    }

    #[test]
    fn test_sntrup_seal_open_roundtrip() {
        let aead_codecs = [
            Codec::Xchacha20Poly1305,
            Codec::Chacha20Poly1305,
            Codec::AesGcm256,
        ];

        for key_codec in SNTRUP_KEY_CODECS {
            let mut rng = rand::rng();
            let sk = Builder::new_from_random_bytes(key_codec, &mut rng)
                .unwrap()
                .try_build()
                .unwrap();
            let pk = sk.conv_view().unwrap().to_public_key().unwrap();

            for aead_codec in &aead_codecs {
                let plaintext = b"hello sntrup world!";
                let (sealed, _) = pk
                    .seal_view()
                    .unwrap()
                    .seal(plaintext, *aead_codec, b"")
                    .unwrap();

                let opened = sk.open_view().unwrap().open(&sealed, None, b"").unwrap();
                assert_eq!(plaintext.as_slice(), opened.as_slice());
            }
        }
    }

    #[test]
    fn test_sntrup_wrong_key_fails() {
        let mut rng = rand::rng();
        let sk1 = Builder::new_from_random_bytes(Codec::Sntrup761Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk1 = sk1.conv_view().unwrap().to_public_key().unwrap();

        let sk2 = Builder::new_from_random_bytes(Codec::Sntrup761Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();

        let (sealed, _) = pk1
            .seal_view()
            .unwrap()
            .seal(b"secret data", Codec::Xchacha20Poly1305, b"")
            .unwrap();

        // Opening with wrong key should fail (decapsulation will produce different shared secret
        // and AEAD open will fail)
        assert!(sk2.open_view().unwrap().open(&sealed, None, b"").is_err());
    }

    #[test]
    fn test_sntrup_seal_requires_public_key() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::Sntrup761Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();

        // seal with private key should fail
        assert!(sk
            .seal_view()
            .unwrap()
            .seal(b"data", Codec::Xchacha20Poly1305, b"")
            .is_err());
    }

    #[test]
    fn test_sntrup_open_requires_private_key() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::Sntrup761Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        let (sealed, _) = pk
            .seal_view()
            .unwrap()
            .seal(b"data", Codec::Xchacha20Poly1305, b"")
            .unwrap();

        // open with public key should fail
        assert!(pk.open_view().unwrap().open(&sealed, None, b"").is_err());
    }

    #[test]
    fn test_sntrup_unsupported_aead_codec() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::Sntrup761Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        // AES-128-GCM is not allowed for sntrup (not PQ-safe)
        assert!(pk
            .seal_view()
            .unwrap()
            .seal(b"data", Codec::AesGcm128, b"")
            .is_err());
    }
}
