// SPDX-License-Identifier: Apache-2.0
//! Classic McEliece multikey view; post-quantum KEM (348864 variant).
//!
//! Note: mceliece460896 codec entries exist in the codec table for future
//! interoperability, but only mceliece348864 is currently supported for key
//! generation and operations. The upstream `classic-mceliece-rust` crate uses
//! mutually exclusive feature flags per variant, preventing both from being
//! compiled in a single dependency graph.

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
use rand_chacha::ChaCha20Rng;
use rand_core_06::SeedableRng;
use zeroize::Zeroizing;

const MCELIECE_SEED_LENGTH: usize = 32;

/// Decoded sealed message: (kem_ct, aead_codec, nonce, ciphertext+tag)
type SealedParts = (Vec<u8>, Codec, Vec<u8>, Vec<u8>);

fn is_mceliece_priv(codec: Codec) -> bool {
    codec == Codec::Mceliece348864Priv
}

fn is_mceliece_pub(codec: Codec) -> bool {
    codec == Codec::Mceliece348864Pub
}

/// Classic McEliece AEAD codecs allowed (256-bit symmetric for PQ safety)
fn is_mceliece_aead_allowed(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::Xchacha20Poly1305 | Codec::Chacha20Poly1305 | Codec::AesGcm256
    )
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
        is_mceliece_priv(self.mk.codec)
    }
    fn is_public_key(&self) -> bool {
        is_mceliece_pub(self.mk.codec)
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

        if secret_bytes.len() != MCELIECE_SEED_LENGTH {
            return Err(ConversionsError::SecretKeyFailure("invalid seed length".into()).into());
        }

        let seed: [u8; 32] = secret_bytes[..32]
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("invalid seed".into()))?;

        let mut rng = ChaCha20Rng::from_seed(seed);
        let (pk, _sk) = mceliece348864::keypair_boxed(&mut rng);
        let pub_bytes: Vec<u8> = pk.as_ref().to_vec();

        Builder::new(Codec::Mceliece348864Pub)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&pub_bytes)
            .try_build()
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "classic mceliece not supported in SSH key format".into(),
        )
        .into())
    }
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "classic mceliece not supported in SSH key format".into(),
        )
        .into())
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
        if !is_mceliece_aead_allowed(aead_codec) {
            return Err(SealError::UnsupportedAeadCodec(aead_codec).into());
        }

        let pub_bytes = self.key_bytes()?;

        let pk_array: Box<[u8; mceliece348864::CRYPTO_PUBLICKEYBYTES]> = pub_bytes
            .to_vec()
            .into_boxed_slice()
            .try_into()
            .map_err(|_| SealError::EncapsulationFailed("invalid public key size".into()))?;
        let pk = mceliece348864::PublicKey::from(pk_array);
        let (ct, ss) = mceliece348864::encapsulate_boxed(&pk, &mut rand_core_06::OsRng);
        let kem_ct: &[u8] = ct.as_ref();
        let shared_secret: &[u8] = ss.as_ref();

        // Derive AEAD key from shared secret via HKDF
        let key_len = aead::key_size(aead_codec)?;
        let aead_key = aead::derive_aead_key(shared_secret, b"mceliece-seal", key_len)?;

        // Encrypt plaintext
        let (nonce, ct_tag) = aead::aead_seal(aead_codec, &aead_key, plaintext, aad)?;

        Ok((encode_sealed(kem_ct, aead_codec, &nonce, &ct_tag), None))
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

        if !is_mceliece_aead_allowed(aead_codec) {
            return Err(SealError::UnsupportedAeadCodec(aead_codec).into());
        }

        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };

        if secret_bytes.len() != MCELIECE_SEED_LENGTH {
            return Err(ConversionsError::SecretKeyFailure("invalid seed length".into()).into());
        }

        let seed: [u8; 32] = secret_bytes[..32]
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("invalid seed".into()))?;

        let mut rng = ChaCha20Rng::from_seed(seed);
        let (_pk, sk) = mceliece348864::keypair_boxed(&mut rng);

        let ct_array: [u8; mceliece348864::CRYPTO_CIPHERTEXTBYTES] = kem_ct
            .try_into()
            .map_err(|_| SealError::DecapsulationFailed("invalid ciphertext size".into()))?;
        let ct = mceliece348864::Ciphertext::from(ct_array);
        let ss = mceliece348864::decapsulate_boxed(&ct, &sk);
        let shared_secret: &[u8] = ss.as_ref();

        // Derive AEAD key from shared secret via HKDF
        let key_len = aead::key_size(aead_codec)?;
        let aead_key = aead::derive_aead_key(shared_secret, b"mceliece-seal", key_len)?;

        // Decrypt ciphertext
        Ok(aead::aead_open(
            aead_codec, &aead_key, &nonce, &ct_tag, aad,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mk::MCELIECE_KEY_CODECS;
    use crate::views::Views;

    #[test]
    fn test_mceliece_key_gen_roundtrip() {
        for codec in MCELIECE_KEY_CODECS {
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
    fn test_mceliece_public_key_derivation() {
        for codec in MCELIECE_KEY_CODECS {
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
    fn test_mceliece_fingerprint() {
        for codec in MCELIECE_KEY_CODECS {
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
    fn test_mceliece_seal_open_roundtrip() {
        let aead_codecs = [
            Codec::Xchacha20Poly1305,
            Codec::Chacha20Poly1305,
            Codec::AesGcm256,
        ];

        for key_codec in MCELIECE_KEY_CODECS {
            let mut rng = rand::rng();
            let sk = Builder::new_from_random_bytes(key_codec, &mut rng)
                .unwrap()
                .try_build()
                .unwrap();
            let pk = sk.conv_view().unwrap().to_public_key().unwrap();

            for aead_codec in &aead_codecs {
                let plaintext = b"hello classic mceliece world!";
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
    fn test_mceliece_wrong_key_fails() {
        let mut rng = rand::rng();
        let sk1 = Builder::new_from_random_bytes(Codec::Mceliece348864Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk1 = sk1.conv_view().unwrap().to_public_key().unwrap();

        let sk2 = Builder::new_from_random_bytes(Codec::Mceliece348864Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();

        let (sealed, _) = pk1
            .seal_view()
            .unwrap()
            .seal(b"secret data", Codec::Xchacha20Poly1305, b"")
            .unwrap();

        // Opening with wrong key should fail
        assert!(sk2.open_view().unwrap().open(&sealed, None, b"").is_err());
    }

    #[test]
    fn test_mceliece_seal_requires_public_key() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::Mceliece348864Priv, &mut rng)
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
    fn test_mceliece_open_requires_private_key() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::Mceliece348864Priv, &mut rng)
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
    fn test_mceliece_unsupported_aead_codec() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::Mceliece348864Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        // AES-128-GCM is not allowed for mceliece (not PQ-safe)
        assert!(pk
            .seal_view()
            .unwrap()
            .seal(b"data", Codec::AesGcm128, b"")
            .is_err());
    }
}
