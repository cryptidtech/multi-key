// SPDX-License-Identifier: Apache-2.0
//! Classic McEliece multikey view; post-quantum KEM (348864 variant).
//!
//! # Deprecation
//!
//! This view is deprecated: 2026 structural key-recovery attacks on binary
//! Goppa codes led Germany's BSI to advise against Classic McEliece in new
//! developments. See the crate-level Deprecations section for the papers and
//! the BSI note. It compiles only with the `deprecated` feature.
//!
//! Note: mceliece460896 codec entries exist in the codec table for future
//! interoperability, but only mceliece348864 is wired up for key generation
//! and operations.
//!
//! The secret key is a 32-byte seed. The Classic McEliece key seed is the
//! first 32 bytes of a ChaCha20 stream keyed by it, which reproduces the keys
//! the earlier `mceliece348864` crate generated from the same seed.

use crate::views::dispatch::dispatch_data_view;
use crate::{
    AttrId, AttrView, Builder, ConvView, DataView, Error, FingerprintView, Multikey, OpenView,
    SealView,
    error::{AttributesError, ConversionsError, SealError},
    views::aead,
};
use multi_codec::Codec;
use multi_hash::{Multihash, mh};
use multi_trait::TryDecodeFrom;
use multi_util::Varbytes;
use pq_mceliece::{Algorithm, DecapsulationKey, EncapsulationKey};
use zeroize::Zeroizing;

const MCELIECE_SEED_LENGTH: usize = 32;

/// The Classic McEliece parameter set these views use.
pub(crate) const ALGORITHM: Algorithm = Algorithm::McEliece348864;

/// Rebuild the keypair from a stored 32-byte seed: the key seed is the first
/// 32 bytes of the ChaCha20 stream the stored seed keys.
pub(crate) fn keypair_from_seed(
    seed: [u8; MCELIECE_SEED_LENGTH],
) -> Result<(EncapsulationKey, DecapsulationKey), Error> {
    use chacha20::ChaCha20Rng;
    use rand_core::{Rng, SeedableRng};
    let mut key_seed = Zeroizing::new([0u8; MCELIECE_SEED_LENGTH]);
    ChaCha20Rng::from_seed(seed).fill_bytes(key_seed.as_mut());
    ALGORITHM
        .generate_keypair_from_seed(key_seed.as_ref())
        .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()).into())
}

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
            let kd = dispatch_data_view(self.mk)?;
            kd.secret_bytes()?
        };

        if secret_bytes.len() != MCELIECE_SEED_LENGTH {
            return Err(ConversionsError::SecretKeyFailure("invalid seed length".into()).into());
        }

        let seed: [u8; 32] = secret_bytes[..32]
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("invalid seed".into()))?;

        let (ek, _dk) = keypair_from_seed(seed)?;

        Builder::new(Codec::Mceliece348864Pub)
            .with_comment(&self.mk.comment)
            .with_key_bytes(ek.value())
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
            let dv = dispatch_data_view(&pk)?;
            dv.key_bytes()?
        } else {
            self.key_bytes()?
        };
        let mut b = mh::Builder::new(codec)?;
        b.update(pub_bytes.as_slice());
        b.output_len(32);
        Ok(b.try_build()?)
    }
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

        let ek = ALGORITHM
            .encapsulation_key_from_bytes(&pub_bytes)
            .map_err(|e| SealError::EncapsulationFailed(e.to_string()))?;
        let (ct, ss) = ALGORITHM
            .encapsulate(&ek, rand::rng())
            .map_err(|e| SealError::EncapsulationFailed(e.to_string()))?;
        let kem_ct = ct.value();
        let shared_secret = ss.value();

        // Derive AEAD key from shared secret via HKDF
        let key_len = aead::key_size(aead_codec)?;
        let aead_key = aead::derive_aead_key(shared_secret, b"mceliece-seal", key_len)?;

        // Encrypt plaintext
        let (nonce, ct_tag) = aead::aead_seal(aead_codec, &aead_key, plaintext, aad)?;

        Ok((
            aead::encode_kem_sealed(kem_ct, aead_codec, &nonce, &ct_tag),
            None,
        ))
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
            let kd = dispatch_data_view(self.mk)?;
            kd.secret_bytes()?
        };

        if secret_bytes.len() != MCELIECE_SEED_LENGTH {
            return Err(ConversionsError::SecretKeyFailure("invalid seed length".into()).into());
        }

        let seed: [u8; 32] = secret_bytes[..32]
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("invalid seed".into()))?;

        let (_ek, dk) = keypair_from_seed(seed)?;
        let ct = ALGORITHM
            .ciphertext_from_bytes(&kem_ct)
            .map_err(|e| SealError::DecapsulationFailed(e.to_string()))?;
        let ss = ALGORITHM
            .decapsulate(&dk, &ct)
            .map_err(|e| SealError::DecapsulationFailed(e.to_string()))?;
        let shared_secret = ss.value();

        // Derive AEAD key from shared secret via HKDF
        let key_len = aead::key_size(aead_codec)?;
        let aead_key = aead::derive_aead_key(shared_secret, b"mceliece-seal", key_len)?;

        // Decrypt ciphertext
        Ok(aead::aead_open(
            aead_codec, &aead_key, &nonce, &ct_tag, aad,
        )?)
    }
}

#[cfg(all(test, feature = "slow-tests"))]
mod tests {
    use super::*;
    use crate::ViewBuilder;
    use crate::mk::MCELIECE_KEY_CODECS;

    /// keys rebuilt from a stored seed match the ones the earlier
    /// `mceliece348864` crate derived from it (golden bytes from that crate)
    #[test]
    fn test_seed_derivation_matches_previous_crate() {
        for (seed, head, tail) in [
            (
                [7u8; 32],
                "51065e02c66c81226bc150f59ae125df",
                "cc84d13ac4a8ca24f7076a0e4f6b352b",
            ),
            (
                [0x5au8; 32],
                "d717a6a0c43bdbb9588eb545255da943",
                "292a7ca6b221011d5543933a060d4d4e",
            ),
        ] {
            let (ek, _dk) = keypair_from_seed(seed).unwrap();
            let pk = ek.value();
            assert_eq!(pk.len(), 261_120);
            assert_eq!(hex::encode(&pk[..16]), head);
            assert_eq!(hex::encode(&pk[pk.len() - 16..]), tail);
        }
    }

    #[test]
    fn test_mceliece_key_gen_roundtrip() {
        for codec in MCELIECE_KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test kem key")
                .try_build()
                .unwrap();

            let attr = ViewBuilder::new(&mk).attr().build().unwrap();
            assert!(attr.is_secret_key());
            assert!(!attr.is_public_key());

            let kd = ViewBuilder::new(&mk).data().build().unwrap();
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

            let conv = ViewBuilder::new(&mk).conv().build().unwrap();
            let pk = conv.to_public_key().unwrap();

            let attr = ViewBuilder::new(&pk).attr().build().unwrap();
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

            let pk = ViewBuilder::new(&mk)
                .conv()
                .build()
                .unwrap()
                .to_public_key()
                .unwrap();
            let fp = ViewBuilder::new(&pk)
                .fingerprint()
                .build()
                .unwrap()
                .fingerprint(Codec::Sha3256)
                .unwrap();
            let fp_bytes: Vec<u8> = fp.into();
            assert_ne!(fp_bytes, Vec::<u8>::new());
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
            let pk = ViewBuilder::new(&sk)
                .conv()
                .build()
                .unwrap()
                .to_public_key()
                .unwrap();

            for aead_codec in &aead_codecs {
                let plaintext = b"hello classic mceliece world!";
                let (sealed, _) = ViewBuilder::new(&pk)
                    .seal()
                    .build()
                    .unwrap()
                    .seal(plaintext, *aead_codec, b"")
                    .unwrap();

                let opened = ViewBuilder::new(&sk)
                    .open()
                    .build()
                    .unwrap()
                    .open(&sealed, None, b"")
                    .unwrap();
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
        let pk1 = ViewBuilder::new(&sk1)
            .conv()
            .build()
            .unwrap()
            .to_public_key()
            .unwrap();

        let sk2 = Builder::new_from_random_bytes(Codec::Mceliece348864Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();

        let (sealed, _) = ViewBuilder::new(&pk1)
            .seal()
            .build()
            .unwrap()
            .seal(b"secret data", Codec::Xchacha20Poly1305, b"")
            .unwrap();

        // Opening with wrong key should fail
        assert!(
            ViewBuilder::new(&sk2)
                .open()
                .build()
                .unwrap()
                .open(&sealed, None, b"")
                .is_err()
        );
    }

    #[test]
    fn test_mceliece_seal_requires_public_key() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::Mceliece348864Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();

        // seal with private key should fail
        assert!(
            ViewBuilder::new(&sk)
                .seal()
                .build()
                .unwrap()
                .seal(b"data", Codec::Xchacha20Poly1305, b"")
                .is_err()
        );
    }

    #[test]
    fn test_mceliece_open_requires_private_key() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::Mceliece348864Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = ViewBuilder::new(&sk)
            .conv()
            .build()
            .unwrap()
            .to_public_key()
            .unwrap();

        let (sealed, _) = ViewBuilder::new(&pk)
            .seal()
            .build()
            .unwrap()
            .seal(b"data", Codec::Xchacha20Poly1305, b"")
            .unwrap();

        // open with public key should fail
        assert!(
            ViewBuilder::new(&pk)
                .open()
                .build()
                .unwrap()
                .open(&sealed, None, b"")
                .is_err()
        );
    }

    #[test]
    fn test_mceliece_unsupported_aead_codec() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::Mceliece348864Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = ViewBuilder::new(&sk)
            .conv()
            .build()
            .unwrap()
            .to_public_key()
            .unwrap();

        // AES-128-GCM is not allowed for mceliece (not PQ-safe)
        assert!(
            ViewBuilder::new(&pk)
                .seal()
                .build()
                .unwrap()
                .seal(b"data", Codec::AesGcm128, b"")
                .is_err()
        );
    }
}
