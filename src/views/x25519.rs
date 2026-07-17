// SPDX-License-Identifier: Apache-2.0
//! X25519 ECIES multikey view; Curve25519 Diffie-Hellman key agreement + AEAD.

use crate::{
    AttrId, AttrView, Builder, ConvView, DataView, Error, FingerprintView, Multikey, OpenView,
    SealView,
    error::{AttributesError, ConversionsError, SealError},
    views::{Views, aead},
};
use multi_codec::Codec;
use multi_hash::{Multihash, mh};
use multi_trait::TryDecodeFrom;
use multi_util::Varbytes;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const X25519_SECRET_LENGTH: usize = 32;
const X25519_PUBLIC_LENGTH: usize = 32;

/// Decoded sealed message: (aead_codec, nonce, ciphertext+tag)
/// The ephemeral public key is carried externally (in the BsMessage outer format).
type SealedParts = (Codec, Vec<u8>, Vec<u8>);

/// X25519 AEAD codecs allowed
fn is_x25519_aead_allowed(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::AesGcm128 | Codec::Chacha20Poly1305 | Codec::Xchacha20Poly1305
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
        self.mk.codec == Codec::X25519Priv
    }
    fn is_public_key(&self) -> bool {
        self.mk.codec == Codec::X25519Pub
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

        if secret_bytes.len() != X25519_SECRET_LENGTH {
            return Err(ConversionsError::SecretKeyFailure(
                "invalid X25519 secret key length".into(),
            )
            .into());
        }

        let secret_arr: [u8; 32] = secret_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("invalid X25519 secret key".into()))?;

        let secret = StaticSecret::from(secret_arr);
        let public = PublicKey::from(&secret);

        Builder::new(Codec::X25519Pub)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&public.as_bytes().to_vec())
            .try_build()
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        Err(
            ConversionsError::UnsupportedAlgorithm("X25519 not supported in SSH key format".into())
                .into(),
        )
    }
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        Err(
            ConversionsError::UnsupportedAlgorithm("X25519 not supported in SSH key format".into())
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

/// Encode a sealed message: [aead_codec Codec][nonce Varbytes][ct+tag Varbytes]
/// The ephemeral public key is carried externally (in the BsMessage outer format).
fn encode_sealed(aead_codec: Codec, nonce: &[u8], ct_tag: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.append(&mut aead_codec.into());
    out.append(&mut Varbytes::new(nonce.to_vec()).into());
    out.append(&mut Varbytes::new(ct_tag.to_vec()).into());
    out
}

/// Decode a sealed message: [aead_codec Codec][nonce Varbytes][ct+tag Varbytes]
fn decode_sealed(data: &[u8]) -> Result<SealedParts, SealError> {
    let (aead_codec, ptr) = Codec::try_decode_from(data)
        .map_err(|_| SealError::InvalidFormat("missing aead codec".into()))?;
    let (nonce, ptr) = Varbytes::try_decode_from(ptr)
        .map_err(|_| SealError::InvalidFormat("missing nonce".into()))?;
    let (ct_tag, _) = Varbytes::try_decode_from(ptr)
        .map_err(|_| SealError::InvalidFormat("missing ciphertext".into()))?;
    Ok((aead_codec, nonce.to_inner(), ct_tag.to_inner()))
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
        if !is_x25519_aead_allowed(aead_codec) {
            return Err(SealError::UnsupportedAeadCodec(aead_codec).into());
        }

        let pub_bytes = self.key_bytes()?;
        if pub_bytes.len() != X25519_PUBLIC_LENGTH {
            return Err(SealError::EncapsulationFailed("invalid public key length".into()).into());
        }

        let recipient_pub: [u8; 32] = pub_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SealError::EncapsulationFailed("invalid public key".into()))?;
        let recipient_pub = PublicKey::from(recipient_pub);

        // Generate ephemeral keypair
        let ephemeral_secret = StaticSecret::random_from_rng(&mut rand::rng());
        let ephemeral_pub = PublicKey::from(&ephemeral_secret);

        // ECDH
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pub);

        // Derive AEAD key from shared secret via HKDF
        let key_len = aead::key_size(aead_codec)?;
        let aead_key = aead::derive_aead_key(shared_secret.as_bytes(), b"x25519-seal", key_len)?;

        // Encrypt plaintext
        let (nonce, ct_tag) = aead::aead_seal(aead_codec, &aead_key, plaintext, aad)?;

        // Build the ephemeral public key as a Multikey so callers can transmit it
        let ephemeral_mk = Builder::new(Codec::X25519Pub)
            .with_key_bytes(&ephemeral_pub.as_bytes().to_vec())
            .try_build()?;

        Ok((
            encode_sealed(aead_codec, &nonce, &ct_tag),
            Some(ephemeral_mk),
        ))
    }
}

impl<'a> OpenView for View<'a> {
    fn open(
        &self,
        sealed_msg: &[u8],
        ephemeral: Option<&Multikey>,
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if !self.is_secret_key() {
            return Err(SealError::NotDecapsulationKey.into());
        }

        let ephemeral_mk = ephemeral.ok_or_else(|| {
            SealError::InvalidFormat("X25519 open requires an ephemeral public key".into())
        })?;

        let (aead_codec, nonce, ct_tag) = decode_sealed(sealed_msg)?;

        if !is_x25519_aead_allowed(aead_codec) {
            return Err(SealError::UnsupportedAeadCodec(aead_codec).into());
        }

        let ephemeral_pub_bytes = ephemeral_mk.data_view()?.key_bytes()?;
        if ephemeral_pub_bytes.len() != X25519_PUBLIC_LENGTH {
            return Err(
                SealError::InvalidFormat("invalid ephemeral public key length".into()).into(),
            );
        }

        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };

        let secret_arr: [u8; 32] = secret_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SealError::DecapsulationFailed("invalid secret key".into()))?;
        let static_secret = StaticSecret::from(secret_arr);

        let ephemeral_pub_arr: [u8; 32] = ephemeral_pub_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SealError::InvalidFormat("invalid ephemeral public key".into()))?;
        let ephemeral_pub = PublicKey::from(ephemeral_pub_arr);

        // ECDH
        let shared_secret = static_secret.diffie_hellman(&ephemeral_pub);

        // Derive AEAD key from shared secret via HKDF
        let key_len = aead::key_size(aead_codec)?;
        let aead_key = aead::derive_aead_key(shared_secret.as_bytes(), b"x25519-seal", key_len)?;

        // Decrypt ciphertext
        Ok(aead::aead_open(
            aead_codec, &aead_key, &nonce, &ct_tag, aad,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mk::X25519_KEY_CODECS;
    use crate::views::Views;

    #[test]
    fn test_x25519_key_gen_roundtrip() {
        for codec in X25519_KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test x25519 key")
                .try_build()
                .unwrap();

            let attr = mk.attr_view().unwrap();
            assert!(attr.is_secret_key());
            assert!(!attr.is_public_key());

            // serialize/deserialize roundtrip
            let bytes: Vec<u8> = mk.clone().into();
            let mk2 = Multikey::try_from(bytes.as_slice()).unwrap();
            assert_eq!(mk, mk2);
        }
    }

    #[test]
    fn test_x25519_public_key_derivation() {
        let mut rng = rand::rng();
        let mk = Builder::new_from_random_bytes(Codec::X25519Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();

        let conv = mk.conv_view().unwrap();
        let pk = conv.to_public_key().unwrap();

        let attr = pk.attr_view().unwrap();
        assert!(attr.is_public_key());
        assert!(!attr.is_secret_key());

        // derive again => same result
        let pk2 = conv.to_public_key().unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_x25519_fingerprint() {
        let mut rng = rand::rng();
        let mk = Builder::new_from_random_bytes(Codec::X25519Priv, &mut rng)
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

    #[test]
    fn test_x25519_seal_open_roundtrip() {
        let aead_codecs = [
            Codec::AesGcm128,
            Codec::Chacha20Poly1305,
            Codec::Xchacha20Poly1305,
        ];

        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::X25519Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        for aead_codec in &aead_codecs {
            let plaintext = b"hello X25519 ECIES world!";
            let (sealed, ephemeral) = pk
                .seal_view()
                .unwrap()
                .seal(plaintext, *aead_codec, b"")
                .unwrap();

            let opened = sk
                .open_view()
                .unwrap()
                .open(&sealed, ephemeral.as_ref(), b"")
                .unwrap();
            assert_eq!(plaintext.as_slice(), opened.as_slice());
        }
    }

    #[test]
    fn test_x25519_wrong_key_fails() {
        let mut rng = rand::rng();
        let sk1 = Builder::new_from_random_bytes(Codec::X25519Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk1 = sk1.conv_view().unwrap().to_public_key().unwrap();

        let sk2 = Builder::new_from_random_bytes(Codec::X25519Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();

        let (sealed, ephemeral) = pk1
            .seal_view()
            .unwrap()
            .seal(b"secret data", Codec::Chacha20Poly1305, b"")
            .unwrap();

        // Opening with wrong key should fail
        assert!(
            sk2.open_view()
                .unwrap()
                .open(&sealed, ephemeral.as_ref(), b"")
                .is_err()
        );
    }

    #[test]
    fn test_x25519_seal_requires_public_key() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::X25519Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();

        assert!(
            sk.seal_view()
                .unwrap()
                .seal(b"data", Codec::Chacha20Poly1305, b"")
                .is_err()
        );
    }

    #[test]
    fn test_x25519_open_requires_private_key() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::X25519Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        let (sealed, ephemeral) = pk
            .seal_view()
            .unwrap()
            .seal(b"data", Codec::Chacha20Poly1305, b"")
            .unwrap();

        assert!(
            pk.open_view()
                .unwrap()
                .open(&sealed, ephemeral.as_ref(), b"")
                .is_err()
        );
    }
}
