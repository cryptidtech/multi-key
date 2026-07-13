// SPDX-License-Identifier: Apache-2.0
//! X25519-ML-KEM-768 hybrid KEM multikey view; combines X25519 ECDH with ML-KEM-768 KEM,
//! ChaCha20-Poly1305 AEAD, and SHA-512 KDF.

use crate::{
    error::{AttributesError, ConversionsError, SealError},
    views::{aead, Views},
    AttrId, AttrView, Builder, ConvView, DataView, Error, FingerprintView, Multikey, OpenView,
    SealView,
};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    EncodedSizeUser, KemCore, MlKem768,
};
use multi_codec::Codec;
use multi_hash::{mh, Multihash};
use multi_trait::TryDecodeFrom;
use multi_util::Varbytes;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const X25519_SEED_LEN: usize = 32;
const MLKEM_D_LEN: usize = 32;
const MLKEM_Z_LEN: usize = 32;
const PRIV_SEED_LEN: usize = X25519_SEED_LEN + MLKEM_D_LEN + MLKEM_Z_LEN; // 96
const X25519_PUB_LEN: usize = 32;
const MLKEM768_PUB_LEN: usize = 1184;
const PUB_KEY_LEN: usize = X25519_PUB_LEN + MLKEM768_PUB_LEN; // 1216

/// Decoded sealed message: (ephemeral_x25519_pub, mlkem_ct, nonce, ciphertext+tag)
type SealedParts = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Only ChaCha20-Poly1305 allowed per spec
fn is_aead_allowed(codec: Codec) -> bool {
    codec == Codec::Chacha20Poly1305
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
        self.mk.codec == Codec::X25519Mlkem768Priv
    }
    fn is_public_key(&self) -> bool {
        self.mk.codec == Codec::X25519Mlkem768Pub
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

        if secret_bytes.len() != PRIV_SEED_LEN {
            return Err(
                ConversionsError::SecretKeyFailure("invalid hybrid seed length".into()).into(),
            );
        }

        // X25519 public key
        let x25519_seed: [u8; 32] = secret_bytes[..X25519_SEED_LEN]
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("invalid x25519 seed".into()))?;
        let x25519_secret = StaticSecret::from(x25519_seed);
        let x25519_pub = PublicKey::from(&x25519_secret);

        // ML-KEM-768 public key
        let d: [u8; 32] = secret_bytes[X25519_SEED_LEN..X25519_SEED_LEN + MLKEM_D_LEN]
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("invalid ml-kem d".into()))?;
        let z: [u8; 32] = secret_bytes[X25519_SEED_LEN + MLKEM_D_LEN..PRIV_SEED_LEN]
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("invalid ml-kem z".into()))?;
        let (_dk, ek) = MlKem768::generate_deterministic(&d.into(), &z.into());

        // Concatenate: x25519_pub (32) || mlkem_pub (1184)
        let mut pub_bytes = Vec::with_capacity(PUB_KEY_LEN);
        pub_bytes.extend_from_slice(x25519_pub.as_bytes());
        pub_bytes.extend_from_slice(&ek.as_bytes());

        Builder::new(Codec::X25519Mlkem768Pub)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&pub_bytes)
            .try_build()
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "X25519-ML-KEM-768 not supported in SSH key format".into(),
        )
        .into())
    }
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "X25519-ML-KEM-768 not supported in SSH key format".into(),
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

/// Combine shared secrets using SHA-512:
/// ss = SHA-512(label || ss_mlkem || ss_x25519 || mlkem_ct || ephemeral_x25519_pub)
fn combine_shared_secrets(
    ss_mlkem: &[u8],
    ss_x25519: &[u8],
    mlkem_ct: &[u8],
    ephemeral_x25519_pub: &[u8],
) -> [u8; 64] {
    let digest = Sha512::new()
        .chain_update(b"x25519-mlkem768-hpke")
        .chain_update(ss_mlkem)
        .chain_update(ss_x25519)
        .chain_update(mlkem_ct)
        .chain_update(ephemeral_x25519_pub)
        .finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

/// Encode sealed message: [ephemeral_x25519_pub Varbytes][mlkem_ct Varbytes][nonce Varbytes][ct+tag Varbytes]
fn encode_sealed(ephemeral_pub: &[u8], mlkem_ct: &[u8], nonce: &[u8], ct_tag: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.append(&mut Varbytes::new(ephemeral_pub.to_vec()).into());
    out.append(&mut Varbytes::new(mlkem_ct.to_vec()).into());
    out.append(&mut Varbytes::new(nonce.to_vec()).into());
    out.append(&mut Varbytes::new(ct_tag.to_vec()).into());
    out
}

/// Decode sealed message
fn decode_sealed(data: &[u8]) -> Result<SealedParts, SealError> {
    let (ephemeral_pub, ptr) = Varbytes::try_decode_from(data)
        .map_err(|_| SealError::InvalidFormat("missing ephemeral public key".into()))?;
    let (mlkem_ct, ptr) = Varbytes::try_decode_from(ptr)
        .map_err(|_| SealError::InvalidFormat("missing ML-KEM ciphertext".into()))?;
    let (nonce, ptr) = Varbytes::try_decode_from(ptr)
        .map_err(|_| SealError::InvalidFormat("missing nonce".into()))?;
    let (ct_tag, _) = Varbytes::try_decode_from(ptr)
        .map_err(|_| SealError::InvalidFormat("missing ciphertext".into()))?;
    Ok((
        ephemeral_pub.to_inner(),
        mlkem_ct.to_inner(),
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
        if !is_aead_allowed(aead_codec) {
            return Err(SealError::UnsupportedAeadCodec(aead_codec).into());
        }

        let pub_bytes = self.key_bytes()?;
        if pub_bytes.len() != PUB_KEY_LEN {
            return Err(
                SealError::EncapsulationFailed("invalid hybrid public key length".into()).into(),
            );
        }

        // Split public key
        let x25519_pub_arr: [u8; 32] = pub_bytes[..X25519_PUB_LEN]
            .try_into()
            .map_err(|_| SealError::EncapsulationFailed("invalid x25519 public key".into()))?;
        let recipient_x25519_pub = PublicKey::from(x25519_pub_arr);

        let mlkem_ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(
            pub_bytes[X25519_PUB_LEN..].try_into().map_err(|_| {
                SealError::EncapsulationFailed("invalid ML-KEM-768 public key".into())
            })?,
        );

        // X25519: generate ephemeral keypair and ECDH
        let ephemeral_secret = StaticSecret::random_from_rng(&mut rand::rng());
        let ephemeral_pub = PublicKey::from(&ephemeral_secret);
        let ss_x25519 = ephemeral_secret.diffie_hellman(&recipient_x25519_pub);

        // ML-KEM-768: encapsulate
        let mut rng = rand_core_06::OsRng;
        let (mlkem_ct, ss_mlkem) = mlkem_ek
            .encapsulate(&mut rng)
            .map_err(|_| SealError::EncapsulationFailed("ML-KEM encapsulation failed".into()))?;

        // Combine shared secrets via SHA-512
        let combined_ss = combine_shared_secrets(
            ss_mlkem.as_slice(),
            ss_x25519.as_bytes(),
            mlkem_ct.as_slice(),
            ephemeral_pub.as_bytes(),
        );

        // Derive AEAD key via HKDF-SHA512
        let key_len = aead::key_size(aead_codec)?;
        let aead_key = aead::derive_aead_key(&combined_ss, b"x25519-mlkem768-seal", key_len)?;

        // AEAD encrypt
        let (nonce, ct_tag) = aead::aead_seal(aead_codec, &aead_key, plaintext, aad)?;

        Ok((
            encode_sealed(
                ephemeral_pub.as_bytes(),
                mlkem_ct.as_slice(),
                &nonce,
                &ct_tag,
            ),
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

        let (ephemeral_pub_bytes, mlkem_ct_bytes, nonce, ct_tag) = decode_sealed(sealed_msg)?;

        if ephemeral_pub_bytes.len() != X25519_PUB_LEN {
            return Err(
                SealError::InvalidFormat("invalid ephemeral public key length".into()).into(),
            );
        }

        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };

        if secret_bytes.len() != PRIV_SEED_LEN {
            return Err(
                ConversionsError::SecretKeyFailure("invalid hybrid seed length".into()).into(),
            );
        }

        // X25519 ECDH
        let x25519_seed: [u8; 32] = secret_bytes[..X25519_SEED_LEN]
            .try_into()
            .map_err(|_| SealError::DecapsulationFailed("invalid x25519 seed".into()))?;
        let x25519_secret = StaticSecret::from(x25519_seed);
        let ephemeral_pub_arr: [u8; 32] = ephemeral_pub_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SealError::InvalidFormat("invalid ephemeral public key".into()))?;
        let ephemeral_pub = PublicKey::from(ephemeral_pub_arr);
        let ss_x25519 = x25519_secret.diffie_hellman(&ephemeral_pub);

        // ML-KEM-768 decapsulate
        let d: [u8; 32] = secret_bytes[X25519_SEED_LEN..X25519_SEED_LEN + MLKEM_D_LEN]
            .try_into()
            .map_err(|_| SealError::DecapsulationFailed("invalid ml-kem d".into()))?;
        let z: [u8; 32] = secret_bytes[X25519_SEED_LEN + MLKEM_D_LEN..PRIV_SEED_LEN]
            .try_into()
            .map_err(|_| SealError::DecapsulationFailed("invalid ml-kem z".into()))?;
        let (dk, _ek) = MlKem768::generate_deterministic(&d.into(), &z.into());

        let mlkem_ct = mlkem_ct_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SealError::DecapsulationFailed("invalid ML-KEM ciphertext size".into()))?;
        let ss_mlkem = dk
            .decapsulate(&mlkem_ct)
            .map_err(|_| SealError::DecapsulationFailed("ML-KEM decapsulation failed".into()))?;

        // Combine shared secrets via SHA-512
        let combined_ss = combine_shared_secrets(
            ss_mlkem.as_slice(),
            ss_x25519.as_bytes(),
            mlkem_ct_bytes.as_slice(),
            ephemeral_pub_bytes.as_slice(),
        );

        // Derive AEAD key via HKDF-SHA512
        let key_len = aead::key_size(Codec::Chacha20Poly1305)?;
        let aead_key = aead::derive_aead_key(&combined_ss, b"x25519-mlkem768-seal", key_len)?;

        // AEAD decrypt
        Ok(aead::aead_open(
            Codec::Chacha20Poly1305,
            &aead_key,
            &nonce,
            &ct_tag,
            aad,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mk::X25519_MLKEM768_KEY_CODECS;
    use crate::views::Views;

    #[test]
    fn test_key_gen_roundtrip() {
        for codec in X25519_MLKEM768_KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test hybrid kem key")
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
    fn test_public_key_derivation() {
        let mut rng = rand::rng();
        let mk = Builder::new_from_random_bytes(Codec::X25519Mlkem768Priv, &mut rng)
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

        // check public key length
        let dv = pk.data_view().unwrap();
        assert_eq!(dv.key_bytes().unwrap().len(), PUB_KEY_LEN);
    }

    #[test]
    fn test_fingerprint() {
        let mut rng = rand::rng();
        let mk = Builder::new_from_random_bytes(Codec::X25519Mlkem768Priv, &mut rng)
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
    fn test_seal_open_roundtrip() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::X25519Mlkem768Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        let plaintext = b"hello X25519-ML-KEM-768 hybrid KEM!";
        let (sealed, _) = pk
            .seal_view()
            .unwrap()
            .seal(plaintext, Codec::Chacha20Poly1305, b"")
            .unwrap();

        let opened = sk.open_view().unwrap().open(&sealed, None, b"").unwrap();
        assert_eq!(plaintext.as_slice(), opened.as_slice());
    }

    #[test]
    fn test_wrong_key_fails() {
        let mut rng = rand::rng();
        let sk1 = Builder::new_from_random_bytes(Codec::X25519Mlkem768Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk1 = sk1.conv_view().unwrap().to_public_key().unwrap();

        let sk2 = Builder::new_from_random_bytes(Codec::X25519Mlkem768Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();

        let (sealed, _) = pk1
            .seal_view()
            .unwrap()
            .seal(b"secret data", Codec::Chacha20Poly1305, b"")
            .unwrap();

        assert!(sk2.open_view().unwrap().open(&sealed, None, b"").is_err());
    }

    #[test]
    fn test_seal_requires_public_key() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::X25519Mlkem768Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();

        assert!(sk
            .seal_view()
            .unwrap()
            .seal(b"data", Codec::Chacha20Poly1305, b"")
            .is_err());
    }

    #[test]
    fn test_open_requires_private_key() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::X25519Mlkem768Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        let (sealed, _) = pk
            .seal_view()
            .unwrap()
            .seal(b"data", Codec::Chacha20Poly1305, b"")
            .unwrap();

        assert!(pk.open_view().unwrap().open(&sealed, None, b"").is_err());
    }

    #[test]
    fn test_unsupported_aead_codec() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::X25519Mlkem768Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        assert!(pk
            .seal_view()
            .unwrap()
            .seal(b"data", Codec::AesGcm128, b"")
            .is_err());
        assert!(pk
            .seal_view()
            .unwrap()
            .seal(b"data", Codec::Xchacha20Poly1305, b"")
            .is_err());
    }
}
