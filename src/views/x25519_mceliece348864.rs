// SPDX-License-Identifier: Apache-2.0
//! X25519-Classic-McEliece-348864 hybrid KEM multikey view (X-Wing-like); combines
//! X25519 ECDH with Classic McEliece 348864, ChaCha20-Poly1305 AEAD, and a BLAKE3
//! combiner feeding HKDF-SHA512.
//!
//! Private key layout: `x25519_seed (32) || mceliece_seed (32)` = 64 bytes.
//! Public key layout (classical-first): `x25519_pub (32) || mceliece_public_key`.

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
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const X25519_SEED_LEN: usize = 32;
const MCELIECE_SEED_LEN: usize = 32;
const PRIV_SEED_LEN: usize = X25519_SEED_LEN + MCELIECE_SEED_LEN; // 64
const X25519_PUB_LEN: usize = 32;

/// Decoded sealed message: (ephemeral_x25519_pub, mceliece_ct, nonce, ciphertext+tag)
type SealedParts = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Only ChaCha20-Poly1305 allowed (matches the other X-Wing-like hybrid KEMs).
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
        self.mk.codec == Codec::X25519Mceliece348864Priv
    }
    fn is_public_key(&self) -> bool {
        self.mk.codec == Codec::X25519Mceliece348864Pub
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

        // Classic McEliece public key from the (deterministic) seed
        let mceliece_seed: [u8; 32] = secret_bytes[X25519_SEED_LEN..PRIV_SEED_LEN]
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("invalid mceliece seed".into()))?;
        let mut rng = ChaCha20Rng::from_seed(mceliece_seed);
        let (pk, _sk) = mceliece348864::keypair_boxed(&mut rng);

        // Concatenate (classical-first): x25519_pub (32) || mceliece_pub
        let mut pub_bytes = Vec::with_capacity(X25519_PUB_LEN + pk.as_ref().len());
        pub_bytes.extend_from_slice(x25519_pub.as_bytes());
        pub_bytes.extend_from_slice(pk.as_ref());

        Builder::new(Codec::X25519Mceliece348864Pub)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&pub_bytes)
            .try_build()
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "X25519-Classic-McEliece-348864 not supported in SSH key format".into(),
        )
        .into())
    }
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "X25519-Classic-McEliece-348864 not supported in SSH key format".into(),
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

/// Combine shared secrets via BLAKE3:
/// ss = BLAKE3(label || ss_mceliece || ss_x25519 || mceliece_ct || ephemeral_x25519_pub)
fn combine_shared_secrets(
    ss_mceliece: &[u8],
    ss_x25519: &[u8],
    mceliece_ct: &[u8],
    ephemeral_x25519_pub: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"x25519-mceliece348864-hpke");
    hasher.update(ss_mceliece);
    hasher.update(ss_x25519);
    hasher.update(mceliece_ct);
    hasher.update(ephemeral_x25519_pub);
    *hasher.finalize().as_bytes()
}

fn encode_sealed(ephemeral_pub: &[u8], mceliece_ct: &[u8], nonce: &[u8], ct_tag: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.append(&mut Varbytes::new(ephemeral_pub.to_vec()).into());
    out.append(&mut Varbytes::new(mceliece_ct.to_vec()).into());
    out.append(&mut Varbytes::new(nonce.to_vec()).into());
    out.append(&mut Varbytes::new(ct_tag.to_vec()).into());
    out
}

fn decode_sealed(data: &[u8]) -> Result<SealedParts, SealError> {
    let (ephemeral_pub, ptr) = Varbytes::try_decode_from(data)
        .map_err(|_| SealError::InvalidFormat("missing ephemeral public key".into()))?;
    let (mceliece_ct, ptr) = Varbytes::try_decode_from(ptr)
        .map_err(|_| SealError::InvalidFormat("missing mceliece ciphertext".into()))?;
    let (nonce, ptr) = Varbytes::try_decode_from(ptr)
        .map_err(|_| SealError::InvalidFormat("missing nonce".into()))?;
    let (ct_tag, _) = Varbytes::try_decode_from(ptr)
        .map_err(|_| SealError::InvalidFormat("missing ciphertext".into()))?;
    Ok((
        ephemeral_pub.to_inner(),
        mceliece_ct.to_inner(),
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
        if pub_bytes.len() != X25519_PUB_LEN + mceliece348864::CRYPTO_PUBLICKEYBYTES {
            return Err(
                SealError::EncapsulationFailed("invalid hybrid public key length".into()).into(),
            );
        }

        let x25519_pub_arr: [u8; 32] = pub_bytes[..X25519_PUB_LEN]
            .try_into()
            .map_err(|_| SealError::EncapsulationFailed("invalid x25519 public key".into()))?;
        let recipient_x25519_pub = PublicKey::from(x25519_pub_arr);

        // X25519: ephemeral ECDH
        let ephemeral_secret = StaticSecret::random_from_rng(&mut rand::rng());
        let ephemeral_pub = PublicKey::from(&ephemeral_secret);
        let ss_x25519 = ephemeral_secret.diffie_hellman(&recipient_x25519_pub);

        // McEliece encapsulate
        let pk_array: Box<[u8; mceliece348864::CRYPTO_PUBLICKEYBYTES]> = pub_bytes
            [X25519_PUB_LEN..]
            .to_vec()
            .into_boxed_slice()
            .try_into()
            .map_err(|_| SealError::EncapsulationFailed("invalid mceliece public key".into()))?;
        let pk = mceliece348864::PublicKey::from(pk_array);
        let (ct, ss_mceliece) = mceliece348864::encapsulate_boxed(&pk, &mut rand_core_06::OsRng);
        let mceliece_ct: &[u8] = ct.as_ref();

        let combined_ss = combine_shared_secrets(
            ss_mceliece.as_ref(),
            ss_x25519.as_bytes(),
            mceliece_ct,
            ephemeral_pub.as_bytes(),
        );

        // Derive the AEAD key from the combined shared secret via HKDF-SHA512,
        // matching the construction used by the other hybrid KEMs.
        let key_len = aead::key_size(aead_codec)?;
        let aead_key = aead::derive_aead_key(&combined_ss, b"x25519-mceliece348864-seal", key_len)?;

        let (nonce, ct_tag) = aead::aead_seal(aead_codec, &aead_key, plaintext, aad)?;

        Ok((
            encode_sealed(ephemeral_pub.as_bytes(), mceliece_ct, &nonce, &ct_tag),
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

        let (ephemeral_pub_bytes, mceliece_ct_bytes, nonce, ct_tag) = decode_sealed(sealed_msg)?;

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

        // McEliece decapsulate
        let mceliece_seed: [u8; 32] = secret_bytes[X25519_SEED_LEN..PRIV_SEED_LEN]
            .try_into()
            .map_err(|_| SealError::DecapsulationFailed("invalid mceliece seed".into()))?;
        let mut rng = ChaCha20Rng::from_seed(mceliece_seed);
        let (_pk, sk) = mceliece348864::keypair_boxed(&mut rng);

        let ct_array: [u8; mceliece348864::CRYPTO_CIPHERTEXTBYTES] = mceliece_ct_bytes
            .clone()
            .try_into()
            .map_err(|_| SealError::DecapsulationFailed("invalid mceliece ciphertext".into()))?;
        let ct = mceliece348864::Ciphertext::from(ct_array);
        let ss_mceliece = mceliece348864::decapsulate_boxed(&ct, &sk);

        let combined_ss = combine_shared_secrets(
            ss_mceliece.as_ref(),
            ss_x25519.as_bytes(),
            mceliece_ct_bytes.as_slice(),
            ephemeral_pub_bytes.as_slice(),
        );

        // Derive the AEAD key from the combined shared secret via HKDF-SHA512,
        // matching the construction used by the other hybrid KEMs.
        let key_len = aead::key_size(Codec::Chacha20Poly1305)?;
        let aead_key = aead::derive_aead_key(&combined_ss, b"x25519-mceliece348864-seal", key_len)?;

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
    use crate::views::Views;

    #[test]
    fn test_seal_open_roundtrip() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::X25519Mceliece348864Priv, &mut rng)
            .unwrap()
            .with_comment("x25519-mceliece hybrid test")
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        let plaintext = b"hello X25519-Classic-McEliece-348864 hybrid KEM!";
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
        let sk1 = Builder::new_from_random_bytes(Codec::X25519Mceliece348864Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk1 = sk1.conv_view().unwrap().to_public_key().unwrap();
        let sk2 = Builder::new_from_random_bytes(Codec::X25519Mceliece348864Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();

        let (sealed, _) = pk1
            .seal_view()
            .unwrap()
            .seal(b"secret", Codec::Chacha20Poly1305, b"")
            .unwrap();
        assert!(sk2.open_view().unwrap().open(&sealed, None, b"").is_err());
    }
}
