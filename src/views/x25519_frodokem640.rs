// SPDX-License-Identifier: Apache-2.0
//! X25519-FrodoKEM-640 hybrid KEM multikey view (X-Wing-like); combines X25519 ECDH
//! with FrodoKEM-640 (AES or SHAKE), ChaCha20-Poly1305 AEAD, and a BLAKE3 combiner
//! feeding HKDF-SHA512.
//!
//! Private key layout: `x25519_seed (32) || frodokem_secret_key`.
//! Public key layout (classical-first): `x25519_pub (32) || frodokem_public_key`.

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

const X25519_SEED_LEN: usize = 32;
const X25519_PUB_LEN: usize = 32;

/// Decoded sealed message: (ephemeral_x25519_pub, frodo_ct, nonce, ciphertext+tag)
type SealedParts = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Only ChaCha20-Poly1305 allowed (matches the other X-Wing-like hybrid KEMs).
fn is_aead_allowed(codec: Codec) -> bool {
    codec == Codec::Chacha20Poly1305
}

fn is_priv(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::X25519Frodokem640AesPriv | Codec::X25519Frodokem640ShakePriv
    )
}

fn is_pub(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::X25519Frodokem640AesPub | Codec::X25519Frodokem640ShakePub
    )
}

fn pub_codec(codec: Codec) -> Codec {
    match codec {
        Codec::X25519Frodokem640AesPriv | Codec::X25519Frodokem640AesPub => {
            Codec::X25519Frodokem640AesPub
        }
        _ => Codec::X25519Frodokem640ShakePub,
    }
}

fn is_shake(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::X25519Frodokem640ShakePriv | Codec::X25519Frodokem640ShakePub
    )
}

/// FrodoKEM-640 keypair for the given hybrid variant. Returns `(pub, secret)`.
fn frodo_keypair(codec: Codec) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    if is_shake(codec) {
        super::frodokem_helper::keypair_640shake()
    } else {
        super::frodokem_helper::keypair_640aes()
    }
}

fn frodo_public_from_private(codec: Codec, secret: &[u8]) -> Result<Vec<u8>, Error> {
    if is_shake(codec) {
        super::frodokem_helper::public_from_private_640shake(secret)
    } else {
        super::frodokem_helper::public_from_private_640aes(secret)
    }
    .map_err(|e| ConversionsError::SecretKeyFailure(e).into())
}

fn frodo_encap(codec: Codec, pub_bytes: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
    if is_shake(codec) {
        super::frodokem_helper::encap_640shake(pub_bytes)
    } else {
        super::frodokem_helper::encap_640aes(pub_bytes)
    }
    .map_err(|e| SealError::EncapsulationFailed(e).into())
}

fn frodo_decap(codec: Codec, secret: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if is_shake(codec) {
        super::frodokem_helper::decap_640shake(secret, ct)
    } else {
        super::frodokem_helper::decap_640aes(secret, ct)
    }
    .map_err(|e| SealError::DecapsulationFailed(e).into())
}

/// Generate a hybrid private key for the builder: `x25519_seed (32) || frodo_secret`.
pub(crate) fn generate_private_key(codec: Codec) -> Vec<u8> {
    let mut x25519_seed = [0u8; X25519_SEED_LEN];
    rand_core::Rng::fill_bytes(&mut rand::rng(), &mut x25519_seed);
    let (_pub, frodo_secret) = frodo_keypair(codec);
    let mut out = Vec::with_capacity(X25519_SEED_LEN + frodo_secret.len());
    out.extend_from_slice(&x25519_seed);
    out.extend_from_slice(&frodo_secret);
    out
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
        is_priv(self.mk.codec)
    }
    fn is_public_key(&self) -> bool {
        is_pub(self.mk.codec)
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

        if secret_bytes.len() <= X25519_SEED_LEN {
            return Err(
                ConversionsError::SecretKeyFailure("invalid hybrid secret length".into()).into(),
            );
        }

        // X25519 public key
        let x25519_seed: [u8; 32] = secret_bytes[..X25519_SEED_LEN]
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("invalid x25519 seed".into()))?;
        let x25519_secret = StaticSecret::from(x25519_seed);
        let x25519_pub = PublicKey::from(&x25519_secret);

        // FrodoKEM public key from the stored full secret key
        let frodo_pub = frodo_public_from_private(self.mk.codec, &secret_bytes[X25519_SEED_LEN..])?;

        // Concatenate (classical-first): x25519_pub (32) || frodokem_pub
        let mut pub_bytes = Vec::with_capacity(X25519_PUB_LEN + frodo_pub.len());
        pub_bytes.extend_from_slice(x25519_pub.as_bytes());
        pub_bytes.extend_from_slice(&frodo_pub);

        Builder::new(pub_codec(self.mk.codec))
            .with_comment(&self.mk.comment)
            .with_key_bytes(&pub_bytes)
            .try_build()
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "X25519-FrodoKEM-640 not supported in SSH key format".into(),
        )
        .into())
    }
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "X25519-FrodoKEM-640 not supported in SSH key format".into(),
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
/// ss = BLAKE3(label || ss_frodo || ss_x25519 || frodo_ct || ephemeral_x25519_pub)
fn combine_shared_secrets(
    ss_frodo: &[u8],
    ss_x25519: &[u8],
    frodo_ct: &[u8],
    ephemeral_x25519_pub: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"x25519-frodokem640-hpke");
    hasher.update(ss_frodo);
    hasher.update(ss_x25519);
    hasher.update(frodo_ct);
    hasher.update(ephemeral_x25519_pub);
    *hasher.finalize().as_bytes()
}

fn encode_sealed(ephemeral_pub: &[u8], frodo_ct: &[u8], nonce: &[u8], ct_tag: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.append(&mut Varbytes::new(ephemeral_pub.to_vec()).into());
    out.append(&mut Varbytes::new(frodo_ct.to_vec()).into());
    out.append(&mut Varbytes::new(nonce.to_vec()).into());
    out.append(&mut Varbytes::new(ct_tag.to_vec()).into());
    out
}

fn decode_sealed(data: &[u8]) -> Result<SealedParts, SealError> {
    let (ephemeral_pub, ptr) = Varbytes::try_decode_from(data)
        .map_err(|_| SealError::InvalidFormat("missing ephemeral public key".into()))?;
    let (frodo_ct, ptr) = Varbytes::try_decode_from(ptr)
        .map_err(|_| SealError::InvalidFormat("missing frodokem ciphertext".into()))?;
    let (nonce, ptr) = Varbytes::try_decode_from(ptr)
        .map_err(|_| SealError::InvalidFormat("missing nonce".into()))?;
    let (ct_tag, _) = Varbytes::try_decode_from(ptr)
        .map_err(|_| SealError::InvalidFormat("missing ciphertext".into()))?;
    Ok((
        ephemeral_pub.to_inner(),
        frodo_ct.to_inner(),
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
        if pub_bytes.len() <= X25519_PUB_LEN {
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

        // FrodoKEM encapsulate
        let (frodo_ct, ss_frodo) = frodo_encap(self.mk.codec, &pub_bytes[X25519_PUB_LEN..])?;

        let combined_ss = combine_shared_secrets(
            ss_frodo.as_ref(),
            ss_x25519.as_bytes(),
            frodo_ct.as_ref(),
            ephemeral_pub.as_bytes(),
        );

        // Derive the AEAD key from the combined shared secret via HKDF-SHA512,
        // matching the construction used by the other hybrid KEMs.
        let key_len = aead::key_size(aead_codec)?;
        let aead_key = aead::derive_aead_key(&combined_ss, b"x25519-frodokem640-seal", key_len)?;

        let (nonce, ct_tag) = aead::aead_seal(aead_codec, &aead_key, plaintext, aad)?;

        Ok((
            encode_sealed(ephemeral_pub.as_bytes(), frodo_ct.as_ref(), &nonce, &ct_tag),
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

        let (ephemeral_pub_bytes, frodo_ct_bytes, nonce, ct_tag) = decode_sealed(sealed_msg)?;

        if ephemeral_pub_bytes.len() != X25519_PUB_LEN {
            return Err(
                SealError::InvalidFormat("invalid ephemeral public key length".into()).into(),
            );
        }

        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };
        if secret_bytes.len() <= X25519_SEED_LEN {
            return Err(
                ConversionsError::SecretKeyFailure("invalid hybrid secret length".into()).into(),
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

        // FrodoKEM decapsulate
        let ss_frodo = frodo_decap(
            self.mk.codec,
            &secret_bytes[X25519_SEED_LEN..],
            &frodo_ct_bytes,
        )?;

        let combined_ss = combine_shared_secrets(
            ss_frodo.as_ref(),
            ss_x25519.as_bytes(),
            frodo_ct_bytes.as_slice(),
            ephemeral_pub_bytes.as_slice(),
        );

        // Derive the AEAD key from the combined shared secret via HKDF-SHA512,
        // matching the construction used by the other hybrid KEMs.
        let key_len = aead::key_size(Codec::Chacha20Poly1305)?;
        let aead_key = aead::derive_aead_key(&combined_ss, b"x25519-frodokem640-seal", key_len)?;

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

    fn roundtrip(priv_codec: Codec) {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(priv_codec, &mut rng)
            .unwrap()
            .with_comment("x25519-frodokem hybrid test")
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        let plaintext = b"hello X25519-FrodoKEM-640 hybrid KEM!";
        let (sealed, _) = pk
            .seal_view()
            .unwrap()
            .seal(plaintext, Codec::Chacha20Poly1305, b"")
            .unwrap();
        let opened = sk.open_view().unwrap().open(&sealed, None, b"").unwrap();
        assert_eq!(plaintext.as_slice(), opened.as_slice());

        // wrong key fails
        let sk2 = Builder::new_from_random_bytes(priv_codec, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        assert!(sk2.open_view().unwrap().open(&sealed, None, b"").is_err());
    }

    #[test]
    fn test_640aes_roundtrip() {
        roundtrip(Codec::X25519Frodokem640AesPriv);
    }

    #[test]
    fn test_640shake_roundtrip() {
        roundtrip(Codec::X25519Frodokem640ShakePriv);
    }
}
