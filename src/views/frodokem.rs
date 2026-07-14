// SPDX-License-Identifier: Apache-2.0
//! FrodoKEM AES/SHAKE multikey view.

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

type SealedParts = (Vec<u8>, Codec, Vec<u8>, Vec<u8>);

fn is_frodokem_priv(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::FrodoKem640AesPriv
            | Codec::FrodoKem976AesPriv
            | Codec::FrodoKem1344AesPriv
            | Codec::FrodoKem640ShakePriv
            | Codec::FrodoKem976ShakePriv
            | Codec::FrodoKem1344ShakePriv
    )
}

fn is_frodokem_pub(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::FrodoKem640AesPub
            | Codec::FrodoKem976AesPub
            | Codec::FrodoKem1344AesPub
            | Codec::FrodoKem640ShakePub
            | Codec::FrodoKem976ShakePub
            | Codec::FrodoKem1344ShakePub
    )
}

fn is_frodokem_aead_allowed(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::Xchacha20Poly1305 | Codec::Chacha20Poly1305 | Codec::AesGcm256
    )
}

fn public_codec(codec: Codec) -> Result<Codec, Error> {
    match codec {
        Codec::FrodoKem640AesPriv => Ok(Codec::FrodoKem640AesPub),
        Codec::FrodoKem976AesPriv => Ok(Codec::FrodoKem976AesPub),
        Codec::FrodoKem1344AesPriv => Ok(Codec::FrodoKem1344AesPub),
        Codec::FrodoKem640ShakePriv => Ok(Codec::FrodoKem640ShakePub),
        Codec::FrodoKem976ShakePriv => Ok(Codec::FrodoKem976ShakePub),
        Codec::FrodoKem1344ShakePriv => Ok(Codec::FrodoKem1344ShakePub),
        _ => Err(ConversionsError::SecretKeyFailure("not a FrodoKEM private key".into()).into()),
    }
}

fn public_from_private(codec: Codec, secret_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    match codec {
        Codec::FrodoKem640AesPriv => {
            super::frodokem_helper::public_from_private_640aes(secret_bytes)
        }
        Codec::FrodoKem976AesPriv => {
            super::frodokem_helper::public_from_private_976aes(secret_bytes)
        }
        Codec::FrodoKem1344AesPriv => {
            super::frodokem_helper::public_from_private_1344aes(secret_bytes)
        }
        Codec::FrodoKem640ShakePriv => {
            super::frodokem_helper::public_from_private_640shake(secret_bytes)
        }
        Codec::FrodoKem976ShakePriv => {
            super::frodokem_helper::public_from_private_976shake(secret_bytes)
        }
        Codec::FrodoKem1344ShakePriv => {
            super::frodokem_helper::public_from_private_1344shake(secret_bytes)
        }
        _ => {
            return Err(
                ConversionsError::SecretKeyFailure("not a FrodoKEM private key".into()).into(),
            )
        }
    }
    .map_err(|e| ConversionsError::SecretKeyFailure(e).into())
}

fn keypair(codec: Codec) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
    match codec {
        Codec::FrodoKem640AesPriv => Ok(super::frodokem_helper::keypair_640aes()),
        Codec::FrodoKem976AesPriv => Ok(super::frodokem_helper::keypair_976aes()),
        Codec::FrodoKem1344AesPriv => Ok(super::frodokem_helper::keypair_1344aes()),
        Codec::FrodoKem640ShakePriv => Ok(super::frodokem_helper::keypair_640shake()),
        Codec::FrodoKem976ShakePriv => Ok(super::frodokem_helper::keypair_976shake()),
        Codec::FrodoKem1344ShakePriv => Ok(super::frodokem_helper::keypair_1344shake()),
        _ => Err(ConversionsError::SecretKeyFailure("not a FrodoKEM private key".into()).into()),
    }
}

fn encap(codec: Codec, pub_key_bytes: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
    match codec {
        Codec::FrodoKem640AesPub => super::frodokem_helper::encap_640aes(pub_key_bytes),
        Codec::FrodoKem976AesPub => super::frodokem_helper::encap_976aes(pub_key_bytes),
        Codec::FrodoKem1344AesPub => super::frodokem_helper::encap_1344aes(pub_key_bytes),
        Codec::FrodoKem640ShakePub => super::frodokem_helper::encap_640shake(pub_key_bytes),
        Codec::FrodoKem976ShakePub => super::frodokem_helper::encap_976shake(pub_key_bytes),
        Codec::FrodoKem1344ShakePub => super::frodokem_helper::encap_1344shake(pub_key_bytes),
        _ => return Err(SealError::NotEncapsulationKey.into()),
    }
    .map_err(|e| SealError::EncapsulationFailed(e).into())
}

fn decap(
    codec: Codec,
    secret_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    match codec {
        Codec::FrodoKem640AesPriv => super::frodokem_helper::decap_640aes(secret_bytes, ciphertext),
        Codec::FrodoKem976AesPriv => super::frodokem_helper::decap_976aes(secret_bytes, ciphertext),
        Codec::FrodoKem1344AesPriv => {
            super::frodokem_helper::decap_1344aes(secret_bytes, ciphertext)
        }
        Codec::FrodoKem640ShakePriv => {
            super::frodokem_helper::decap_640shake(secret_bytes, ciphertext)
        }
        Codec::FrodoKem976ShakePriv => {
            super::frodokem_helper::decap_976shake(secret_bytes, ciphertext)
        }
        Codec::FrodoKem1344ShakePriv => {
            super::frodokem_helper::decap_1344shake(secret_bytes, ciphertext)
        }
        _ => return Err(SealError::NotDecapsulationKey.into()),
    }
    .map_err(|e| SealError::DecapsulationFailed(e).into())
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
        is_frodokem_priv(self.mk.codec)
    }
    fn is_public_key(&self) -> bool {
        is_frodokem_pub(self.mk.codec)
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
        let pub_bytes = public_from_private(self.mk.codec, secret_bytes.as_slice())?;
        Builder::new(public_codec(self.mk.codec)?)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&pub_bytes)
            .try_build()
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "FrodoKEM not supported in SSH key format".into(),
        )
        .into())
    }
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "FrodoKEM not supported in SSH key format".into(),
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

fn encode_sealed(kem_ct: &[u8], aead_codec: Codec, nonce: &[u8], ct_tag: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.append(&mut Varbytes::new(kem_ct.to_vec()).into());
    out.append(&mut aead_codec.into());
    out.append(&mut Varbytes::new(nonce.to_vec()).into());
    out.append(&mut Varbytes::new(ct_tag.to_vec()).into());
    out
}

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
        if !is_frodokem_aead_allowed(aead_codec) {
            return Err(SealError::UnsupportedAeadCodec(aead_codec).into());
        }
        let pub_bytes = self.key_bytes()?;
        let (kem_ct, shared_secret) = encap(self.mk.codec, pub_bytes.as_slice())?;
        let key_len = aead::key_size(aead_codec)?;
        let aead_key = aead::derive_aead_key(&shared_secret, b"frodokem-seal", key_len)?;
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
        if !is_frodokem_aead_allowed(aead_codec) {
            return Err(SealError::UnsupportedAeadCodec(aead_codec).into());
        }
        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };
        let shared_secret = decap(self.mk.codec, secret_bytes.as_slice(), &kem_ct)?;
        let key_len = aead::key_size(aead_codec)?;
        let aead_key = aead::derive_aead_key(&shared_secret, b"frodokem-seal", key_len)?;
        Ok(aead::aead_open(
            aead_codec, &aead_key, &nonce, &ct_tag, aad,
        )?)
    }
}

pub(crate) fn generate_private_key(codec: Codec) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (_pk, sk) = keypair(codec)?;
    Ok(sk)
}
