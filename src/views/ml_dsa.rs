// SPDX-License-Identifier: Apache-2.0
//! ML-DSA 65/87 multikey view; FIPS 204.

use crate::{
    error::{AttributesError, ConversionsError, SignError, VerifyError},
    views::Views,
    AttrId, AttrView, Builder, ConvView, DataView, Error, FingerprintView, Multikey, SignView,
    VerifyView,
};
use multi_codec::Codec;
use multi_hash::{mh, Multihash};
use multi_sig::{ms, Views as _};
use ml_dsa::{
    signature::{Keypair, Signer, Verifier},
    EncodedSignature, EncodedVerifyingKey, MlDsa65, MlDsa87, Seed, Signature, SigningKey,
    VerifyingKey,
};
use ssh_encoding::{Decode, Encode};
use zeroize::Zeroizing;

/// SSH algorithm name for ML-DSA-65
pub const ALGORITHM_NAME_65: &str = "ml-dsa-65@multikey";
/// SSH algorithm name for ML-DSA-87
pub const ALGORITHM_NAME_87: &str = "ml-dsa-87@multikey";

fn is_ml_dsa_priv(codec: Codec) -> bool {
    codec == Codec::MlDsa65Priv || codec == Codec::MlDsa87Priv
}

fn is_ml_dsa_pub(codec: Codec) -> bool {
    codec == Codec::MlDsa65Pub || codec == Codec::MlDsa87Pub
}

const ML_DSA_SEED_LENGTH: usize = 32;

const ML_DSA_65_PUBLIC_KEY_LENGTH: usize = 1952;
const ML_DSA_87_PUBLIC_KEY_LENGTH: usize = 2592;

const ML_DSA_65_SIGNATURE_LENGTH: usize = 3309;
const ML_DSA_87_SIGNATURE_LENGTH: usize = 4627;

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
        is_ml_dsa_priv(self.mk.codec)
    }
    fn is_public_key(&self) -> bool {
        is_ml_dsa_pub(self.mk.codec)
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

        let (public_key, codec) = match (self.mk.codec, secret_bytes.len()) {
            (Codec::MlDsa65Priv, ML_DSA_SEED_LENGTH) => {
                let seed_bytes: [u8; ML_DSA_SEED_LENGTH] =
                    secret_bytes.as_slice().try_into().map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid seed length".into())
                    })?;
                let seed = Seed::from(seed_bytes);
                let kp = SigningKey::<MlDsa65>::from_seed(&seed);
                (
                    kp.verifying_key().encode().as_slice().to_vec(),
                    Codec::MlDsa65Pub,
                )
            }
            (Codec::MlDsa87Priv, ML_DSA_SEED_LENGTH) => {
                let seed_bytes: [u8; ML_DSA_SEED_LENGTH] =
                    secret_bytes.as_slice().try_into().map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid seed length".into())
                    })?;
                let seed = Seed::from(seed_bytes);
                let kp = SigningKey::<MlDsa87>::from_seed(&seed);
                (
                    kp.verifying_key().encode().as_slice().to_vec(),
                    Codec::MlDsa87Pub,
                )
            }
            _ => {
                return Err(ConversionsError::SecretKeyFailure(
                    "invalid secret key or seed length".into(),
                )
                .into());
            }
        };

        Builder::new(codec)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&public_key)
            .try_build()
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        let mut pk = self.mk.clone();
        if self.is_secret_key() {
            pk = self.to_public_key()?;
        }

        let key_bytes = {
            let kd = pk.data_view()?;
            kd.key_bytes()?
        };

        // Determine algorithm name based on codec
        let algorithm_name = match pk.codec {
            Codec::MlDsa65Pub => ALGORITHM_NAME_65,
            Codec::MlDsa87Pub => ALGORITHM_NAME_87,
            _ => return Err(ConversionsError::UnsupportedCodec(pk.codec).into()),
        };

        let mut buff: Vec<u8> = Vec::new();
        key_bytes
            .encode(&mut buff)
            .map_err(|e| ConversionsError::Ssh(e.into()))?;
        let opaque_key_bytes = ssh_key::public::OpaquePublicKeyBytes::decode(&mut buff.as_slice())
            .map_err(|e| ConversionsError::Ssh(e.into()))?;

        Ok(ssh_key::PublicKey::new(
            ssh_key::public::KeyData::Other(ssh_key::public::OpaquePublicKey {
                algorithm: ssh_key::Algorithm::Other(
                    ssh_key::AlgorithmName::new(algorithm_name)
                        .map_err(|e| ConversionsError::Ssh(e.into()))?,
                ),
                key: opaque_key_bytes,
            }),
            pk.comment,
        ))
    }

    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };

        // Determine algorithm name based on codec
        let algorithm_name = match self.mk.codec {
            Codec::MlDsa65Priv => ALGORITHM_NAME_65,
            Codec::MlDsa87Priv => ALGORITHM_NAME_87,
            _ => return Err(ConversionsError::UnsupportedCodec(self.mk.codec).into()),
        };

        let mut buf: Vec<u8> = Vec::new();
        secret_bytes
            .encode(&mut buf)
            .map_err(|e| ConversionsError::Ssh(e.into()))?;
        let opaque_private_key_bytes =
            ssh_key::private::OpaquePrivateKeyBytes::decode(&mut buf.as_slice())
                .map_err(|e| ConversionsError::Ssh(e.into()))?;

        let pk = self.to_public_key()?;
        let key_bytes = {
            let kd = pk.data_view()?;
            kd.key_bytes()?
        };

        buf.clear();
        key_bytes
            .encode(&mut buf)
            .map_err(|e| ConversionsError::Ssh(e.into()))?;
        let opaque_public_key_bytes =
            ssh_key::public::OpaquePublicKeyBytes::decode(&mut buf.as_slice())
                .map_err(|e| ConversionsError::Ssh(e.into()))?;

        Ok(ssh_key::PrivateKey::new(
            ssh_key::private::KeypairData::Other(ssh_key::private::OpaqueKeypair {
                public: ssh_key::public::OpaquePublicKey {
                    algorithm: ssh_key::Algorithm::Other(
                        ssh_key::AlgorithmName::new(algorithm_name)
                            .map_err(|e| ConversionsError::Ssh(e.into()))?,
                    ),
                    key: opaque_public_key_bytes,
                },
                private: opaque_private_key_bytes,
            }),
            self.mk.comment.clone(),
        )
        .map_err(|e| ConversionsError::Ssh(e.into()))?)
    }
}

impl<'a> FingerprintView for View<'a> {
    fn fingerprint(&self, codec: Codec) -> Result<Multihash, Error> {
        if self.is_secret_key() {
            return Err(ConversionsError::SecretKeyFailure(
                "ML-DSA public key derivation not yet implemented".into(),
            )
            .into());
        }
        let bytes = self.key_bytes()?;
        Ok(mh::Builder::new_from_bytes(codec, bytes.as_slice())?.try_build()?)
    }
}

impl<'a> SignView for View<'a> {
    fn sign(
        &self,
        msg: &[u8],
        combined: bool,
        _scheme: Option<u8>,
    ) -> Result<multi_sig::Multisig, Error> {
        let attr = self.mk.attr_view()?;
        if !attr.is_secret_key() {
            return Err(SignError::NotSigningKey.into());
        }

        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };
        let (signature, codec) = match (self.mk.codec, secret_bytes.len()) {
            (Codec::MlDsa65Priv, ML_DSA_SEED_LENGTH) => {
                let seed_bytes: [u8; ML_DSA_SEED_LENGTH] =
                    secret_bytes.as_slice().try_into().map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid seed length".into())
                    })?;
                let seed = Seed::from(seed_bytes);
                let kp = SigningKey::<MlDsa65>::from_seed(&seed);
                (
                    kp.sign(msg).encode().as_slice().to_vec(),
                    Codec::MlDsa65Msig,
                )
            }
            (Codec::MlDsa87Priv, ML_DSA_SEED_LENGTH) => {
                let seed_bytes: [u8; ML_DSA_SEED_LENGTH] =
                    secret_bytes.as_slice().try_into().map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid seed length".into())
                    })?;
                let seed = Seed::from(seed_bytes);
                let kp = SigningKey::<MlDsa87>::from_seed(&seed);
                (
                    kp.sign(msg).encode().as_slice().to_vec(),
                    Codec::MlDsa87Msig,
                )
            }
            _ => {
                return Err(ConversionsError::SecretKeyFailure(
                    "invalid secret key or seed length".into(),
                )
                .into());
            }
        };

        let mut ms = ms::Builder::new(codec).with_signature_bytes(&signature);
        if combined {
            ms = ms.with_message_bytes(&msg);
        }
        Ok(ms.try_build()?)
    }
}

impl<'a> VerifyView for View<'a> {
    fn verify(&self, sig: &multi_sig::Multisig, msg: Option<&[u8]>) -> Result<(), Error> {
        let msg_bytes = if let Some(m) = msg {
            m
        } else if !sig.message.is_empty() {
            sig.message.as_slice()
        } else {
            return Err(VerifyError::MissingMessage.into());
        };

        let attr = self.mk.attr_view()?;
        let pubmk = if attr.is_secret_key() {
            let kc = self.mk.conv_view()?;
            kc.to_public_key()?
        } else {
            self.mk.clone()
        };

        let key_bytes = {
            let kd = pubmk.data_view()?;
            kd.key_bytes()?
        };

        let sv = sig.data_view()?;
        let sig_bytes = sv.sig_bytes()?;

        match (key_bytes.len(), sig_bytes.len()) {
            (ML_DSA_65_PUBLIC_KEY_LENGTH, ML_DSA_65_SIGNATURE_LENGTH) => {
                let encoded_verifying_key =
                    EncodedVerifyingKey::<MlDsa65>::try_from(key_bytes.as_slice()).map_err(
                        |_| ConversionsError::PublicKeyFailure("invalid public key length".into()),
                    )?;
                let verifying_key = VerifyingKey::<MlDsa65>::decode(&encoded_verifying_key);
                let encoded_signature = EncodedSignature::<MlDsa65>::try_from(sig_bytes.as_slice())
                    .map_err(|_| VerifyError::BadSignature("invalid signature length".into()))?;
                let signature = Signature::decode(&encoded_signature)
                    .ok_or(VerifyError::BadSignature("invalid signature".into()))?;
                verifying_key
                    .verify(msg_bytes, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
                Ok(())
            }
            (ML_DSA_87_PUBLIC_KEY_LENGTH, ML_DSA_87_SIGNATURE_LENGTH) => {
                let encoded_verifying_key =
                    EncodedVerifyingKey::<MlDsa87>::try_from(key_bytes.as_slice()).map_err(
                        |_| ConversionsError::PublicKeyFailure("invalid public key length".into()),
                    )?;
                let verifying_key = VerifyingKey::<MlDsa87>::decode(&encoded_verifying_key);
                let encoded_signature = EncodedSignature::<MlDsa87>::try_from(sig_bytes.as_slice())
                    .map_err(|_| VerifyError::BadSignature("invalid signature length".into()))?;
                let signature = Signature::decode(&encoded_signature)
                    .ok_or(VerifyError::BadSignature("invalid signature".into()))?;
                verifying_key
                    .verify(msg_bytes, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
                Ok(())
            }
            _ => Err(
                VerifyError::BadSignature("invalid public key or signature length".into()).into(),
            ),
        }
    }
}
