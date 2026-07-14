// SPDX-License-Identifier: Apache-2.0
//! MAYO-1/2/3/5 multikey view; post-quantum multivariate signature.

use crate::{
    error::{AttributesError, ConversionsError, SignError, VerifyError},
    views::Views,
    AttrId, AttrView, Builder, ConvView, DataView, Error, FingerprintView, Multikey, SignView,
    VerifyView,
};
use multi_codec::Codec;
use multi_hash::{mh, Multihash};
use multi_sig::{ms, Views as _};
use pq_mayo::{KeyPair, Mayo1, Mayo2, Mayo3, Mayo5, Signature, VerifyingKey};
use ssh_encoding::{Decode, Encode};
use zeroize::Zeroizing;

/// SSH algorithm name for MAYO-1
pub const ALGORITHM_NAME_1: &str = "mayo-1@multikey";
/// SSH algorithm name for MAYO-2
pub const ALGORITHM_NAME_2: &str = "mayo-2@multikey";
/// SSH algorithm name for MAYO-3
pub const ALGORITHM_NAME_3: &str = "mayo-3@multikey";
/// SSH algorithm name for MAYO-5
pub const ALGORITHM_NAME_5: &str = "mayo-5@multikey";

fn is_mayo_priv(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::Mayo1Priv | Codec::Mayo2Priv | Codec::Mayo3Priv | Codec::Mayo5Priv
    )
}

fn is_mayo_pub(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::Mayo1Pub | Codec::Mayo2Pub | Codec::Mayo3Pub | Codec::Mayo5Pub
    )
}

/// Compact-secret-key (seed) lengths per MAYO parameter set.
const MAYO_SEED_LENGTH: usize = 24; // MAYO-1 and MAYO-2
const MAYO_3_SEED_LENGTH: usize = 32;
const MAYO_5_SEED_LENGTH: usize = 40;

const MAYO_1_PUBLIC_KEY_LENGTH: usize = 1420;
const MAYO_2_PUBLIC_KEY_LENGTH: usize = 4368;
const MAYO_3_PUBLIC_KEY_LENGTH: usize = 2986;
const MAYO_5_PUBLIC_KEY_LENGTH: usize = 5554;

const MAYO_1_SIGNATURE_LENGTH: usize = 454;
const MAYO_2_SIGNATURE_LENGTH: usize = 216;
const MAYO_3_SIGNATURE_LENGTH: usize = 681;
const MAYO_5_SIGNATURE_LENGTH: usize = 964;

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
        is_mayo_priv(self.mk.codec)
    }
    fn is_public_key(&self) -> bool {
        is_mayo_pub(self.mk.codec)
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
            (Codec::Mayo1Priv, MAYO_SEED_LENGTH) => {
                let kp = KeyPair::<Mayo1>::from_seed(secret_bytes.as_slice()).map_err(|e| {
                    ConversionsError::SecretKeyFailure(format!("MAYO-1 seed error: {}", e))
                })?;
                (kp.verifying_key().as_ref().to_vec(), Codec::Mayo1Pub)
            }
            (Codec::Mayo2Priv, MAYO_SEED_LENGTH) => {
                let kp = KeyPair::<Mayo2>::from_seed(secret_bytes.as_slice()).map_err(|e| {
                    ConversionsError::SecretKeyFailure(format!("MAYO-2 seed error: {}", e))
                })?;
                (kp.verifying_key().as_ref().to_vec(), Codec::Mayo2Pub)
            }
            (Codec::Mayo3Priv, MAYO_3_SEED_LENGTH) => {
                let kp = KeyPair::<Mayo3>::from_seed(secret_bytes.as_slice()).map_err(|e| {
                    ConversionsError::SecretKeyFailure(format!("MAYO-3 seed error: {}", e))
                })?;
                (kp.verifying_key().as_ref().to_vec(), Codec::Mayo3Pub)
            }
            (Codec::Mayo5Priv, MAYO_5_SEED_LENGTH) => {
                let kp = KeyPair::<Mayo5>::from_seed(secret_bytes.as_slice()).map_err(|e| {
                    ConversionsError::SecretKeyFailure(format!("MAYO-5 seed error: {}", e))
                })?;
                (kp.verifying_key().as_ref().to_vec(), Codec::Mayo5Pub)
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

        let algorithm_name = match pk.codec {
            Codec::Mayo1Pub => ALGORITHM_NAME_1,
            Codec::Mayo2Pub => ALGORITHM_NAME_2,
            Codec::Mayo3Pub => ALGORITHM_NAME_3,
            Codec::Mayo5Pub => ALGORITHM_NAME_5,
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

        let algorithm_name = match self.mk.codec {
            Codec::Mayo1Priv => ALGORITHM_NAME_1,
            Codec::Mayo2Priv => ALGORITHM_NAME_2,
            Codec::Mayo3Priv => ALGORITHM_NAME_3,
            Codec::Mayo5Priv => ALGORITHM_NAME_5,
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
                "MAYO public key derivation not yet implemented".into(),
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
        use ml_dsa::signature::Signer;

        let attr = self.mk.attr_view()?;
        if !attr.is_secret_key() {
            return Err(SignError::NotSigningKey.into());
        }

        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };
        let (signature, codec) = match (self.mk.codec, secret_bytes.len()) {
            (Codec::Mayo1Priv, MAYO_SEED_LENGTH) => {
                let kp = KeyPair::<Mayo1>::from_seed(secret_bytes.as_slice()).map_err(|e| {
                    ConversionsError::SecretKeyFailure(format!("MAYO-1 seed error: {}", e))
                })?;
                let sig = kp
                    .signing_key()
                    .try_sign(msg)
                    .map_err(|e| SignError::SigningFailed(e.to_string()))?;
                (sig.as_ref().to_vec(), Codec::Mayo1Msig)
            }
            (Codec::Mayo2Priv, MAYO_SEED_LENGTH) => {
                let kp = KeyPair::<Mayo2>::from_seed(secret_bytes.as_slice()).map_err(|e| {
                    ConversionsError::SecretKeyFailure(format!("MAYO-2 seed error: {}", e))
                })?;
                let sig = kp
                    .signing_key()
                    .try_sign(msg)
                    .map_err(|e| SignError::SigningFailed(e.to_string()))?;
                (sig.as_ref().to_vec(), Codec::Mayo2Msig)
            }
            (Codec::Mayo3Priv, MAYO_3_SEED_LENGTH) => {
                let kp = KeyPair::<Mayo3>::from_seed(secret_bytes.as_slice()).map_err(|e| {
                    ConversionsError::SecretKeyFailure(format!("MAYO-3 seed error: {}", e))
                })?;
                let sig = kp
                    .signing_key()
                    .try_sign(msg)
                    .map_err(|e| SignError::SigningFailed(e.to_string()))?;
                (sig.as_ref().to_vec(), Codec::Mayo3Msig)
            }
            (Codec::Mayo5Priv, MAYO_5_SEED_LENGTH) => {
                let kp = KeyPair::<Mayo5>::from_seed(secret_bytes.as_slice()).map_err(|e| {
                    ConversionsError::SecretKeyFailure(format!("MAYO-5 seed error: {}", e))
                })?;
                let sig = kp
                    .signing_key()
                    .try_sign(msg)
                    .map_err(|e| SignError::SigningFailed(e.to_string()))?;
                (sig.as_ref().to_vec(), Codec::Mayo5Msig)
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
        use ml_dsa::signature::Verifier;

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
            (MAYO_1_PUBLIC_KEY_LENGTH, MAYO_1_SIGNATURE_LENGTH) => {
                let vk = VerifyingKey::<Mayo1>::try_from(key_bytes.as_slice()).map_err(|_| {
                    ConversionsError::PublicKeyFailure("invalid public key length".into())
                })?;
                let signature = Signature::<Mayo1>::try_from(sig_bytes.as_slice())
                    .map_err(|_| VerifyError::BadSignature("invalid signature length".into()))?;
                vk.verify(msg_bytes, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
                Ok(())
            }
            (MAYO_2_PUBLIC_KEY_LENGTH, MAYO_2_SIGNATURE_LENGTH) => {
                let vk = VerifyingKey::<Mayo2>::try_from(key_bytes.as_slice()).map_err(|_| {
                    ConversionsError::PublicKeyFailure("invalid public key length".into())
                })?;
                let signature = Signature::<Mayo2>::try_from(sig_bytes.as_slice())
                    .map_err(|_| VerifyError::BadSignature("invalid signature length".into()))?;
                vk.verify(msg_bytes, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
                Ok(())
            }
            (MAYO_3_PUBLIC_KEY_LENGTH, MAYO_3_SIGNATURE_LENGTH) => {
                let vk = VerifyingKey::<Mayo3>::try_from(key_bytes.as_slice()).map_err(|_| {
                    ConversionsError::PublicKeyFailure("invalid public key length".into())
                })?;
                let signature = Signature::<Mayo3>::try_from(sig_bytes.as_slice())
                    .map_err(|_| VerifyError::BadSignature("invalid signature length".into()))?;
                vk.verify(msg_bytes, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
                Ok(())
            }
            (MAYO_5_PUBLIC_KEY_LENGTH, MAYO_5_SIGNATURE_LENGTH) => {
                let vk = VerifyingKey::<Mayo5>::try_from(key_bytes.as_slice()).map_err(|_| {
                    ConversionsError::PublicKeyFailure("invalid public key length".into())
                })?;
                let signature = Signature::<Mayo5>::try_from(sig_bytes.as_slice())
                    .map_err(|_| VerifyError::BadSignature("invalid signature length".into()))?;
                vk.verify(msg_bytes, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
                Ok(())
            }
            _ => Err(
                VerifyError::BadSignature("invalid public key or signature length".into()).into(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::Views;

    fn sign_verify_roundtrip(priv_codec: Codec) {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(priv_codec, &mut rng)
            .unwrap()
            .with_comment("mayo test")
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        let msg = b"hello MAYO multivariate signature";
        let sig = sk.sign_view().unwrap().sign(msg, false, None).unwrap();
        pk.verify_view().unwrap().verify(&sig, Some(msg)).unwrap();

        // wrong message must fail
        assert!(pk
            .verify_view()
            .unwrap()
            .verify(&sig, Some(b"tampered"))
            .is_err());
    }

    #[test]
    fn test_mayo3_sign_verify_roundtrip() {
        sign_verify_roundtrip(Codec::Mayo3Priv);
    }

    #[test]
    fn test_mayo5_sign_verify_roundtrip() {
        sign_verify_roundtrip(Codec::Mayo5Priv);
    }
}
