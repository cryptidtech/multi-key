// SPDX-License-Identifier: Apache-2.0
//! SLH-DSA multikey view; FIPS 205. Supports all 12 parameter sets (Sha2_128f/s through Shake256f/s).

use crate::{
    error::{AttributesError, ConversionsError, SignError, VerifyError},
    AttrId, AttrView, Builder, ConvView, DataView, Error, FingerprintView, Multikey, SignView,
    VerifyView, Views,
};
use multi_codec::Codec;
use multi_hash::{mh, Multihash};
use multi_sig::ms;
use multi_sig::Views as _;
use slh_dsa::signature::{Keypair, Signer, Verifier};
use slh_dsa::ParameterSet;
use slh_dsa::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s, Signature, SigningKey, VerifyingKey,
};
use ssh_encoding::{Decode, Encode};
use zeroize::Zeroizing;

/// SSH algorithm name for SLH-DSA-SHA2-128f
pub const ALGORITHM_NAME_SHA2_128F: &str = "slh-dsa-sha2-128f@multikey";
/// SSH algorithm name for SLH-DSA-SHA2-128s
pub const ALGORITHM_NAME_SHA2_128S: &str = "slh-dsa-sha2-128s@multikey";
/// SSH algorithm name for SLH-DSA-SHA2-192f
pub const ALGORITHM_NAME_SHA2_192F: &str = "slh-dsa-sha2-192f@multikey";
/// SSH algorithm name for SLH-DSA-SHA2-192s
pub const ALGORITHM_NAME_SHA2_192S: &str = "slh-dsa-sha2-192s@multikey";
/// SSH algorithm name for SLH-DSA-SHA2-256f
pub const ALGORITHM_NAME_SHA2_256F: &str = "slh-dsa-sha2-256f@multikey";
/// SSH algorithm name for SLH-DSA-SHA2-256s
pub const ALGORITHM_NAME_SHA2_256S: &str = "slh-dsa-sha2-256s@multikey";
/// SSH algorithm name for SLH-DSA-SHAKE-128f
pub const ALGORITHM_NAME_SHAKE_128F: &str = "slh-dsa-shake-128f@multikey";
/// SSH algorithm name for SLH-DSA-SHAKE-128s
pub const ALGORITHM_NAME_SHAKE_128S: &str = "slh-dsa-shake-128s@multikey";
/// SSH algorithm name for SLH-DSA-SHAKE-192f
pub const ALGORITHM_NAME_SHAKE_192F: &str = "slh-dsa-shake-192f@multikey";
/// SSH algorithm name for SLH-DSA-SHAKE-192s
pub const ALGORITHM_NAME_SHAKE_192S: &str = "slh-dsa-shake-192s@multikey";
/// SSH algorithm name for SLH-DSA-SHAKE-256f
pub const ALGORITHM_NAME_SHAKE_256F: &str = "slh-dsa-shake-256f@multikey";
/// SSH algorithm name for SLH-DSA-SHAKE-256s
pub const ALGORITHM_NAME_SHAKE_256S: &str = "slh-dsa-shake-256s@multikey";

/// Generate SLH-DSA key bytes for the given parameter set. Used by Builder::new_from_random_bytes.
pub(crate) fn gen_slh_dsa_key<P>() -> Vec<u8>
where
    P: ParameterSet,
{
    // slh-dsa 0.2.0-rc.5 uses rand_core 0.10 CryptoRng; use getrandom 0.4 SysRng.
    use getrandom::rand_core::UnwrapErr;
    let mut rng = UnwrapErr(getrandom::SysRng);
    SigningKey::<P>::new(&mut rng).to_vec()
}

fn is_slh_dsa_priv(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::SlhDsaSha2128FPriv
            | Codec::SlhDsaSha2128SPriv
            | Codec::SlhDsaSha2192FPriv
            | Codec::SlhDsaSha2192SPriv
            | Codec::SlhDsaSha2256FPriv
            | Codec::SlhDsaSha2256SPriv
            | Codec::SlhDsaShake128FPriv
            | Codec::SlhDsaShake128SPriv
            | Codec::SlhDsaShake192FPriv
            | Codec::SlhDsaShake192SPriv
            | Codec::SlhDsaShake256FPriv
            | Codec::SlhDsaShake256SPriv
    )
}

fn is_slh_dsa_pub(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::SlhDsaSha2128FPub
            | Codec::SlhDsaSha2128SPub
            | Codec::SlhDsaSha2192FPub
            | Codec::SlhDsaSha2192SPub
            | Codec::SlhDsaSha2256FPub
            | Codec::SlhDsaSha2256SPub
            | Codec::SlhDsaShake128FPub
            | Codec::SlhDsaShake128SPub
            | Codec::SlhDsaShake192FPub
            | Codec::SlhDsaShake192SPub
            | Codec::SlhDsaShake256FPub
            | Codec::SlhDsaShake256SPub
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
        is_slh_dsa_priv(self.mk.codec)
    }
    fn is_public_key(&self) -> bool {
        is_slh_dsa_pub(self.mk.codec)
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

        let (public_key, codec) = match self.mk.codec {
            Codec::SlhDsaSha2128FPriv => (
                SigningKey::<Sha2_128f>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?
                    .verifying_key()
                    .to_vec(),
                Codec::SlhDsaSha2128FPub,
            ),
            Codec::SlhDsaSha2128SPriv => (
                SigningKey::<Sha2_128s>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?
                    .verifying_key()
                    .to_vec(),
                Codec::SlhDsaSha2128SPub,
            ),
            Codec::SlhDsaSha2192FPriv => (
                SigningKey::<Sha2_192f>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?
                    .verifying_key()
                    .to_vec(),
                Codec::SlhDsaSha2192FPub,
            ),
            Codec::SlhDsaSha2192SPriv => (
                SigningKey::<Sha2_192s>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?
                    .verifying_key()
                    .to_vec(),
                Codec::SlhDsaSha2192SPub,
            ),
            Codec::SlhDsaSha2256FPriv => (
                SigningKey::<Sha2_256f>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?
                    .verifying_key()
                    .to_vec(),
                Codec::SlhDsaSha2256FPub,
            ),
            Codec::SlhDsaSha2256SPriv => (
                SigningKey::<Sha2_256s>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?
                    .verifying_key()
                    .to_vec(),
                Codec::SlhDsaSha2256SPub,
            ),
            Codec::SlhDsaShake128FPriv => (
                SigningKey::<Shake128f>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?
                    .verifying_key()
                    .to_vec(),
                Codec::SlhDsaShake128FPub,
            ),
            Codec::SlhDsaShake128SPriv => (
                SigningKey::<Shake128s>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?
                    .verifying_key()
                    .to_vec(),
                Codec::SlhDsaShake128SPub,
            ),
            Codec::SlhDsaShake192FPriv => (
                SigningKey::<Shake192f>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?
                    .verifying_key()
                    .to_vec(),
                Codec::SlhDsaShake192FPub,
            ),
            Codec::SlhDsaShake192SPriv => (
                SigningKey::<Shake192s>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?
                    .verifying_key()
                    .to_vec(),
                Codec::SlhDsaShake192SPub,
            ),
            Codec::SlhDsaShake256FPriv => (
                SigningKey::<Shake256f>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?
                    .verifying_key()
                    .to_vec(),
                Codec::SlhDsaShake256FPub,
            ),
            Codec::SlhDsaShake256SPriv => (
                SigningKey::<Shake256s>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?
                    .verifying_key()
                    .to_vec(),
                Codec::SlhDsaShake256SPub,
            ),
            _ => {
                return Err(
                    ConversionsError::SecretKeyFailure("invalid SLH-DSA codec".into()).into(),
                );
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
            Codec::SlhDsaSha2128FPub => ALGORITHM_NAME_SHA2_128F,
            Codec::SlhDsaSha2128SPub => ALGORITHM_NAME_SHA2_128S,
            Codec::SlhDsaSha2192FPub => ALGORITHM_NAME_SHA2_192F,
            Codec::SlhDsaSha2192SPub => ALGORITHM_NAME_SHA2_192S,
            Codec::SlhDsaSha2256FPub => ALGORITHM_NAME_SHA2_256F,
            Codec::SlhDsaSha2256SPub => ALGORITHM_NAME_SHA2_256S,
            Codec::SlhDsaShake128FPub => ALGORITHM_NAME_SHAKE_128F,
            Codec::SlhDsaShake128SPub => ALGORITHM_NAME_SHAKE_128S,
            Codec::SlhDsaShake192FPub => ALGORITHM_NAME_SHAKE_192F,
            Codec::SlhDsaShake192SPub => ALGORITHM_NAME_SHAKE_192S,
            Codec::SlhDsaShake256FPub => ALGORITHM_NAME_SHAKE_256F,
            Codec::SlhDsaShake256SPub => ALGORITHM_NAME_SHAKE_256S,
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
            Codec::SlhDsaSha2128FPriv => ALGORITHM_NAME_SHA2_128F,
            Codec::SlhDsaSha2128SPriv => ALGORITHM_NAME_SHA2_128S,
            Codec::SlhDsaSha2192FPriv => ALGORITHM_NAME_SHA2_192F,
            Codec::SlhDsaSha2192SPriv => ALGORITHM_NAME_SHA2_192S,
            Codec::SlhDsaSha2256FPriv => ALGORITHM_NAME_SHA2_256F,
            Codec::SlhDsaSha2256SPriv => ALGORITHM_NAME_SHA2_256S,
            Codec::SlhDsaShake128FPriv => ALGORITHM_NAME_SHAKE_128F,
            Codec::SlhDsaShake128SPriv => ALGORITHM_NAME_SHAKE_128S,
            Codec::SlhDsaShake192FPriv => ALGORITHM_NAME_SHAKE_192F,
            Codec::SlhDsaShake192SPriv => ALGORITHM_NAME_SHAKE_192S,
            Codec::SlhDsaShake256FPriv => ALGORITHM_NAME_SHAKE_256F,
            Codec::SlhDsaShake256SPriv => ALGORITHM_NAME_SHAKE_256S,
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
        let attr = self.mk.attr_view()?;
        if attr.is_secret_key() {
            let pk = self.mk.conv_view()?.to_public_key()?;
            return pk.fingerprint_view()?.fingerprint(codec);
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
        let (signature, codec) = match self.mk.codec {
            Codec::SlhDsaSha2128FPriv => {
                let signing_key = SigningKey::<Sha2_128f>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?;
                (signing_key.sign(msg).to_vec(), Codec::SlhDsaSha2128FMsig)
            }
            Codec::SlhDsaSha2128SPriv => {
                let signing_key = SigningKey::<Sha2_128s>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?;
                (signing_key.sign(msg).to_vec(), Codec::SlhDsaSha2128SMsig)
            }
            Codec::SlhDsaSha2192FPriv => {
                let signing_key = SigningKey::<Sha2_192f>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?;
                (signing_key.sign(msg).to_vec(), Codec::SlhDsaSha2192FMsig)
            }
            Codec::SlhDsaSha2192SPriv => {
                let signing_key = SigningKey::<Sha2_192s>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?;
                (signing_key.sign(msg).to_vec(), Codec::SlhDsaSha2192SMsig)
            }
            Codec::SlhDsaSha2256FPriv => {
                let signing_key = SigningKey::<Sha2_256f>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?;
                (signing_key.sign(msg).to_vec(), Codec::SlhDsaSha2256FMsig)
            }
            Codec::SlhDsaSha2256SPriv => {
                let signing_key = SigningKey::<Sha2_256s>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?;
                (signing_key.sign(msg).to_vec(), Codec::SlhDsaSha2256SMsig)
            }
            Codec::SlhDsaShake128FPriv => {
                let signing_key = SigningKey::<Shake128f>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?;
                (signing_key.sign(msg).to_vec(), Codec::SlhDsaShake128FMsig)
            }
            Codec::SlhDsaShake128SPriv => {
                let signing_key = SigningKey::<Shake128s>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?;
                (signing_key.sign(msg).to_vec(), Codec::SlhDsaShake128SMsig)
            }
            Codec::SlhDsaShake192FPriv => {
                let signing_key = SigningKey::<Shake192f>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?;
                (signing_key.sign(msg).to_vec(), Codec::SlhDsaShake192FMsig)
            }
            Codec::SlhDsaShake192SPriv => {
                let signing_key = SigningKey::<Shake192s>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?;
                (signing_key.sign(msg).to_vec(), Codec::SlhDsaShake192SMsig)
            }
            Codec::SlhDsaShake256FPriv => {
                let signing_key = SigningKey::<Shake256f>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?;
                (signing_key.sign(msg).to_vec(), Codec::SlhDsaShake256FMsig)
            }
            Codec::SlhDsaShake256SPriv => {
                let signing_key = SigningKey::<Shake256s>::try_from(secret_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure("invalid secret key length".into())
                    })?;
                (signing_key.sign(msg).to_vec(), Codec::SlhDsaShake256SMsig)
            }
            _ => {
                return Err(
                    ConversionsError::SecretKeyFailure("invalid secret key length".into()).into(),
                );
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

        match self.mk.codec {
            Codec::SlhDsaSha2128FPriv | Codec::SlhDsaSha2128FPub => {
                let verifying_key = VerifyingKey::<Sha2_128f>::try_from(key_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::PublicKeyFailure("invalid public key length".into())
                    })?;
                let signature = Signature::try_from(sig_bytes.as_slice())
                    .map_err(|_| VerifyError::BadSignature("invalid signature length".into()))?;
                verifying_key
                    .verify(msg_bytes, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()).into())
            }
            Codec::SlhDsaSha2128SPriv | Codec::SlhDsaSha2128SPub => {
                let verifying_key = VerifyingKey::<Sha2_128s>::try_from(key_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::PublicKeyFailure("invalid public key length".into())
                    })?;
                let signature = Signature::try_from(sig_bytes.as_slice())
                    .map_err(|_| VerifyError::BadSignature("invalid signature length".into()))?;
                verifying_key
                    .verify(msg_bytes, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()).into())
            }
            Codec::SlhDsaSha2192FPriv | Codec::SlhDsaSha2192FPub => {
                let verifying_key = VerifyingKey::<Sha2_192f>::try_from(key_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::PublicKeyFailure("invalid public key length".into())
                    })?;
                let signature = Signature::try_from(sig_bytes.as_slice())
                    .map_err(|_| VerifyError::BadSignature("invalid signature length".into()))?;
                verifying_key
                    .verify(msg_bytes, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()).into())
            }
            Codec::SlhDsaSha2192SPriv | Codec::SlhDsaSha2192SPub => {
                let verifying_key = VerifyingKey::<Sha2_192s>::try_from(key_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::PublicKeyFailure("invalid public key length".into())
                    })?;
                let signature = Signature::try_from(sig_bytes.as_slice())
                    .map_err(|_| VerifyError::BadSignature("invalid signature length".into()))?;
                verifying_key
                    .verify(msg_bytes, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()).into())
            }
            Codec::SlhDsaSha2256FPriv | Codec::SlhDsaSha2256FPub => {
                let verifying_key = VerifyingKey::<Sha2_256f>::try_from(key_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::PublicKeyFailure("invalid public key length".into())
                    })?;
                let signature = Signature::try_from(sig_bytes.as_slice())
                    .map_err(|_| VerifyError::BadSignature("invalid signature length".into()))?;
                verifying_key
                    .verify(msg_bytes, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()).into())
            }
            Codec::SlhDsaSha2256SPriv | Codec::SlhDsaSha2256SPub => {
                let verifying_key = VerifyingKey::<Sha2_256s>::try_from(key_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::PublicKeyFailure("invalid public key length".into())
                    })?;
                let signature = Signature::try_from(sig_bytes.as_slice())
                    .map_err(|_| VerifyError::BadSignature("invalid signature length".into()))?;
                verifying_key
                    .verify(msg_bytes, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()).into())
            }
            Codec::SlhDsaShake128FPriv | Codec::SlhDsaShake128FPub => {
                let verifying_key = VerifyingKey::<Shake128f>::try_from(key_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::PublicKeyFailure("invalid public key length".into())
                    })?;
                let signature = Signature::try_from(sig_bytes.as_slice())
                    .map_err(|_| VerifyError::BadSignature("invalid signature length".into()))?;
                verifying_key
                    .verify(msg_bytes, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()).into())
            }
            Codec::SlhDsaShake128SPriv | Codec::SlhDsaShake128SPub => {
                let verifying_key = VerifyingKey::<Shake128s>::try_from(key_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::PublicKeyFailure("invalid public key length".into())
                    })?;
                let signature = Signature::try_from(sig_bytes.as_slice())
                    .map_err(|_| VerifyError::BadSignature("invalid signature length".into()))?;
                verifying_key
                    .verify(msg_bytes, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()).into())
            }
            Codec::SlhDsaShake192FPriv | Codec::SlhDsaShake192FPub => {
                let verifying_key = VerifyingKey::<Shake192f>::try_from(key_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::PublicKeyFailure("invalid public key length".into())
                    })?;
                let signature = Signature::try_from(sig_bytes.as_slice())
                    .map_err(|_| VerifyError::BadSignature("invalid signature length".into()))?;
                verifying_key
                    .verify(msg_bytes, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()).into())
            }
            Codec::SlhDsaShake192SPriv | Codec::SlhDsaShake192SPub => {
                let verifying_key = VerifyingKey::<Shake192s>::try_from(key_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::PublicKeyFailure("invalid public key length".into())
                    })?;
                let signature = Signature::try_from(sig_bytes.as_slice())
                    .map_err(|_| VerifyError::BadSignature("invalid signature length".into()))?;
                verifying_key
                    .verify(msg_bytes, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()).into())
            }
            Codec::SlhDsaShake256FPriv | Codec::SlhDsaShake256FPub => {
                let verifying_key = VerifyingKey::<Shake256f>::try_from(key_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::PublicKeyFailure("invalid public key length".into())
                    })?;
                let signature = Signature::try_from(sig_bytes.as_slice())
                    .map_err(|_| VerifyError::BadSignature("invalid signature length".into()))?;
                verifying_key
                    .verify(msg_bytes, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()).into())
            }
            Codec::SlhDsaShake256SPriv | Codec::SlhDsaShake256SPub => {
                let verifying_key = VerifyingKey::<Shake256s>::try_from(key_bytes.as_slice())
                    .map_err(|_| {
                        ConversionsError::PublicKeyFailure("invalid public key length".into())
                    })?;
                let signature = Signature::try_from(sig_bytes.as_slice())
                    .map_err(|_| VerifyError::BadSignature("invalid signature length".into()))?;
                verifying_key
                    .verify(msg_bytes, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()).into())
            }
            _ => Err(ConversionsError::PublicKeyFailure("invalid public key length".into()).into()),
        }
    }
}
