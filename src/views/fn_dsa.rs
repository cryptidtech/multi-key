// SPDX-License-Identifier: Apache-2.0
//! FN-DSA (Falcon) 512/1024 multikey view; FIPS 206 (draft).

use crate::{
    error::{AttributesError, ConversionsError, SignError, VerifyError},
    views::Views,
    AttrId, AttrView, Builder, ConvView, DataView, Error, FingerprintView, Multikey, SignView,
    VerifyView,
};
use multi_codec::Codec;
use multi_hash::{mh, Multihash};
use multi_sig::{ms, Views as _};
use fn_dsa::{
    signature_size, vrfy_key_size, SigningKey, SigningKeyStandard, VerifyingKey,
    VerifyingKeyStandard, DOMAIN_NONE, FN_DSA_LOGN_1024, FN_DSA_LOGN_512, HASH_ID_RAW,
};
use ssh_encoding::{Decode, Encode};
use zeroize::Zeroizing;

/// SSH algorithm name for FN-DSA-512
pub const ALGORITHM_NAME_512: &str = "fn-dsa-512@multikey";
/// SSH algorithm name for FN-DSA-1024
pub const ALGORITHM_NAME_1024: &str = "fn-dsa-1024@multikey";

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
        self.mk.codec == Codec::FnDsa512Priv || self.mk.codec == Codec::FnDsa1024Priv
    }
    fn is_public_key(&self) -> bool {
        self.mk.codec == Codec::FnDsa512Pub || self.mk.codec == Codec::FnDsa1024Pub
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
        if self.is_encrypted() {
            return Err(AttributesError::EncryptedKey.into());
        }
        self.key_bytes()
    }
}

impl<'a> FingerprintView for View<'a> {
    fn fingerprint(&self, codec: Codec) -> Result<Multihash, Error> {
        let attr = self.mk.attr_view()?;
        if attr.is_secret_key() {
            // convert to a public key Multikey
            let pk = self.to_public_key()?;
            // get a conversions view on the public key
            let fp = pk.fingerprint_view()?;
            // get the fingerprint
            let f = fp.fingerprint(codec)?;
            Ok(f)
        } else {
            // get the key bytes
            let bytes = {
                let kd = self.mk.data_view()?;

                kd.key_bytes()?
            };
            // hash the key bytes using the given codec
            Ok(mh::Builder::new_from_bytes(codec, bytes)?.try_build()?)
        }
    }
}

impl<'a> ConvView for View<'a> {
    fn to_public_key(&self) -> Result<Multikey, Error> {
        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };

        let key = SigningKeyStandard::decode(secret_bytes.as_slice()).ok_or(
            ConversionsError::SecretKeyFailure("invalid secret key length".into()),
        )?;

        let logn = key.get_logn();
        let mut verifying_key = vec![0u8; vrfy_key_size(logn)];
        key.to_verifying_key(&mut verifying_key);

        let pub_codec = if logn == FN_DSA_LOGN_512 {
            Codec::FnDsa512Pub
        } else {
            Codec::FnDsa1024Pub
        };
        Builder::new(pub_codec)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&verifying_key)
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
            Codec::FnDsa512Pub => ALGORITHM_NAME_512,
            Codec::FnDsa1024Pub => ALGORITHM_NAME_1024,
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
            Codec::FnDsa512Priv => ALGORITHM_NAME_512,
            Codec::FnDsa1024Priv => ALGORITHM_NAME_1024,
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

        let mut key = SigningKeyStandard::decode(secret_bytes.as_slice()).ok_or(
            ConversionsError::SecretKeyFailure("invalid secret key length".into()),
        )?;

        let logn = key.get_logn();
        let mut sig = vec![0u8; signature_size(logn)];
        key.sign(
            &mut rand_core_06::OsRng,
            &DOMAIN_NONE,
            &HASH_ID_RAW,
            msg,
            &mut sig,
        );

        let msig_codec = if logn == FN_DSA_LOGN_512 {
            Codec::FnDsa512Msig
        } else {
            Codec::FnDsa1024Msig
        };
        let mut ms = ms::Builder::new(msig_codec).with_signature_bytes(&sig);
        if combined {
            ms = ms.with_message_bytes(&msg);
        }
        Ok(ms.try_build()?)
    }
}

impl<'a> VerifyView for View<'a> {
    fn verify(&self, multisig: &multi_sig::Multisig, msg: Option<&[u8]>) -> Result<(), Error> {
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

        let key = VerifyingKeyStandard::decode(key_bytes.as_slice()).ok_or(
            ConversionsError::PublicKeyFailure("invalid public key length".into()),
        )?;

        let sv = multisig.data_view()?;
        let sig_bytes = sv.sig_bytes()?;

        let expected_sig_len = if key_bytes.len() == vrfy_key_size(FN_DSA_LOGN_512) {
            signature_size(FN_DSA_LOGN_512)
        } else {
            signature_size(FN_DSA_LOGN_1024)
        };
        if sig_bytes.len() != expected_sig_len {
            return Err(VerifyError::BadSignature("invalid signature length".into()).into());
        }

        let msg_bytes = if let Some(m) = msg {
            m
        } else if !multisig.message.is_empty() {
            multisig.message.as_slice()
        } else {
            return Err(VerifyError::MissingMessage.into());
        };

        if key.verify(sig_bytes.as_slice(), &DOMAIN_NONE, &HASH_ID_RAW, msg_bytes) {
            Ok(())
        } else {
            Err(VerifyError::BadSignature("invalid signature".into()).into())
        }
    }
}
