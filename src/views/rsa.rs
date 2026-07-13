// SPDX-License-Identifier: Apache-2.0
//! RSA-2048/3072/4096 multikey view — signing (PSS SHA-256) + encryption (RSA-OAEP + AEAD).

use crate::{
    error::{
        AttributesError, CipherError, ConversionsError, KdfError, SealError, SignError, VerifyError,
    },
    views::{aead, Views},
    AttrId, AttrView, Builder, CipherAttrView, ConvView, DataView, Error, FingerprintView,
    KdfAttrView, Multikey, OpenView, SealView, SignView, VerifyView,
};

use ::rsa::sha2::Sha256;
use ::rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey},
    pss, Oaep, RsaPrivateKey, RsaPublicKey,
};
use multi_codec::Codec;
use multi_hash::{mh, Multihash};
use multi_sig::{ms, Multisig, Views as SigViews};
use multi_trait::TryDecodeFrom;
use multi_util::{Varbytes, Varuint};
use ssh_encoding::{Decode, Encode};
use zeroize::Zeroizing;

/// OsRng compatible with rsa 0.10 (rand_core 0.10) using getrandom 0.4
pub(crate) struct OsRng;

impl ::rsa::rand_core::TryRng for OsRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf).expect("getrandom failed");
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf).expect("getrandom failed");
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dest).expect("getrandom failed");
        Ok(())
    }
}

impl ::rsa::rand_core::TryCryptoRng for OsRng {}

fn pub_codec(codec: Codec) -> Codec {
    match codec {
        Codec::Rsa2048Pub | Codec::Rsa2048Priv => Codec::Rsa2048Pub,
        Codec::Rsa3072Pub | Codec::Rsa3072Priv => Codec::Rsa3072Pub,
        Codec::Rsa4096Pub | Codec::Rsa4096Priv => Codec::Rsa4096Pub,
        _ => codec,
    }
}

fn is_priv(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::Rsa2048Priv | Codec::Rsa3072Priv | Codec::Rsa4096Priv
    )
}

fn is_pub(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::Rsa2048Pub | Codec::Rsa3072Pub | Codec::Rsa4096Pub
    )
}

const ALGORITHM_NAME: &str = "rsa-sha256@multikey";

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
        if let Some(v) = self.mk.attributes.get(&AttrId::KeyIsEncrypted) {
            if let Ok((b, _)) = Varuint::<bool>::try_decode_from(v.as_slice()) {
                return b.to_inner();
            }
        }
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
        if self.is_encrypted() {
            return Err(AttributesError::EncryptedKey.into());
        }
        self.key_bytes()
    }
}

impl<'a> CipherAttrView for View<'a> {
    fn cipher_codec(&self) -> Result<Codec, Error> {
        let codec = self
            .mk
            .attributes
            .get(&AttrId::CipherCodec)
            .ok_or(CipherError::MissingCodec)?;
        Ok(Codec::try_from(codec.as_slice())?)
    }

    fn nonce_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.mk
            .attributes
            .get(&AttrId::CipherNonce)
            .ok_or(CipherError::MissingNonce.into())
            .cloned()
    }

    fn key_length(&self) -> Result<usize, Error> {
        let key_length = self
            .mk
            .attributes
            .get(&AttrId::CipherKeyLen)
            .ok_or(CipherError::MissingKeyLen)?;
        Ok(Varuint::<usize>::try_from(key_length.as_slice())?.to_inner())
    }
}

impl<'a> KdfAttrView for View<'a> {
    fn kdf_codec(&self) -> Result<Codec, Error> {
        let codec = self
            .mk
            .attributes
            .get(&AttrId::KdfCodec)
            .ok_or(KdfError::MissingCodec)?;
        Ok(Codec::try_from(codec.as_slice())?)
    }

    fn salt_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.mk
            .attributes
            .get(&AttrId::KdfSalt)
            .ok_or(KdfError::MissingSalt.into())
            .cloned()
    }

    fn rounds(&self) -> Result<usize, Error> {
        let rounds = self
            .mk
            .attributes
            .get(&AttrId::KdfRounds)
            .ok_or(KdfError::MissingRounds)?;
        Ok(Varuint::<usize>::try_from(rounds.as_slice())?.to_inner())
    }
}

impl<'a> FingerprintView for View<'a> {
    fn fingerprint(&self, codec: Codec) -> Result<Multihash, Error> {
        let attr = self.mk.attr_view()?;
        if attr.is_secret_key() {
            let pk = self.to_public_key()?;
            let fp = pk.fingerprint_view()?;
            fp.fingerprint(codec)
        } else {
            let bytes = {
                let kd = self.mk.data_view()?;
                kd.key_bytes()?
            };
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

        let private_key = RsaPrivateKey::from_pkcs1_der(&secret_bytes)
            .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;
        let public_key = private_key.to_public_key();
        let pub_der = public_key
            .to_pkcs1_der()
            .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;

        Builder::new(pub_codec(self.mk.codec))
            .with_comment(&self.mk.comment)
            .with_key_bytes(&pub_der)
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

        let mut buff: Vec<u8> = Vec::new();
        key_bytes
            .encode(&mut buff)
            .map_err(|e| ConversionsError::Ssh(e.into()))?;
        let opaque_key_bytes = ssh_key::public::OpaquePublicKeyBytes::decode(&mut buff.as_slice())
            .map_err(|e| ConversionsError::Ssh(e.into()))?;

        Ok(ssh_key::PublicKey::new(
            ssh_key::public::KeyData::Other(ssh_key::public::OpaquePublicKey {
                algorithm: ssh_key::Algorithm::Other(
                    ssh_key::AlgorithmName::new(ALGORITHM_NAME)
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
                        ssh_key::AlgorithmName::new(ALGORITHM_NAME)
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
    fn sign(&self, msg: &[u8], combined: bool, _scheme: Option<u8>) -> Result<Multisig, Error> {
        let attr = self.mk.attr_view()?;
        if !attr.is_secret_key() {
            return Err(SignError::NotSigningKey.into());
        }

        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };

        let private_key = RsaPrivateKey::from_pkcs1_der(&secret_bytes)
            .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;

        use ::rsa::signature::RandomizedSigner;
        let signing_key = pss::SigningKey::<Sha256>::new(private_key);
        let signature = signing_key
            .try_sign_with_rng(&mut OsRng, msg)
            .map_err(|e| SignError::SigningFailed(e.to_string()))?;

        use ::rsa::signature::SignatureEncoding;
        let sig_bytes = signature.to_bytes();

        let mut ms = ms::Builder::new(Codec::Rs256Msig).with_signature_bytes(&sig_bytes);
        if combined {
            ms = ms.with_message_bytes(&msg);
        }
        Ok(ms.try_build()?)
    }
}

impl<'a> VerifyView for View<'a> {
    fn verify(&self, multisig: &Multisig, msg: Option<&[u8]>) -> Result<(), Error> {
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

        let public_key = RsaPublicKey::from_pkcs1_der(&key_bytes)
            .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;

        let sv = multisig.data_view()?;
        let sig = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;

        let msg = if let Some(msg) = msg {
            msg
        } else if !multisig.message.is_empty() {
            multisig.message.as_slice()
        } else {
            return Err(VerifyError::MissingMessage.into());
        };

        use ::rsa::signature::Verifier;
        let verifying_key = pss::VerifyingKey::<Sha256>::new(public_key);
        let signature = pss::Signature::try_from(sig.as_slice())
            .map_err(|e| VerifyError::BadSignature(e.to_string()))?;

        verifying_key
            .verify(msg, &signature)
            .map_err(|e| VerifyError::BadSignature(e.to_string()))?;

        Ok(())
    }
}

// --- Seal / Open: RSA-OAEP + AEAD hybrid encryption ---

/// Allowed AEAD codecs for RSA hybrid encryption
fn is_rsa_aead_allowed(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::AesGcm128 | Codec::AesGcm256 | Codec::Chacha20Poly1305 | Codec::Xchacha20Poly1305
    )
}

/// Encode: [rsa_oaep_ciphertext Varbytes][aead_codec Codec][nonce Varbytes][ciphertext Varbytes]
fn encode_sealed(rsa_ct: &[u8], aead_codec: Codec, nonce: &[u8], ct_tag: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.append(&mut Varbytes::new(rsa_ct.to_vec()).into());
    out.append(&mut aead_codec.into());
    out.append(&mut Varbytes::new(nonce.to_vec()).into());
    out.append(&mut Varbytes::new(ct_tag.to_vec()).into());
    out
}

/// RSA-OAEP ciphertext, AEAD codec, nonce, ciphertext+tag
type SealedParts = (Vec<u8>, Codec, Vec<u8>, Vec<u8>);

/// Decode sealed message
fn decode_sealed(data: &[u8]) -> Result<SealedParts, SealError> {
    let (rsa_ct, ptr) = Varbytes::try_decode_from(data)
        .map_err(|_| SealError::InvalidFormat("missing RSA-OAEP ciphertext".into()))?;
    let (aead_codec, ptr) = Codec::try_decode_from(ptr)
        .map_err(|_| SealError::InvalidFormat("missing AEAD codec".into()))?;
    let (nonce, ptr) = Varbytes::try_decode_from(ptr)
        .map_err(|_| SealError::InvalidFormat("missing nonce".into()))?;
    let (ct_tag, _) = Varbytes::try_decode_from(ptr)
        .map_err(|_| SealError::InvalidFormat("missing ciphertext".into()))?;
    Ok((
        rsa_ct.to_inner(),
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
        if !is_rsa_aead_allowed(aead_codec) {
            return Err(SealError::UnsupportedAeadCodec(aead_codec).into());
        }

        let pub_bytes = self.key_bytes()?;
        let public_key = RsaPublicKey::from_pkcs1_der(&pub_bytes)
            .map_err(|e| SealError::EncapsulationFailed(e.to_string()))?;

        // Generate random AEAD key
        let key_len = aead::key_size(aead_codec)?;
        let mut aead_key = vec![0u8; key_len];
        use ::rsa::rand_core::Rng;
        OsRng.fill_bytes(&mut aead_key);

        // Encrypt AEAD key with RSA-OAEP
        let padding = Oaep::<Sha256>::new();
        let rsa_ct = public_key
            .encrypt(&mut OsRng, padding, &aead_key)
            .map_err(|e| SealError::EncapsulationFailed(e.to_string()))?;

        // Encrypt plaintext with AEAD
        let (nonce, ct_tag) = aead::aead_seal(aead_codec, &aead_key, plaintext, aad)?;

        Ok((encode_sealed(&rsa_ct, aead_codec, &nonce, &ct_tag), None))
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

        let (rsa_ct, aead_codec, nonce, ct_tag) = decode_sealed(sealed_msg)?;

        if !is_rsa_aead_allowed(aead_codec) {
            return Err(SealError::UnsupportedAeadCodec(aead_codec).into());
        }

        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };

        let private_key = RsaPrivateKey::from_pkcs1_der(&secret_bytes)
            .map_err(|e| SealError::DecapsulationFailed(e.to_string()))?;

        // Decrypt AEAD key with RSA-OAEP
        let padding = Oaep::<Sha256>::new();
        let aead_key = private_key
            .decrypt(padding, &rsa_ct)
            .map_err(|e| SealError::DecapsulationFailed(e.to_string()))?;

        // Decrypt ciphertext with AEAD
        Ok(aead::aead_open(
            aead_codec, &aead_key, &nonce, &ct_tag, aad,
        )?)
    }
}
