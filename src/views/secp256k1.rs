// SPDX-License-Identifier: Apache-2.0
use crate::{
    error::{
        AttributesError, CipherError, ConversionsError, KdfError, SealError, SignError, VerifyError,
    },
    views::aead,
    AttrId, AttrView, Builder, CipherAttrView, ConvView, DataView, Error, FingerprintView,
    KdfAttrView, Multikey, OpenView, SealView, SignView, VerifyView, Views,
};

use elliptic_curve::sec1::ToSec1Point;
use elliptic_curve::Generate;
use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use multi_codec::Codec;
use multi_hash::{mh, Multihash};
use multi_sig::{ms, Multisig, Views as SigViews};
use multi_trait::TryDecodeFrom;
use multi_util::{Varbytes, Varuint};
use ssh_encoding::{Decode, Encode};
use zeroize::Zeroizing;

/// the number of bytes in an secp256k1 secret key
pub const SECRET_KEY_LENGTH: usize = 32;
/// the number of bytes in an secp256k1 public key
pub const PUBLIC_KEY_LENGTH: usize = 33;
/// the RFC 4251 algorithm name for SSH compatibility
pub const ALGORITHM_NAME: &str = "secp256k1@multikey";

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
        self.mk.codec == Codec::Secp256K1Priv
    }

    fn is_public_key(&self) -> bool {
        self.mk.codec == Codec::Secp256K1Pub
    }

    fn is_secret_key_share(&self) -> bool {
        false
    }
}

impl<'a> DataView for View<'a> {
    /// For Secp256K1Pub and Secp256K1Priv Multikey values, the key data is stored
    /// using the AttrId::Data attribute id.
    fn key_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let key = self
            .mk
            .attributes
            .get(&AttrId::KeyData)
            .ok_or(AttributesError::MissingKey)?;
        Ok(key.clone())
    }

    /// Check to see if this is a secret key before returning the key bytes
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
        // try to look up the cipher codec in the multikey attributes
        let codec = self
            .mk
            .attributes
            .get(&AttrId::CipherCodec)
            .ok_or(CipherError::MissingCodec)?;
        Ok(Codec::try_from(codec.as_slice())?)
    }

    fn nonce_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        // try to look up the salt in the multikey attributes
        self.mk
            .attributes
            .get(&AttrId::CipherNonce)
            .ok_or(CipherError::MissingNonce.into())
            .cloned()
    }

    fn key_length(&self) -> Result<usize, Error> {
        // try to look up the cipher key length in the multikey attributes
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
        // try to look up the kdf codec in the multikey attributes
        let codec = self
            .mk
            .attributes
            .get(&AttrId::KdfCodec)
            .ok_or(KdfError::MissingCodec)?;
        Ok(Codec::try_from(codec.as_slice())?)
    }

    fn salt_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        // try to look up the salt in the multikey attributes
        self.mk
            .attributes
            .get(&AttrId::KdfSalt)
            .ok_or(KdfError::MissingSalt.into())
            .cloned()
    }

    fn rounds(&self) -> Result<usize, Error> {
        // try to look up the rounds in the multikey attributes
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
    /// try to convert a secret key to a public key
    fn to_public_key(&self) -> Result<Multikey, Error> {
        // get the secret key bytes
        let secret_bytes = {
            let kd = self.mk.data_view()?;

            kd.secret_bytes()?
        };

        // build an secp256k1 signing key so that we can derive the verifying key
        let bytes: [u8; SECRET_KEY_LENGTH] = secret_bytes.as_slice()[..SECRET_KEY_LENGTH]
            .try_into()
            .map_err(|_| {
                ConversionsError::SecretKeyFailure("failed to get secret key bytes".to_string())
            })?;
        let secret_key = SigningKey::from_bytes(&bytes.into())
            .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;
        // get the public key and build a Multikey out of it
        let public_key = secret_key.verifying_key();
        Builder::new(Codec::Secp256K1Pub)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&public_key.to_sec1_bytes())
            .try_build()
    }

    /// try to convert a Multikey to an ssh_key::PublicKey
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

    /// try to convert a Multikey to an ssh_key::PrivateKey
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
    /// try to create a Multisig by siging the passed-in data with the Multikey
    fn sign(&self, msg: &[u8], combined: bool, _scheme: Option<u8>) -> Result<Multisig, Error> {
        let attr = self.mk.attr_view()?;
        if !attr.is_secret_key() {
            return Err(SignError::NotSigningKey.into());
        }

        // get the secret key bytes
        let secret_bytes = {
            let kd = self.mk.data_view()?;

            kd.secret_bytes()?
        };

        let secret_key = {
            // build an secp256k1 signing key so that we can derive the verifying key
            let bytes: [u8; SECRET_KEY_LENGTH] = secret_bytes.as_slice()[..SECRET_KEY_LENGTH]
                .try_into()
                .map_err(|_| {
                    ConversionsError::SecretKeyFailure("failed to get secret key bytes".to_string())
                })?;

            SigningKey::from_bytes(&bytes.into())
                .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?
        };

        // sign the data
        let signature: Signature = secret_key
            .try_sign(msg)
            .map_err(|e| SignError::SigningFailed(e.to_string()))?;

        let mut ms =
            ms::Builder::new(Codec::Es256KMsig).with_signature_bytes(&signature.to_bytes());
        if combined {
            ms = ms.with_message_bytes(&msg);
        }
        Ok(ms.try_build()?)
    }
}

impl<'a> VerifyView for View<'a> {
    /// try to verify a Multisig using the Multikey
    fn verify(&self, multisig: &Multisig, msg: Option<&[u8]>) -> Result<(), Error> {
        let attr = self.mk.attr_view()?;
        let pubmk = if attr.is_secret_key() {
            let kc = self.mk.conv_view()?;

            kc.to_public_key()?
        } else {
            self.mk.clone()
        };

        // get the secret key bytes
        let key_bytes = {
            let kd = pubmk.data_view()?;

            kd.key_bytes()?
        };

        // build an secp256k1 verifying key so that we can derive the verifying key
        let bytes: [u8; PUBLIC_KEY_LENGTH] = key_bytes.as_slice()[..PUBLIC_KEY_LENGTH]
            .try_into()
            .map_err(|_| {
            ConversionsError::PublicKeyFailure("failed to get public key bytes".to_string())
        })?;

        // create the verifying key
        let verifying_key = VerifyingKey::from_sec1_bytes(&bytes)
            .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;

        // get the signature data
        let sv = multisig.data_view()?;
        let sig = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;

        // create the signature
        let sig = Signature::from_slice(sig.as_slice())
            .map_err(|e| VerifyError::BadSignature(e.to_string()))?;

        // get the message
        let msg = if let Some(msg) = msg {
            msg
        } else if !multisig.message.is_empty() {
            multisig.message.as_slice()
        } else {
            return Err(VerifyError::MissingMessage.into());
        };

        verifying_key.verify(msg, &sig).map_err(|e| {
            println!("{}", e);
            VerifyError::BadSignature(e.to_string())
        })?;

        Ok(())
    }
}

// ----------------------------------------------------------------------------
// secp256k1 ECIES (ECDH + HKDF + AEAD).
//
// Same scheme as the NIST-P and X25519 ECIES paths: an ephemeral keypair is
// generated per seal, ECDH against the recipient's public key yields a shared
// secret, HKDF-SHA512 expands it into an AEAD key, and the ephemeral public key
// is carried externally as a Multikey.
// ----------------------------------------------------------------------------

/// HKDF info string binding the derived key to the secp256k1 ECIES scheme.
const SECP256K1_SEAL_INFO: &[u8] = b"secp256k1-ecies-seal";

/// AEAD codecs allowed for secp256k1 ECIES sealing.
fn is_secp_aead_allowed(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::AesGcm128 | Codec::AesGcm256 | Codec::Chacha20Poly1305 | Codec::Xchacha20Poly1305
    )
}

/// Encode a sealed message: `[aead_codec Codec][nonce Varbytes][ct+tag Varbytes]`.
fn encode_sealed(aead_codec: Codec, nonce: &[u8], ct_tag: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.append(&mut aead_codec.into());
    out.append(&mut Varbytes::new(nonce.to_vec()).into());
    out.append(&mut Varbytes::new(ct_tag.to_vec()).into());
    out
}

/// Decode a sealed message produced by [`encode_sealed`].
fn decode_sealed(data: &[u8]) -> Result<(Codec, Vec<u8>, Vec<u8>), SealError> {
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
        if !is_secp_aead_allowed(aead_codec) {
            return Err(SealError::UnsupportedAeadCodec(aead_codec).into());
        }

        let pub_bytes = self.key_bytes()?;
        let recipient = k256::PublicKey::from_sec1_bytes(&pub_bytes)
            .map_err(|e| SealError::EncapsulationFailed(e.to_string()))?;

        let eph = k256::ecdh::EphemeralSecret::generate_from_rng(&mut rand::rng());
        let eph_pub = eph.public_key();
        let shared = eph.diffie_hellman(&recipient);

        let key_len = aead::key_size(aead_codec)?;
        let aead_key = aead::derive_aead_key(
            shared.raw_secret_bytes().as_slice(),
            SECP256K1_SEAL_INFO,
            key_len,
        )?;
        let (nonce, ct_tag) = aead::aead_seal(aead_codec, &aead_key, plaintext, aad)?;

        let eph_pub_bytes = eph_pub.to_sec1_point(true).as_bytes().to_vec();
        let ephemeral_mk = Builder::new(Codec::Secp256K1Pub)
            .with_key_bytes(&eph_pub_bytes)
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
            SealError::InvalidFormat("secp256k1 open requires an ephemeral public key".into())
        })?;

        let (aead_codec, nonce, ct_tag) = decode_sealed(sealed_msg)?;
        if !is_secp_aead_allowed(aead_codec) {
            return Err(SealError::UnsupportedAeadCodec(aead_codec).into());
        }

        let eph_bytes = ephemeral_mk.data_view()?.key_bytes()?;
        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };

        let secret = k256::SecretKey::from_slice(&secret_bytes[..SECRET_KEY_LENGTH])
            .map_err(|e| SealError::DecapsulationFailed(e.to_string()))?;
        let eph_pub = k256::PublicKey::from_sec1_bytes(&eph_bytes)
            .map_err(|_| SealError::InvalidFormat("invalid ephemeral public key".into()))?;
        let shared = k256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), eph_pub.as_affine());

        let key_len = aead::key_size(aead_codec)?;
        let aead_key = aead::derive_aead_key(
            shared.raw_secret_bytes().as_slice(),
            SECP256K1_SEAL_INFO,
            key_len,
        )?;

        Ok(aead::aead_open(
            aead_codec, &aead_key, &nonce, &ct_tag, aad,
        )?)
    }
}

#[cfg(test)]
mod ecies_tests {
    use super::*;
    use crate::views::Views;

    #[test]
    fn test_secp256k1_seal_open_roundtrip() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::Secp256K1Priv, &mut rng)
            .unwrap()
            .with_comment("secp256k1 ecies test")
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        let plaintext = b"the quick brown fox jumps over the lazy dog";
        for aead_codec in [
            Codec::Chacha20Poly1305,
            Codec::Xchacha20Poly1305,
            Codec::AesGcm128,
            Codec::AesGcm256,
        ] {
            let (sealed, ephemeral) = pk
                .seal_view()
                .unwrap()
                .seal(plaintext, aead_codec, b"")
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
    fn test_secp256k1_wrong_key_fails_to_open() {
        let mut rng = rand::rng();
        let sk1 = Builder::new_from_random_bytes(Codec::Secp256K1Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let sk2 = Builder::new_from_random_bytes(Codec::Secp256K1Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk1 = sk1.conv_view().unwrap().to_public_key().unwrap();

        let (sealed, ephemeral) = pk1
            .seal_view()
            .unwrap()
            .seal(b"secret", Codec::Chacha20Poly1305, b"")
            .unwrap();
        assert!(sk2
            .open_view()
            .unwrap()
            .open(&sealed, ephemeral.as_ref(), b"")
            .is_err());
    }
}
