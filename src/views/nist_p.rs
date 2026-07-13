// SPDX-License-Identifier: Apache-2.0
//! NIST P-256, P-384, P-521 ECDSA multikey view.

use crate::{
    error::{
        AttributesError, CipherError, ConversionsError, KdfError, SealError, SignError, VerifyError,
    },
    views::aead,
    AttrId, AttrView, Builder, CipherAttrView, ConvView, DataView, Error, FingerprintView,
    KdfAttrView, Multikey, OpenView, SealView, SignView, VerifyView, Views,
};

use multi_codec::Codec;
use multi_hash::{mh, Multihash};
use multi_sig::{ms, Multisig, Views as SigViews};
use multi_trait::TryDecodeFrom;
use multi_util::Varbytes;
use multi_util::Varuint;
use elliptic_curve::sec1::ToSec1Point;
use elliptic_curve::Generate;
use zeroize::Zeroizing;

/// P-256: 32-byte secret
const P256_SECRET_LEN: usize = 32;
/// P-384: 48-byte secret
const P384_SECRET_LEN: usize = 48;
/// P-521: 66-byte secret
const P521_SECRET_LEN: usize = 66;

fn pub_codec(codec: Codec) -> Codec {
    match codec {
        Codec::P256Pub | Codec::P256Priv => Codec::P256Pub,
        Codec::P384Pub | Codec::P384Priv => Codec::P384Pub,
        Codec::P521Pub | Codec::P521Priv => Codec::P521Pub,
        _ => codec,
    }
}

fn msig_codec(codec: Codec) -> Codec {
    match codec {
        Codec::P256Pub | Codec::P256Priv => Codec::Es256Msig,
        Codec::P384Pub | Codec::P384Priv => Codec::Es384Msig,
        Codec::P521Pub | Codec::P521Priv => Codec::Es521Msig,
        _ => Codec::Es256Msig,
    }
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
        if let Some(v) = self.mk.attributes.get(&AttrId::KeyIsEncrypted) {
            if let Ok((b, _)) = Varuint::<bool>::try_decode_from(v.as_slice()) {
                return b.to_inner();
            }
        }
        false
    }

    fn is_secret_key(&self) -> bool {
        matches!(
            self.mk.codec,
            Codec::P256Priv | Codec::P384Priv | Codec::P521Priv
        )
    }

    fn is_public_key(&self) -> bool {
        matches!(
            self.mk.codec,
            Codec::P256Pub | Codec::P384Pub | Codec::P521Pub
        )
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

        let pub_bytes = match self.mk.codec {
            Codec::P256Priv => {
                let sk = p256::ecdsa::SigningKey::from_slice(&secret_bytes[..P256_SECRET_LEN])
                    .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;
                sk.verifying_key().to_sec1_bytes().to_vec()
            }
            Codec::P384Priv => {
                let sk = p384::ecdsa::SigningKey::from_slice(&secret_bytes[..P384_SECRET_LEN])
                    .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;
                sk.verifying_key().to_sec1_bytes().to_vec()
            }
            Codec::P521Priv => {
                let sk = p521::ecdsa::SigningKey::from_slice(&secret_bytes[..P521_SECRET_LEN])
                    .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;
                let vk = p521::ecdsa::VerifyingKey::from(&sk);
                vk.as_affine().to_sec1_point(true).as_bytes().to_vec()
            }
            _ => {
                return Err(
                    ConversionsError::SecretKeyFailure("not a NIST-P secret key".into()).into(),
                )
            }
        };

        Builder::new(pub_codec(self.mk.codec))
            .with_comment(&self.mk.comment)
            .with_key_bytes(&pub_bytes)
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

        // Build proper SSH ECDSA public key from compressed SEC1 point.
        // SSH ECDSA requires uncompressed points, so decompress via VerifyingKey.
        let key_data = match pub_codec(self.mk.codec) {
            Codec::P256Pub => {
                let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key_bytes)
                    .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
                let uncompressed = vk.as_affine().to_sec1_point(false);
                let ssh_point =
                    sec1::EncodedPoint::<typenum::U32>::from_bytes(uncompressed.as_bytes())
                        .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
                ssh_key::public::KeyData::Ecdsa(ssh_key::public::EcdsaPublicKey::NistP256(
                    ssh_point,
                ))
            }
            Codec::P384Pub => {
                let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&key_bytes)
                    .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
                let uncompressed = vk.as_affine().to_sec1_point(false);
                let ssh_point =
                    sec1::EncodedPoint::<typenum::U48>::from_bytes(uncompressed.as_bytes())
                        .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
                ssh_key::public::KeyData::Ecdsa(ssh_key::public::EcdsaPublicKey::NistP384(
                    ssh_point,
                ))
            }
            Codec::P521Pub => {
                let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(&key_bytes)
                    .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
                let uncompressed = vk.as_affine().to_sec1_point(false);
                let ssh_point =
                    sec1::EncodedPoint::<typenum::U66>::from_bytes(uncompressed.as_bytes())
                        .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
                ssh_key::public::KeyData::Ecdsa(ssh_key::public::EcdsaPublicKey::NistP521(
                    ssh_point,
                ))
            }
            _ => return Err(ConversionsError::UnsupportedCodec(self.mk.codec).into()),
        };

        Ok(ssh_key::PublicKey::new(key_data, pk.comment))
    }

    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };

        // Build proper SSH ECDSA keypair
        let keypair_data = match self.mk.codec {
            Codec::P256Priv => {
                let secret_key = p256::SecretKey::from_slice(&secret_bytes[..P256_SECRET_LEN])
                    .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;
                let vk = secret_key.public_key();
                let uncompressed = vk.as_affine().to_sec1_point(false);
                let ssh_point =
                    sec1::EncodedPoint::<typenum::U32>::from_bytes(uncompressed.as_bytes())
                        .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
                let priv_key: ssh_key::private::EcdsaPrivateKey<32> = secret_key.into();
                ssh_key::private::KeypairData::Ecdsa(ssh_key::private::EcdsaKeypair::NistP256 {
                    public: ssh_point,
                    private: priv_key,
                })
            }
            Codec::P384Priv => {
                let secret_key = p384::SecretKey::from_slice(&secret_bytes[..P384_SECRET_LEN])
                    .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;
                let vk = secret_key.public_key();
                let uncompressed = vk.as_affine().to_sec1_point(false);
                let ssh_point =
                    sec1::EncodedPoint::<typenum::U48>::from_bytes(uncompressed.as_bytes())
                        .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
                let priv_key: ssh_key::private::EcdsaPrivateKey<48> = secret_key.into();
                ssh_key::private::KeypairData::Ecdsa(ssh_key::private::EcdsaKeypair::NistP384 {
                    public: ssh_point,
                    private: priv_key,
                })
            }
            Codec::P521Priv => {
                let secret_key = p521::SecretKey::from_slice(&secret_bytes[..P521_SECRET_LEN])
                    .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;
                let vk = secret_key.public_key();
                let uncompressed = vk.as_affine().to_sec1_point(false);
                let ssh_point =
                    sec1::EncodedPoint::<typenum::U66>::from_bytes(uncompressed.as_bytes())
                        .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
                let priv_key: ssh_key::private::EcdsaPrivateKey<66> = secret_key.into();
                ssh_key::private::KeypairData::Ecdsa(ssh_key::private::EcdsaKeypair::NistP521 {
                    public: ssh_point,
                    private: priv_key,
                })
            }
            _ => return Err(ConversionsError::UnsupportedCodec(self.mk.codec).into()),
        };

        Ok(
            ssh_key::PrivateKey::new(keypair_data, self.mk.comment.clone())
                .map_err(|e| ConversionsError::Ssh(e.into()))?,
        )
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

        let sig_bytes = match self.mk.codec {
            Codec::P256Priv => {
                use p256::ecdsa::{signature::Signer, Signature, SigningKey};
                let sk = SigningKey::from_slice(&secret_bytes[..P256_SECRET_LEN])
                    .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;
                let signature: Signature = sk
                    .try_sign(msg)
                    .map_err(|e| SignError::SigningFailed(e.to_string()))?;
                signature.to_bytes().to_vec()
            }
            Codec::P384Priv => {
                use p384::ecdsa::{signature::Signer, Signature, SigningKey};
                let sk = SigningKey::from_slice(&secret_bytes[..P384_SECRET_LEN])
                    .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;
                let signature: Signature = sk
                    .try_sign(msg)
                    .map_err(|e| SignError::SigningFailed(e.to_string()))?;
                signature.to_bytes().to_vec()
            }
            Codec::P521Priv => {
                use p521::ecdsa::{signature::Signer, Signature, SigningKey};
                let sk = SigningKey::from_slice(&secret_bytes[..P521_SECRET_LEN])
                    .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;
                let signature: Signature = sk
                    .try_sign(msg)
                    .map_err(|e| SignError::SigningFailed(e.to_string()))?;
                signature.to_bytes().to_vec()
            }
            _ => return Err(SignError::NotSigningKey.into()),
        };

        let sig_codec = msig_codec(self.mk.codec);
        let mut ms = ms::Builder::new(sig_codec).with_signature_bytes(&sig_bytes);
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

        let sv = multisig.data_view()?;
        let sig = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;

        let msg = if let Some(msg) = msg {
            msg
        } else if !multisig.message.is_empty() {
            multisig.message.as_slice()
        } else {
            return Err(VerifyError::MissingMessage.into());
        };

        match pubmk.codec {
            Codec::P256Pub => {
                use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
                let vk = VerifyingKey::from_sec1_bytes(&key_bytes)
                    .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
                let signature = Signature::from_slice(&sig)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
                vk.verify(msg, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
            }
            Codec::P384Pub => {
                use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
                let vk = VerifyingKey::from_sec1_bytes(&key_bytes)
                    .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
                let signature = Signature::from_slice(&sig)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
                vk.verify(msg, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
            }
            Codec::P521Pub => {
                use p521::ecdsa::{signature::Verifier, Signature, VerifyingKey};
                let vk = VerifyingKey::from_sec1_bytes(&key_bytes)
                    .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
                let signature = Signature::from_slice(&sig)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
                vk.verify(msg, &signature)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
            }
            _ => return Err(ConversionsError::UnsupportedCodec(pubmk.codec).into()),
        }

        Ok(())
    }
}

// ----------------------------------------------------------------------------
// NIST-P ECIES (ECDH + HKDF + AEAD) — P-256 and P-384.
//
// Mirrors the X25519 ECIES scheme: an ephemeral keypair is generated per seal,
// ECDH against the recipient's public key yields a shared secret, HKDF-SHA512
// expands it into an AEAD key, and the ephemeral public key is carried
// externally as a Multikey (like X25519). P-521 is intentionally not wired here
// (sign/verify only).
// ----------------------------------------------------------------------------

/// HKDF info string binding the derived key to the NIST-P ECIES scheme.
const NISTP_SEAL_INFO: &[u8] = b"nistp-ecies-seal";

/// AEAD codecs allowed for NIST-P ECIES sealing.
fn is_nistp_aead_allowed(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::AesGcm128 | Codec::AesGcm256 | Codec::Chacha20Poly1305 | Codec::Xchacha20Poly1305
    )
}

/// Encode a sealed message: `[aead_codec Codec][nonce Varbytes][ct+tag Varbytes]`.
/// The ephemeral public key is carried externally (as a Multikey), like X25519.
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

/// HKDF-expand the ECDH shared secret and AEAD-seal the plaintext.
fn seal_from_shared(
    aead_codec: Codec,
    shared: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SealError> {
    let key_len = aead::key_size(aead_codec)?;
    let aead_key = aead::derive_aead_key(shared, NISTP_SEAL_INFO, key_len)?;
    let (nonce, ct_tag) = aead::aead_seal(aead_codec, &aead_key, plaintext, aad)?;
    Ok(encode_sealed(aead_codec, &nonce, &ct_tag))
}

/// HKDF-expand the ECDH shared secret and AEAD-open the ciphertext.
fn open_from_shared(
    aead_codec: Codec,
    shared: &[u8],
    nonce: &[u8],
    ct_tag: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let key_len = aead::key_size(aead_codec)?;
    let aead_key = aead::derive_aead_key(shared, NISTP_SEAL_INFO, key_len)?;
    aead::aead_open(aead_codec, &aead_key, nonce, ct_tag, aad)
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
        if !is_nistp_aead_allowed(aead_codec) {
            return Err(SealError::UnsupportedAeadCodec(aead_codec).into());
        }

        let pub_bytes = self.key_bytes()?;

        let (sealed, eph_pub_bytes) = match self.mk.codec {
            Codec::P256Pub => {
                let recipient = p256::PublicKey::from_sec1_bytes(&pub_bytes)
                    .map_err(|e| SealError::EncapsulationFailed(e.to_string()))?;
                let eph = p256::ecdh::EphemeralSecret::generate_from_rng(&mut rand::rng());
                let eph_pub = eph.public_key();
                let shared = eph.diffie_hellman(&recipient);
                let sealed = seal_from_shared(
                    aead_codec,
                    shared.raw_secret_bytes().as_slice(),
                    plaintext,
                    aad,
                )?;
                (
                    sealed,
                    eph_pub.as_affine().to_sec1_point(true).as_bytes().to_vec(),
                )
            }
            Codec::P384Pub => {
                let recipient = p384::PublicKey::from_sec1_bytes(&pub_bytes)
                    .map_err(|e| SealError::EncapsulationFailed(e.to_string()))?;
                let eph = p384::ecdh::EphemeralSecret::generate_from_rng(&mut rand::rng());
                let eph_pub = eph.public_key();
                let shared = eph.diffie_hellman(&recipient);
                let sealed = seal_from_shared(
                    aead_codec,
                    shared.raw_secret_bytes().as_slice(),
                    plaintext,
                    aad,
                )?;
                (
                    sealed,
                    eph_pub.as_affine().to_sec1_point(true).as_bytes().to_vec(),
                )
            }
            Codec::P521Pub => {
                let recipient = p521::PublicKey::from_sec1_bytes(&pub_bytes)
                    .map_err(|e| SealError::EncapsulationFailed(e.to_string()))?;
                let eph = p521::ecdh::EphemeralSecret::generate_from_rng(&mut rand::rng());
                let eph_pub = eph.public_key();
                let shared = eph.diffie_hellman(&recipient);
                let sealed = seal_from_shared(
                    aead_codec,
                    shared.raw_secret_bytes().as_slice(),
                    plaintext,
                    aad,
                )?;
                (
                    sealed,
                    eph_pub.as_affine().to_sec1_point(true).as_bytes().to_vec(),
                )
            }
            _ => return Err(SealError::NotEncapsulationKey.into()),
        };

        let ephemeral_mk = Builder::new(pub_codec(self.mk.codec))
            .with_key_bytes(&eph_pub_bytes)
            .try_build()?;

        Ok((sealed, Some(ephemeral_mk)))
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
            SealError::InvalidFormat("NIST-P open requires an ephemeral public key".into())
        })?;

        let (aead_codec, nonce, ct_tag) = decode_sealed(sealed_msg)?;
        if !is_nistp_aead_allowed(aead_codec) {
            return Err(SealError::UnsupportedAeadCodec(aead_codec).into());
        }

        let eph_bytes = ephemeral_mk.data_view()?.key_bytes()?;
        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };

        let pt = match self.mk.codec {
            Codec::P256Priv => {
                let secret = p256::SecretKey::from_slice(&secret_bytes[..P256_SECRET_LEN])
                    .map_err(|e| SealError::DecapsulationFailed(e.to_string()))?;
                let eph_pub = p256::PublicKey::from_sec1_bytes(&eph_bytes)
                    .map_err(|_| SealError::InvalidFormat("invalid ephemeral public key".into()))?;
                let shared =
                    p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), eph_pub.as_affine());
                open_from_shared(
                    aead_codec,
                    shared.raw_secret_bytes().as_slice(),
                    &nonce,
                    &ct_tag,
                    aad,
                )?
            }
            Codec::P384Priv => {
                let secret = p384::SecretKey::from_slice(&secret_bytes[..P384_SECRET_LEN])
                    .map_err(|e| SealError::DecapsulationFailed(e.to_string()))?;
                let eph_pub = p384::PublicKey::from_sec1_bytes(&eph_bytes)
                    .map_err(|_| SealError::InvalidFormat("invalid ephemeral public key".into()))?;
                let shared =
                    p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), eph_pub.as_affine());
                open_from_shared(
                    aead_codec,
                    shared.raw_secret_bytes().as_slice(),
                    &nonce,
                    &ct_tag,
                    aad,
                )?
            }
            Codec::P521Priv => {
                let secret = p521::SecretKey::from_slice(&secret_bytes[..P521_SECRET_LEN])
                    .map_err(|e| SealError::DecapsulationFailed(e.to_string()))?;
                let eph_pub = p521::PublicKey::from_sec1_bytes(&eph_bytes)
                    .map_err(|_| SealError::InvalidFormat("invalid ephemeral public key".into()))?;
                let shared =
                    p521::ecdh::diffie_hellman(secret.to_nonzero_scalar(), eph_pub.as_affine());
                open_from_shared(
                    aead_codec,
                    shared.raw_secret_bytes().as_slice(),
                    &nonce,
                    &ct_tag,
                    aad,
                )?
            }
            _ => return Err(SealError::NotDecapsulationKey.into()),
        };

        Ok(pt)
    }
}

#[cfg(test)]
mod ecies_tests {
    use super::*;
    use crate::views::Views;

    fn seal_open_roundtrip(priv_codec: Codec) {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(priv_codec, &mut rng)
            .unwrap()
            .with_comment("nistp ecies test")
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
    fn test_p256_seal_open_roundtrip() {
        seal_open_roundtrip(Codec::P256Priv);
    }

    #[test]
    fn test_p384_seal_open_roundtrip() {
        seal_open_roundtrip(Codec::P384Priv);
    }

    #[test]
    fn test_p521_seal_open_roundtrip() {
        seal_open_roundtrip(Codec::P521Priv);
    }

    #[test]
    fn test_p256_wrong_key_fails_to_open() {
        let mut rng = rand::rng();
        let sk1 = Builder::new_from_random_bytes(Codec::P256Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let sk2 = Builder::new_from_random_bytes(Codec::P256Priv, &mut rng)
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
