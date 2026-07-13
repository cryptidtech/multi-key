// SPDX-License-Identifier: Apache-2.0
//! Ed25519-ML-DSA-65 hybrid signing multikey view; combines Ed25519 with ML-DSA-65 post-quantum signatures.
//! Sign: s1 = Ed25519(m), s2 = MlDsa65(m || s1), sig = s1 || s2
//! Verify: verify Ed25519(m, s1) && verify MlDsa65(m || s1, s2)
//! Public encoding is classical-first: ed25519_pub (32) || mldsa65_pub.

use crate::{
    error::{AttributesError, ConversionsError, SignError, VerifyError},
    views::Views,
    AttrId, AttrView, Builder, ConvView, DataView, Error, FingerprintView, Multikey, SignView,
    VerifyView,
};
use multi_codec::Codec;
use multi_hash::{mh, Multihash};
use multi_sig::{ms, Multisig, Views as SigViews};
use ed25519_dalek::{Signature as Ed25519Sig, SigningKey, VerifyingKey};
use ml_dsa::{
    signature::{Keypair, Signer as MlDsaSigner, Verifier as MlDsaVerifier},
    EncodedSignature, EncodedVerifyingKey, MlDsa65, Seed as MlDsaSeed, Signature as MlDsaSig,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
use zeroize::Zeroizing;

const ED25519_SEED_LEN: usize = 32;
const MLDSA65_SEED_LEN: usize = 32;
const PRIV_SEED_LEN: usize = ED25519_SEED_LEN + MLDSA65_SEED_LEN; // 64

const ED25519_PUB_LEN: usize = 32;
const MLDSA65_PUB_LEN: usize = 1952;
const PUB_KEY_LEN: usize = ED25519_PUB_LEN + MLDSA65_PUB_LEN; // 1984

const ED25519_SIG_LEN: usize = 64;
const MLDSA65_SIG_LEN: usize = 3309;
const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + MLDSA65_SIG_LEN; // 3373

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
        self.mk.codec == Codec::Ed25519Mldsa65Priv
    }
    fn is_public_key(&self) -> bool {
        self.mk.codec == Codec::Ed25519Mldsa65Pub
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

        // Ed25519 public key
        let ed_seed: [u8; 32] = secret_bytes[..ED25519_SEED_LEN]
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("invalid ed25519 seed".into()))?;
        let ed_signing_key = SigningKey::from_bytes(&ed_seed);
        let ed_pub = ed_signing_key.verifying_key();

        // ML-DSA-65 public key
        let mldsa_seed: [u8; 32] = secret_bytes[ED25519_SEED_LEN..PRIV_SEED_LEN]
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("invalid ml-dsa-65 seed".into()))?;
        let mldsa_seed = MlDsaSeed::from(mldsa_seed);
        let kp = MlDsaSigningKey::<MlDsa65>::from_seed(&mldsa_seed);

        // Concatenate (classical-first): ed25519_pub (32) || mldsa65_pub (1952)
        let mut pub_bytes = Vec::with_capacity(PUB_KEY_LEN);
        pub_bytes.extend_from_slice(ed_pub.as_bytes());
        pub_bytes.extend_from_slice(kp.verifying_key().encode().as_slice());

        Builder::new(Codec::Ed25519Mldsa65Pub)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&pub_bytes)
            .try_build()
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "Ed25519-ML-DSA-65 not supported in SSH key format".into(),
        )
        .into())
    }
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "Ed25519-ML-DSA-65 not supported in SSH key format".into(),
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

        if secret_bytes.len() != PRIV_SEED_LEN {
            return Err(
                ConversionsError::SecretKeyFailure("invalid hybrid seed length".into()).into(),
            );
        }

        // Step 1: Ed25519 sign
        let ed_seed: [u8; 32] = secret_bytes[..ED25519_SEED_LEN]
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("failed to get ed25519 seed".into()))?;
        let ed_signing_key = SigningKey::from_bytes(&ed_seed);
        let s1: Ed25519Sig = ed25519_dalek::Signer::sign(&ed_signing_key, msg);

        // Step 2: ML-DSA-65 sign(m || s1)
        let mldsa_seed: [u8; 32] = secret_bytes[ED25519_SEED_LEN..PRIV_SEED_LEN]
            .try_into()
            .map_err(|_| {
                ConversionsError::SecretKeyFailure("failed to get ml-dsa-65 seed".into())
            })?;
        let mldsa_seed = MlDsaSeed::from(mldsa_seed);
        let kp = MlDsaSigningKey::<MlDsa65>::from_seed(&mldsa_seed);

        let mut m2 = Vec::with_capacity(msg.len() + ED25519_SIG_LEN);
        m2.extend_from_slice(msg);
        m2.extend_from_slice(&s1.to_bytes());

        let s2 = MlDsaSigner::sign(&kp, &m2);

        // Step 3: sig = s1 || s2
        let mut sig_bytes = Vec::with_capacity(HYBRID_SIG_LEN);
        sig_bytes.extend_from_slice(&s1.to_bytes());
        sig_bytes.extend_from_slice(s2.encode().as_slice());

        let mut ms = ms::Builder::new(Codec::Ed25519Mldsa65Msig).with_signature_bytes(&sig_bytes);
        if combined {
            ms = ms.with_message_bytes(&msg);
        }
        Ok(ms.try_build()?)
    }
}

impl<'a> VerifyView for View<'a> {
    fn verify(&self, multisig: &Multisig, msg: Option<&[u8]>) -> Result<(), Error> {
        let msg_bytes = if let Some(m) = msg {
            m
        } else if !multisig.message.is_empty() {
            multisig.message.as_slice()
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

        if key_bytes.len() != PUB_KEY_LEN {
            return Err(ConversionsError::PublicKeyFailure(
                "invalid hybrid public key length".into(),
            )
            .into());
        }

        // Get signature bytes
        let sv = multisig.data_view()?;
        let sig_bytes = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;

        if sig_bytes.len() != HYBRID_SIG_LEN {
            return Err(VerifyError::BadSignature("invalid hybrid signature length".into()).into());
        }

        // Split public key
        let ed_pub_bytes: [u8; 32] = key_bytes[..ED25519_PUB_LEN]
            .try_into()
            .map_err(|_| ConversionsError::PublicKeyFailure("invalid ed25519 public key".into()))?;
        let mldsa_pub_bytes = &key_bytes[ED25519_PUB_LEN..PUB_KEY_LEN];

        // Split signature
        let s1_bytes = &sig_bytes[..ED25519_SIG_LEN];
        let s2_bytes = &sig_bytes[ED25519_SIG_LEN..HYBRID_SIG_LEN];

        // Verify Ed25519: verify(m, s1)
        let ed_verifying_key = VerifyingKey::from_bytes(&ed_pub_bytes)
            .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
        let s1 = Ed25519Sig::from_slice(s1_bytes)
            .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
        ed_verifying_key
            .verify_strict(msg_bytes, &s1)
            .map_err(|e| VerifyError::BadSignature(format!("Ed25519 verify failed: {}", e)))?;

        // Verify ML-DSA-65: verify(m || s1, s2)
        let encoded_vk =
            EncodedVerifyingKey::<MlDsa65>::try_from(mldsa_pub_bytes).map_err(|_| {
                ConversionsError::PublicKeyFailure("invalid ML-DSA-65 public key".into())
            })?;
        let mldsa_vk = MlDsaVerifyingKey::<MlDsa65>::decode(&encoded_vk);
        let encoded_sig = EncodedSignature::<MlDsa65>::try_from(s2_bytes)
            .map_err(|_| VerifyError::BadSignature("invalid ML-DSA-65 signature".into()))?;
        let s2 = MlDsaSig::decode(&encoded_sig).ok_or(VerifyError::BadSignature(
            "invalid ML-DSA-65 signature".into(),
        ))?;

        let mut m2 = Vec::with_capacity(msg_bytes.len() + ED25519_SIG_LEN);
        m2.extend_from_slice(msg_bytes);
        m2.extend_from_slice(s1_bytes);

        mldsa_vk
            .verify(&m2, &s2)
            .map_err(|e| VerifyError::BadSignature(format!("ML-DSA-65 verify failed: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::Views;

    #[test]
    fn test_sign_verify_roundtrip() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::Ed25519Mldsa65Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        let msg = b"hello Ed25519-ML-DSA-65 hybrid signing!";
        let sig = sk.sign_view().unwrap().sign(msg, false, None).unwrap();
        pk.verify_view().unwrap().verify(&sig, Some(msg)).unwrap();

        // wrong message must fail
        assert!(pk
            .verify_view()
            .unwrap()
            .verify(&sig, Some(b"wrong message"))
            .is_err());
    }

    #[test]
    fn test_public_key_length() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::Ed25519Mldsa65Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();
        let dv = pk.data_view().unwrap();
        assert_eq!(dv.key_bytes().unwrap().len(), PUB_KEY_LEN);
    }
}
