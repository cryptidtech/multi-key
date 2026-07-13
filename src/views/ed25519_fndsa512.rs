// SPDX-License-Identifier: Apache-2.0
//! Ed25519-FN-DSA-512 hybrid signing multikey view; combines Ed25519 with FN-DSA-512 (Falcon) post-quantum signatures.
//! Sign: s1 = Ed25519(m), s2 = FnDsa512(m || s1), sig = s1 || s2
//! Verify: verify Ed25519(m, s1) && verify FnDsa512(m || s1, s2)
//! Secret layout: ed25519_seed (32) || fn_dsa_signing_key (sign_key_size).
//! Public encoding is classical-first: ed25519_pub (32) || fn_dsa_verifying_key.

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
use fn_dsa::{
    sign_key_size, signature_size, vrfy_key_size, SigningKey as _, SigningKeyStandard,
    VerifyingKey as _, VerifyingKeyStandard, DOMAIN_NONE, FN_DSA_LOGN_512, HASH_ID_RAW,
};
use zeroize::Zeroizing;

const LOGN: u32 = FN_DSA_LOGN_512;

const ED25519_SEED_LEN: usize = 32;
const ED25519_PUB_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;

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
        self.mk.codec == Codec::Ed25519Fndsa512Priv
    }
    fn is_public_key(&self) -> bool {
        self.mk.codec == Codec::Ed25519Fndsa512Pub
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

        if secret_bytes.len() != ED25519_SEED_LEN + sign_key_size(LOGN) {
            return Err(
                ConversionsError::SecretKeyFailure("invalid hybrid secret length".into()).into(),
            );
        }

        // Ed25519 public key
        let ed_seed: [u8; 32] = secret_bytes[..ED25519_SEED_LEN]
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("invalid ed25519 seed".into()))?;
        let ed_signing_key = SigningKey::from_bytes(&ed_seed);
        let ed_pub = ed_signing_key.verifying_key();

        // FN-DSA verifying key
        let fndsa_sk = SigningKeyStandard::decode(&secret_bytes[ED25519_SEED_LEN..]).ok_or(
            ConversionsError::SecretKeyFailure("invalid fn-dsa signing key".into()),
        )?;
        let mut fndsa_vk = vec![0u8; vrfy_key_size(LOGN)];
        fndsa_sk.to_verifying_key(&mut fndsa_vk);

        // Concatenate (classical-first): ed25519_pub (32) || fndsa_vk
        let mut pub_bytes = Vec::with_capacity(ED25519_PUB_LEN + fndsa_vk.len());
        pub_bytes.extend_from_slice(ed_pub.as_bytes());
        pub_bytes.extend_from_slice(&fndsa_vk);

        Builder::new(Codec::Ed25519Fndsa512Pub)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&pub_bytes)
            .try_build()
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "Ed25519-FN-DSA-512 not supported in SSH key format".into(),
        )
        .into())
    }
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "Ed25519-FN-DSA-512 not supported in SSH key format".into(),
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

        if secret_bytes.len() != ED25519_SEED_LEN + sign_key_size(LOGN) {
            return Err(
                ConversionsError::SecretKeyFailure("invalid hybrid secret length".into()).into(),
            );
        }

        // Step 1: Ed25519 sign
        let ed_seed: [u8; 32] = secret_bytes[..ED25519_SEED_LEN]
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("failed to get ed25519 seed".into()))?;
        let ed_signing_key = SigningKey::from_bytes(&ed_seed);
        let s1: Ed25519Sig = ed25519_dalek::Signer::sign(&ed_signing_key, msg);

        // Step 2: FN-DSA-512 sign(m || s1)
        let mut fndsa_sk = SigningKeyStandard::decode(&secret_bytes[ED25519_SEED_LEN..]).ok_or(
            ConversionsError::SecretKeyFailure("invalid fn-dsa signing key".into()),
        )?;

        let mut m2 = Vec::with_capacity(msg.len() + ED25519_SIG_LEN);
        m2.extend_from_slice(msg);
        m2.extend_from_slice(&s1.to_bytes());

        let mut s2 = vec![0u8; signature_size(LOGN)];
        fndsa_sk.sign(
            &mut rand_core_06::OsRng,
            &DOMAIN_NONE,
            &HASH_ID_RAW,
            &m2,
            &mut s2,
        );

        // Step 3: sig = s1 || s2
        let mut sig_bytes = Vec::with_capacity(ED25519_SIG_LEN + s2.len());
        sig_bytes.extend_from_slice(&s1.to_bytes());
        sig_bytes.extend_from_slice(&s2);

        let mut ms = ms::Builder::new(Codec::Ed25519Fndsa512Msig).with_signature_bytes(&sig_bytes);
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

        if key_bytes.len() != ED25519_PUB_LEN + vrfy_key_size(LOGN) {
            return Err(ConversionsError::PublicKeyFailure(
                "invalid hybrid public key length".into(),
            )
            .into());
        }

        // Get signature bytes
        let sv = multisig.data_view()?;
        let sig_bytes = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;

        if sig_bytes.len() != ED25519_SIG_LEN + signature_size(LOGN) {
            return Err(VerifyError::BadSignature("invalid hybrid signature length".into()).into());
        }

        // Split public key
        let ed_pub_bytes: [u8; 32] = key_bytes[..ED25519_PUB_LEN]
            .try_into()
            .map_err(|_| ConversionsError::PublicKeyFailure("invalid ed25519 public key".into()))?;
        let fndsa_vk_bytes = &key_bytes[ED25519_PUB_LEN..];

        // Split signature
        let s1_bytes = &sig_bytes[..ED25519_SIG_LEN];
        let s2_bytes = &sig_bytes[ED25519_SIG_LEN..];

        // Verify Ed25519: verify(m, s1)
        let ed_verifying_key = VerifyingKey::from_bytes(&ed_pub_bytes)
            .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
        let s1 = Ed25519Sig::from_slice(s1_bytes)
            .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
        ed_verifying_key
            .verify_strict(msg_bytes, &s1)
            .map_err(|e| VerifyError::BadSignature(format!("Ed25519 verify failed: {}", e)))?;

        // Verify FN-DSA-512: verify(m || s1, s2)
        let fndsa_vk = VerifyingKeyStandard::decode(fndsa_vk_bytes).ok_or(
            ConversionsError::PublicKeyFailure("invalid fn-dsa verifying key".into()),
        )?;

        let mut m2 = Vec::with_capacity(msg_bytes.len() + ED25519_SIG_LEN);
        m2.extend_from_slice(msg_bytes);
        m2.extend_from_slice(s1_bytes);

        if fndsa_vk.verify(s2_bytes, &DOMAIN_NONE, &HASH_ID_RAW, &m2) {
            Ok(())
        } else {
            Err(VerifyError::BadSignature("FN-DSA-512 verify failed".into()).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::Views;

    #[test]
    fn test_sign_verify_roundtrip() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::Ed25519Fndsa512Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        let msg = b"hello Ed25519-FN-DSA-512 hybrid signing!";
        let sig = sk.sign_view().unwrap().sign(msg, false, None).unwrap();
        pk.verify_view().unwrap().verify(&sig, Some(msg)).unwrap();

        // wrong message must fail
        assert!(pk
            .verify_view()
            .unwrap()
            .verify(&sig, Some(b"wrong message"))
            .is_err());
    }
}
