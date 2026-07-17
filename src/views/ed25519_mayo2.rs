// SPDX-License-Identifier: Apache-2.0
//! Ed25519-MAYO2 hybrid signing multikey view; combines Ed25519 with MAYO-2 post-quantum signatures.
//! Sign: s1 = Ed25519(m), s2 = Mayo2(m || s1), sig = s1 || s2
//! Verify: verify Ed25519(m, s1) && verify Mayo2(m || s1, s2)

use crate::{
    AttrId, AttrView, Builder, ConvView, DataView, Error, FingerprintView, Multikey, SignView,
    VerifyView,
    error::{AttributesError, ConversionsError, SignError, VerifyError},
    views::Views,
};
use ed25519_dalek::{Signature as Ed25519Sig, SigningKey, VerifyingKey};
use multi_codec::Codec;
use multi_hash::{Multihash, mh};
use multi_sig::{Multisig, Views as SigViews, ms};
use pq_mayo::{KeyPair, Mayo2};
use zeroize::Zeroizing;

const ED25519_SEED_LEN: usize = 32;
const MAYO2_SEED_LEN: usize = 24;
const PRIV_SEED_LEN: usize = ED25519_SEED_LEN + MAYO2_SEED_LEN; // 56

const ED25519_PUB_LEN: usize = 32;
const MAYO2_PUB_LEN: usize = 4368;
const PUB_KEY_LEN: usize = ED25519_PUB_LEN + MAYO2_PUB_LEN; // 4400

const ED25519_SIG_LEN: usize = 64;
const MAYO2_SIG_LEN: usize = 216;
const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + MAYO2_SIG_LEN; // 280

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
        self.mk.codec == Codec::Ed25519Mayo2Priv
    }
    fn is_public_key(&self) -> bool {
        self.mk.codec == Codec::Ed25519Mayo2Pub
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

        // MAYO-2 public key
        let mayo_seed = &secret_bytes[ED25519_SEED_LEN..PRIV_SEED_LEN];
        let kp = KeyPair::<Mayo2>::from_seed(mayo_seed)
            .map_err(|e| ConversionsError::SecretKeyFailure(format!("MAYO-2 seed error: {}", e)))?;

        // Concatenate: ed25519_pub (32) || mayo2_pub (4368)
        let mut pub_bytes = Vec::with_capacity(PUB_KEY_LEN);
        pub_bytes.extend_from_slice(ed_pub.as_bytes());
        pub_bytes.extend_from_slice(kp.verifying_key().as_ref());

        Builder::new(Codec::Ed25519Mayo2Pub)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&pub_bytes)
            .try_build()
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "Ed25519-MAYO2 not supported in SSH key format".into(),
        )
        .into())
    }
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "Ed25519-MAYO2 not supported in SSH key format".into(),
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

        // Step 2: MAYO-2 sign(m || s1)
        let mayo_seed = &secret_bytes[ED25519_SEED_LEN..PRIV_SEED_LEN];
        let kp = KeyPair::<Mayo2>::from_seed(mayo_seed)
            .map_err(|e| ConversionsError::SecretKeyFailure(format!("MAYO-2 seed error: {}", e)))?;

        let mut m2 = Vec::with_capacity(msg.len() + ED25519_SIG_LEN);
        m2.extend_from_slice(msg);
        m2.extend_from_slice(&s1.to_bytes());

        let s2 = {
            use ml_dsa::signature::Signer;
            kp.signing_key()
                .try_sign(&m2)
                .map_err(|e| SignError::SigningFailed(e.to_string()))?
        };

        // Step 3: sig = s1 || s2
        let mut sig_bytes = Vec::with_capacity(HYBRID_SIG_LEN);
        sig_bytes.extend_from_slice(&s1.to_bytes());
        sig_bytes.extend_from_slice(s2.as_ref());

        let mut ms = ms::Builder::new(Codec::Ed25519Mayo2Msig).with_signature_bytes(&sig_bytes);
        if combined {
            ms = ms.with_message_bytes(&msg);
        }
        Ok(ms.try_build()?)
    }
}

impl<'a> VerifyView for View<'a> {
    fn verify(&self, multisig: &Multisig, msg: Option<&[u8]>) -> Result<(), Error> {
        use ml_dsa::signature::Verifier as MayoVerifier;

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
        let mayo_pub_bytes = &key_bytes[ED25519_PUB_LEN..PUB_KEY_LEN];

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

        // Verify MAYO-2: verify(m || s1, s2)
        let mayo_vk = pq_mayo::VerifyingKey::<Mayo2>::try_from(mayo_pub_bytes)
            .map_err(|_| ConversionsError::PublicKeyFailure("invalid MAYO-2 public key".into()))?;
        let s2 = pq_mayo::Signature::<Mayo2>::try_from(s2_bytes)
            .map_err(|_| VerifyError::BadSignature("invalid MAYO-2 signature".into()))?;

        let mut m2 = Vec::with_capacity(msg_bytes.len() + ED25519_SIG_LEN);
        m2.extend_from_slice(msg_bytes);
        m2.extend_from_slice(s1_bytes);

        mayo_vk
            .verify(&m2, &s2)
            .map_err(|e| VerifyError::BadSignature(format!("MAYO-2 verify failed: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mk::ED25519_MAYO2_KEY_CODECS;
    use crate::views::Views;

    #[test]
    fn test_key_gen_roundtrip() {
        for codec in ED25519_MAYO2_KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test hybrid signing key")
                .try_build()
                .unwrap();

            let attr = mk.attr_view().unwrap();
            assert!(attr.is_secret_key());
            assert!(!attr.is_public_key());

            // serialize/deserialize roundtrip
            let bytes: Vec<u8> = mk.clone().into();
            let mk2 = Multikey::try_from(bytes.as_slice()).unwrap();
            assert_eq!(mk, mk2);
        }
    }

    #[test]
    fn test_public_key_derivation() {
        let mut rng = rand::rng();
        let mk = Builder::new_from_random_bytes(Codec::Ed25519Mayo2Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();

        let conv = mk.conv_view().unwrap();
        let pk = conv.to_public_key().unwrap();

        let attr = pk.attr_view().unwrap();
        assert!(attr.is_public_key());
        assert!(!attr.is_secret_key());

        // derive again => same result
        let pk2 = conv.to_public_key().unwrap();
        assert_eq!(pk, pk2);

        // check public key length
        let dv = pk.data_view().unwrap();
        assert_eq!(dv.key_bytes().unwrap().len(), PUB_KEY_LEN);
    }

    #[test]
    fn test_fingerprint() {
        let mut rng = rand::rng();
        let mk = Builder::new_from_random_bytes(Codec::Ed25519Mayo2Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();

        // Fingerprint from private key (derives public key internally)
        let fp1 = mk
            .fingerprint_view()
            .unwrap()
            .fingerprint(Codec::Sha3256)
            .unwrap();

        // Fingerprint from public key
        let pk = mk.conv_view().unwrap().to_public_key().unwrap();
        let fp2 = pk
            .fingerprint_view()
            .unwrap()
            .fingerprint(Codec::Sha3256)
            .unwrap();

        let fp1_bytes: Vec<u8> = fp1.into();
        let fp2_bytes: Vec<u8> = fp2.into();
        assert_eq!(fp1_bytes, fp2_bytes);
        assert!(!fp1_bytes.is_empty());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::Ed25519Mayo2Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        let msg = b"hello Ed25519-MAYO2 hybrid signing!";
        let sig = sk.sign_view().unwrap().sign(msg, false, None).unwrap();

        // Verify with public key
        pk.verify_view().unwrap().verify(&sig, Some(msg)).unwrap();

        // Verify with private key (auto-derives public key)
        sk.verify_view().unwrap().verify(&sig, Some(msg)).unwrap();
    }

    #[test]
    fn test_sign_verify_combined() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::Ed25519Mayo2Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        let msg = b"combined message test";
        let sig = sk.sign_view().unwrap().sign(msg, true, None).unwrap();

        // Verify without explicit message (uses embedded message)
        pk.verify_view().unwrap().verify(&sig, None).unwrap();
    }

    #[test]
    fn test_tampered_signature_fails() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::Ed25519Mayo2Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        let msg = b"tamper test";
        let sig = sk.sign_view().unwrap().sign(msg, false, None).unwrap();

        // Tamper with message
        assert!(
            pk.verify_view()
                .unwrap()
                .verify(&sig, Some(b"wrong message"))
                .is_err()
        );
    }

    #[test]
    fn test_wrong_key_fails() {
        let mut rng = rand::rng();
        let sk1 = Builder::new_from_random_bytes(Codec::Ed25519Mayo2Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let sk2 = Builder::new_from_random_bytes(Codec::Ed25519Mayo2Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk2 = sk2.conv_view().unwrap().to_public_key().unwrap();

        let msg = b"wrong key test";
        let sig = sk1.sign_view().unwrap().sign(msg, false, None).unwrap();

        // Verify with wrong key should fail
        assert!(pk2.verify_view().unwrap().verify(&sig, Some(msg)).is_err());
    }
}
