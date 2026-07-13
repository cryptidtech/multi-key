// SPDX-License-Identifier: Apache-2.0
//! BLS12-381-G1-ML-DSA-65 hybrid signing multikey view (Birds-of-Prey-1);
//! combines BLS12-381 G1 with ML-DSA-65 post-quantum signatures.
//! Sign: s1 = BLS_G1(m), s2 = MlDsa65(m || s1), sig = s1 || s2
//! Verify: verify BLS_G1(m, s1) && verify MlDsa65(m || s1, s2)
//! Public encoding is classical-first: bls_g1_pub (96) || mldsa65_pub.

use super::bls12381_hybrid as bls;
use crate::{
    error::{AttributesError, ConversionsError, SignError, VerifyError},
    views::Views,
    AttrId, AttrView, Builder, ConvView, DataView, Error, FingerprintView, Multikey, SignView,
    VerifyView,
};
use multi_codec::Codec;
use multi_hash::{mh, Multihash};
use multi_sig::{ms, Multisig, Views as SigViews};
use ml_dsa::{
    signature::{Keypair, Signer as MlDsaSigner, Verifier as MlDsaVerifier},
    EncodedSignature, EncodedVerifyingKey, MlDsa65, Seed as MlDsaSeed, Signature as MlDsaSig,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
use zeroize::Zeroizing;

const MLDSA65_SEED_LEN: usize = 32;
const PRIV_SEED_LEN: usize = bls::BLS_G1_SECRET_LEN + MLDSA65_SEED_LEN; // 64

const MLDSA65_PUB_LEN: usize = 1952;
const PUB_KEY_LEN: usize = bls::BLS_G1_PUB_LEN + MLDSA65_PUB_LEN; // 2048

const MLDSA65_SIG_LEN: usize = 3309;
const HYBRID_SIG_LEN: usize = bls::BLS_G1_SIG_LEN + MLDSA65_SIG_LEN; // 3357

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
        self.mk.codec == Codec::Bls12381G1Mldsa65Priv
    }
    fn is_public_key(&self) -> bool {
        self.mk.codec == Codec::Bls12381G1Mldsa65Pub
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

        // BLS-G1 public key
        let bls_pub = bls::public_from_secret(&secret_bytes[..bls::BLS_G1_SECRET_LEN])?;

        // ML-DSA-65 public key
        let mldsa_seed: [u8; 32] = secret_bytes[bls::BLS_G1_SECRET_LEN..PRIV_SEED_LEN]
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("invalid ml-dsa-65 seed".into()))?;
        let mldsa_seed = MlDsaSeed::from(mldsa_seed);
        let kp = MlDsaSigningKey::<MlDsa65>::from_seed(&mldsa_seed);

        // Concatenate (classical-first): bls_g1_pub (96) || mldsa65_pub (1952)
        let mut pub_bytes = Vec::with_capacity(PUB_KEY_LEN);
        pub_bytes.extend_from_slice(&bls_pub);
        pub_bytes.extend_from_slice(kp.verifying_key().encode().as_slice());

        Builder::new(Codec::Bls12381G1Mldsa65Pub)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&pub_bytes)
            .try_build()
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "BLS12-381-G1-ML-DSA-65 not supported in SSH key format".into(),
        )
        .into())
    }
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "BLS12-381-G1-ML-DSA-65 not supported in SSH key format".into(),
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

        // Step 1: BLS-G1 sign
        let s1 = bls::sign(&secret_bytes[..bls::BLS_G1_SECRET_LEN], msg)?;

        // Step 2: ML-DSA-65 sign(m || s1)
        let mldsa_seed: [u8; 32] = secret_bytes[bls::BLS_G1_SECRET_LEN..PRIV_SEED_LEN]
            .try_into()
            .map_err(|_| ConversionsError::SecretKeyFailure("invalid ml-dsa-65 seed".into()))?;
        let mldsa_seed = MlDsaSeed::from(mldsa_seed);
        let kp = MlDsaSigningKey::<MlDsa65>::from_seed(&mldsa_seed);

        let mut m2 = Vec::with_capacity(msg.len() + s1.len());
        m2.extend_from_slice(msg);
        m2.extend_from_slice(&s1);
        let s2 = MlDsaSigner::sign(&kp, &m2);

        // Step 3: sig = s1 || s2
        let mut sig_bytes = Vec::with_capacity(HYBRID_SIG_LEN);
        sig_bytes.extend_from_slice(&s1);
        sig_bytes.extend_from_slice(s2.encode().as_slice());

        let mut ms =
            ms::Builder::new(Codec::Bls12381G1Mldsa65Msig).with_signature_bytes(&sig_bytes);
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

        let sv = multisig.data_view()?;
        let sig_bytes = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;
        if sig_bytes.len() != HYBRID_SIG_LEN {
            return Err(VerifyError::BadSignature("invalid hybrid signature length".into()).into());
        }

        // Split public key
        let bls_pub_bytes = &key_bytes[..bls::BLS_G1_PUB_LEN];
        let mldsa_pub_bytes = &key_bytes[bls::BLS_G1_PUB_LEN..PUB_KEY_LEN];

        // Split signature
        let s1_bytes = &sig_bytes[..bls::BLS_G1_SIG_LEN];
        let s2_bytes = &sig_bytes[bls::BLS_G1_SIG_LEN..HYBRID_SIG_LEN];

        // Verify BLS-G1: verify(m, s1)
        bls::verify(bls_pub_bytes, s1_bytes, msg_bytes)?;

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

        let mut m2 = Vec::with_capacity(msg_bytes.len() + s1_bytes.len());
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
        let sk = Builder::new_from_random_bytes(Codec::Bls12381G1Mldsa65Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        let msg = b"hello BLS12-381-G1-ML-DSA-65 hybrid (Birds of Prey 1)!";
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
        let sk = Builder::new_from_random_bytes(Codec::Bls12381G1Mldsa65Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();
        assert_eq!(
            pk.data_view().unwrap().key_bytes().unwrap().len(),
            PUB_KEY_LEN
        );
    }
}
