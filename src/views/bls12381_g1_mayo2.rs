// SPDX-License-Identifier: Apache-2.0
//! BLS12-381-G1-MAYO-2 hybrid signing multikey view (Birds-of-Prey-1);
//! combines BLS12-381 G1 with MAYO-2 post-quantum multivariate signatures.
//! Sign: s1 = BLS_G1(m), s2 = Mayo2(m || s1), sig = s1 || s2
//! Verify: verify BLS_G1(m, s1) && verify Mayo2(m || s1, s2)
//! Secret layout: bls_g1_secret (32) || mayo2_seed (24) = 56 bytes.
//! Public encoding is classical-first: bls_g1_pub (96) || mayo2_pub.

use super::bls12381_hybrid as bls;
use crate::{
    AttrId, AttrView, Builder, ConvView, DataView, Error, FingerprintView, Multikey, SignView,
    VerifyView,
    error::{AttributesError, ConversionsError, SignError, VerifyError},
    views::Views,
};
use ml_dsa::signature::{Signer, Verifier};
use multi_codec::Codec;
use multi_hash::{Multihash, mh};
use multi_sig::{Multisig, Views as SigViews, ms};
use pq_mayo::{KeyPair, Mayo2, Signature, VerifyingKey};
use zeroize::Zeroizing;

const MAYO2_SEED_LEN: usize = 24;
const PRIV_SEED_LEN: usize = bls::BLS_G1_SECRET_LEN + MAYO2_SEED_LEN; // 56
const MAYO2_PUB_LEN: usize = 4368;
const PUB_KEY_LEN: usize = bls::BLS_G1_PUB_LEN + MAYO2_PUB_LEN; // 4464
const MAYO2_SIG_LEN: usize = 216;
const HYBRID_SIG_LEN: usize = bls::BLS_G1_SIG_LEN + MAYO2_SIG_LEN; // 264

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
        self.mk.codec == Codec::Bls12381G1Mayo2Priv
    }
    fn is_public_key(&self) -> bool {
        self.mk.codec == Codec::Bls12381G1Mayo2Pub
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

        let bls_pub = bls::public_from_secret(&secret_bytes[..bls::BLS_G1_SECRET_LEN])?;

        let kp = KeyPair::<Mayo2>::from_seed(&secret_bytes[bls::BLS_G1_SECRET_LEN..])
            .map_err(|e| ConversionsError::SecretKeyFailure(format!("MAYO-2 seed error: {}", e)))?;

        let mut pub_bytes = Vec::with_capacity(PUB_KEY_LEN);
        pub_bytes.extend_from_slice(&bls_pub);
        pub_bytes.extend_from_slice(kp.verifying_key().as_ref());

        Builder::new(Codec::Bls12381G1Mayo2Pub)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&pub_bytes)
            .try_build()
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "BLS12-381-G1-MAYO-2 not supported in SSH key format".into(),
        )
        .into())
    }
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "BLS12-381-G1-MAYO-2 not supported in SSH key format".into(),
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

        // Step 2: MAYO-2 sign(m || s1)
        let kp = KeyPair::<Mayo2>::from_seed(&secret_bytes[bls::BLS_G1_SECRET_LEN..])
            .map_err(|e| ConversionsError::SecretKeyFailure(format!("MAYO-2 seed error: {}", e)))?;

        let mut m2 = Vec::with_capacity(msg.len() + s1.len());
        m2.extend_from_slice(msg);
        m2.extend_from_slice(&s1);
        let s2 = kp
            .signing_key()
            .try_sign(&m2)
            .map_err(|e| SignError::SigningFailed(e.to_string()))?;

        // Step 3: sig = s1 || s2
        let mut sig_bytes = Vec::with_capacity(HYBRID_SIG_LEN);
        sig_bytes.extend_from_slice(&s1);
        sig_bytes.extend_from_slice(s2.as_ref());

        let mut ms = ms::Builder::new(Codec::Bls12381G1Mayo2Msig).with_signature_bytes(&sig_bytes);
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

        let bls_pub_bytes = &key_bytes[..bls::BLS_G1_PUB_LEN];
        let mayo_pub_bytes = &key_bytes[bls::BLS_G1_PUB_LEN..PUB_KEY_LEN];
        let s1_bytes = &sig_bytes[..bls::BLS_G1_SIG_LEN];
        let s2_bytes = &sig_bytes[bls::BLS_G1_SIG_LEN..HYBRID_SIG_LEN];

        // Verify BLS-G1
        bls::verify(bls_pub_bytes, s1_bytes, msg_bytes)?;

        // Verify MAYO-2: verify(m || s1, s2)
        let vk = VerifyingKey::<Mayo2>::try_from(mayo_pub_bytes)
            .map_err(|_| ConversionsError::PublicKeyFailure("invalid MAYO-2 public key".into()))?;
        let signature = Signature::<Mayo2>::try_from(s2_bytes)
            .map_err(|_| VerifyError::BadSignature("invalid MAYO-2 signature".into()))?;

        let mut m2 = Vec::with_capacity(msg_bytes.len() + s1_bytes.len());
        m2.extend_from_slice(msg_bytes);
        m2.extend_from_slice(s1_bytes);

        vk.verify(&m2, &signature)
            .map_err(|e| VerifyError::BadSignature(format!("MAYO-2 verify failed: {}", e)))?;

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
        let sk = Builder::new_from_random_bytes(Codec::Bls12381G1Mayo2Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        let msg = b"hello BLS12-381-G1-MAYO-2 hybrid (Birds of Prey 1)!";
        let sig = sk.sign_view().unwrap().sign(msg, false, None).unwrap();
        pk.verify_view().unwrap().verify(&sig, Some(msg)).unwrap();

        assert!(
            pk.verify_view()
                .unwrap()
                .verify(&sig, Some(b"wrong message"))
                .is_err()
        );
    }
}
