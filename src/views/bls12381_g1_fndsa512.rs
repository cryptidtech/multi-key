// SPDX-License-Identifier: Apache-2.0
//! BLS12-381-G1-FN-DSA-512 hybrid signing multikey view (Birds-of-Prey-1);
//! combines BLS12-381 G1 with FN-DSA-512 (Falcon) post-quantum signatures.
//! Sign: s1 = BLS_G1(m), s2 = FnDsa512(m || s1), sig = s1 || s2
//! Verify: verify BLS_G1(m, s1) && verify FnDsa512(m || s1, s2)
//! Secret layout: bls_g1_secret (32) || fn_dsa_signing_key.
//! Public encoding is classical-first: bls_g1_pub (96) || fn_dsa_verifying_key.

use super::bls12381_hybrid as bls;
use crate::{
    error::{AttributesError, ConversionsError, SignError, VerifyError},
    views::Views,
    AttrId, AttrView, Builder, ConvView, DataView, Error, FingerprintView, Multikey, SignView,
    VerifyView,
};
use fn_dsa::{
    sign_key_size, signature_size, vrfy_key_size, SigningKey as _, SigningKeyStandard,
    VerifyingKey as _, VerifyingKeyStandard, DOMAIN_NONE, FN_DSA_LOGN_512, HASH_ID_RAW,
};
use multi_codec::Codec;
use multi_hash::{mh, Multihash};
use multi_sig::{ms, Multisig, Views as SigViews};
use zeroize::Zeroizing;

const LOGN: u32 = FN_DSA_LOGN_512;

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
        self.mk.codec == Codec::Bls12381G1Fndsa512Priv
    }
    fn is_public_key(&self) -> bool {
        self.mk.codec == Codec::Bls12381G1Fndsa512Pub
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

        if secret_bytes.len() != bls::BLS_G1_SECRET_LEN + sign_key_size(LOGN) {
            return Err(
                ConversionsError::SecretKeyFailure("invalid hybrid secret length".into()).into(),
            );
        }

        // BLS-G1 public key
        let bls_pub = bls::public_from_secret(&secret_bytes[..bls::BLS_G1_SECRET_LEN])?;

        // FN-DSA verifying key
        let fndsa_sk = SigningKeyStandard::decode(&secret_bytes[bls::BLS_G1_SECRET_LEN..]).ok_or(
            ConversionsError::SecretKeyFailure("invalid fn-dsa signing key".into()),
        )?;
        let mut fndsa_vk = vec![0u8; vrfy_key_size(LOGN)];
        fndsa_sk.to_verifying_key(&mut fndsa_vk);

        // Concatenate (classical-first): bls_g1_pub (96) || fndsa_vk
        let mut pub_bytes = Vec::with_capacity(bls::BLS_G1_PUB_LEN + fndsa_vk.len());
        pub_bytes.extend_from_slice(&bls_pub);
        pub_bytes.extend_from_slice(&fndsa_vk);

        Builder::new(Codec::Bls12381G1Fndsa512Pub)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&pub_bytes)
            .try_build()
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "BLS12-381-G1-FN-DSA-512 not supported in SSH key format".into(),
        )
        .into())
    }
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "BLS12-381-G1-FN-DSA-512 not supported in SSH key format".into(),
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
        if secret_bytes.len() != bls::BLS_G1_SECRET_LEN + sign_key_size(LOGN) {
            return Err(
                ConversionsError::SecretKeyFailure("invalid hybrid secret length".into()).into(),
            );
        }

        // Step 1: BLS-G1 sign
        let s1 = bls::sign(&secret_bytes[..bls::BLS_G1_SECRET_LEN], msg)?;

        // Step 2: FN-DSA-512 sign(m || s1)
        let mut fndsa_sk = SigningKeyStandard::decode(&secret_bytes[bls::BLS_G1_SECRET_LEN..])
            .ok_or(ConversionsError::SecretKeyFailure(
                "invalid fn-dsa signing key".into(),
            ))?;

        let mut m2 = Vec::with_capacity(msg.len() + s1.len());
        m2.extend_from_slice(msg);
        m2.extend_from_slice(&s1);

        let mut s2 = vec![0u8; signature_size(LOGN)];
        fndsa_sk.sign(
            &mut rand_core_06::OsRng,
            &DOMAIN_NONE,
            &HASH_ID_RAW,
            &m2,
            &mut s2,
        );

        // Step 3: sig = s1 || s2
        let mut sig_bytes = Vec::with_capacity(s1.len() + s2.len());
        sig_bytes.extend_from_slice(&s1);
        sig_bytes.extend_from_slice(&s2);

        let mut ms =
            ms::Builder::new(Codec::Bls12381G1Fndsa512Msig).with_signature_bytes(&sig_bytes);
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
        if key_bytes.len() != bls::BLS_G1_PUB_LEN + vrfy_key_size(LOGN) {
            return Err(ConversionsError::PublicKeyFailure(
                "invalid hybrid public key length".into(),
            )
            .into());
        }

        let sv = multisig.data_view()?;
        let sig_bytes = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;
        if sig_bytes.len() != bls::BLS_G1_SIG_LEN + signature_size(LOGN) {
            return Err(VerifyError::BadSignature("invalid hybrid signature length".into()).into());
        }

        let bls_pub_bytes = &key_bytes[..bls::BLS_G1_PUB_LEN];
        let fndsa_vk_bytes = &key_bytes[bls::BLS_G1_PUB_LEN..];

        let s1_bytes = &sig_bytes[..bls::BLS_G1_SIG_LEN];
        let s2_bytes = &sig_bytes[bls::BLS_G1_SIG_LEN..];

        // Verify BLS-G1
        bls::verify(bls_pub_bytes, s1_bytes, msg_bytes)?;

        // Verify FN-DSA-512: verify(m || s1, s2)
        let fndsa_vk = VerifyingKeyStandard::decode(fndsa_vk_bytes).ok_or(
            ConversionsError::PublicKeyFailure("invalid fn-dsa verifying key".into()),
        )?;

        let mut m2 = Vec::with_capacity(msg_bytes.len() + s1_bytes.len());
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
        let sk = Builder::new_from_random_bytes(Codec::Bls12381G1Fndsa512Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        let msg = b"hello BLS12-381-G1-FN-DSA-512 hybrid (Birds of Prey 1)!";
        let sig = sk.sign_view().unwrap().sign(msg, false, None).unwrap();
        pk.verify_view().unwrap().verify(&sig, Some(msg)).unwrap();

        assert!(pk
            .verify_view()
            .unwrap()
            .verify(&sig, Some(b"wrong message"))
            .is_err());
    }
}
