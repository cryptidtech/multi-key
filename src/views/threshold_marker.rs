// SPDX-License-Identifier: Apache-2.0
//! Split (Shamir) threshold marker attributes and classifier.
//!
//! This module is **additive**: it does not change any existing signing,
//! combine, or verify logic. It introduces a way to stamp a *controller*
//! [`Multikey`] with the metadata needed to drive a BLS threshold-signing
//! ceremony for a Shamir-split key:
//!
//! - [`AttrId::ThresholdGroupPublicKey`] — the group/combined BLS public key
//!   bytes (the split analogue of [`AttrId::DkgGroupPublicKey`]).
//! - [`AttrId::ThresholdParticipants`] — a CBOR map keyed by share-identifier
//!   bytes (the Shamir x-coordinate, exactly as stored in
//!   [`AttrId::ShareIdentifier`]/`SigShare`) to a [`ThresholdParticipant`].
//!
//! It also provides a [`ThresholdScheme`] classifier ([`threshold_kind`]) and a
//! parameter reader ([`threshold_params`]) that work across both the Shamir
//! split codecs (`Bls12381G1PrivShare`/`PubShare`, `Bls12381G2PrivShare`/
//! `PubShare`) and the DKG codecs (`*ThreshPrivShare`/`*ThreshPubShare`).

use crate::{AttrId, Error, Multikey, error::AttributesError};
use multi_codec::Codec;
use multi_util::Varuint;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A single participant in a split (Shamir) threshold key.
///
/// `public_share` is the participant's **BLS public key share** `v_i` bytes —
/// i.e. the compressed group-element bytes obtained by converting the
/// participant's private share Multikey to its public share (see
/// `ConvView::to_public_key` for `Bls12381G1PrivShare`/`Bls12381G2PrivShare`).
/// This is what a controller uses to verify a participant's partial signature
/// before accumulating it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdParticipant {
    /// The participant's VLAD bytes (verifiable long-lived address / identity).
    pub vlad: Vec<u8>,
    /// The participant's BLS public key share `v_i` bytes.
    pub public_share: Vec<u8>,
}

/// The kind of threshold key a [`Multikey`] participates in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThresholdScheme {
    /// Shamir-split key (trusted-dealer split of an existing BLS secret key).
    ShamirSplit,
    /// Distributed key generation (frost-dkg) key.
    Dkg,
}

/// Classify the threshold scheme of a [`Multikey`].
///
/// Returns:
/// - [`ThresholdScheme::ShamirSplit`] for the BLS split share codecs
///   (`Bls12381G1PrivShare`, `Bls12381G1PubShare`, `Bls12381G2PrivShare`,
///   `Bls12381G2PubShare`),
/// - [`ThresholdScheme::Dkg`] for the DKG threshold share codecs
///   (`*ThreshPrivShare` / `*ThreshPubShare`),
/// - `None` for anything else (ordinary keys, non-threshold BLS keys, etc.).
pub fn threshold_kind(mk: &Multikey) -> Option<ThresholdScheme> {
    match mk.codec {
        Codec::Bls12381G1PrivShare
        | Codec::Bls12381G1PubShare
        | Codec::Bls12381G2PrivShare
        | Codec::Bls12381G2PubShare => Some(ThresholdScheme::ShamirSplit),
        Codec::Ed25519ThreshPrivShare
        | Codec::Ed25519ThreshPubShare
        | Codec::P256ThreshPrivShare
        | Codec::P256ThreshPubShare
        | Codec::P384ThreshPrivShare
        | Codec::P384ThreshPubShare
        | Codec::Secp256K1ThreshPrivShare
        | Codec::Secp256K1ThreshPubShare
        | Codec::Bls12381ThreshPrivShare
        | Codec::Bls12381ThreshPubShare
        | Codec::Ed448ThreshPrivShare
        | Codec::Ed448ThreshPubShare => Some(ThresholdScheme::Dkg),
        _ => None,
    }
}

/// Read the `(threshold, limit)` params off a threshold [`Multikey`].
///
/// For Shamir split keys this reads [`AttrId::Threshold`]/[`AttrId::Limit`]
/// (varuint-encoded). For DKG keys it reads [`AttrId::DkgThreshold`]/
/// [`AttrId::DkgLimit`] (u16 little-endian). Returns `None` for non-threshold
/// keys or when the params are absent/malformed.
pub fn threshold_params(mk: &Multikey) -> Option<(u16, u16)> {
    match threshold_kind(mk)? {
        ThresholdScheme::ShamirSplit => {
            let t = mk.attributes.get(&AttrId::Threshold)?;
            let n = mk.attributes.get(&AttrId::Limit)?;
            let t = *Varuint::<usize>::try_from(t.as_slice()).ok()?;
            let n = *Varuint::<usize>::try_from(n.as_slice()).ok()?;
            Some((u16::try_from(t).ok()?, u16::try_from(n).ok()?))
        }
        ThresholdScheme::Dkg => {
            let t = mk.attributes.get(&AttrId::DkgThreshold)?;
            let n = mk.attributes.get(&AttrId::DkgLimit)?;
            if t.len() < 2 || n.len() < 2 {
                return None;
            }
            Some((
                u16::from_le_bytes([t[0], t[1]]),
                u16::from_le_bytes([n[0], n[1]]),
            ))
        }
    }
}

/// Read-only / mutating helper view over a [`Multikey`]'s split-threshold
/// marker attributes.
///
/// This is intentionally a thin helper rather than a trait impl so it can both
/// read and (additively) mutate marker attributes without touching the
/// existing view traits or their codec dispatch.
pub struct MarkerView<'a> {
    mk: &'a Multikey,
}

impl<'a> MarkerView<'a> {
    /// Create a marker view over a [`Multikey`].
    pub fn new(mk: &'a Multikey) -> Self {
        Self { mk }
    }

    /// Get the group/combined BLS public key bytes stamped on this key, if any.
    pub fn group_public_key(&self) -> Result<Vec<u8>, Error> {
        let v = self
            .mk
            .attributes
            .get(&AttrId::ThresholdGroupPublicKey)
            .ok_or(AttributesError::MissingGroupPublicKey)?;
        Ok(v.to_vec())
    }

    /// Get the participant map stamped on this key, if any.
    pub fn participants(&self) -> Result<BTreeMap<Vec<u8>, ThresholdParticipant>, Error> {
        let v = self
            .mk
            .attributes
            .get(&AttrId::ThresholdParticipants)
            .ok_or(AttributesError::MissingThresholdParticipants)?;
        let map: BTreeMap<Vec<u8>, ThresholdParticipant> = serde_cbor::from_slice(v.as_slice())
            .map_err(|e| AttributesError::ThresholdMarkerCbor(e.to_string()))?;
        // CBOR-01: bound the registry size. A t-of-n threshold key has at most
        // `Limit` participants; reject an oversized map (decode amplification /
        // attacker-influenced blob) well below serde_cbor's generic map cap.
        const MAX_THRESHOLD_PARTICIPANTS: usize = 1024;
        if map.len() > MAX_THRESHOLD_PARTICIPANTS {
            return Err(AttributesError::ThresholdMarkerCbor(
                "threshold participant registry exceeds maximum size".to_string(),
            )
            .into());
        }
        Ok(map)
    }

    /// Split-key answer for the group public key.
    pub fn group_pubkey(&self) -> Result<Vec<u8>, Error> {
        self.group_public_key()
    }

    /// Split-key answer for the threshold `t`, read from [`AttrId::Threshold`].
    pub fn threshold(&self) -> Result<u16, Error> {
        let v = self
            .mk
            .attributes
            .get(&AttrId::Threshold)
            .ok_or(AttributesError::MissingThreshold)?;
        let t = *Varuint::<usize>::try_from(v.as_slice())?;
        u16::try_from(t).map_err(|_| AttributesError::MissingThreshold.into())
    }

    /// Split-key answer for the participant count `n`, read from
    /// [`AttrId::Limit`].
    pub fn participant_count(&self) -> Result<u16, Error> {
        let v = self
            .mk
            .attributes
            .get(&AttrId::Limit)
            .ok_or(AttributesError::MissingLimit)?;
        let n = *Varuint::<usize>::try_from(v.as_slice())?;
        u16::try_from(n).map_err(|_| AttributesError::MissingLimit.into())
    }
}

/// Stamp (set) the group/combined BLS public key bytes on a [`Multikey`].
///
/// Additive: only inserts/overwrites [`AttrId::ThresholdGroupPublicKey`].
pub fn set_group_public_key(mk: &mut Multikey, group_pubkey: &[u8]) {
    mk.attributes.insert(
        AttrId::ThresholdGroupPublicKey,
        group_pubkey.to_vec().into(),
    );
}

/// Stamp (set) the participant map on a [`Multikey`].
///
/// Serializes a `BTreeMap<Vec<u8>, ThresholdParticipant>` to CBOR and inserts
/// it under [`AttrId::ThresholdParticipants`]. Additive only.
pub fn set_participants(
    mk: &mut Multikey,
    participants: &BTreeMap<Vec<u8>, ThresholdParticipant>,
) -> Result<(), Error> {
    let bytes = serde_cbor::to_vec(participants)
        .map_err(|e| AttributesError::ThresholdMarkerCbor(e.to_string()))?;
    mk.attributes
        .insert(AttrId::ThresholdParticipants, bytes.into());
    Ok(())
}

/// Read the group public key bytes from a [`Multikey`]'s marker attribute.
pub fn group_public_key(mk: &Multikey) -> Result<Vec<u8>, Error> {
    MarkerView::new(mk).group_public_key()
}

/// Read the participant map from a [`Multikey`]'s marker attribute.
pub fn participants(mk: &Multikey) -> Result<BTreeMap<Vec<u8>, ThresholdParticipant>, Error> {
    MarkerView::new(mk).participants()
}

/// Canonical, deterministic bytes of the marker *bundle* — the tuple
/// `(group_public_key, participants, threshold, limit)` — that is signed to
/// authenticate the marker (TSIG-1). The signature attribute itself is excluded
/// (the getters read only the bundle attrs), so signing and verifying recompute
/// the same bytes. `BTreeMap` serializes in deterministic key order.
pub fn canonical_marker_bytes(mk: &Multikey) -> Result<Vec<u8>, Error> {
    let mv = MarkerView::new(mk);
    let group = mv.group_public_key()?;
    let participants = mv.participants()?;
    let threshold = mv.threshold()?;
    let limit = mv.participant_count()?;
    let payload = (group, participants, threshold, limit);
    serde_cbor::to_vec(&payload)
        .map_err(|e| AttributesError::ThresholdMarkerCbor(e.to_string()).into())
}

/// Authenticate the marker bundle: sign `canonical_marker_bytes(mk)` with
/// `signer` and stamp the resulting `Multisig` under
/// [`AttrId::ThresholdMarkerSig`]. Call AFTER the group key + participants +
/// threshold/limit are set. `signer` is normally the controller's own signing
/// key; the verifier must hold an independently-trusted copy of its public key.
pub fn sign_marker(mk: &mut Multikey, signer: &Multikey, scheme: Option<u8>) -> Result<(), Error> {
    use crate::Views;
    let bytes = canonical_marker_bytes(mk)?;
    let sig = signer.sign_view()?.sign(&bytes, false, scheme)?;
    let sig_bytes: Vec<u8> = sig.into();
    mk.attributes
        .insert(AttrId::ThresholdMarkerSig, sig_bytes.into());
    Ok(())
}

/// Verify the marker bundle's authenticating signature against
/// `verifier_pubkey` (which must be an independently-trusted controller key —
/// passing the same secret key works because its `verify_view` derives the
/// public key). Returns an error if the signature is absent or does not verify
/// over the recomputed canonical bytes — defeating TSIG-1 marker tampering.
pub fn verify_marker(mk: &Multikey, verifier_pubkey: &Multikey) -> Result<(), Error> {
    use crate::Views;
    let sig_bytes = mk
        .attributes
        .get(&AttrId::ThresholdMarkerSig)
        .ok_or(AttributesError::MissingThresholdMarkerSig)?;
    let sig = multi_sig::Multisig::try_from(sig_bytes.as_slice())
        .map_err(|_| AttributesError::ThresholdMarkerSigInvalid)?;
    let bytes = canonical_marker_bytes(mk)?;
    verifier_pubkey
        .verify_view()?
        .verify(&sig, Some(&bytes))
        .map_err(|_| AttributesError::ThresholdMarkerSigInvalid.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Builder, Views};
    fn g1_priv() -> Multikey {
        Builder::new_from_random_bytes(Codec::Bls12381G1Priv, &mut rand::rng())
            .unwrap()
            .try_build()
            .unwrap()
    }

    #[test]
    fn classify_split_share_g1() {
        let mk = g1_priv();
        let shares = mk.threshold_view().unwrap().split(3, 5).unwrap();
        let share = &shares[0];
        assert_eq!(threshold_kind(share), Some(ThresholdScheme::ShamirSplit));
        assert_eq!(threshold_params(share), Some((3, 5)));
    }

    #[test]
    fn classify_split_pub_share_g1() {
        let mk = g1_priv();
        let shares = mk.threshold_view().unwrap().split(2, 4).unwrap();
        let pub_share = shares[0].conv_view().unwrap().to_public_key().unwrap();
        assert_eq!(pub_share.codec, Codec::Bls12381G1PubShare);
        assert_eq!(
            threshold_kind(&pub_share),
            Some(ThresholdScheme::ShamirSplit)
        );
        assert_eq!(threshold_params(&pub_share), Some((2, 4)));
    }

    #[test]
    fn classify_dkg_share() {
        // Build a synthetic DKG private-share Multikey carrying the Dkg attrs.
        let mut mk = Builder::new(Codec::Bls12381ThreshPrivShare)
            .try_build()
            .unwrap();
        mk.attributes
            .insert(AttrId::DkgThreshold, 2u16.to_le_bytes().to_vec().into());
        mk.attributes
            .insert(AttrId::DkgLimit, 3u16.to_le_bytes().to_vec().into());
        assert_eq!(threshold_kind(&mk), Some(ThresholdScheme::Dkg));
        assert_eq!(threshold_params(&mk), Some((2, 3)));
    }

    #[test]
    fn classify_non_threshold_none() {
        // Ed25519 ordinary key
        let ed = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rand::rng())
            .unwrap()
            .try_build()
            .unwrap();
        assert_eq!(threshold_kind(&ed), None);
        assert_eq!(threshold_params(&ed), None);

        // Plain (non-share) BLS G1 secret key
        let bls = g1_priv();
        assert_eq!(threshold_kind(&bls), None);
        assert_eq!(threshold_params(&bls), None);
    }

    #[test]
    fn marker_roundtrip() {
        let mut mk = g1_priv();
        set_group_public_key(&mut mk, &[1, 2, 3, 4]);
        assert_eq!(group_public_key(&mk).unwrap(), vec![1, 2, 3, 4]);

        let mut map = BTreeMap::new();
        map.insert(
            vec![0u8; 32],
            ThresholdParticipant {
                vlad: vec![9, 9, 9],
                public_share: vec![7; 48],
            },
        );
        set_participants(&mut mk, &map).unwrap();
        let got = participants(&mk).unwrap();
        assert_eq!(got, map);
    }
}
