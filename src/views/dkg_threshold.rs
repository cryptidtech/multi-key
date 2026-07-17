// SPDX-License-Identifier: Apache-2.0
//! DKG threshold attribute view.
//!
//! Implements [`ThresholdAttrView`] for the four DKG private-share codecs
//! introduced alongside the `bs-dkg` crate. The view reads its values out of
//! the four new [`AttrId::Dkg*`] attributes:
//!
//! - [`AttrId::DkgThreshold`]   → [`threshold`](ThresholdAttrView::threshold)
//! - [`AttrId::DkgLimit`]       → [`limit`](ThresholdAttrView::limit)
//! - [`AttrId::DkgIdentifier`]  → [`identifier`](ThresholdAttrView::identifier)
//! - [`AttrId::DkgGroupPublicKey`] → [`threshold_data`](ThresholdAttrView::threshold_data)

use crate::Error;
use crate::error::AttributesError;
use crate::{AttrId, AttrView, Multikey, ThresholdAttrView, ThresholdKeyView};
use multi_trait::TryDecodeFrom;
use multi_util::Varuint;

/// Read-only DKG threshold view over a [`Multikey`].
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
        // A DKG share may itself be encrypted (the `KeyIsEncrypted` attribute is
        // stamped on the multikey). Earlier revisions hardcoded `false`, which
        // meant callers using `threshold_attr_view()` alone saw an unencrypted
        // share even when it was sealed. Read the attribute directly so the
        // status is authoritative regardless of which view the caller holds.
        if let Some(v) = self.mk.attributes.get(&AttrId::KeyIsEncrypted) {
            if let Ok((b, _)) = Varuint::<bool>::try_decode_from(v.as_slice()) {
                return b.to_inner();
            }
        }
        false
    }

    fn is_public_key(&self) -> bool {
        false
    }

    fn is_secret_key(&self) -> bool {
        // A DKG private share is a secret-bearing key share; treat it as a
        // secret key for status purposes so callers gating on `is_secret_key()`
        // (e.g. before signing or exporting) do not silently treat a
        // secret share as public.
        true
    }

    fn is_secret_key_share(&self) -> bool {
        true
    }
}

impl<'a> ThresholdAttrView for View<'a> {
    fn threshold(&self) -> Result<usize, Error> {
        let bytes = self
            .mk
            .attributes
            .get(&AttrId::DkgThreshold)
            .ok_or(AttributesError::MissingThreshold)?;
        if bytes.len() < 2 {
            return Err(AttributesError::MissingThreshold.into());
        }
        let v = u16::from_le_bytes([bytes[0], bytes[1]]);
        Ok(v as usize)
    }

    fn limit(&self) -> Result<usize, Error> {
        let bytes = self
            .mk
            .attributes
            .get(&AttrId::DkgLimit)
            .ok_or(AttributesError::MissingLimit)?;
        if bytes.len() < 2 {
            return Err(AttributesError::MissingLimit.into());
        }
        let v = u16::from_le_bytes([bytes[0], bytes[1]]);
        Ok(v as usize)
    }

    fn identifier(&self) -> Result<&[u8], Error> {
        let bytes = self
            .mk
            .attributes
            .get(&AttrId::DkgIdentifier)
            .ok_or(AttributesError::MissingShareIdentifier)?;
        Ok(bytes.as_slice())
    }

    fn threshold_data(&self) -> Result<&[u8], Error> {
        let bytes = self
            .mk
            .attributes
            .get(&AttrId::DkgGroupPublicKey)
            .ok_or(AttributesError::MissingThresholdData)?;
        Ok(bytes.as_slice())
    }
}

impl<'a> ThresholdKeyView for View<'a> {
    /// Get the group public key bytes for the t-of-n key.
    fn group_pubkey(&self) -> Result<Vec<u8>, Error> {
        let bytes = self
            .mk
            .attributes
            .get(&AttrId::DkgGroupPublicKey)
            .ok_or(AttributesError::MissingThresholdData)?;
        Ok(bytes.to_vec())
    }

    /// Returns `true` if the underlying Multikey is part of a threshold key.
    fn is_threshold_key(&self) -> bool {
        true
    }

    /// Number of participants `n` in the t-of-n scheme.
    fn participant_count(&self) -> Result<u16, Error> {
        let bytes = self
            .mk
            .attributes
            .get(&AttrId::DkgLimit)
            .ok_or(AttributesError::MissingLimit)?;
        if bytes.len() < 2 {
            return Err(AttributesError::MissingLimit.into());
        }
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Threshold `t` in the t-of-n scheme.
    fn threshold(&self) -> Result<u16, Error> {
        let bytes = self
            .mk
            .attributes
            .get(&AttrId::DkgThreshold)
            .ok_or(AttributesError::MissingThreshold)?;
        if bytes.len() < 2 {
            return Err(AttributesError::MissingThreshold.into());
        }
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// VLAD bytes of the session owner.
    fn owner_vlad(&self) -> Result<Vec<u8>, Error> {
        let bytes = self
            .mk
            .attributes
            .get(&AttrId::DkgOwnerId)
            .ok_or(AttributesError::MissingShareIdentifier)?;
        Ok(bytes.to_vec())
    }
}
