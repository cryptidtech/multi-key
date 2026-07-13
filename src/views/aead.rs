// SPDX-License-Identifier: Apache-2.0
//! Shared AEAD helper functions for ML-KEM and X25519 seal/open operations.

use crate::error::SealError;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Aes256Gcm,
};
use multi_codec::Codec;
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

/// Derive an AEAD key from a shared secret using HKDF-SHA512.
pub(crate) fn derive_aead_key(
    shared_secret: &[u8],
    info: &[u8],
    key_len: usize,
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let hk = Hkdf::<Sha512>::new(None, shared_secret);
    let mut okm = Zeroizing::new(vec![0u8; key_len]);
    hk.expand(info, &mut okm)
        .map_err(|e| SealError::KeyDerivationFailed(e.to_string()))?;
    Ok(okm)
}

/// Return the symmetric key size in bytes for the given AEAD codec.
pub(crate) fn key_size(codec: Codec) -> Result<usize, SealError> {
    match codec {
        Codec::Chacha20Poly1305 => Ok(32),
        Codec::Xchacha20Poly1305 => Ok(32),
        Codec::AesGcm256 => Ok(32),
        Codec::AesGcm128 => Ok(16),
        _ => Err(SealError::UnsupportedAeadCodec(codec)),
    }
}

/// Return the nonce size in bytes for the given AEAD codec.
pub(crate) fn nonce_size(codec: Codec) -> Result<usize, SealError> {
    match codec {
        Codec::Chacha20Poly1305 => Ok(12),
        Codec::Xchacha20Poly1305 => Ok(24),
        Codec::AesGcm256 => Ok(12),
        Codec::AesGcm128 => Ok(12),
        _ => Err(SealError::UnsupportedAeadCodec(codec)),
    }
}

/// Encrypt plaintext with the given AEAD codec and key.
/// Returns `(nonce, ciphertext_with_tag)`.
pub(crate) fn aead_seal(
    codec: Codec,
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), SealError> {
    use rand::Rng;
    let ns = nonce_size(codec)?;
    let mut nonce_bytes = vec![0u8; ns];
    rand::rng().fill_bytes(&mut nonce_bytes);

    let ct = match codec {
        Codec::Chacha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| SealError::AeadSealFailed(e.to_string()))?;
            cipher
                .encrypt(
                    chacha20poly1305::Nonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|e| SealError::AeadSealFailed(e.to_string()))?
        }
        Codec::Xchacha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| SealError::AeadSealFailed(e.to_string()))?;
            cipher
                .encrypt(
                    chacha20poly1305::XNonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|e| SealError::AeadSealFailed(e.to_string()))?
        }
        Codec::AesGcm256 => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| SealError::AeadSealFailed(e.to_string()))?;
            cipher
                .encrypt(
                    aes_gcm::Nonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|e| SealError::AeadSealFailed(e.to_string()))?
        }
        Codec::AesGcm128 => {
            let cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|e| SealError::AeadSealFailed(e.to_string()))?;
            cipher
                .encrypt(
                    aes_gcm::Nonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|e| SealError::AeadSealFailed(e.to_string()))?
        }
        _ => return Err(SealError::UnsupportedAeadCodec(codec)),
    };

    Ok((nonce_bytes, ct))
}

/// Decrypt ciphertext with the given AEAD codec, key, and nonce.
pub(crate) fn aead_open(
    codec: Codec,
    key: &[u8],
    nonce: &[u8],
    ct_tag: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let pt = match codec {
        Codec::Chacha20Poly1305 => {
            let cipher =
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| SealError::AeadOpenFailed)?;
            cipher
                .decrypt(
                    chacha20poly1305::Nonce::from_slice(nonce),
                    Payload { msg: ct_tag, aad },
                )
                .map_err(|_| SealError::AeadOpenFailed)?
        }
        Codec::Xchacha20Poly1305 => {
            let cipher =
                XChaCha20Poly1305::new_from_slice(key).map_err(|_| SealError::AeadOpenFailed)?;
            cipher
                .decrypt(
                    chacha20poly1305::XNonce::from_slice(nonce),
                    Payload { msg: ct_tag, aad },
                )
                .map_err(|_| SealError::AeadOpenFailed)?
        }
        Codec::AesGcm256 => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| SealError::AeadOpenFailed)?;
            cipher
                .decrypt(
                    aes_gcm::Nonce::from_slice(nonce),
                    Payload { msg: ct_tag, aad },
                )
                .map_err(|_| SealError::AeadOpenFailed)?
        }
        Codec::AesGcm128 => {
            let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| SealError::AeadOpenFailed)?;
            cipher
                .decrypt(
                    aes_gcm::Nonce::from_slice(nonce),
                    Payload { msg: ct_tag, aad },
                )
                .map_err(|_| SealError::AeadOpenFailed)?
        }
        _ => return Err(SealError::UnsupportedAeadCodec(codec)),
    };

    Ok(Zeroizing::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_roundtrip_chacha20() {
        let key = [0x42u8; 32];
        let plaintext = b"hello world";
        let (nonce, ct) = aead_seal(Codec::Chacha20Poly1305, &key, plaintext, b"").unwrap();
        let pt = aead_open(Codec::Chacha20Poly1305, &key, &nonce, &ct, b"").unwrap();
        assert_eq!(plaintext.as_slice(), pt.as_slice());
    }

    #[test]
    fn test_aead_roundtrip_xchacha20() {
        let key = [0x42u8; 32];
        let plaintext = b"hello world";
        let (nonce, ct) = aead_seal(Codec::Xchacha20Poly1305, &key, plaintext, b"").unwrap();
        let pt = aead_open(Codec::Xchacha20Poly1305, &key, &nonce, &ct, b"").unwrap();
        assert_eq!(plaintext.as_slice(), pt.as_slice());
    }

    #[test]
    fn test_aead_roundtrip_aes256() {
        let key = [0x42u8; 32];
        let plaintext = b"hello world";
        let (nonce, ct) = aead_seal(Codec::AesGcm256, &key, plaintext, b"").unwrap();
        let pt = aead_open(Codec::AesGcm256, &key, &nonce, &ct, b"").unwrap();
        assert_eq!(plaintext.as_slice(), pt.as_slice());
    }

    #[test]
    fn test_aead_roundtrip_aes128() {
        let key = [0x42u8; 16];
        let plaintext = b"hello world";
        let (nonce, ct) = aead_seal(Codec::AesGcm128, &key, plaintext, b"").unwrap();
        let pt = aead_open(Codec::AesGcm128, &key, &nonce, &ct, b"").unwrap();
        assert_eq!(plaintext.as_slice(), pt.as_slice());
    }

    #[test]
    fn test_aead_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"hello world";
        let (nonce, mut ct) = aead_seal(Codec::Chacha20Poly1305, &key, plaintext, b"").unwrap();
        ct[0] ^= 0xff; // tamper
        assert!(aead_open(Codec::Chacha20Poly1305, &key, &nonce, &ct, b"").is_err());
    }

    #[test]
    fn test_hkdf_derive() {
        let secret = [0xabu8; 32];
        let key = derive_aead_key(&secret, b"test", 32).unwrap();
        assert_eq!(key.len(), 32);
        // derive again with same inputs => same output
        let key2 = derive_aead_key(&secret, b"test", 32).unwrap();
        assert_eq!(key.as_slice(), key2.as_slice());
    }
}
