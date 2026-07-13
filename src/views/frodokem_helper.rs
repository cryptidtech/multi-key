// SPDX-License-Identifier: Apache-2.0
//! FrodoKEM AES/SHAKE helper — inlined from the former bs-frodokem wrapper.
//!
//! Keys and ciphertexts are passed as raw byte slices; shared secrets are
//! returned as `Vec<u8>` wrapped in [`zeroize::Zeroizing`].
use frodo_kem_rs::Algorithm;
use getrandom::rand_core::UnwrapErr;
use getrandom::SysRng;
use zeroize::Zeroizing;

fn rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

fn keypair(alg: Algorithm) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let (ek, dk) = alg.generate_keypair(rng());
    (ek.as_ref().to_vec(), Zeroizing::new(dk.as_ref().to_vec()))
}

fn encap(alg: Algorithm, pub_key_bytes: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
    let ek = alg
        .encryption_key_from_bytes(pub_key_bytes)
        .map_err(|e| e.to_string())?;
    let (ct, ss) = alg
        .encapsulate_with_rng(&ek, rng())
        .map_err(|e| e.to_string())?;
    Ok((ct.as_ref().to_vec(), Zeroizing::new(ss.as_ref().to_vec())))
}

fn decap(
    alg: Algorithm,
    secret_key_bytes: &[u8],
    ciphertext_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    let dk = alg
        .decryption_key_from_bytes(secret_key_bytes)
        .map_err(|e| e.to_string())?;
    let ct = alg
        .ciphertext_from_bytes(ciphertext_bytes)
        .map_err(|e| e.to_string())?;
    let (ss, _msg) = alg.decapsulate(&dk, &ct).map_err(|e| e.to_string())?;
    Ok(Zeroizing::new(ss.as_ref().to_vec()))
}

pub fn public_from_private(alg: Algorithm, secret_key_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let dk = alg
        .decryption_key_from_bytes(secret_key_bytes)
        .map_err(|e| e.to_string())?;
    Ok(alg
        .encryption_key_from_decryption_key(&dk)
        .as_ref()
        .to_vec())
}

// ── FrodoKEM-640-AES ────────────────────────────────────────────────────────

pub fn keypair_640aes() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    keypair(Algorithm::FrodoKem640Aes)
}

pub fn encap_640aes(pub_key_bytes: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
    encap(Algorithm::FrodoKem640Aes, pub_key_bytes)
}

pub fn decap_640aes(
    secret_key_bytes: &[u8],
    ciphertext_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    decap(
        Algorithm::FrodoKem640Aes,
        secret_key_bytes,
        ciphertext_bytes,
    )
}

pub fn public_from_private_640aes(secret_key_bytes: &[u8]) -> Result<Vec<u8>, String> {
    public_from_private(Algorithm::FrodoKem640Aes, secret_key_bytes)
}

// ── FrodoKEM-976-AES ────────────────────────────────────────────────────────

pub fn keypair_976aes() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    keypair(Algorithm::FrodoKem976Aes)
}

pub fn encap_976aes(pub_key_bytes: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
    encap(Algorithm::FrodoKem976Aes, pub_key_bytes)
}

pub fn decap_976aes(
    secret_key_bytes: &[u8],
    ciphertext_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    decap(
        Algorithm::FrodoKem976Aes,
        secret_key_bytes,
        ciphertext_bytes,
    )
}

pub fn public_from_private_976aes(secret_key_bytes: &[u8]) -> Result<Vec<u8>, String> {
    public_from_private(Algorithm::FrodoKem976Aes, secret_key_bytes)
}

// ── FrodoKEM-1344-AES ───────────────────────────────────────────────────────

pub fn keypair_1344aes() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    keypair(Algorithm::FrodoKem1344Aes)
}

pub fn encap_1344aes(pub_key_bytes: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
    encap(Algorithm::FrodoKem1344Aes, pub_key_bytes)
}

pub fn decap_1344aes(
    secret_key_bytes: &[u8],
    ciphertext_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    decap(
        Algorithm::FrodoKem1344Aes,
        secret_key_bytes,
        ciphertext_bytes,
    )
}

pub fn public_from_private_1344aes(secret_key_bytes: &[u8]) -> Result<Vec<u8>, String> {
    public_from_private(Algorithm::FrodoKem1344Aes, secret_key_bytes)
}

// ── FrodoKEM-640-SHAKE ──────────────────────────────────────────────────────

pub fn keypair_640shake() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    keypair(Algorithm::FrodoKem640Shake)
}

pub fn encap_640shake(pub_key_bytes: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
    encap(Algorithm::FrodoKem640Shake, pub_key_bytes)
}

pub fn decap_640shake(
    secret_key_bytes: &[u8],
    ciphertext_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    decap(
        Algorithm::FrodoKem640Shake,
        secret_key_bytes,
        ciphertext_bytes,
    )
}

pub fn public_from_private_640shake(secret_key_bytes: &[u8]) -> Result<Vec<u8>, String> {
    public_from_private(Algorithm::FrodoKem640Shake, secret_key_bytes)
}

// ── FrodoKEM-976-SHAKE ──────────────────────────────────────────────────────

pub fn keypair_976shake() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    keypair(Algorithm::FrodoKem976Shake)
}

pub fn encap_976shake(pub_key_bytes: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
    encap(Algorithm::FrodoKem976Shake, pub_key_bytes)
}

pub fn decap_976shake(
    secret_key_bytes: &[u8],
    ciphertext_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    decap(
        Algorithm::FrodoKem976Shake,
        secret_key_bytes,
        ciphertext_bytes,
    )
}

pub fn public_from_private_976shake(secret_key_bytes: &[u8]) -> Result<Vec<u8>, String> {
    public_from_private(Algorithm::FrodoKem976Shake, secret_key_bytes)
}

// ── FrodoKEM-1344-SHAKE ─────────────────────────────────────────────────────

pub fn keypair_1344shake() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    keypair(Algorithm::FrodoKem1344Shake)
}

pub fn encap_1344shake(pub_key_bytes: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
    encap(Algorithm::FrodoKem1344Shake, pub_key_bytes)
}

pub fn decap_1344shake(
    secret_key_bytes: &[u8],
    ciphertext_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    decap(
        Algorithm::FrodoKem1344Shake,
        secret_key_bytes,
        ciphertext_bytes,
    )
}

pub fn public_from_private_1344shake(secret_key_bytes: &[u8]) -> Result<Vec<u8>, String> {
    public_from_private(Algorithm::FrodoKem1344Shake, secret_key_bytes)
}
