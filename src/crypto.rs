//! # Hybrid Encryption: RSA-4096-OAEP-SHA512 + XChaCha20-Poly1305
//!
//! ## Why hybrid encryption?
//! RSA can only encrypt small payloads (limited by key size). For large files we use
//! a fast symmetric cipher (XChaCha20-Poly1305) to encrypt the data, and then use
//! RSA to "wrap" (encrypt) the symmetric key. Only the RSA private key holder can
//! recover the symmetric key and thus decrypt the data.
//!
//! ## Why XChaCha20-Poly1305?
//! - Extended 192-bit nonce: eliminates nonce-collision risk even with random nonces
//! - Constant-time: immune to timing side-channels (unlike AES without hardware support)
//! - 256-bit security: no known feasible attacks
//! - Authenticated encryption: Poly1305 MAC provides integrity + confidentiality together
//! - Software speed: ~3-4 GB/s on modern hardware without AES-NI; faster than AES-GCM on
//!   systems lacking AES hardware acceleration (e.g., some ARM servers)
//! - Widely deployed: used in TLS 1.3, WireGuard, Signal, SSH
//!
//! ## Why RSA-4096-OAEP-SHA512?
//! - 4096-bit key: ~140-bit equivalent security, resistant to foreseeable classical computers
//! - OAEP padding: probabilistic padding scheme, IND-CCA2 secure (semantically secure)
//! - SHA-512 hash: collision-resistant hash function for the OAEP MGF
//!
//! ## Nonce derivation for chunks
//! Each file gets a 16-byte random nonce_seed. For chunk n:
//!   nonce = nonce_seed[0..16] || n.to_be_bytes()[0..8]  (total 24 bytes)
//! This is deterministic: re-uploading the same chunk produces identical ciphertext,
//! enabling idempotent resumable uploads.

use anyhow::{Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::rngs::OsRng;
use rsa::{
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha512;

// ── Key generation ──────────────────────────────────────────────────────────

/// Generate a new RSA-4096 key pair.
/// NOTE: This operation takes 1-3 seconds. Call from an async context with
/// `tokio::task::spawn_blocking`.
pub fn generate_rsa_keypair() -> Result<(RsaPrivateKey, RsaPublicKey)> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 4096)
        .context("Failed to generate RSA-4096 keypair")?;
    let public_key = RsaPublicKey::from(&private_key);
    Ok((private_key, public_key))
}

/// Generate a cryptographically random 32-byte XChaCha20-Poly1305 key.
pub fn generate_sym_key() -> [u8; 32] {
    use rand::RngCore;
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Generate a cryptographically random 16-byte nonce seed.
pub fn generate_nonce_seed() -> [u8; 16] {
    use rand::RngCore;
    let mut seed = [0u8; 16];
    OsRng.fill_bytes(&mut seed);
    seed
}

// ── Nonce derivation ────────────────────────────────────────────────────────

/// Derive the 24-byte XChaCha20 nonce for a specific chunk.
/// nonce = nonce_seed[0..16] || chunk_index.to_be_bytes()
pub fn derive_chunk_nonce(nonce_seed: &[u8; 16], chunk_index: u32) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(nonce_seed);
    nonce[16..].copy_from_slice(&(chunk_index as u64).to_be_bytes());
    nonce
}

// ── Symmetric encryption / decryption ───────────────────────────────────────

/// Encrypt a chunk of plaintext with XChaCha20-Poly1305.
/// Returns ciphertext which is `plaintext.len() + 16` bytes (Poly1305 tag appended).
pub fn encrypt_chunk(
    plaintext: &[u8],
    sym_key: &[u8; 32],
    nonce_seed: &[u8; 16],
    chunk_index: u32,
) -> Result<Vec<u8>> {
    let key = Key::from_slice(sym_key);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce_bytes = derive_chunk_nonce(nonce_seed, chunk_index);
    let nonce = XNonce::from(nonce_bytes);
    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("XChaCha20-Poly1305 encrypt error: {e}"))
}

/// Decrypt a chunk of ciphertext with XChaCha20-Poly1305.
/// The Poly1305 tag is verified before any plaintext is returned (AEAD guarantee).
pub fn decrypt_chunk(
    ciphertext: &[u8],
    sym_key: &[u8; 32],
    nonce_seed: &[u8; 16],
    chunk_index: u32,
) -> Result<Vec<u8>> {
    let key = Key::from_slice(sym_key);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce_bytes = derive_chunk_nonce(nonce_seed, chunk_index);
    let nonce = XNonce::from(nonce_bytes);
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("XChaCha20-Poly1305 decrypt/auth error: {e}"))
}

// ── Key wrapping (RSA) ───────────────────────────────────────────────────────

/// Wrap (encrypt) a 32-byte symmetric key with an RSA-4096 public key using OAEP-SHA512.
pub fn wrap_sym_key(sym_key: &[u8; 32], public_key: &RsaPublicKey) -> Result<Vec<u8>> {
    let mut rng = OsRng;
    public_key
        .encrypt(&mut rng, Oaep::new::<Sha512>(), sym_key)
        .context("RSA-OAEP key wrap failed")
}

/// Unwrap (decrypt) the symmetric key using an RSA-4096 private key.
pub fn unwrap_sym_key(
    wrapped_key: &[u8],
    private_key: &RsaPrivateKey,
) -> Result<[u8; 32]> {
    let plaintext = private_key
        .decrypt(Oaep::new::<Sha512>(), wrapped_key)
        .context("RSA-OAEP key unwrap failed")?;
    plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("Decrypted key has wrong length (expected 32 bytes)"))
}

// ── PEM serialization ────────────────────────────────────────────────────────

pub fn private_key_to_pem(key: &RsaPrivateKey) -> Result<String> {
    key.to_pkcs8_pem(LineEnding::LF)
        .map(|z| z.to_string())
        .context("Failed to serialize RSA private key to PEM")
}

pub fn public_key_to_pem(key: &RsaPublicKey) -> Result<String> {
    key.to_public_key_pem(LineEnding::LF)
        .context("Failed to serialize RSA public key to PEM")
}

pub fn private_key_from_pem(pem: &str) -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs8_pem(pem).context("Failed to parse RSA private key from PEM")
}

pub fn public_key_from_pem(pem: &str) -> Result<RsaPublicKey> {
    use rsa::pkcs8::DecodePublicKey;
    RsaPublicKey::from_public_key_pem(pem).context("Failed to parse RSA public key from PEM")
}

// ── Base62 encoding for URL embedding ───────────────────────────────────────
//
// Base62 uses only [0-9A-Za-z] — no special characters, no percent-encoding
// needed in URLs, copy-paste friendly. It is ~0.8% longer than base64url
// (log2(62) ≈ 5.954 bits/char vs 6 bits/char for base64) but the tradeoff
// is worth it for clean, all-alphanumeric URLs.
//
// Alphabet: 0-9 first (digits), then A-Z, then a-z  (same order as ASCII).
// Leading 0x00 bytes are preserved as leading '0' characters.

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn base62_encode(data: &[u8]) -> String {
    use num_bigint::BigUint;
    use num_traits::Zero;

    if data.is_empty() {
        return String::new();
    }

    // Count leading zero bytes — each maps to a leading '0' character.
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

    let mut n = BigUint::from_bytes_be(data);
    let base = BigUint::from(62u32);
    let mut digits: Vec<u8> = Vec::new();

    while !n.is_zero() {
        let remainder = (&n % &base).to_u64_digits();
        let idx = remainder.first().copied().unwrap_or(0) as usize;
        digits.push(BASE62[idx]);
        n /= &base;
    }

    // Prepend one '0' per leading zero byte, then reverse the rest.
    let mut out = vec![b'0'; leading_zeros];
    digits.reverse();
    out.extend_from_slice(&digits);
    String::from_utf8(out).expect("base62 alphabet is valid UTF-8")
}

fn base62_decode(s: &str) -> Result<Vec<u8>> {
    use num_bigint::BigUint;
    use num_traits::Zero;

    let leading_zeros = s.bytes().take_while(|&b| b == b'0').count();

    let base = BigUint::from(62u32);
    let mut n = BigUint::zero();

    for c in s.bytes() {
        let idx = BASE62
            .iter()
            .position(|&b| b == c)
            .ok_or_else(|| anyhow::anyhow!("Invalid base62 character: '{}'", c as char))?;
        n = n * &base + BigUint::from(idx as u32);
    }

    let mut bytes = n.to_bytes_be();
    let mut out = vec![0u8; leading_zeros];
    out.append(&mut bytes);
    Ok(out)
}

/// Serialize the RSA private key to a base62 [0-9A-Za-z] string for embedding
/// in the download URL's `?key=` parameter. No special characters — URL-safe
/// without percent-encoding.
pub fn private_key_to_base62(key: &RsaPrivateKey) -> Result<String> {
    let der = key
        .to_pkcs8_der()
        .context("Failed to DER-encode RSA private key")?;
    Ok(base62_encode(der.as_bytes()))
}

/// Decode an RSA private key from a base62 string.
pub fn private_key_from_base62(s: &str) -> Result<RsaPrivateKey> {
    let der_bytes = base62_decode(s).context("Failed to base62-decode private key")?;
    RsaPrivateKey::from_pkcs8_der(&der_bytes).context("Failed to parse RSA private key from DER")
}
