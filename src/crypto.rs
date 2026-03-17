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
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

// ── Key generation ──────────────────────────────────────────────────────────

/// Generate a cryptographically random 32-byte XChaCha20-Poly1305 key.
pub fn generate_sym_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Generate a cryptographically random 16-byte nonce seed.
pub fn generate_nonce_seed() -> [u8; 16] {
    let mut seed = [0u8; 16];
    OsRng.fill_bytes(&mut seed);
    seed
}

/// Generate an X25519 keypair. Returns (private_key_bytes, public_key_bytes).
/// Instantaneous — no blocking needed.
pub fn generate_x25519_keypair() -> ([u8; 32], [u8; 32]) {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&private);
    (private.to_bytes(), *public.as_bytes())
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

// ── ECIES key wrapping (X25519 + HKDF-SHA256 + XChaCha20-Poly1305) ──────────
//
// Replaces RSA-OAEP. Same security goal: only the holder of the private key
// can recover the symmetric file-encryption key.
//
// Scheme (similar to NaCl box / ECIES):
//   1. Generate an ephemeral X25519 keypair (eph_priv, eph_pub).
//   2. ECDH: shared = eph_priv · static_pub  (32 bytes)
//   3. HKDF-SHA256(salt=eph_pub, ikm=shared, info="rexnet-v1-key-wrap") → 32-byte wrap_key
//   4. XChaCha20-Poly1305(wrap_key, nonce, sym_key) → ciphertext (48 bytes = 32 + 16-byte tag)
//   5. Store (eph_pub, nonce, ciphertext) in metadata.json.
//
// Decryption (given static_priv from URL):
//   1. ECDH: shared = static_priv · eph_pub  (same shared secret by ECDH commutativity)
//   2. Re-derive wrap_key via HKDF with the same parameters.
//   3. Decrypt → sym_key.
//
// Private key in URL: 32 bytes → 43 base62 chars. Done.

fn xchacha20_nonce() -> [u8; 24] {
    let mut n = [0u8; 24];
    OsRng.fill_bytes(&mut n);
    n
}

fn xchacha20_encrypt(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 24]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(&XNonce::from(*nonce), plaintext)
        .map_err(|e| anyhow::anyhow!("XChaCha20 encrypt: {e}"))
}

fn xchacha20_decrypt(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 24]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(&XNonce::from(*nonce), ciphertext)
        .map_err(|e| anyhow::anyhow!("XChaCha20 decrypt/auth: {e}"))
}

/// Wrap the 32-byte symmetric key using ECIES with the session's X25519 static public key.
/// Returns (ephemeral_public_bytes, nonce, ciphertext).
pub fn ecies_wrap(
    sym_key: &[u8; 32],
    static_public: &[u8; 32],
) -> Result<([u8; 32], [u8; 24], Vec<u8>)> {
    let static_pub = X25519PublicKey::from(*static_public);

    let eph_priv = StaticSecret::random_from_rng(OsRng);
    let eph_pub = X25519PublicKey::from(&eph_priv);
    let shared = eph_priv.diffie_hellman(&static_pub);

    let mut wrap_key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(eph_pub.as_bytes()), shared.as_bytes())
        .expand(b"rexnet-v1-key-wrap", &mut wrap_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    let nonce = xchacha20_nonce();
    let ciphertext = xchacha20_encrypt(sym_key, &wrap_key, &nonce)?;

    Ok((*eph_pub.as_bytes(), nonce, ciphertext))
}

/// Unwrap the symmetric key using the X25519 static private key from the URL.
pub fn ecies_unwrap(
    static_private: &[u8; 32],
    eph_public: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<[u8; 32]> {
    let static_priv = StaticSecret::from(*static_private);
    let eph_pub = X25519PublicKey::from(*eph_public);
    let shared = static_priv.diffie_hellman(&eph_pub);

    let mut wrap_key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(eph_pub.as_bytes()), shared.as_bytes())
        .expand(b"rexnet-v1-key-wrap", &mut wrap_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    xchacha20_decrypt(ciphertext, &wrap_key, nonce)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Unwrapped key has wrong length"))
}

// ── Base62 encoding for URL embedding ───────────────────────────────────────
//
// Base62 uses only [0-9A-Za-z] — no special characters, no percent-encoding
// needed in URLs, copy-paste friendly. It is ~0.8% longer than base64url
// (log2(62) ≈ 5.954 bits/char vs 6 bits/char for base64) but the tradeoff
// is worth it for clean, all-alphanumeric URLs.
//
// X25519 private key: 32 bytes → 43 base62 chars.
// Alphabet: 0-9 first (digits), then A-Z, then a-z.
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

/// Encode arbitrary bytes as a base62 string.
pub fn bytes_to_base62(data: &[u8]) -> String {
    base62_encode(data)
}

/// Decode a base62 string back to bytes.
pub fn bytes_from_base62(s: &str) -> Result<Vec<u8>> {
    base62_decode(s)
}
