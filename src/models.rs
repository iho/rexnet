use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Session state persisted to uploads/{uuid}/session.json during active upload.
/// Contains the RSA keypair and per-file chunk state.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UploadSession {
    pub upload_id: String,
    /// "ready" | "uploading" | "complete"
    pub status: String,
    /// 32-byte XChaCha20-Poly1305 key, base64url-encoded
    pub sym_key_b64: String,
    /// X25519 static public key, base62-encoded (32 bytes → ~43 chars)
    pub x25519_public_b62: String,
    /// X25519 static private key, base62-encoded — returned to user in download URL at complete
    pub x25519_private_b62: String,
    /// Per-file upload state, keyed by sanitized filename
    pub files: HashMap<String, SessionFileState>,
    /// Unix timestamp seconds
    pub created_at: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SessionFileState {
    pub filename: String,
    /// 16-byte per-file nonce seed, base64url-encoded.
    /// Chunk nonce = nonce_seed[0..16] || chunk_index.to_be_bytes() (total 24 bytes for XChaCha20)
    pub nonce_seed_b64: String,
    /// Total chunk count (set when first chunk is received)
    pub total_chunks: u32,
    /// Encrypted chunk sizes (index = chunk index, None = not yet received).
    /// Encrypted size = plaintext size + 16 (Poly1305 authentication tag).
    pub chunk_sizes: Vec<Option<u64>>,
}

/// ECIES envelope stored in metadata.json. Contains everything needed to recover
/// the symmetric key given the X25519 static private key from the URL.
#[derive(Debug, Serialize, Deserialize)]
pub struct EciesEnvelope {
    /// Ephemeral X25519 public key used during wrap (32 bytes → ~43 base62 chars)
    pub eph_pub_b62: String,
    /// XChaCha20-Poly1305 nonce for key wrapping (24 bytes → ~32 base62 chars)
    pub nonce_b62: String,
    /// Encrypted symmetric key + 16-byte Poly1305 tag (48 bytes → ~65 base62 chars)
    pub ciphertext_b62: String,
}

/// Written to uploads/{uuid}/metadata.json after upload completion.
/// This is what the download endpoint reads.
#[derive(Debug, Serialize, Deserialize)]
pub struct DownloadMetadata {
    pub upload_id: String,
    pub ecies: EciesEnvelope,
    pub files: Vec<DownloadFileMetadata>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DownloadFileMetadata {
    pub filename: String,
    pub nonce_seed_b64: String,
    pub total_chunks: u32,
    /// Encrypted sizes of each chunk in order (for boundary detection during decryption)
    pub chunk_sizes: Vec<u64>,
}

// ── Request / Response DTOs ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateUploadRequest {
    pub filenames: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateUploadResponse {
    pub upload_id: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct ChunkUploadResponse {
    pub upload_id: String,
    pub filename: String,
    pub chunk_index: u32,
    pub chunks_received: usize,
    pub total_chunks: u32,
    pub progress_percent: f32,
}
