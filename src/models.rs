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
    /// RSA-4096 public key in PEM (PKCS#8 SubjectPublicKeyInfo format)
    pub public_key_pem: String,
    /// RSA-4096 private key in PEM (PKCS#8 format) — deleted/moved after complete
    pub private_key_pem: String,
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

/// Written to uploads/{uuid}/metadata.json after upload completion.
/// This is what the download endpoint reads.
#[derive(Debug, Serialize, Deserialize)]
pub struct DownloadMetadata {
    pub upload_id: String,
    /// RSA-4096-OAEP-SHA512 wrapped 32-byte symmetric key, base64url-encoded
    pub wrapped_key_b64: String,
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
