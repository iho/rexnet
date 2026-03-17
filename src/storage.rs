//! Filesystem layout for upload sessions:
//!
//! uploads/
//!   {upload_id}/
//!     session.json          ← mutable session state during upload
//!     temp/
//!       {filename}/
//!         chunk_0.enc       ← encrypted chunks (each = plaintext + 16-byte tag)
//!         chunk_1.enc
//!         ...
//!     {filename}.enc        ← assembled encrypted file (written at complete)
//!     metadata.json         ← immutable download metadata (written at complete)

use crate::models::{DownloadMetadata, UploadSession};
use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;

pub struct Storage {
    pub root: PathBuf,
}

impl Storage {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn session_dir(&self, upload_id: &str) -> PathBuf {
        self.root.join(upload_id)
    }

    pub fn session_file(&self, upload_id: &str) -> PathBuf {
        self.session_dir(upload_id).join("session.json")
    }

    pub fn metadata_file(&self, upload_id: &str) -> PathBuf {
        self.session_dir(upload_id).join("metadata.json")
    }

    pub fn temp_dir(&self, upload_id: &str) -> PathBuf {
        self.session_dir(upload_id).join("temp")
    }

    pub fn chunk_file(&self, upload_id: &str, filename: &str, chunk_index: u32) -> PathBuf {
        self.temp_dir(upload_id)
            .join(filename)
            .join(format!("chunk_{chunk_index}.enc"))
    }

    pub fn encrypted_file(&self, upload_id: &str, filename: &str) -> PathBuf {
        self.session_dir(upload_id)
            .join(format!("{filename}.enc"))
    }

    /// Create the directory structure for a new upload session.
    pub async fn init_session(&self, upload_id: &str) -> Result<()> {
        fs::create_dir_all(self.session_dir(upload_id))
            .await
            .context("Failed to create session directory")?;
        fs::create_dir_all(self.temp_dir(upload_id))
            .await
            .context("Failed to create temp directory")?;
        Ok(())
    }

    /// Create the per-file temp directory for chunk storage.
    pub async fn init_file_temp(&self, upload_id: &str, filename: &str) -> Result<()> {
        fs::create_dir_all(self.temp_dir(upload_id).join(filename))
            .await
            .context("Failed to create file temp directory")
    }

    // ── Session JSON ──────────────────────────────────────────────────────────

    pub async fn save_session(&self, session: &UploadSession) -> Result<()> {
        let json = serde_json::to_string_pretty(session)?;
        let path = self.session_file(&session.upload_id);
        let mut file = fs::File::create(&path)
            .await
            .with_context(|| format!("Failed to create {path:?}"))?;
        file.write_all(json.as_bytes()).await?;
        file.flush().await?;
        Ok(())
    }

    pub async fn load_session(&self, upload_id: &str) -> Result<UploadSession> {
        let path = self.session_file(upload_id);
        let json = fs::read_to_string(&path)
            .await
            .with_context(|| format!("Session '{upload_id}' not found — create a new upload"))?;
        serde_json::from_str(&json)
            .with_context(|| format!("Session '{upload_id}' is in an incompatible format — create a new upload"))
    }

    // ── Metadata JSON ─────────────────────────────────────────────────────────

    pub async fn save_metadata(&self, meta: &DownloadMetadata) -> Result<()> {
        let json = serde_json::to_string_pretty(meta)?;
        let path = self.metadata_file(&meta.upload_id);
        let mut file = fs::File::create(&path).await?;
        file.write_all(json.as_bytes()).await?;
        file.flush().await?;
        Ok(())
    }

    pub async fn load_metadata(&self, upload_id: &str) -> Result<DownloadMetadata> {
        let path = self.metadata_file(upload_id);
        let json = fs::read_to_string(&path)
            .await
            .with_context(|| format!("Metadata for {upload_id} not found"))?;
        serde_json::from_str(&json).context("Failed to parse metadata.json")
    }

    // ── Chunk I/O ─────────────────────────────────────────────────────────────

    /// Write an encrypted chunk to disk.
    pub async fn write_chunk(
        &self,
        upload_id: &str,
        filename: &str,
        chunk_index: u32,
        data: &[u8],
    ) -> Result<()> {
        let path = self.chunk_file(upload_id, filename, chunk_index);
        let mut file = fs::File::create(&path)
            .await
            .with_context(|| format!("Failed to create chunk file {path:?}"))?;
        file.write_all(data).await?;
        file.flush().await?;
        Ok(())
    }

    /// Read an encrypted chunk from disk.
    pub async fn read_chunk(
        &self,
        upload_id: &str,
        filename: &str,
        chunk_index: u32,
    ) -> Result<Vec<u8>> {
        let path = self.chunk_file(upload_id, filename, chunk_index);
        fs::read(&path)
            .await
            .with_context(|| format!("Failed to read chunk {chunk_index} of {filename}"))
    }

    // ── File assembly ─────────────────────────────────────────────────────────

    /// Concatenate all encrypted chunk files into a single .enc file.
    /// Returns the list of chunk sizes (encrypted byte counts) in order.
    pub async fn assemble_file(
        &self,
        upload_id: &str,
        filename: &str,
        total_chunks: u32,
    ) -> Result<Vec<u64>> {
        let out_path = self.encrypted_file(upload_id, filename);
        let mut out_file = fs::File::create(&out_path)
            .await
            .with_context(|| format!("Failed to create assembled file {out_path:?}"))?;

        let mut sizes = Vec::with_capacity(total_chunks as usize);
        for i in 0..total_chunks {
            let chunk_data = self.read_chunk(upload_id, filename, i).await?;
            sizes.push(chunk_data.len() as u64);
            out_file.write_all(&chunk_data).await?;
        }
        out_file.flush().await?;
        Ok(sizes)
    }

    /// Delete session.json — called after upload completes so the plaintext
    /// symmetric key no longer lives on disk. Everything needed for download
    /// is in metadata.json (ECIES-wrapped; private key is only in the URL).
    pub async fn delete_session(&self, upload_id: &str) -> Result<()> {
        let path = self.session_file(upload_id);
        if path.exists() {
            fs::remove_file(&path).await.context("Failed to delete session.json")?;
        }
        Ok(())
    }

    /// Delete the temporary chunk directory for a file (after assembly).
    pub async fn cleanup_temp(&self, upload_id: &str) -> Result<()> {
        let temp = self.temp_dir(upload_id);
        if temp.exists() {
            fs::remove_dir_all(&temp).await.context("Failed to remove temp dir")?;
        }
        Ok(())
    }
}
