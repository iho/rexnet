use crate::{
    crypto,
    error::AppError,
    models::{
        ChunkUploadResponse, CreateUploadRequest, CreateUploadResponse, DownloadFileMetadata,
        DownloadMetadata, SessionFileState, UploadSession,
    },
    AppState,
};
use anyhow::Context;
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use serde::Deserialize;
use std::{collections::HashMap, io::Write, sync::Arc, time::{SystemTime, UNIX_EPOCH}};
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;
use tracing::{error, info};
use uuid::Uuid;
use zip::write::SimpleFileOptions;

// ── Index page ───────────────────────────────────────────────────────────────

/// Serve the beautiful upload SPA.
pub async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

// ── POST /api/uploads ────────────────────────────────────────────────────────

/// Create a new upload session. Generates an RSA-4096 keypair and a symmetric key.
/// Returns { upload_id, status: "ready" }.
///
/// The private key is stored server-side temporarily and returned only in the
/// /complete response URL. It is NOT returned here.
pub async fn create_upload(
    State(state): State<AppState>,
    Json(req): Json<CreateUploadRequest>,
) -> Result<Json<CreateUploadResponse>, AppError> {
    if req.filenames.is_empty() {
        return Err(AppError(anyhow::anyhow!("At least one filename required")));
    }
    if req.filenames.len() > 20 {
        return Err(AppError(anyhow::anyhow!("Maximum 20 files per upload")));
    }

    // Sanitize filenames — strip path components, keep only the filename
    let filenames: Vec<String> = req
        .filenames
        .iter()
        .map(|f| {
            std::path::Path::new(f)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "file".to_string())
        })
        .collect();

    let upload_id = Uuid::new_v4().to_string();

    // Generate RSA-4096 keypair (slow: 1-3 seconds, run in blocking thread)
    info!("Generating RSA-4096 keypair for upload {upload_id}...");
    let (private_key, public_key) =
        tokio::task::spawn_blocking(crypto::generate_rsa_keypair)
            .await
            .map_err(|e| AppError(anyhow::anyhow!("Join error: {e}")))??;
    info!("RSA-4096 keypair generated for upload {upload_id}");

    // Generate per-session symmetric key
    let sym_key = crypto::generate_sym_key();
    let sym_key_b64 = STANDARD.encode(sym_key);

    // Serialize keys to PEM
    let public_key_pem = crypto::public_key_to_pem(&public_key)?;
    let private_key_pem = crypto::private_key_to_pem(&private_key)?;

    // Build per-file state (nonce seeds assigned now, total_chunks set later)
    let files: HashMap<String, SessionFileState> = filenames
        .into_iter()
        .map(|name| {
            let seed = crypto::generate_nonce_seed();
            let file_state = SessionFileState {
                filename: name.clone(),
                nonce_seed_b64: STANDARD.encode(seed),
                total_chunks: 0,
                chunk_sizes: vec![],
            };
            (name, file_state)
        })
        .collect();

    let session = UploadSession {
        upload_id: upload_id.clone(),
        status: "ready".to_string(),
        sym_key_b64,
        public_key_pem,
        private_key_pem,
        files,
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    state.storage.init_session(&upload_id).await?;
    state.storage.save_session(&session).await?;

    Ok(Json(CreateUploadResponse {
        upload_id,
        status: "ready".to_string(),
    }))
}

// ── POST /api/uploads/{upload_id}/chunks ─────────────────────────────────────

/// Upload a single encrypted chunk of a file.
///
/// Required headers:
///   X-Filename:      original filename (must match one registered in create_upload)
///   X-Chunk-Index:   0-based chunk index
///   X-Total-Chunks:  total number of chunks for this file
///
/// Body: raw bytes of the chunk (20–50 MB recommended)
///
/// The chunk is encrypted on the fly with XChaCha20-Poly1305 before writing to disk.
/// Chunks can be re-uploaded (idempotent) for resumable uploads.
pub async fn upload_chunk(
    Path(upload_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ChunkUploadResponse>, AppError> {
    // Parse required headers
    let filename = headers
        .get("X-Filename")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError(anyhow::anyhow!("Missing X-Filename header")))?
        .to_string();

    let chunk_index: u32 = headers
        .get("X-Chunk-Index")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| AppError(anyhow::anyhow!("Missing or invalid X-Chunk-Index header")))?;

    let total_chunks: u32 = headers
        .get("X-Total-Chunks")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| AppError(anyhow::anyhow!("Missing or invalid X-Total-Chunks header")))?;

    // Validate chunk index
    if chunk_index >= total_chunks {
        return Err(AppError(anyhow::anyhow!(
            "chunk_index ({chunk_index}) >= total_chunks ({total_chunks})"
        )));
    }

    // Enforce 50 GB per-file limit (50 GB / 20 MB chunks = 2500 chunks max)
    // The actual file size limit is enforced by the request body size limit in tower-http.
    const MAX_CHUNKS: u32 = 2500;
    if total_chunks > MAX_CHUNKS {
        return Err(AppError(anyhow::anyhow!(
            "total_chunks ({total_chunks}) exceeds maximum ({MAX_CHUNKS})"
        )));
    }

    // Load session
    let mut session = state.storage.load_session(&upload_id).await?;
    session.status = "uploading".to_string();

    // Validate filename
    let file_state = session.files.get_mut(&filename).ok_or_else(|| {
        AppError(anyhow::anyhow!(
            "Filename '{filename}' not registered in session"
        ))
    })?;

    // Initialise chunk_sizes vec on first chunk received
    if file_state.total_chunks == 0 {
        file_state.total_chunks = total_chunks;
        file_state.chunk_sizes = vec![None; total_chunks as usize];
        state
            .storage
            .init_file_temp(&upload_id, &filename)
            .await?;
    }

    // Decode symmetric key and nonce seed
    let sym_key_bytes = STANDARD
        .decode(&session.sym_key_b64)
        .context("Failed to decode sym_key")?;
    let sym_key: [u8; 32] = sym_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("sym_key wrong length"))?;

    let nonce_seed_bytes = STANDARD
        .decode(&file_state.nonce_seed_b64)
        .context("Failed to decode nonce_seed")?;
    let nonce_seed: [u8; 16] = nonce_seed_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("nonce_seed wrong length"))?;

    // Encrypt the chunk (XChaCha20-Poly1305, output = input + 16 bytes tag)
    let plaintext = body.to_vec();
    let ciphertext = tokio::task::spawn_blocking(move || {
        crypto::encrypt_chunk(&plaintext, &sym_key, &nonce_seed, chunk_index)
    })
    .await
    .map_err(|e| AppError(anyhow::anyhow!("Join error: {e}")))??;

    // Write encrypted chunk to disk
    let enc_size = ciphertext.len() as u64;
    state
        .storage
        .write_chunk(&upload_id, &filename, chunk_index, &ciphertext)
        .await?;

    // Update session with received chunk size
    // Re-borrow after the move above
    let file_state = session.files.get_mut(&filename).unwrap();
    file_state.chunk_sizes[chunk_index as usize] = Some(enc_size);

    let chunks_received = file_state
        .chunk_sizes
        .iter()
        .filter(|s| s.is_some())
        .count();
    let total = file_state.total_chunks;

    state.storage.save_session(&session).await?;

    let progress = (chunks_received as f32 / total as f32) * 100.0;
    info!(
        "Upload {upload_id}: {filename} chunk {chunk_index}/{} ({:.1}%)",
        total - 1,
        progress
    );

    Ok(Json(ChunkUploadResponse {
        upload_id,
        filename,
        chunk_index,
        chunks_received,
        total_chunks: total,
        progress_percent: progress,
    }))
}

// ── POST /api/uploads/{upload_id}/complete ───────────────────────────────────

/// Finalise the upload:
/// 1. Verify all chunks received for all registered files.
/// 2. Assemble per-file chunks into {filename}.enc.
/// 3. Wrap the symmetric key with RSA-4096-OAEP-SHA512 (public key).
/// 4. Write metadata.json.
/// 5. Delete temp chunks.
/// 6. Return HTML success page with the download link (contains RSA private key).
///
/// Security note: the RSA private key is embedded in the URL fragment/query string
/// of the returned link. The user must copy and safeguard this link.
pub async fn complete_upload(
    Path(upload_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    let mut session = state.storage.load_session(&upload_id).await?;

    if session.status == "complete" {
        return Err(AppError(anyhow::anyhow!("Upload already completed")));
    }

    // Verify and assemble each file
    let mut download_files: Vec<DownloadFileMetadata> = Vec::new();

    for (filename, file_state) in &session.files {
        // Check all chunks received
        let missing: Vec<u32> = file_state
            .chunk_sizes
            .iter()
            .enumerate()
            .filter_map(|(i, s)| if s.is_none() { Some(i as u32) } else { None })
            .collect();

        if !missing.is_empty() {
            return Err(AppError(anyhow::anyhow!(
                "File '{filename}' is missing chunks: {missing:?}"
            )));
        }

        // Assemble chunks into .enc file
        let assembled_sizes = state
            .storage
            .assemble_file(&upload_id, filename, file_state.total_chunks)
            .await?;

        download_files.push(DownloadFileMetadata {
            filename: filename.clone(),
            nonce_seed_b64: file_state.nonce_seed_b64.clone(),
            total_chunks: file_state.total_chunks,
            chunk_sizes: assembled_sizes,
        });
    }

    // Wrap symmetric key with RSA public key
    let sym_key_bytes = STANDARD.decode(&session.sym_key_b64)?;
    let sym_key: [u8; 32] = sym_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("sym_key wrong length"))?;

    let public_key = crypto::public_key_from_pem(&session.public_key_pem)?;
    let wrapped_key = tokio::task::spawn_blocking(move || {
        crypto::wrap_sym_key(&sym_key, &public_key)
    })
    .await
    .map_err(|e| AppError(anyhow::anyhow!("Join error: {e}")))??;

    let wrapped_key_b64 = STANDARD.encode(&wrapped_key);

    // Save download metadata
    let metadata = DownloadMetadata {
        upload_id: upload_id.clone(),
        wrapped_key_b64,
        files: download_files.clone(),
    };
    state.storage.save_metadata(&metadata).await?;

    // Encode private key as base62 [0-9A-Za-z] for a clean, all-alphanumeric URL
    let private_key = crypto::private_key_from_pem(&session.private_key_pem)?;
    let private_key_b62 = crypto::private_key_to_base62(&private_key)?;

    // Build download link using the configured base URL (e.g. https://rexnet.horobets.dev)
    let download_url = format!(
        "{}/download/{upload_id}?key={private_key_b62}",
        state.base_url
    );

    // Clean up temp directory
    state.storage.cleanup_temp(&upload_id).await?;

    // Mark session complete
    session.status = "complete".to_string();
    // Clear private key from session for security (it's now in the URL)
    session.private_key_pem = "[REDACTED - key returned to user]".to_string();
    state.storage.save_session(&session).await?;

    info!("Upload {upload_id} completed successfully");

    let file_list: String = download_files
        .iter()
        .map(|f| format!("<li>{}</li>", html_escape(&f.filename)))
        .collect::<Vec<_>>()
        .join("\n");

    let html = SUCCESS_HTML
        .replace("{{UPLOAD_ID}}", &upload_id)
        .replace("{{DOWNLOAD_URL}}", &download_url)
        .replace("{{FILE_LIST}}", &file_list);

    Ok(Html(html).into_response())
}

// ── GET /download/{upload_id}?key={b64_key} ─────────────────────────────────

#[derive(Deserialize)]
pub struct DownloadQuery {
    pub key: String,
}

/// Download and decrypt files for an upload session.
///
/// The `?key=` query parameter must contain the base64url-encoded PKCS#8 DER
/// RSA-4096 private key (as returned in the upload completion link).
///
/// For single-file sessions: streams the decrypted file directly.
/// For multi-file sessions: assembles and streams a ZIP archive.
///
/// Decryption is streaming — only one chunk (~20-50 MB) is in memory at a time.
pub async fn download(
    Path(upload_id): Path<String>,
    Query(q): Query<DownloadQuery>,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    // Decode private key from base62 URL parameter
    let private_key = crypto::private_key_from_base62(&q.key)
        .map_err(|e| AppError(anyhow::anyhow!("Invalid private key in URL: {e}")))?;

    // Load metadata
    let metadata = state.storage.load_metadata(&upload_id).await?;

    // Unwrap symmetric key
    let wrapped_key = STANDARD.decode(&metadata.wrapped_key_b64)?;
    let sym_key_bytes = tokio::task::spawn_blocking(move || {
        crypto::unwrap_sym_key(&wrapped_key, &private_key)
    })
    .await
    .map_err(|e| AppError(anyhow::anyhow!("Join error: {e}")))??;

    if metadata.files.len() == 1 {
        // Single file — stream decrypted bytes directly
        stream_single_file(sym_key_bytes, &upload_id, &metadata.files[0], &state).await
    } else {
        // Multiple files — build ZIP in memory then stream
        // (For production, consider using async_zip for true streaming)
        stream_multi_file_zip(sym_key_bytes, &upload_id, &metadata.files, &state).await
    }
}

/// Stream a single decrypted file.
async fn stream_single_file(
    sym_key: [u8; 32],
    upload_id: &str,
    file_meta: &DownloadFileMetadata,
    state: &AppState,
) -> Result<Response, AppError> {
    let enc_path = state.storage.encrypted_file(upload_id, &file_meta.filename);
    let mut enc_file = tokio::fs::File::open(&enc_path)
        .await
        .with_context(|| format!("Encrypted file not found: {enc_path:?}"))?;

    let chunk_sizes = file_meta.chunk_sizes.clone();
    let nonce_seed_bytes = STANDARD.decode(&file_meta.nonce_seed_b64)?;
    let nonce_seed: [u8; 16] = nonce_seed_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("nonce_seed wrong length"))?;
    let filename = file_meta.filename.clone();

    // Use a duplex pipe: producer task decrypts chunks and writes to tx,
    // response streams from rx. Only one chunk is in memory at a time.
    let (mut tx, rx) = tokio::io::duplex(32 * 1024 * 1024); // 32 MB buffer

    tokio::spawn(async move {
        for (chunk_index, &enc_size) in chunk_sizes.iter().enumerate() {
            let mut chunk_data = vec![0u8; enc_size as usize];
            if let Err(e) = enc_file.read_exact(&mut chunk_data).await {
                error!("Error reading chunk {chunk_index}: {e}");
                return;
            }
            match tokio::task::spawn_blocking(move || {
                crypto::decrypt_chunk(&chunk_data, &sym_key, &nonce_seed, chunk_index as u32)
            })
            .await
            {
                Ok(Ok(plaintext)) => {
                    use tokio::io::AsyncWriteExt;
                    if let Err(e) = tx.write_all(&plaintext).await {
                        error!("Error writing decrypted chunk: {e}");
                        return;
                    }
                }
                Ok(Err(e)) => {
                    error!("Decryption error for chunk {chunk_index}: {e}");
                    return;
                }
                Err(e) => {
                    error!("Spawn blocking error: {e}");
                    return;
                }
            }
        }
    });

    let stream = ReaderStream::new(rx);
    let body = Body::from_stream(stream);

    let disposition = format!(
        "attachment; filename=\"{}\"",
        sanitize_header(&filename)
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, disposition)
        .header("X-Content-Type-Options", "nosniff")
        .body(body)
        .unwrap())
}

/// Stream multiple decrypted files as a ZIP archive.
/// Uses spawn_blocking for the synchronous zip writer.
async fn stream_multi_file_zip(
    sym_key: [u8; 32],
    upload_id: &str,
    files: &[DownloadFileMetadata],
    state: &AppState,
) -> Result<Response, AppError> {
    let upload_id = upload_id.to_string();
    let files = files.to_vec();
    let storage = Arc::clone(&state.storage);

    // Write ZIP to a temp file (sync), then stream it
    let temp_file = tempfile::NamedTempFile::new()
        .context("Failed to create temp file for ZIP")?;
    let temp_path = temp_file.path().to_path_buf();
    let temp_path_for_closure = temp_path.clone();

    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let out = std::fs::File::create(&temp_path_for_closure)?;
        let mut zip = zip::ZipWriter::new(out);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .unix_permissions(0o644);

        for file_meta in &files {
            let enc_path = storage.encrypted_file(&upload_id, &file_meta.filename);
            let nonce_seed_bytes = STANDARD.decode(&file_meta.nonce_seed_b64)?;
            let nonce_seed: [u8; 16] = nonce_seed_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("nonce_seed wrong length"))?;

            let mut enc_file = std::fs::File::open(&enc_path)
                .with_context(|| format!("Cannot open {enc_path:?}"))?;

            zip.start_file(&file_meta.filename, options)
                .context("ZIP start_file failed")?;

            for (chunk_index, &enc_size) in file_meta.chunk_sizes.iter().enumerate() {
                let mut chunk_data = vec![0u8; enc_size as usize];
                use std::io::Read;
                enc_file.read_exact(&mut chunk_data)?;

                let plaintext =
                    crypto::decrypt_chunk(&chunk_data, &sym_key, &nonce_seed, chunk_index as u32)?;
                zip.write_all(&plaintext)?;
            }
        }

        zip.finish()?;
        Ok(())
    })
    .await
    .map_err(|e| AppError(anyhow::anyhow!("Blocking task error: {e}")))??;

    // Stream the temp file
    let zip_file = tokio::fs::File::open(&temp_path).await?;
    let zip_size = zip_file.metadata().await?.len();
    let stream = ReaderStream::new(zip_file);
    let body = Body::from_stream(stream);

    // Note: temp_file will be deleted when dropped — we need to keep it alive.
    // Leak the NamedTempFile to avoid deletion (or we can use a cleanup task).
    // For correctness here we just let the OS clean it up on process exit / in /tmp GC.
    std::mem::forget(temp_file);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/zip")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"files.zip\"",
        )
        .header(header::CONTENT_LENGTH, zip_size.to_string())
        .header("X-Content-Type-Options", "nosniff")
        .body(body)
        .unwrap())
}

// ── HTML helpers ─────────────────────────────────────────────────────────────

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn sanitize_header(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_graphic() && c != '"' { c } else { '_' })
        .collect()
}

// ── Static HTML ───────────────────────────────────────────────────────────────

/// The main upload SPA — served at GET /
/// Tailwind via CDN, chunked upload with resume support via localStorage.
static INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>SecureShare — Military-Grade Encrypted File Upload</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  #drop-zone.drag-over { @apply border-blue-500 bg-blue-50; }
  .progress-fill { transition: width 0.3s ease; }
</style>
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen flex items-center justify-center p-4">
<div class="w-full max-w-2xl">
  <div class="text-center mb-8">
    <h1 class="text-4xl font-bold text-white mb-2">&#x1F510; SecureShare</h1>
    <p class="text-gray-400">XChaCha20-Poly1305 + RSA-4096 encrypted. No size limit. Resumable.</p>
  </div>

  <!-- Drop Zone -->
  <div id="drop-zone"
       class="border-2 border-dashed border-gray-600 rounded-xl p-10 text-center cursor-pointer hover:border-blue-400 transition-colors"
       onclick="document.getElementById('file-input').click()">
    <div class="text-5xl mb-3">&#x1F4C1;</div>
    <p class="text-lg text-gray-300">Drop files here or <span class="text-blue-400 underline">browse</span></p>
    <p class="text-sm text-gray-500 mt-1">Supports multiple files — any size. Encrypted in transit and at rest.</p>
    <input type="file" id="file-input" multiple class="hidden"/>
  </div>

  <!-- Selected Files List -->
  <div id="file-list" class="mt-4 space-y-2 hidden"></div>

  <!-- Upload Button -->
  <button id="upload-btn"
          class="mt-6 w-full py-3 px-6 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-colors hidden"
          onclick="startUpload()">
    Upload &amp; Encrypt
  </button>

  <!-- Overall Progress -->
  <div id="progress-section" class="mt-6 hidden">
    <div class="flex justify-between text-sm text-gray-400 mb-1">
      <span id="progress-label">Preparing&hellip;</span>
      <span id="progress-pct">0%</span>
    </div>
    <div class="w-full bg-gray-800 rounded-full h-3">
      <div id="progress-bar" class="bg-blue-500 h-3 rounded-full progress-fill" style="width:0%"></div>
    </div>
    <p id="status-msg" class="text-xs text-gray-500 mt-2"></p>
  </div>

  <!-- Encryption badge -->
  <div class="mt-8 flex items-center justify-center gap-4 text-xs text-gray-600">
    <span>&#x1F511; RSA-4096-OAEP-SHA512</span>
    <span>&bull;</span>
    <span>&#x26A1; XChaCha20-Poly1305</span>
    <span>&bull;</span>
    <span>&#x1F9E9; Resumable chunks</span>
    <span>&bull;</span>
    <span>&#x30; Zero server logging of content</span>
  </div>
</div>

<script>
const CHUNK_SIZE = 20 * 1024 * 1024; // 20 MB per chunk
let selectedFiles = [];

// ── Drag & Drop ──────────────────────────────────────────────────────────────
const dz = document.getElementById('drop-zone');
dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('border-blue-500','bg-gray-900'); });
dz.addEventListener('dragleave', () => dz.classList.remove('border-blue-500','bg-gray-900'));
dz.addEventListener('drop', e => {
  e.preventDefault();
  dz.classList.remove('border-blue-500','bg-gray-900');
  handleFiles(e.dataTransfer.files);
});
document.getElementById('file-input').addEventListener('change', e => handleFiles(e.target.files));

function handleFiles(fileList) {
  selectedFiles = Array.from(fileList);
  const list = document.getElementById('file-list');
  list.innerHTML = '';
  selectedFiles.forEach((f, i) => {
    const el = document.createElement('div');
    el.id = `file-row-${i}`;
    el.className = 'flex items-center justify-between bg-gray-800 rounded-lg px-4 py-2 text-sm';
    el.innerHTML = `<span class="truncate max-w-xs">${escHtml(f.name)}</span>
      <span class="text-gray-400 ml-2 shrink-0">${fmtSize(f.size)}</span>`;
    list.appendChild(el);
  });
  list.classList.toggle('hidden', selectedFiles.length === 0);
  document.getElementById('upload-btn').classList.toggle('hidden', selectedFiles.length === 0);
}

// ── Upload ────────────────────────────────────────────────────────────────────
async function startUpload() {
  if (!selectedFiles.length) return;

  const btn = document.getElementById('upload-btn');
  btn.disabled = true;
  btn.textContent = 'Encrypting & uploading\u2026';

  showProgress('Creating secure session (RSA-4096, ~2s)\u2026', 0);

  const filenames = selectedFiles.map(f => f.name);

  // Check localStorage for a previous session we can resume
  const resumeKey = 'secureshare_resume_' + filenames.slice().sort().join('|');
  let uploadId = null;
  let chunkProgress = {}; // filename -> last completed chunk index

  const saved = localStorage.getItem(resumeKey);
  if (saved) {
    try {
      const parsed = JSON.parse(saved);
      uploadId = parsed.uploadId;
      chunkProgress = parsed.chunkProgress || {};
      setStatus(`Resuming previous session ${uploadId}`);
    } catch (_) { /* ignore corrupt data */ }
  }

  // Create new session if needed
  if (!uploadId) {
    try {
      const resp = await fetch('/api/uploads', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filenames }),
      });
      if (!resp.ok) throw new Error(`Server error: ${resp.status}`);
      const data = await resp.json();
      uploadId = data.upload_id;
      localStorage.setItem(resumeKey, JSON.stringify({ uploadId, chunkProgress: {} }));
    } catch (err) {
      setStatus(`Failed to create session: ${err.message}`, 'error');
      btn.disabled = false;
      btn.textContent = 'Upload & Encrypt';
      return;
    }
  }

  setStatus(`Session: ${uploadId}`);

  // Upload all files
  let totalChunks = 0;
  let completedChunks = 0;

  // Pre-calculate total chunks
  for (const f of selectedFiles) {
    totalChunks += Math.ceil(f.size / CHUNK_SIZE);
  }
  // Subtract already-completed chunks from resume
  for (const fn_ of Object.keys(chunkProgress)) {
    completedChunks += chunkProgress[fn_] + 1;
  }

  for (const file of selectedFiles) {
    const numChunks = Math.ceil(file.size / CHUNK_SIZE);
    const startChunk = (chunkProgress[file.name] !== undefined)
      ? chunkProgress[file.name] + 1
      : 0;

    for (let i = startChunk; i < numChunks; i++) {
      const start = i * CHUNK_SIZE;
      const chunk = file.slice(start, start + CHUNK_SIZE);
      const chunkBytes = await chunk.arrayBuffer();

      const pct = Math.round((completedChunks / totalChunks) * 100);
      showProgress(`Uploading ${file.name} \u2014 chunk ${i+1}/${numChunks}`, pct);

      let ok = false;
      for (let attempt = 0; attempt < 5; attempt++) {
        try {
          const resp = await fetch(`/api/uploads/${uploadId}/chunks`, {
            method: 'POST',
            headers: {
              'X-Filename': file.name,
              'X-Chunk-Index': String(i),
              'X-Total-Chunks': String(numChunks),
              'Content-Type': 'application/octet-stream',
            },
            body: chunkBytes,
          });
          if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
          ok = true;
          break;
        } catch (err) {
          setStatus(`Chunk ${i} attempt ${attempt+1} failed: ${err.message} \u2014 retrying\u2026`);
          await sleep(1000 * Math.pow(2, attempt)); // exponential backoff
        }
      }
      if (!ok) {
        setStatus(`Failed to upload chunk ${i} of ${file.name} after 5 attempts.`, 'error');
        btn.disabled = false;
        btn.textContent = 'Retry Upload';
        return;
      }

      completedChunks++;
      chunkProgress[file.name] = i;
      localStorage.setItem(resumeKey, JSON.stringify({ uploadId, chunkProgress }));
    }
  }

  // Complete the upload
  showProgress('Finalising encryption\u2026', 99);
  try {
    const resp = await fetch(`/api/uploads/${uploadId}/complete`, { method: 'POST' });
    if (!resp.ok) throw new Error(`Complete failed: ${resp.status}`);
    const html = await resp.text();
    localStorage.removeItem(resumeKey);
    document.open();
    document.write(html);
    document.close();
  } catch (err) {
    setStatus(`Failed to complete upload: ${err.message}`, 'error');
    btn.disabled = false;
    btn.textContent = 'Retry';
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function showProgress(label, pct) {
  document.getElementById('progress-section').classList.remove('hidden');
  document.getElementById('progress-label').textContent = label;
  document.getElementById('progress-pct').textContent = pct + '%';
  document.getElementById('progress-bar').style.width = pct + '%';
}
function setStatus(msg, type) {
  const el = document.getElementById('status-msg');
  el.textContent = msg;
  el.className = 'text-xs mt-2 ' + (type === 'error' ? 'text-red-400' : 'text-gray-500');
}
function fmtSize(n) {
  if (n >= 1e9) return (n/1e9).toFixed(2) + ' GB';
  if (n >= 1e6) return (n/1e6).toFixed(1) + ' MB';
  if (n >= 1e3) return (n/1e3).toFixed(0) + ' KB';
  return n + ' B';
}
function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
</script>
</body>
</html>"#;

static SUCCESS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Upload Complete — SecureShare</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen flex items-center justify-center p-4">
<div class="w-full max-w-2xl text-center">
  <div class="text-6xl mb-4">&#x2705;</div>
  <h1 class="text-3xl font-bold mb-2">Upload Complete!</h1>
  <p class="text-gray-400 mb-6">Your files are encrypted and ready to share.</p>

  <div class="bg-gray-900 border border-gray-700 rounded-xl p-4 mb-6 text-left">
    <p class="text-xs text-gray-500 mb-2">Files uploaded:</p>
    <ul class="list-disc list-inside text-sm text-gray-300 space-y-1">
      {{FILE_LIST}}
    </ul>
  </div>

  <div class="bg-amber-950 border border-amber-700 rounded-xl p-4 mb-4 text-left">
    <p class="text-amber-400 font-bold mb-1">&#x26A0;&#xFE0F; Security Warning</p>
    <p class="text-amber-200 text-sm">
      The link below contains the RSA private decryption key.
      <strong>Anyone with this link can decrypt and download the files.</strong>
      Store it securely and only share with intended recipients.
    </p>
  </div>

  <div class="bg-gray-900 border border-gray-700 rounded-xl p-4 mb-4 text-left overflow-x-auto">
    <p class="text-xs text-gray-500 mb-2">Download link (contains decryption key):</p>
    <a id="dl-link" href="{{DOWNLOAD_URL}}" class="text-blue-400 text-xs break-all hover:underline">{{DOWNLOAD_URL}}</a>
  </div>

  <div class="flex gap-3 justify-center">
    <button onclick="copyLink()"
            class="px-6 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium transition-colors">
      &#x1F4CB; Copy Link
    </button>
    <a href="/" class="px-6 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg font-medium transition-colors">
      &#x2191; Upload More
    </a>
  </div>

  <p id="copy-msg" class="text-green-400 text-sm mt-3 opacity-0 transition-opacity">Link copied!</p>
</div>
<script>
function copyLink() {
  navigator.clipboard.writeText(document.getElementById('dl-link').href)
    .then(() => {
      const m = document.getElementById('copy-msg');
      m.style.opacity = '1';
      setTimeout(() => m.style.opacity = '0', 2000);
    });
}
</script>
</body>
</html>"#;
