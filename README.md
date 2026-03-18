# rexnet

End-to-end encrypted file transfer. No size limit. Files are encrypted in the browser before upload; the server never sees plaintext. The decryption key lives only in the download URL — not on disk.

## How it works

1. Client generates a random 256-bit symmetric key and a per-file nonce seed
2. File is split into 20 MB chunks, each encrypted with XChaCha20-Poly1305 before upload
3. Chunks are uploaded sequentially; progress is saved to `localStorage` for resumable uploads
4. On completion the symmetric key is wrapped with X25519 ECIES — the private key becomes the `?key=` parameter in the download URL
5. Server stores only ciphertext and ECIES envelopes; `session.json` (which held the plaintext key during upload) is deleted immediately after completion

Download URL format:
```
https://rexnet.horobets.dev/download/{upload_id}?key={43-char-base62-private-key}
```

## Cryptography

| Primitive | Purpose |
|---|---|
| XChaCha20-Poly1305 | File encryption (256-bit key, 192-bit nonce) |
| X25519 ECDH | Key agreement for ECIES wrapping |
| HKDF-SHA256 | Derive wrap key from ECDH shared secret |
| XChaCha20-Poly1305 | Wrap the 32-byte symmetric key (ECIES) |
| Base62 `[0-9A-Za-z]` | Encode 32-byte private key as 43 URL-safe chars |

### Key wrapping (ECIES)

```
eph_priv, eph_pub  ← random X25519 keypair
shared             = ECDH(eph_priv, static_pub)
wrap_key           = HKDF-SHA256(salt=eph_pub, ikm=shared, info="rexnet-v1-key-wrap")
ciphertext         = XChaCha20-Poly1305(wrap_key, nonce, sym_key)

store in metadata.json: { eph_pub, nonce, ciphertext }
give to user:            static_priv  (in ?key= URL param)
```

### Nonce derivation per chunk

```
nonce[0..16] = file_nonce_seed   (random, stored in metadata.json)
nonce[16..24] = chunk_index.to_be_bytes()
```

Deterministic per chunk — re-uploading the same chunk produces identical ciphertext, enabling idempotent resumable uploads.

### What's on disk after upload completes

```
uploads/
  {upload_id}/
    {filename}.enc      ← ciphertext; useless without the key
    metadata.json       ← ECIES envelope; private key is in the URL, not here
```

`session.json` (which holds the plaintext symmetric key during upload) is deleted the moment `complete` is called. A stolen hard drive yields only ciphertext and ECIES envelopes.

## Admin master key (optional)

Generates an additional ECIES envelope for every upload, wrapped with a server-configured master public key. Admins holding the corresponding private key can decrypt any upload.

```bash
# Generate a keypair (run once, off-server)
rexnet --generate-master-key

# Private key (give to admins, NEVER put on server):
#   <43-char base62>
# Public key (set as MASTER_PUBLIC_KEY env var on server):
#   <43-char base62>
```

The master private key never touches the server.

## Deduplication

Duplicate detection is entirely client-side:

- Files are fingerprinted with SHA-256 (computed in 64 MB slices to avoid OOM on large files)
- On upload completion the browser saves `sha256 → download_url` to `localStorage`
- On the next upload from the same browser, matching files are detected before any data is sent
- Nothing is stored server-side

This keeps dedup from becoming a key oracle: the server cannot map a hash to a decryption key, so a stolen disk reveals nothing.

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Upload SPA |
| `POST` | `/api/uploads` | Create upload session |
| `POST` | `/api/uploads/:id/chunks` | Upload one encrypted chunk |
| `POST` | `/api/uploads/:id/complete` | Finalise upload, get download link |
| `GET` | `/download/:id?key=...` | Stream-decrypt and download |

## Building

```bash
cargo build --release
# binary: target/release/rexnet
```

## Running

```bash
BASE_URL=https://rexnet.horobets.dev \
MASTER_PUBLIC_KEY=<43-char-base62-pubkey> \
RUST_LOG=info \
./rexnet
```

Listens on `0.0.0.0:3000`. Creates `./uploads/` on first run.

## Deployment

### systemd

```ini
[Unit]
Description=rexnet encrypted file transfer
After=network.target

[Service]
ExecStart=/usr/local/bin/rexnet
WorkingDirectory=/opt/rexnet
Environment=RUST_LOG=info
Environment=BASE_URL=https://rexnet.horobets.dev
Environment=MASTER_PUBLIC_KEY=<pubkey>
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### nginx

```nginx
server {
    access_log off;
    listen 443 ssl;
    server_name rexnet.horobets.dev;

    client_max_body_size 0;       # unlimited — rexnet enforces its own limit
    proxy_request_buffering off;  # stream chunks directly, don't buffer to disk
    proxy_buffering off;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;

    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
```

> `client_max_body_size 0` is required. Certbot may reset this to `800m` after certificate renewal — verify after each renewal.

## Limits

| Parameter | Value |
|---|---|
| Max file size | 50 GB |
| Max files per upload | 20 |
| Chunk size (client) | 20 MB |
| Max chunk body (server) | 60 MB |
| Resumable uploads | Yes — via `localStorage` |
| Unicode filenames | Yes — RFC 5987 `filename*=UTF-8''...` |
