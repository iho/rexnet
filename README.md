# SecureShare

Military-grade encrypted large file sharing service built with Rust + Axum.

## Features
- XChaCha20-Poly1305 symmetric encryption (streaming, per-chunk)
- RSA-4096-OAEP-SHA512 key wrapping
- Resumable chunked uploads (JS stores progress in localStorage)
- Supports files up to 50 GB (no memory pressure — streaming throughout)
- Drag & drop UI with real-time progress bar
- Single-link sharing with embedded decryption key

## Quick start
```
cargo run
```
Then open http://localhost:3000

## API
| Method | Path | Description |
|--------|------|-------------|
| GET | / | Upload SPA |
| POST | /api/uploads | Create session |
| POST | /api/uploads/:id/chunks | Upload chunk |
| POST | /api/uploads/:id/complete | Finalise & get link |
| GET | /download/:id?key=... | Download & decrypt |

## Security notes
- The RSA private key is embedded in the download URL. Treat it like a password.
- Session files (including the temporary private key) are stored in `./uploads/`.
- In production, set `./uploads/` permissions to 700 and run behind HTTPS.
