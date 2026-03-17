mod crypto;
mod error;
mod handlers;
mod models;
mod storage;

use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};
use std::{net::SocketAddr, sync::Arc};
use storage::Storage;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Maximum request body size: 60 MB per chunk (slightly above CHUNK_SIZE to allow overhead).
/// The JS client sends 20 MB chunks by default.
const MAX_BODY_BYTES: usize = 60 * 1024 * 1024;

/// Maximum supported file size: 50 GB.
/// Configured via the MAX_CHUNKS constant in handlers.
pub const MAX_FILE_SIZE_GB: u64 = 50;

/// Shared application state injected into all handlers via axum::extract::State.
#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<Storage>,
    /// Base URL used for generating download links (e.g. "https://rexnet.horobets.dev")
    pub base_url: String,
    /// Optional master X25519 public key. When set, every upload's symmetric key is also
    /// wrapped with this key, letting admins decrypt any file using the master private key.
    /// Set via the MASTER_PUBLIC_KEY environment variable (base62-encoded 32 bytes).
    /// Generate a keypair with: rexnet --generate-master-key
    pub master_public_key: Option<[u8; 32]>,
}

#[tokio::main]
async fn main() {
    // Handle --generate-master-key before anything else
    if std::env::args().any(|a| a == "--generate-master-key") {
        let (priv_bytes, pub_bytes) = crypto::generate_x25519_keypair();
        println!("=== Master Key Pair ===");
        println!("Private key (give to admins, NEVER put on server):");
        println!("  {}", crypto::bytes_to_base62(&priv_bytes));
        println!();
        println!("Public key (set as MASTER_PUBLIC_KEY env var on server):");
        println!("  {}", crypto::bytes_to_base62(&pub_bytes));
        return;
    }

    // Initialise tracing (RUST_LOG=info by default)
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Ensure the uploads directory exists
    tokio::fs::create_dir_all("uploads")
        .await
        .expect("Failed to create uploads directory");

    let base_url = std::env::var("BASE_URL")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());
    info!("Base URL: {base_url}");

    let master_public_key = match std::env::var("MASTER_PUBLIC_KEY") {
        Ok(s) => match crypto::bytes_from_base62(&s).and_then(|b| {
            b.try_into().map_err(|_| anyhow::anyhow!("MASTER_PUBLIC_KEY must be 32 bytes"))
        }) {
            Ok(key) => {
                info!("Master key configured — every upload will have an admin escrow envelope");
                Some(key)
            }
            Err(e) => {
                eprintln!("ERROR: Invalid MASTER_PUBLIC_KEY: {e}");
                std::process::exit(1);
            }
        },
        Err(_) => {
            info!("No MASTER_PUBLIC_KEY set — uploads will not have an admin escrow envelope");
            None
        }
    };

    let state = AppState {
        storage: Arc::new(Storage::new("uploads")),
        base_url,
        master_public_key,
    };

    let app = Router::new()
        // Frontend
        .route("/", get(handlers::index))
        // API
        .route("/api/uploads", post(handlers::create_upload))
        // Chunk uploads need a large body limit — override axum's 2 MB default here.
        // DefaultBodyLimit is the axum-level extractor limit (controls the Bytes extractor).
        // The global tower-http RequestBodyLimitLayer is NOT enough on its own.
        .route(
            "/api/uploads/:upload_id/chunks",
            post(handlers::upload_chunk).layer(DefaultBodyLimit::max(MAX_BODY_BYTES)),
        )
        .route("/api/uploads/:upload_id/complete", post(handlers::complete_upload))
        // Download
        .route("/download/:upload_id", get(handlers::download))
        .with_state(state)
        // Global middleware — all other routes keep the default 2 MB body limit
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    info!("SecureShare listening on http://{addr}");
    info!("Max file size: {} GB | Max chunk size: {} MB", MAX_FILE_SIZE_GB, MAX_BODY_BYTES / 1024 / 1024);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind port 3000");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}
