mod crypto;
mod error;
mod handlers;
mod models;
mod storage;

use axum::{
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
}

#[tokio::main]
async fn main() {
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

    let state = AppState {
        storage: Arc::new(Storage::new("uploads")),
        base_url,
    };

    let app = Router::new()
        // Frontend
        .route("/", get(handlers::index))
        // API
        .route("/api/uploads", post(handlers::create_upload))
        .route("/api/uploads/:upload_id/chunks", post(handlers::upload_chunk))
        .route("/api/uploads/:upload_id/complete", post(handlers::complete_upload))
        // Download
        .route("/download/:upload_id", get(handlers::download))
        .with_state(state)
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .layer(tower_http::limit::RequestBodyLimitLayer::new(MAX_BODY_BYTES));

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
