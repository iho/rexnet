use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;

#[derive(Debug)]
pub struct AppError(pub anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let msg = self.0.to_string();
        // Classify: client errors (bad input / missing session) → 400, server faults → 500
        let status = if msg.contains("not found")
            || msg.contains("not registered")
            || msg.contains("incompatible format")
            || msg.contains("Invalid")
            || msg.contains("wrong length")
            || msg.contains("missing chunks")
            || msg.contains("already completed")
        {
            StatusCode::BAD_REQUEST
        } else {
            tracing::error!("handler error: {:?}", self.0);
            StatusCode::INTERNAL_SERVER_ERROR
        };
        (status, Json(json!({"error": msg}))).into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self { AppError(e.into()) }
}
