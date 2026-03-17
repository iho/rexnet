use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;

#[derive(Debug)]
pub struct AppError(pub anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = StatusCode::INTERNAL_SERVER_ERROR;
        let body = Json(json!({"error": self.0.to_string()}));
        (status, body).into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self { AppError(e.into()) }
}
