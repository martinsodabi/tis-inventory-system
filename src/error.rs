use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
    InvalidToken,
    WrongCredential,
    MissingCredential,
    TokenCreation,
    Unauthorized,
    InternalServerError,
    UserDoesNotExist,
    UserAlreadyExist,
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, err_msg) = match self {
            Self::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid Token"),
            Self::WrongCredential => (StatusCode::UNAUTHORIZED, "Wrong Credentials"),
            Self::MissingCredential => (StatusCode::BAD_REQUEST, "Missing Credentials"),
            Self::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create Token"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized Request"),
            Self::InternalServerError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
            }
            Self::UserDoesNotExist => (StatusCode::UNAUTHORIZED, "User does not Exist"),
            Self::UserAlreadyExist => (StatusCode::CONFLICT, "User already exist"),
        };
        return (status, Json(json!({ "error": err_msg}))).into_response();
    }
}
