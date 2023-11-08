use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
}

#[derive(Deserialize, FromRow)]
pub struct RegisterUserSchema {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize, FromRow)]
pub struct LoginUserSchema {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserClaims {
    pub sub: String,
    pub exp: usize,
}
