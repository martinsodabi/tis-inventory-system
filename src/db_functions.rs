use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::{error::AppError, models::auth::User};

pub async fn check_user_exists(
    username: &String,
    db_pool: &Pool<Postgres>,
) -> Result<bool, AppError> {
    let user_exists =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM manager WHERE username = $1)")
            .bind(username.to_ascii_lowercase())
            .fetch_optional(db_pool)
            .await
            .map_err(|err| {
                dbg!(err);
                AppError::InternalServerError
            })?;

    match user_exists {
        Some(v) => return Ok(v),
        None => return Err(AppError::InternalServerError),
    }
}

pub async fn insert_new_user(
    username: &String,
    hashed_password: &String,
    db_pool: &Pool<Postgres>,
) -> Result<User, AppError> {
    let user_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO manager (id, username, password, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(username.to_ascii_lowercase())
    .bind(hashed_password)
    .bind(sqlx::types::chrono::Utc::now())
    .fetch_one(db_pool)
    .await
    .map_err(|err| {
        dbg!(err);
        return AppError::InternalServerError;
    })?;

    return Ok(User {
        id: user_id,
        username: username.to_ascii_lowercase(),
    });
}

pub async fn get_user_by_id(user_id: &String, db_pool: &Pool<Postgres>) -> Result<User, AppError> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM manager WHERE id = $1")
        .bind(Uuid::parse_str(user_id).unwrap())
        .fetch_optional(db_pool)
        .await
        .map_err(|err| {
            dbg!(err);
            return AppError::InternalServerError;
        })?;

    match user {
        Some(v) => return Ok(v),
        None => return Err(AppError::UserDoesNotExist),
    }
}

pub async fn get_user_by_username(
    username: &String,
    db_pool: &Pool<Postgres>,
) -> Result<User, AppError> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM manager WHERE username = $1")
        .bind(username)
        .fetch_optional(db_pool)
        .await
        .map_err(|err| {
            dbg!(err);
            return AppError::InternalServerError;
        })?;

    match user {
        Some(v) => return Ok(v),
        None => return Err(AppError::UserDoesNotExist),
    }
}

pub async fn get_user_hashed_password(
    username: &String,
    db_pool: &Pool<Postgres>,
) -> Result<String, AppError> {
    let hashed_password =
        sqlx::query_scalar::<_, String>("SELECT password FROM manager WHERE username = $1")
            .bind(username.to_ascii_lowercase())
            .fetch_optional(db_pool)
            .await
            .map_err(|err| {
                dbg!(err);
                return AppError::InternalServerError;
            })?;

    match hashed_password {
        Some(v) => return Ok(v),
        None => return Err(AppError::UserDoesNotExist),
    }
}
