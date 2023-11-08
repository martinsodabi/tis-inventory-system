use std::usize;

use crate::{
    app_state::AppState,
    db_functions::{
        check_user_exists, get_user_by_username, get_user_hashed_password, insert_new_user,
    },
    error::AppError,
    middlewares::jwt_auth::encode_user_claims,
    models::auth::{LoginUserSchema, RegisterUserSchema, User, UserClaims},
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{extract::State, response::IntoResponse, Json};
use axum_macros::debug_handler;
use serde_json::json;

#[debug_handler]
pub async fn register(
    State(app_state): State<AppState>,
    Json(body): Json<RegisterUserSchema>,
) -> Result<impl IntoResponse, AppError> {
    if body.username.is_empty() || body.password.is_empty() {
        return Err(AppError::MissingCredential);
    }

    let user_exists = check_user_exists(&body.username, &app_state.pg_pool)
        .await
        .map_err(|err| {
            dbg!(&err);
            return err;
        })?;

    if user_exists {
        return Err(AppError::UserAlreadyExist);
    }

    let hashed_password = hash_password(&body.password).map_err(|err| {
        dbg!(err);
        return AppError::InternalServerError;
    })?;

    let user = insert_new_user(&body.username, &hashed_password, &app_state.pg_pool)
        .await
        .map_err(|err| {
            dbg!(&err);
            return err;
        })?;

    // TODO Place jwt_token in http header instead
    let jwt_token = get_jwt_token(&app_state, &user);
    return Ok(Json(json!({ "user": user, "token": jwt_token })));
}

#[debug_handler]
pub async fn login(
    State(app_state): State<AppState>,
    Json(body): Json<LoginUserSchema>,
) -> Result<impl IntoResponse, AppError> {
    if body.username.is_empty() || body.password.is_empty() {
        return Err(AppError::MissingCredential);
    }

    let hashed_password = get_user_hashed_password(&body.username, &app_state.pg_pool)
        .await
        .map_err(|err| {
            dbg!(&err);
            return err;
        })?;

    //TODO Return a jwt instead!
    match verify_password(&body.password, &hashed_password) {
        Ok(is_correct) => {
            if is_correct {
                let user = get_user_by_username(&body.username, &app_state.pg_pool)
                    .await
                    .map_err(|err| {
                        dbg!(&err);
                        return err;
                    })?;

                // TODO Place jwt_token in http header instead
                let jwt_token = get_jwt_token(&app_state, &user);
                return Ok(Json(json!({ "user": user, "token": jwt_token })));
            } else {
                return Err(AppError::WrongCredential);
            }
        }
        Err(_) => Err(AppError::InternalServerError),
    }
}

fn hash_password(password: &String) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| {
            dbg!(err);
            return err;
        })?;

    return Ok(password_hash.to_string());
}

fn verify_password(
    password: &String,
    hashed_password: &String,
) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hashed_password).map_err(|err| {
        dbg!(err);
        return err;
    })?;

    return Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok());
}

fn get_jwt_token(app_state: &AppState, user: &User) -> String {
    let now = chrono::Utc::now();
    let jwt_expiry_minute = app_state.config.jwt_expiry_minute;
    let exp = (now + chrono::Duration::minutes(jwt_expiry_minute.into())).timestamp() as usize;
    let claims = UserClaims {
        sub: user.id.to_string(),
        exp,
    };

    let jwt_secret = &app_state.config.jwt_secret;
    let jwt_token = encode_user_claims(&claims, &jwt_secret).unwrap();

    return jwt_token;
}
