use axum::{extract::State, http::Request, middleware::Next, response::IntoResponse};
use jsonwebtoken::{encode, DecodingKey, EncodingKey, Header, Validation};

use crate::{
    app_state::AppState, db_functions::get_user_by_id, error::AppError, models::auth::UserClaims,
};

const AUTHORIZATION: &str = "Authorization";
const BEARER: &str = "Bearer";

pub async fn authenticate<B>(
    State(app_state): State<AppState>,
    mut request: Request<B>,
    next: Next<B>,
) -> Result<impl IntoResponse, AppError> {
    // Get authorization header from the http request
    let authorization_header = match request.headers().get(AUTHORIZATION) {
        Some(auth_header) => auth_header,
        None => return Err(AppError::Unauthorized),
    };

    let authorization = authorization_header.to_str().map_err(|err| {
        dbg!(err);
        return AppError::Unauthorized;
    })?;

    if !authorization.starts_with(BEARER) {
        return Err(AppError::Unauthorized);
    }

    let jwt_token = authorization.trim_start_matches(BEARER);

    let token_header = jsonwebtoken::decode_header(jwt_token.trim()).map_err(|err| {
        dbg!(err);
        return AppError::Unauthorized;
    })?;

    let user_claims = jsonwebtoken::decode::<UserClaims>(
        jwt_token.trim(),
        &DecodingKey::from_secret(app_state.config.jwt_secret.as_bytes()),
        &Validation::new(token_header.alg),
    )
    .map_err(|err| {
        dbg!(err);
        return AppError::Unauthorized;
    })?;

    let user_ref = user_claims.claims.sub;
    let user = get_user_by_id(&user_ref, &app_state.pg_pool)
        .await
        .map_err(|err| {
            dbg!(err);
            return AppError::Unauthorized;
        })?;

    request.extensions_mut().insert(user);
    return Ok(next.run(request).await);
}

pub fn encode_user_claims(user_claims: &UserClaims, secret: &String) -> Result<String, AppError> {
    let token = encode(
        &Header::default(),
        user_claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|err| {
        dbg!(err);
        return AppError::InternalServerError;
    })?;

    return Ok(token);
}
