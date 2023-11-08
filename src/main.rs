mod app_state;
mod config;
mod controllers;
mod db_functions;
mod error;
mod middlewares;
mod models;

use axum::{
    extract::Extension,
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use dotenv::dotenv;
use models::auth::User;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::app_state::AppState;
use crate::config::Config;
use crate::middlewares::jwt_auth::authenticate;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let config = Config::init();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "axum-api=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Initialize cors, defaulting to any, TODO might change later!
    let cors = CorsLayer::new().allow_origin(Any);

    // Initialize postgres database pool
    let pg_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await
        .expect("Unable to connect to database");

    // TODO - Remove this quick and dirty migration ...
    // use sqlx cli tool instead!
    match sqlx::migrate!("./migrations").run(&pg_pool).await {
        Ok(_) => {
            println!("Migrations successful");
        }
        Err(err) => match err {
            sqlx::migrate::MigrateError::VersionMismatch(_) => {
                match sqlx::query("DROP TABLE _sqlx_migrations, users")
                    .execute(&pg_pool)
                    .await
                {
                    Ok(_) => match sqlx::migrate!("./migrations").run(&pg_pool).await {
                        Ok(_) => println!("Migrations successful after tables were droped"),
                        Err(err) => panic!("Failed to run migrations after tabled droped {}", err),
                    },
                    Err(err) => {
                        panic!("Failed to run query {}", err);
                    }
                }
            }
            _ => {
                panic!("Failed to run migrations {}", err);
            }
        },
    }

    let app_state = AppState { pg_pool, config };

    let app = Router::new()
        .route(
            "/auth",
            get(check_auth_route).route_layer(middleware::from_fn_with_state(
                app_state.clone(),
                authenticate,
            )),
        )
        .route("/", get(health_checker))
        .route("/register", post(controllers::auth::register))
        .route("/login", post(controllers::auth::login))
        .layer(cors)
        // .layer(Extension(app_state))
        .with_state(app_state);

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .expect("Failed to start server");
}

pub async fn health_checker() -> impl IntoResponse {
    let json_response = json!({
        "status": "success",
        "message": "Server is running"
    });

    return Json(json_response);
}

pub async fn check_auth_route(Extension(user): Extension<User>) -> impl IntoResponse {
    let json_response = json!({
        "status": "success",
        "message": "Auth is working",
        "user": user,
    });

    return Json(json_response);
}
