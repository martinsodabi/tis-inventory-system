use crate::Config;
use sqlx::{Pool, Postgres};

#[derive(Clone)]
pub struct AppState {
    pub pg_pool: Pool<Postgres>,
    pub config: Config,
}
