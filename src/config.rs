#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expiry_minute: u32,
    pub jwt_maxage: u32,
}

impl Config {
    pub fn init() -> Config {
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        let jwt_expiry_minute =
            std::env::var("JWT_EXPIRY_MINUTE").expect("JWT_EXPIRY_MINUTE must be set");
        let jwt_maxage = std::env::var("JWT_MAXAGE").expect("JWT_MAXAGE must be set");

        return Config {
            database_url,
            jwt_secret,
            jwt_expiry_minute: jwt_expiry_minute.parse::<u32>().unwrap(),
            jwt_maxage: jwt_maxage.parse::<u32>().unwrap(),
        };
    }
}
