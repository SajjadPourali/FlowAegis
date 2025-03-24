use thiserror::Error;

#[derive(Error, Debug)]
pub enum AegisError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Config error: {0}")]
    ConfigError(#[from] toml::de::Error),
}
