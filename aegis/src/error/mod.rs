use thiserror::Error;

#[derive(Error, Debug)]
pub enum AegisError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Config error: {0}")]
    ConfigError(#[from] toml::de::Error),
    #[error("Command Not Found")]
    CommandNotFound,
    #[error("Error: illegal character\nTry 'tool --help' for more information.")]
    Encoding,
    #[error("Config Not Found")]
    ConfigNotFound,
    #[error("Invalid Config")]
    InvalidConfig,
    #[error("Invalid Config Path")]
    InvalidConfigPath,
    #[error("Error: argument {0} is required")]
    RequiredValue(&'static str),
    #[error("Error: argument {0} is invalid")]
    InvalidValue(&'static str),
}
