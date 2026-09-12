use thiserror::Error;

#[derive(Error, Debug)]
pub enum ComputeError {
    #[error("Provider error: {0}")]
    ProviderError(String),

    #[error("Execution error: {0}")]
    ExecutionError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Unsupported operation: {0}")]
    Unsupported(String),
}
