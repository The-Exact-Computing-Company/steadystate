use once_cell::sync::Lazy;

pub const SERVICE_NAME: &str = "steadystate";
pub const BACKEND_ENV: &str = "STEADYSTATE_BACKEND"; // e.g. https://api.steadystate.dev
pub const CONFIG_OVERRIDE_ENV: &str = "STEADYSTATE_CONFIG_DIR";
pub const DEFAULT_BACKEND: &str = "https://localhost:8080";
pub const JWT_REFRESH_BUFFER_SECS: u64 = 60;
pub const DEVICE_POLL_MAX_INTERVAL_SECS: u64 = 30;
pub const DEVICE_POLL_REQUEST_TIMEOUT_SECS: u64 = 10;
pub const HTTP_TIMEOUT_SECS: u64 = 30;
pub const RETRY_DELAY_MS: u64 = 500;
pub const MAX_NETWORK_RETRIES: u32 = 3;
pub const USER_AGENT: &str = "SteadyStateCLI/0.2";
pub const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

pub static BACKEND_URL: Lazy<String> =
    Lazy::new(|| std::env::var(BACKEND_ENV).unwrap_or_else(|_| DEFAULT_BACKEND.to_string()));
