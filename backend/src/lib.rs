// backend/src/lib.rs

use std::net::SocketAddr;
use std::sync::Arc;
use axum::Router;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{EnvFilter, fmt};

// Make modules public so they can be used by the binary and integration tests
pub mod state;
pub mod jwt;
pub mod models;
pub mod routes;
pub mod auth;

use crate::state::AppState;
use crate::routes::auth::router as auth_router;

/// The main application entry point, now in the library.
pub async fn run() -> anyhow::Result<()> {
    // ---- Logging Setup ----
    let filter = EnvFilter::from_default_env()
        .add_directive("axum::rejection=warn".parse()?)
        .add_directive("reqwest=warn".parse()?)
        .add_directive("steadystate_backend=info".parse()?);

    fmt()
        .with_env_filter(filter)
        .compact()
        .init();

    // ---- Application State ----
    let state = AppState::try_new().await?;

    // ---- Router Setup ----
    let app = app_router(state);

    // ---- Bind & Serve ----
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    tracing::info!("SteadyState backend listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Creates the application's Axum router.
/// This is public so that it can be used by integration tests.
pub fn app_router(state: Arc<AppState>) -> Router {
    Router::new()
        .nest("/auth", auth_router())
        .with_state(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
} 
