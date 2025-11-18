// backend/src/main.rs

// ... (same imports)
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{EnvFilter, fmt};

mod state;
mod jwt;
mod models;
mod routes;
mod auth;
mod compute;

use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ... (logging setup)

    let state = AppState::try_new().await?;

    let app: Router = Router::new()
        .nest("/auth", crate::routes::auth::router())
        .nest("/sessions", crate::routes::sessions::router())
        // Dereference the Arc<AppState> to pass AppState by value (it clones cheaply now)
        .with_state((*state).clone()) 
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    // ... (bind & serve)
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
