// backend/src/main.rs

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{EnvFilter, fmt};

// Declare all the top-level modules your binary will use.
mod state;
mod jwt;
mod models;
mod routes;
mod auth;
mod compute;

use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    //
    // ---- Logging Setup ----
    //
    let filter = EnvFilter::from_default_env()
        .add_directive("axum::rejection=warn".parse()?)
        .add_directive("reqwest=warn".parse()?)
        .add_directive("steadystate_backend=info".parse()?);

    fmt()
        .with_env_filter(filter)
        .compact()
        .init();

    //
    // ---- Application State ----
    //
    let state = AppState::try_new().await?;

    //
    // ---- Router Setup ----
    //
    let app: Router = Router::new()
        // Use the full path from the crate root to the router function.
        // This is the clearest and most idiomatic way.
        .nest("/auth", crate::routes::auth::router())
        .nest("/sessions", crate::routes::sessions::router())
        .with_state(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    //
    // ---- Bind & Serve ----
    //
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
