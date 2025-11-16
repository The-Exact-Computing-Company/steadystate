// src/main.rs

use std::net::SocketAddr;

use axum::Router;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{EnvFilter, fmt};

mod state;
mod jwt;
mod models;
mod routes;
mod auth;

use crate::state::AppState;
use crate::routes::auth::router as auth_router;

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
    let app: Router<_,> = Router::new()
        .nest("/auth", auth_router())
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
