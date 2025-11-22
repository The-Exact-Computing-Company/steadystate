// backend/src/main.rs

// ... (same imports)
use std::net::SocketAddr;
use axum::Router;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use steadystate_backend::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let state = AppState::try_new().await?;

    let app: Router = Router::new()
        .nest("/auth", steadystate_backend::routes::auth::router())
        .nest("/sessions", steadystate_backend::routes::sessions::router())
        // Pass Arc<AppState> directly - do NOT dereference and clone!
        // Each clone of Arc points to the same underlying AppState.
        .with_state(state.clone()) 
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

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
