// backend/src/main.rs

use steadystate_backend::run;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // The main binary is now just a thin wrapper that calls
    // the library's run function.
    run().await
} 
