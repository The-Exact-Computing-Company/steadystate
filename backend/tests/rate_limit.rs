// backend/tests/rate_limit.rs
//
//! Black-box rate-limit tests: serve the real auth router on loopback with
//! tiny per-minute tiers and assert 429s with JSON bodies + retry-after.

// Shared env lock is a tokio Mutex so a guard can be held across `.await`
// (env-mutating tests are serialized; std guards would be a lint error).
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct TestApp {
    base: String,
    _guard: tokio::sync::MutexGuard<'static, ()>,
    saved: Vec<(String, Option<String>)>,
}

impl Drop for TestApp {
    fn drop(&mut self) {
        // SAFETY: still holding the shared lock.
        unsafe {
            for (k, old) in self.saved.drain(..) {
                match old {
                    Some(v) => std::env::set_var(&k, v),
                    None => std::env::remove_var(&k),
                }
            }
        }
    }
}

async fn serve_with_limits(vars: &[(&str, &str)]) -> TestApp {
    let guard = ENV_LOCK.lock().await;
    let mut saved = Vec::new();
    for k in [
        "JWT_SECRET",
        "NOENV_FLAKE_PATH",
        "STEADYSTATE_DB_PATH",
        "HCLOUD_TOKEN",
        "ENABLE_FAKE_AUTH",
        "GITLAB_URL",
        "RATE_LIMIT_TOKEN_PER_MIN",
        "RATE_LIMIT_AUTH_PER_MIN",
        "RATE_LIMIT_DEFAULT_PER_MIN",
    ] {
        saved.push((k.to_string(), std::env::var(k).ok()));
    }
    // SAFETY: serialized by the shared lock.
    unsafe {
        std::env::set_var("JWT_SECRET", "test-secret-for-ratelimit");
        std::env::set_var("NOENV_FLAKE_PATH", "/tmp/dummy-flake");
        std::env::set_var("STEADYSTATE_DB_PATH", ":memory:");
        std::env::remove_var("HCLOUD_TOKEN");
        std::env::set_var("ENABLE_FAKE_AUTH", "1");
        for (k, v) in vars {
            std::env::set_var(k, v);
        }
    }

    let state = steadystate_backend::state::AppState::try_new()
        .await
        .expect("test AppState");
    let app: axum::Router = axum::Router::new()
        .nest("/auth", steadystate_backend::routes::auth::router())
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("serve test app");
    });
    TestApp {
        base,
        _guard: guard,
        saved,
    }
}

/// Local GitLab stand-in that rejects every PAT with 401. Keeps the
/// `/auth/token` test hermetic: without this, `GITLAB_URL` defaults to
/// gitlab.com and the result depends on whether CI has network access
/// (401 when reachable, 502 when the sandbox blocks it).
async fn mock_gitlab_401() -> String {
    let app = axum::Router::new().route(
        "/api/v4/user",
        axum::routing::get(|| async {
            (
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({ "message": "401 Unauthorized" })),
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock gitlab");
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve mock gitlab");
    });
    base
}

#[tokio::test]
async fn token_tier_returns_429_with_json_and_retry_after() {
    let gitlab = mock_gitlab_401().await;
    let app = serve_with_limits(&[
        ("GITLAB_URL", &gitlab),
        ("RATE_LIMIT_TOKEN_PER_MIN", "2"),
        ("RATE_LIMIT_AUTH_PER_MIN", "0"),
        ("RATE_LIMIT_DEFAULT_PER_MIN", "0"),
    ])
    .await;
    let client = reqwest::Client::new();

    // Bogus PAT: the mock GitLab rejects it -> 401, deterministically.
    let mut statuses = Vec::new();
    for _ in 0..3 {
        let resp = client
            .post(format!("{}/auth/token", app.base))
            .json(&serde_json::json!({ "provider": "gitlab", "token": "bogus" }))
            .send()
            .await
            .expect("post token");
        statuses.push(resp.status());
    }
    assert_eq!(
        statuses,
        vec![
            reqwest::StatusCode::UNAUTHORIZED,
            reqwest::StatusCode::UNAUTHORIZED,
            reqwest::StatusCode::TOO_MANY_REQUESTS,
        ]
    );

    // 429 carries the API JSON error shape and Retry-After.
    let resp = client
        .post(format!("{}/auth/token", app.base))
        .json(&serde_json::json!({ "provider": "gitlab", "token": "bogus" }))
        .send()
        .await
        .expect("post token again");
    assert_eq!(resp.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().contains_key("retry-after"));
    let body: serde_json::Value = resp.json().await.expect("429 json body");
    assert!(
        body.get("error")
            .and_then(|e| e.as_str())
            .map(|e| e.contains("rate limited"))
            .unwrap_or(false),
        "unexpected 429 body: {}",
        body
    );
}

#[tokio::test]
async fn device_tier_returns_429() {
    let app = serve_with_limits(&[
        ("RATE_LIMIT_TOKEN_PER_MIN", "0"),
        ("RATE_LIMIT_AUTH_PER_MIN", "1"),
        ("RATE_LIMIT_DEFAULT_PER_MIN", "0"),
    ])
    .await;
    let client = reqwest::Client::new();

    // Fake provider is enabled: first device start succeeds.
    let first = client
        .post(format!("{}/auth/device?provider=fake", app.base))
        .send()
        .await
        .expect("post device");
    assert_eq!(first.status(), reqwest::StatusCode::OK);

    let second = client
        .post(format!("{}/auth/device?provider=fake", app.base))
        .send()
        .await
        .expect("post device again");
    assert_eq!(second.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
}
