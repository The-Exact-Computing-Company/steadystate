// backend/tests/test_routes.rs

use axum::{body::Body, http::{Request, StatusCode}, Router};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt; // <-- ADD THIS LINE to bring the .oneshot() method into scope

use steadystate_backend::app_router; // Use the public router function
use steadystate_backend::state::AppState;

/// Helper to create a router backed by a test-configured AppState.
async fn setup_router() -> Router {
    // Setting environment variables is an unsafe operation because it affects
    // the global state of the process and can cause data races if tests run in parallel.
    // We acknowledge this risk by using an unsafe block.
    unsafe {
        std::env::set_var("JWT_SECRET", "api-test-secret");
        std::env::set_var("ENABLE_FAKE_AUTH", "1");
        std::env::remove_var("GITHUB_CLIENT_ID");
        std::env::remove_var("GITHUB_CLIENT_SECRET");
    }

    let state = AppState::try_new().await.unwrap();
    // This now correctly builds the router with the /auth prefix and all layers.
    app_router(state)
}

#[tokio::test]
async fn test_device_start_with_valid_provider() {
    let app = setup_router().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/device?provider=fake")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let data: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(data["user_code"], "FAKE-CODE");
    assert_eq!(data["device_code"], "fake-device-code-123");
}

#[tokio::test]
async fn test_device_start_with_unconfigured_provider() {
    let app = setup_router().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/device?provider=github")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let error_msg = String::from_utf8(body.to_vec()).unwrap();
    assert!(error_msg.contains("GITHUB_CLIENT_ID") && error_msg.contains("not configured"));
}

#[tokio::test]
async fn test_device_start_with_unknown_provider() {
    let app = setup_router().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/device?provider=bogus")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let error_msg = String::from_utf8(body.to_vec()).unwrap();
    assert!(error_msg.contains("Unknown") || error_msg.contains("unsupported"));
}

// --- Expanded tests for /auth/me endpoint ---

#[tokio::test]
async fn test_me_route_success() {
    let app = setup_router().await;
    let state = app.layer_state::<Arc<AppState>>().unwrap().clone();
    let token = state.jwt.sign("test-user", "fake").unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/auth/me")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let data: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(data["login"], "test-user");
    assert_eq!(data["provider"], "fake");
}

#[tokio::test]
async fn test_me_route_fails_for_expired_token() {
    let app = setup_router().await;
    // Create a new JWT key with 0 TTL to make an instantly-expired token
    let expired_keys = steadystate_backend::jwt::JwtKeys::new("api-test-secret", "steadystate", 0);
    let token = expired_keys.sign("test-user", "fake").unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/auth/me")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_me_route_fails_for_wrong_secret() {
    let app = setup_router().await;
    // Token signed with a different secret
    let other_keys = steadystate_backend::jwt::JwtKeys::new("a-different-secret", "steadystate", 60);
    let token = other_keys.sign("test-user", "fake").unwrap();
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/auth/me")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_me_route_fails_for_malformed_header() {
    let app = setup_router().await;
    let state = app.layer_state::<Arc<AppState>>().unwrap().clone();
    let token = state.jwt.sign("test-user", "fake").unwrap();

    // Test case 1: "Bearer" prefix is missing
    let response1 = app.clone().oneshot(
        Request::builder()
            .uri("/auth/me")
            .header("Authorization", token.clone()) // No "Bearer "
            .body(Body::empty())
            .unwrap()
    ).await.unwrap();
    assert_eq!(response1.status(), StatusCode::BAD_REQUEST);

    // Test case 2: No Authorization header at all
    let response2 = app.oneshot(
        Request::builder()
            .uri("/auth/me")
            .body(Body::empty())
            .unwrap()
    ).await.unwrap();
    assert_eq!(response2.status(), StatusCode::UNAUTHORIZED);
} 
