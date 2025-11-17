// backend/tests/test_state.rs

use steadystate_backend::models::ProviderId;
use steadystate_backend::state::AppState;
use std::sync::Arc;

/// Helper to create a test AppState.
async fn setup_state() -> Arc<AppState> {
    // Ensure env vars are clean for each test
    std::env::remove_var("GITHUB_CLIENT_ID");
    std::env::remove_var("GITHUB_CLIENT_SECRET");
    std::env::set_var("JWT_SECRET", "test-secret");
    std::env::set_var("ENABLE_FAKE_AUTH", "1");
    
    AppState::try_new().await.expect("Failed to create test state")
}

#[tokio::test]
async fn test_get_provider_success_and_cache() {
    let state = setup_state().await;

    // First call: should create and return the fake provider
    let provider_id = ProviderId::from("fake");
    let provider1_result = state.get_or_create_provider(&provider_id).await;
    assert!(provider1_result.is_ok());
    let provider1 = provider1_result.unwrap();
    assert_eq!(provider1.id().as_str(), "fake");

    // Second call: should return the cached instance
    let provider2_result = state.get_or_create_provider(&provider_id).await;
    assert!(provider2_result.is_ok());
    let provider2 = provider2_result.unwrap();

    // Verify they are the same instance by comparing the Arc pointers
    assert!(Arc::ptr_eq(&provider1, &provider2), "Provider was not cached!");
}

#[tokio::test]
async fn test_get_provider_fails_for_unconfigured_provider() {
    let state = setup_state().await;
    
    // Attempt to get the GitHub provider without setting its env vars
    let provider_id = ProviderId::from("github");
    let result = state.get_or_create_provider(&provider_id).await;

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    // More robust assertion: check for stable keywords.
    assert!(err_msg.contains("GITHUB_CLIENT_ID"));
    assert!(err_msg.contains("not configured"));
}

#[tokio::test]
async fn test_get_provider_fails_for_unknown_provider() {
    let state = setup_state().await;

    let provider_id = ProviderId::from("non-existent-provider");
    let result = state.get_or_create_provider(&provider_id).await;

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    // More robust assertion.
    assert!(err_msg.contains("Unknown") || err_msg.contains("unsupported"));
    assert!(err_msg.contains("provider"));
}
