use std::path::PathBuf;
use steadystate_backend::compute::LocalComputeProvider;
use steadystate_backend::compute::LocalProviderConfig;
use steadystate_backend::compute::ComputeProvider;
use steadystate_backend::models::{Session, SessionRequest, SessionState};

#[tokio::test]
#[ignore]
async fn test_integration_nix_check() {
    // This test runs with the RealCommandExecutor, so it interacts with the system.
    // It checks if `nix` is installed (or tries to install it, which might fail in CI if not privileged/configured).
    // We assume the environment has nix or we can at least run the check.

    // We need a dummy flake path.
    let flake_path = PathBuf::from("/tmp/dummy-flake");
    let session_root = PathBuf::from("/tmp/steadystate-sessions");
    
    let config = LocalProviderConfig {
        session_root,
        flake_path,
    };
    
    let provider = LocalComputeProvider::new(config, reqwest::Client::new());

    // We can't easily call private methods like ensure_nix_installed directly unless we expose them or use start_session.
    // Using start_session involves cloning and upterm, which is heavy.
    // Ideally, we'd test public methods.
    
    // Let's try to start a session with a repo that definitely exists and is small, 
    // or just check if we can instantiate and run something simple.
    // But start_session does everything.
    
    // For this integration test, let's just verify we can create the provider and it has the real executor.
    // To actually test functionality, we'd need to run start_session.
    
    // Let's try to run a session with a non-existent repo, expecting a git failure from the REAL git command.
    // This verifies that the RealCommandExecutor is working and propagating errors.

    let session = Session {
        id: "integration-test-session".into(),
        repo_url: "https://github.com/this-repo/does-not-exist-12345.git".into(),
        branch: None,
        environment: None,
        compute_provider: "local".into(),
        creator_login: "integration-user".into(),
        state: SessionState::Provisioning,
        endpoint: None,
        created_at: std::time::SystemTime::now(),
        updated_at: std::time::SystemTime::now(),
        error_message: None,
        magic_link: None,
        host_public_key: None,
    };

    let request = SessionRequest {
        repo_url: "https://github.com/this-repo/does-not-exist-12345.git".into(),
        branch: None,
        environment: None,
        provider_config: None,
        allowed_users: None,
        public: false,
        mode: Some("pair".to_string()),
    };

    let result = provider.start_session(&session.id, &request).await;
    
    // We expect an error because the repo doesn't exist.
    // If RealCommandExecutor is working, it will try to run `git clone ...` and fail.
    assert!(result.is_err());
    
    // Verify the error message contains something about git or not found
    let err = result.unwrap_err();
    println!("Integration test error (expected): {:#}", err);
    // The error from LocalComputeProvider::clone_repo is "git clone failed for ..."
    assert!(err.to_string().contains("git clone failed"));
}
