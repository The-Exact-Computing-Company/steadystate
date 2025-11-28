#![cfg(not(target_os = "macos"))]

// cli/tests/auth_integration.rs

mod common;
use common::{MockResponse, TestHarness};
use serde_json::json;

#[test]
fn up_refreshes_proactively_when_jwt_expired() {
    let script = vec![
        // Proactive refresh call
        MockResponse::Json(json!({ "jwt": "fresh-jwt-123" })),
        // Session creation call
        MockResponse::Json(json!({ "id": "session-xyz", "state": "Running", "endpoint": "ssh://fresh", "message": null, "compute_provider": "local" })),
    ];
    let mut harness = TestHarness::new(script);
    harness.create_expired_session();
    harness.set_keyring_password("tester", "refresh-token-abc");

    let (out, reqs) = harness.run_cli_and_assert_success(&["up", "https://github.com/example/repo", "--env=noenv", "--mode=pair"]);

    assert_eq!(reqs.len(), 2);
    assert!(reqs[0].starts_with("POST /auth/refresh"));
    assert!(reqs[1].starts_with("POST /sessions"));
    assert!(String::from_utf8_lossy(&out.stdout).contains("session-xyz"));
}


#[test]
fn up_errors_gracefully_if_server_returns_401() {
    let script = vec![
        // The server will immediately reject our valid JWT
        MockResponse::Unauthorized,
    ];
    let mut harness = TestHarness::new(script);
    harness.create_future_session(); // Create a session with a non-expired JWT

    // Run the CLI but don't assert success
    let output = harness.run_cli(&["up", "https://github.com/example/repo", "--env=noenv", "--mode=pair"]);
    harness.join_server();

    // Assert that the command failed as expected
    assert!(!output.status.success(), "CLI should exit with a non-zero status");
    
    let stderr = String::from_utf8_lossy(&output.stderr);
    
    // This is the key part of the error message from our `anyhow::bail!` call.
    // By checking for this specific substring, we are robust against formatting
    // changes from the `tracing` crate or the error prefix in `main.rs`.
    let expected_error_substring = "Your session has expired or been revoked";

    assert!(
        stderr.contains(expected_error_substring),
        "Stderr should contain the correct error message.\n\nExpected to find: '{}'\n\nActual stderr:\n---\n{}\n---",
        expected_error_substring,
        stderr
    );
}

#[test]
fn logout_removes_session_and_revokes_refresh() {
    let script = vec![MockResponse::Ok];
    let mut harness = TestHarness::new(script);
    harness.create_future_session();
    harness.set_keyring_password("tester", "refresh-to-revoke");

    let (_, reqs) = harness.run_cli_and_assert_success(&["logout"]);

    assert_eq!(reqs.len(), 1);
    assert!(reqs[0].starts_with("POST /auth/revoke"));
    let json_path = harness.tempdir.path().join("steadystate/session.json");
    assert!(!json_path.exists());
    let res = harness.get_keyring_password("tester");
    assert!(res.is_err()); // Should be deleted
}
