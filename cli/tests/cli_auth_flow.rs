use std::fs;
use std::io::Read;
use std::process::Output;
use tempfile::TempDir;
use mockito::{Matcher, Server};

// --- Utility helpers ---

fn write_session(path: &TempDir, login: &str, jwt: &str, jwt_exp: Option<u64>) {
    let dir = path.path().join("steadystate");
    fs::create_dir_all(&dir).unwrap();
    let sess_path = dir.join("session.json");
    let sess = serde_json::json!({
        "login": login,
        "jwt": jwt,
        "jwt_exp": jwt_exp
    });
    fs::write(sess_path, serde_json::to_vec_pretty(&sess).unwrap()).unwrap();
}

fn run_cli(path: Option<&TempDir>, envs: &[(&str, String)], args: &[&str]) -> Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_steadystate"));
    if let Some(p) = path {
        cmd.env("STEADYSTATE_CONFIG_DIR", p.path());
    }
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.args(args);
    cmd.output().expect("run cli")
}

// --- TESTS ---
#[test]
fn up_makes_authenticated_request() {
    let td = TempDir::new().unwrap();

    // Write a valid session with a non-expired JWT
    let future_exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() + 3600; // Expires in 1 hour
    write_session(&td, "me", "VALID_JWT", Some(future_exp));
    
    let mut server = Server::new();
    let url = server.url();

    // Mock successful authenticated request
    let mock_sessions = server.mock("POST", "/sessions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"abc","ssh_url":"ssh://ok"}"#)
        .match_header("Authorization", "Bearer VALID_JWT")
        .expect(1)
        .create();

    let out = run_cli(
        Some(&td),
        &[("STEADYSTATE_BACKEND", url)],
        &["up", "https://github.com/x/y"],
    );
    
    mock_sessions.assert();
    
    assert!(out.status.success(), "CLI command failed with stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("✅ Session created"));
}

#[test]
fn up_forces_refresh_when_jwt_expired() {
    let td = TempDir::new().unwrap();

    let setup = run_cli(None, &[], &["test-setup-keychain", "me", "MY_REFRESH_TOKEN"]);
    assert!(setup.status.success(), "Failed to set up keychain for test. Stderr: {}", String::from_utf8_lossy(&setup.stderr));

    let expired = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - 10;
    write_session(&td, "me", "EXPIRED_JWT", Some(expired));

    let mut server = Server::new();
    let url = server.url();

    // Mock the proactive refresh request.
    // FIX: We remove `.match_body()` here too for robustness.
    let mock_refresh = server.mock("POST", "/auth/refresh")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"jwt":"FRESH"}"#)
        .expect(1)
        .create();

    // Mock the original /sessions request, now with the fresh token
    let mock_sessions = server.mock("POST", "/sessions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"abc","ssh_url":"ssh://ok"}"#)
        .match_header("Authorization", "Bearer FRESH")
        .expect(1)
        .create();

    let out = run_cli(
        Some(&td),
        &[("STEADYSTATE_BACKEND", url)],
        &["up", "https://github.com/x/y"],
    );

    mock_refresh.assert();
    mock_sessions.assert();

    assert!(out.status.success(), "CLI command failed with stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("✅ Session created"));
}

#[test]
fn logout_removes_session_and_revokes_refresh() {
    let td = TempDir::new().unwrap();

    write_session(&td, "me", "jwt", Some(5_000_000_000));
    
    let setup = run_cli(None, &[], &["test-setup-keychain", "me", "MY_REFRESH_TOKEN"]);
    assert!(setup.status.success(), "Failed to set up keychain for test. Stderr: {}", String::from_utf8_lossy(&setup.stderr));
    
    let mut server = Server::new();
    let url = server.url();

    // Mock the revoke endpoint
    let mock_revoke = server.mock("POST", "/auth/revoke")
        .with_status(204)
        .match_body(Matcher::JsonString(r#"{"refresh_token":"MY_REFRESH_TOKEN"}"#.to_string()))
        .expect(1)
        .create();

    let out = run_cli(
        Some(&td),
        &[("STEADYSTATE_BACKEND", url)],
        &["logout"],
    );

    mock_revoke.assert();

    assert!(out.status.success(), "CLI command failed with stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Logged out"));
    assert!(!td.path().join("steadystate/session.json").exists());
}
