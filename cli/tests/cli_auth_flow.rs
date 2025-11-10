use std::fs;
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

// Helper to setup keychain via CLI (since we can't import the lib)
fn setup_keychain(login: &str, token: &str) -> Output {
    run_cli(None, &[], &["test-setup-keychain", login, token])
}

// --- TESTS ---

#[tokio::test]
async fn up_handles_401_then_refreshes_then_succeeds() {
    let td = TempDir::new().unwrap();
    
    let setup = setup_keychain("me", "MY_REFRESH_TOKEN");
    assert!(setup.status.success(), "Failed to set up keychain");

    write_session(&td, "me", "OLD_JWT", Some(5_000_000_000));
    
    let mut server = Server::new_async().await;
    let url = server.url();

    let mock_sessions_1 = server.mock("POST", "/sessions")
        .with_status(401)
        .match_header("authorization", Matcher::Regex("Bearer OLD_JWT".to_string()))
        .expect(1)
        .create_async().await;

    let mock_refresh = server.mock("POST", "/auth/refresh")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"jwt":"NEW_JWT"}"#)
        .expect(1)
        .create_async().await;

    let mock_sessions_2 = server.mock("POST", "/sessions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"abc","ssh_url":"ssh://ok"}"#)
        .match_header("authorization", Matcher::Regex("Bearer NEW_JWT".to_string()))
        .expect(1)
        .create_async().await;

    let out = run_cli(
        Some(&td),
        &[("STEADYSTATE_BACKEND", url)],
        &["up", "https://github.com/x/y"],
    );
    
    mock_sessions_1.assert_async().await;
    mock_refresh.assert_async().await;
    mock_sessions_2.assert_async().await;
    
    assert!(out.status.success(), "CLI command failed with stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("✅ Session created"));
}

#[tokio::test]
async fn up_forces_refresh_when_jwt_expired() {
    let td = TempDir::new().unwrap();

    let setup = setup_keychain("me", "MY_REFRESH_TOKEN");
    assert!(setup.status.success(), "Failed to set up keychain");

    let expired = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() - 10;
    write_session(&td, "me", "EXPIRED_JWT", Some(expired));

    let mut server = Server::new_async().await;
    let url = server.url();

    let mock_refresh = server.mock("POST", "/auth/refresh")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"jwt":"FRESH"}"#)
        .expect(1)
        .create_async().await;

    let mock_sessions = server.mock("POST", "/sessions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"abc","ssh_url":"ssh://ok"}"#)
        .match_header("authorization", Matcher::Regex("Bearer FRESH".to_string()))
        .expect(1)
        .create_async().await;

    let out = run_cli(
        Some(&td),
        &[("STEADYSTATE_BACKEND", url)],
        &["up", "https://github.com/x/y"],
    );

    mock_refresh.assert_async().await;
    mock_sessions.assert_async().await;

    assert!(out.status.success(), "CLI command failed with stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("✅ Session created"));
}

#[tokio::test]
async fn logout_removes_session_and_revokes_refresh() {
    let td = TempDir::new().unwrap();

    write_session(&td, "me", "jwt", Some(5_000_000_000));
    
    let setup = setup_keychain("me", "MY_REFRESH_TOKEN");
    assert!(setup.status.success(), "Failed to set up keychain");
    
    let mut server = Server::new_async().await;
    let url = server.url();

    let mock_revoke = server.mock("POST", "/auth/revoke")
        .with_status(204)
        .match_body(Matcher::JsonString(r#"{"refresh_token":"MY_REFRESH_TOKEN"}"#.to_string()))
        .expect(1)
        .create_async().await;

    let out = run_cli(
        Some(&td),
        &[("STEADYSTATE_BACKEND", url)],
        &["logout"],
    );

    mock_revoke.assert_async().await;

    assert!(out.status.success(), "CLI command failed with stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Logged out"));
    assert!(!td.path().join("steadystate/session.json").exists());
}
