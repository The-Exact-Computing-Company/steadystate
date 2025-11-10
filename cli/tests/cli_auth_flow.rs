use std::fs;
use std::io::Read;
use std::process::Output;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::TempDir;

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

// --- Mock Server using `rouille` ---

struct MockServer {
    addr: String,
    // The handle to the server. When this is dropped, the server shuts down.
    _handle: rouille::Server<()>,
}

impl MockServer {
    fn new<F>(handler: F) -> Self
    where
        F: Fn(&rouille::Request) -> rouille::Response + Send + Sync + 'static,
    {
        // rouille::Server::new will find an available port on 127.0.0.1
        let server = rouille::Server::new("127.0.0.1:0", handler).unwrap();
        let addr = server.server_addr().to_string();

        Self {
            addr: format!("http://{}", addr),
            _handle: server,
        }
    }
}

//
// --- TESTS ---
//

#[test]
fn up_handles_401_then_refreshes_then_succeeds() {
    let td = TempDir::new().unwrap();

    let setup = run_cli(None, &[], &["test-setup-keychain", "me", "MY_REFRESH_TOKEN"]);
    assert!(setup.status.success(), "Failed to set up keychain for test");

    write_session(&td, "me", "OLD_JWT", Some(5_000_000_000));

    let call_counter = Arc::new(AtomicUsize::new(0));
    let mock_server = MockServer::new({
        let call_counter = Arc::clone(&call_counter);
        move |request| {
            let call = call_counter.fetch_add(1, Ordering::SeqCst);
            match (call, request.url().as_str()) {
                (0, "/sessions") => {
                    assert_eq!(request.method(), "POST");
                    assert_eq!(request.header("Authorization").unwrap(), "Bearer OLD_JWT");
                    rouille::Response::empty_401()
                }
                (1, "/auth/refresh") => {
                    assert_eq!(request.method(), "POST");
                    rouille::Response::json(&serde_json::json!({"jwt": "NEW_JWT"}))
                }
                (2, "/sessions") => {
                    assert_eq!(request.method(), "POST");
                    assert_eq!(request.header("Authorization").unwrap(), "Bearer NEW_JWT");
                    rouille::Response::json(&serde_json::json!({"id":"abc","ssh_url":"ssh://ok"}))
                }
                _ => {
                    panic!("Unexpected request: call {} to {}", call, request.url());
                }
            }
        }
    });

    let out = run_cli(
        Some(&td),
        &[("STEADYSTATE_BACKEND", mock_server.addr.clone())],
        &["up", "https://github.com/x/y"],
    );

    assert!(out.status.success(), "CLI command failed with stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("✅ Session created"));
}

#[test]
fn up_forces_refresh_when_jwt_expired() {
    let td = TempDir::new().unwrap();

    let setup = run_cli(None, &[], &["test-setup-keychain", "me", "MY_REFRESH_TOKEN"]);
    assert!(setup.status.success(), "Failed to set up keychain for test");

    let expired = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - 10;
    write_session(&td, "me", "EXPIRED_JWT", Some(expired));

    let call_counter = Arc::new(AtomicUsize::new(0));
    let mock_server = MockServer::new({
        let call_counter = Arc::clone(&call_counter);
        move |request| {
            let call = call_counter.fetch_add(1, Ordering::SeqCst);
            match (call, request.url().as_str()) {
                (0, "/auth/refresh") => {
                    assert_eq!(request.method(), "POST");
                    rouille::Response::json(&serde_json::json!({"jwt":"FRESH"}))
                }
                (1, "/sessions") => {
                    assert_eq!(request.method(), "POST");
                    assert_eq!(request.header("Authorization").unwrap(), "Bearer FRESH");
                    rouille::Response::json(&serde_json::json!({"id":"abc","ssh_url":"ssh://ok"}))
                }
                _ => panic!("Unexpected request: call {} to {}", call, request.url()),
            }
        }
    });

    let out = run_cli(
        Some(&td),
        &[("STEADYSTATE_BACKEND", mock_server.addr.clone())],
        &["up", "https://github.com/x/y"],
    );

    assert!(out.status.success(), "CLI command failed with stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("✅ Session created"));
}

#[test]
fn logout_removes_session_and_revokes_refresh() {
    let td = TempDir::new().unwrap();

    write_session(&td, "me", "jwt", Some(5_000_000_000));
    
    let setup = run_cli(None, &[], &["test-setup-keychain", "me", "MY_REFRESH_TOKEN"]);
    assert!(setup.status.success(), "Failed to set up keychain for test");

    let mock_server = MockServer::new(|request| {
        assert_eq!(request.method(), "POST");
        assert_eq!(request.url(), "/auth/revoke");
        
        let mut data = request.data().unwrap();
        let mut body = String::new();
        data.read_to_string(&mut body).unwrap();
        let json_body: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(json_body["refresh_token"], "MY_REFRESH_TOKEN");

        rouille::Response::empty_204()
    });

    let out = run_cli(
        Some(&td),
        &[("STEADYSTATE_BACKEND", mock_server.addr.clone())],
        &["logout"],
    );

    assert!(out.status.success(), "CLI command failed with stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Logged out"));
    assert!(!td.path().join("steadystate/session.json").exists());
}
