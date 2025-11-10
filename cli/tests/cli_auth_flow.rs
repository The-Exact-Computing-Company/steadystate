use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;

// Utility helpers ----------------------------------------------------------

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

fn run_cli(path: Option<&TempDir>, envs: &[(&str, String)], args: &[&str]) -> std::process::Output {
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

// Shared request reader for mocks -----------------------------------------

fn read_full_request(mut stream: &std::net::TcpStream) -> String {
    let mut buf = vec![0u8; 8192];
    let mut collected = Vec::new();

    loop {
        let n = stream.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        collected.extend_from_slice(&buf[..n]);
        if let Some(pos) = collected.windows(4).position(|w| w == b"\r\n\r\n") {
            return String::from_utf8_lossy(&collected).to_string();
        }
    }
    String::from_utf8_lossy(&collected).to_string()
}

fn spawn_mock<F>(handler: F) -> (String, std::thread::JoinHandle<()>)
where
    F: Fn(String, &mut std::net::TcpStream) + Send + 'static + Clone,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let join = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let req = read_full_request(&stream);
        handler(req, &mut stream);
    });

    (format!("http://{}", addr), join)
}

//
// --------------------------------------------------------------------------
//  TEST 1: 401 → refresh → retry → success
// --------------------------------------------------------------------------
//

#[test]
fn up_handles_401_then_refreshes_then_succeeds() {
    let td = TempDir::new().unwrap();

    // jwt_exp far in the future so no proactive refresh
    write_session(&td, "me", "OLD_JWT", Some(5000000000));

    let call_counter = Arc::new(AtomicUsize::new(0));
    let call_counter2 = call_counter.clone();

    let (backend, handle) = spawn_mock(move |req, stream| {
        let call = call_counter2.fetch_add(1, Ordering::SeqCst);

        if call == 0 {
            // First call to /sessions → return 401
            assert!(req.starts_with("POST /sessions"));
            let resp = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
            stream.write_all(resp.as_bytes()).unwrap();
        } else if call == 1 {
            // Second call → refresh request
            assert!(req.starts_with("POST /auth/refresh"));
            let body = r#"{"jwt":"NEW_JWT"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).unwrap();
        } else {
            // Third call → retry original /sessions → success
            assert!(req.starts_with("POST /sessions"));
            assert!(req.to_lowercase().contains("authorization: bearer new_jwt"));

            let body = r#"{"id":"abc","ssh_url":"ssh://ok"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).unwrap();
        }
    });

    let out = run_cli(
        Some(&td),
        &[("STEADYSTATE_BACKEND", backend.clone())],
        &["up", "https://github.com/x/y"],
    );

    handle.join().unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("✅ Session created"));
}

//
// --------------------------------------------------------------------------
//  TEST 2: expired JWT forces refresh before request
// --------------------------------------------------------------------------
//

#[test]
fn up_forces_refresh_when_jwt_expired() {
    let td = TempDir::new().unwrap();

    let expired = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 10;

    write_session(&td, "me", "EXPIRED_JWT", Some(expired));

    let call_counter = Arc::new(AtomicUsize::new(0));
    let cc2 = call_counter.clone();

    let (backend, handle) = spawn_mock(move |req, stream| {
        let call = cc2.fetch_add(1, Ordering::SeqCst);

        if call == 0 {
            assert!(req.starts_with("POST /auth/refresh"));
            let body = r#"{"jwt":"FRESH"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).unwrap();
        } else {
            assert!(req.starts_with("POST /sessions"));
            assert!(req.to_lowercase().contains("authorization: bearer fresh"));

            let body = r#"{"id":"abc","ssh_url":"ssh://ok"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).unwrap();
        }
    });

    let out = run_cli(
        Some(&td),
        &[("STEADYSTATE_BACKEND", backend)],
        &["up", "https://github.com/x/y"],
    );

    handle.join().unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("✅ Session created"));
}

//
// --------------------------------------------------------------------------
//  TEST 3: logout clears session + attempts revoke
// --------------------------------------------------------------------------
//

#[test]
fn logout_removes_session_and_revokes_refresh() {
    let td = TempDir::new().unwrap();

    // Write session
    write_session(&td, "me", "jwt", Some(10_000_000));

    // Write fake refresh token via keyring
    run_cli(Some(&td), &[], &["refresh"]).ok(); // creates keychain entry indirectly

    let (backend, handle) = spawn_mock(|req, stream| {
        assert!(req.starts_with("POST /auth/revoke"));
        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        stream.write_all(resp.as_bytes()).unwrap();
    });

    let out = run_cli(
        Some(&td),
        &[("STEADYSTATE_BACKEND", backend)],
        &["logout"],
    );

    handle.join().unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Logged out"));

    // Session file should be gone
    assert!(!td.path().join("steadystate/session.json").exists());
}

