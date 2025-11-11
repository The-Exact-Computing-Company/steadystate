use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::time::Duration;

use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Test Helpers (copied from your existing tests so this file is standalone)
// ---------------------------------------------------------------------------

fn run_cli(
    tempdir: Option<&TempDir>,
    extra_env: &[(&str, String)],
    args: &[&str],
) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_steadystate"));
    if let Some(dir) = tempdir {
        cmd.env("STEADYSTATE_CONFIG_DIR", dir.path());
    }
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    cmd.args(args);
    cmd.output().expect("run steadystate cli")
}

fn write_session(tempdir: &TempDir, login: &str, jwt: &str, jwt_exp: Option<u64>) {
    let service_dir = tempdir.path().join("steadystate");
    fs::create_dir_all(&service_dir).expect("create service dir");
    let session_path = service_dir.join("session.json");
    let session = serde_json::json!({
        "login": login,
        "jwt": jwt,
        "jwt_exp": jwt_exp,
    });
    fs::write(&session_path, serde_json::to_vec_pretty(&session).unwrap())
        .expect("write session file");
}

fn create_session_with_future_expiry(tempdir: &TempDir) {
    let future = std::time::SystemTime::now()
        .checked_add(Duration::from_secs(3600))
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    write_session(tempdir, "tester", "test-jwt", Some(future));
}

fn full_request_length(buffer: &[u8]) -> Option<usize> {
    let header_end = buffer.windows(4).position(|w| w == b"\r\n\r\n")?;
    let headers = &buffer[..header_end + 4];
    let headers_str = std::str::from_utf8(headers).ok()?;
    let content_length = headers_str
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("Content-Length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let total = header_end + 4 + content_length;
    if buffer.len() >= total {
        Some(total)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Scripted mock server supporting multiple sequential responses
// ---------------------------------------------------------------------------

fn spawn_scripted_server(
    responses: Vec<(String, bool)>,
) -> (String, std::thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind scripted server");
    let addr = listener.local_addr().unwrap();

    let handle = std::thread::spawn(move || {
        let mut requests = Vec::new();

        for (body, is_json) in responses {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buffer = Vec::new();

            loop {
                let mut chunk = [0u8; 1024];
                let n = stream.read(&mut chunk).unwrap();
                if n == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..n]);
                if let Some(len) = full_request_length(&buffer) {
                    buffer.truncate(len);
                    break;
                }
            }

            requests.push(String::from_utf8_lossy(&buffer).to_string());

            let response = if is_json {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
            } else {
                body.clone()
            };

            stream.write_all(response.as_bytes()).unwrap();
        }

        requests
    });

    (format!("http://{}", addr), handle)
}

// ---------------------------------------------------------------------------
// ✅ TEST 1: up handles 401 -> refresh -> success
// ---------------------------------------------------------------------------

#[test]
fn up_handles_401_then_refreshes_then_succeeds() {
    let tempdir = TempDir::new().expect("tempdir");
    create_session_with_future_expiry(&tempdir);

    // Put refresh token in keychain
    keyring::Entry::new("steadystate", "tester")
        .unwrap()
        .set_password("refresh-abc")
        .unwrap();

    let script = vec![
        // First /sessions → 401 unauthorized
        (
            "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_string(),
            false,
        ),
        // /auth/refresh → return fresh JWT
        (r#"{ "jwt": "new-jwt-123" }"#.to_string(), true),
        // Second /sessions → success
        (
            r#"{ "id": "session-999", "ssh_url": "ssh://after-refresh" }"#.to_string(),
            true,
        ),
    ];

    let (base_url, handle) = spawn_scripted_server(script);

    let output = run_cli(
    Some(&tempdir),
    &[("STEADYSTATE_BACKEND", base_url.clone())],
    &["up", "https://github.com/example/repo"],
);

if !output.status.success() {
    eprintln!("=== CLI STDOUT ===\n{}", String::from_utf8_lossy(&output.stdout));
    eprintln!("=== CLI STDERR ===\n{}", String::from_utf8_lossy(&output.stderr));

    let requests = handle.join().unwrap();
    eprintln!("=== SERVER REQUESTS ===");
    for (i, r) in requests.iter().enumerate() {
        eprintln!("--- Request {} ---\n{}\n", i, r);
    }

    panic!("CLI failed unexpectedly");
}
 
    assert!(output.status.success());

    let requests = handle.join().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("POST /sessions"));
    assert!(requests[1].starts_with("POST /auth/refresh"));
    assert!(requests[2].starts_with("POST /sessions"));

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("session-999"));
}

// ---------------------------------------------------------------------------
// ✅ TEST 2: expired JWT forces immediate refresh before /sessions
// ---------------------------------------------------------------------------

#[test]
fn up_forces_refresh_when_jwt_expired() {
    let tempdir = TempDir::new().expect("tempdir");

    // Write expired JWT session
    let expired = std::time::SystemTime::now()
        .checked_sub(Duration::from_secs(10))
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    write_session(&tempdir, "tester", "expired-jwt", Some(expired));

    keyring::Entry::new("steadystate", "tester")
        .unwrap()
        .set_password("refresh-token-xyz")
        .unwrap();

    let script = vec![
        // Refresh returns new JWT
        (r#"{ "jwt": "fresh-jwt-321" }"#.to_string(), true),
        // Then /sessions returns success
        (
            r#"{ "id": "session-expired", "ssh_url": "ssh://expired.example" }"#.to_string(),
            true,
        ),
    ];

    let (base_url, handle) = spawn_scripted_server(script);

    let output = run_cli(
        Some(&tempdir),
        &[("STEADYSTATE_BACKEND", base_url.clone())],
        &["up", "https://github.com/example/repo"],
    );

    assert!(output.status.success());

    let requests = handle.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("POST /auth/refresh"));
    assert!(requests[1].starts_with("POST /sessions"));
}

// ---------------------------------------------------------------------------
// ✅ TEST 3: logout revokes refresh token + removes session file
// ---------------------------------------------------------------------------

#[test]
fn logout_removes_session_and_revokes_refresh() {
    let tempdir = TempDir::new().expect("tempdir");
    create_session_with_future_expiry(&tempdir);

    keyring::Entry::new("steadystate", "tester")
        .unwrap()
        .set_password("refresh-to-revoke")
        .unwrap();

    let script = vec![(
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string(),
        false,
    )];

    let (base_url, handle) = spawn_scripted_server(script);

    let output = run_cli(
        Some(&tempdir),
        &[("STEADYSTATE_BACKEND", base_url.clone())],
        &["logout"],
    );

    assert!(output.status.success());

    let requests = handle.join().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("POST /auth/revoke"));

    // Session file removed
    let session_path = tempdir.path().join("steadystate/session.json");
    assert!(!session_path.exists());

    // Keychain token removed
    let res = keyring::Entry::new("steadystate", "tester")
        .unwrap()
        .get_password();
    assert!(res.is_err());
}
