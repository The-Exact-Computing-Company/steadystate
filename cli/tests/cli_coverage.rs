use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::time::Duration;

use tempfile::TempDir;

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

#[test]
fn whoami_displays_human_output_when_logged_in() {
    let tempdir = TempDir::new().expect("tempdir");
    write_session(&tempdir, "test-user", "unused", None);

    let output = run_cli(Some(&tempdir), &[], &["whoami"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Logged in as: test-user"));
    assert!(!stdout.contains("\"logged_in\""));
}

#[test]
fn whoami_displays_json_when_logged_in() {
    let tempdir = TempDir::new().expect("tempdir");
    write_session(&tempdir, "json-user", "unused", Some(1_234_567));

    let output = run_cli(Some(&tempdir), &[], &["whoami", "--json"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("parse json");
    assert_eq!(value["logged_in"], true);
    assert_eq!(value["login"], "json-user");
    assert_eq!(value["jwt_expires_at"], 1_234_567);
}

#[test]
fn whoami_reports_missing_session_plain_text() {
    let tempdir = TempDir::new().expect("tempdir");

    let output = run_cli(Some(&tempdir), &[], &["whoami"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("No active session found. Run 'steadystate login' first."));
}

#[test]
fn whoami_reports_missing_session_json() {
    let tempdir = TempDir::new().expect("tempdir");

    let output = run_cli(Some(&tempdir), &[], &["whoami", "--json"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("parse json");
    assert_eq!(value["logged_in"], false);
    assert!(value["login"].is_null());
    assert!(value["jwt_expires_at"].is_null());
}

#[test]
fn version_flag_prints_version() {
    let output = run_cli(None, &[], &["--version"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("SteadyState CLI version"));
}

#[test]
fn running_without_subcommand_prints_help() {
    let output = run_cli(None, &[], &[]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("SteadyState CLI — Exact reproducible dev envs"));
}

#[test]
fn up_rejects_invalid_repository_url() {
    let tempdir = TempDir::new().expect("tempdir");
    write_session(&tempdir, "tester", "jwt", Some(4_000_000_000));

    let output = run_cli(Some(&tempdir), &[], &["up", "not-a-url"]);
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Invalid repository URL"));
}

fn spawn_mock_server(response_body: String) -> (String, std::thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        let mut buffer = Vec::new();
        let request_len = loop {
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).expect("read request");
            if n == 0 {
                break buffer.len();
            }
            buffer.extend_from_slice(&chunk[..n]);
            if let Some(len) = full_request_length(&buffer) {
                break len;
            }
        };
        let request = String::from_utf8_lossy(&buffer[..request_len]).to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
        request
    });
    (format!("http://{}", addr), handle)
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

fn create_session_with_future_expiry(tempdir: &TempDir) {
    let future = std::time::SystemTime::now()
        .checked_add(Duration::from_secs(3_600))
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    write_session(tempdir, "tester", "test-jwt", Some(future));
}

#[test]
fn up_prints_human_output_on_success() {
    let tempdir = TempDir::new().expect("tempdir");
    create_session_with_future_expiry(&tempdir);

    let response = r#"{"id":"session-123","ssh_url":"ssh://example.com"}"#.to_string();
    let (base_url, handle) = spawn_mock_server(response);

    let output = run_cli(
        Some(&tempdir),
        &[("STEADYSTATE_BACKEND", base_url.clone())],
        &["up", "https://example.com/repo.git"],
    );
    assert!(output.status.success());

    let request = handle.join().expect("join mock server");
    assert!(request.starts_with("POST /sessions"));
    assert!(
        request
            .to_lowercase()
            .contains("authorization: bearer test-jwt")
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("✅ Session created: session-123"));
    assert!(stdout.contains("SSH: ssh://example.com"));
}

#[test]
fn up_prints_json_on_success() {
    let tempdir = TempDir::new().expect("tempdir");
    create_session_with_future_expiry(&tempdir);

    let response = r#"{"id":"session-456","ssh_url":"ssh://json.example.com"}"#.to_string();
    let (base_url, handle) = spawn_mock_server(response);

    let output = run_cli(
        Some(&tempdir),
        &[("STEADYSTATE_BACKEND", base_url.clone())],
        &["up", "https://example.com/repo.git", "--json"],
    );
    assert!(output.status.success());

    let request = handle.join().expect("join mock server");
    assert!(request.starts_with("POST /sessions"));
    assert!(
        request
            .to_lowercase()
            .contains("authorization: bearer test-jwt")
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("parse json");
    assert_eq!(value["id"], "session-456");
    assert_eq!(value["ssh_url"], "ssh://json.example.com");
}
