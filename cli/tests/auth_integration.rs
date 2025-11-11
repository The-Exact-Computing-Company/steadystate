use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::time::Duration;
use tempfile::TempDir;

// Using a module to encapsulate all the test infrastructure.
// The tests themselves remain clean and at the top level.
mod helpers {
    use super::*;
    use serde_json::json;

    /// Defines the possible scripted responses from the mock server.
    /// This makes test scripts more readable and less error-prone.
    pub enum MockResponse {
        /// Responds with HTTP 200 OK and a JSON body.
        Json(serde_json::Value),
        /// Responds with HTTP 401 Unauthorized.
        Unauthorized,
        /// Responds with a generic HTTP 200 OK and no body.
        Ok,
    }

    impl MockResponse {
        /// Converts the enum variant into a full HTTP response string.
        /// Crucially, it ensures `Connection: close` is always present.
        fn into_http_string(self) -> String {
            match self {
                MockResponse::Json(val) => {
                    let body = serde_json::to_string(&val).unwrap();
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    )
                }
                MockResponse::Unauthorized => {
                    "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_string()
                }
                MockResponse::Ok => {
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_string()
                }
            }
        }
    }

    /// Manages the entire environment for a single integration test run.
    /// - Creates a temporary directory for config/session files.
    /// - Spawns a scripted mock backend server.
    /// - Provides helpers to set up preconditions (session files, keyring).
    /// - Provides a method to run the CLI and assert its success, capturing
    ///   server requests and providing rich debug output on failure.
    pub struct TestHarness {
        pub tempdir: TempDir,
        server_url: String,
        server_handle: Option<std::thread::JoinHandle<Vec<String>>>,
    }

    impl TestHarness {
        /// Creates a new test harness, spinning up a mock server with the given script.
        pub fn new(script: Vec<MockResponse>) -> Self {
            let tempdir = TempDir::new().expect("create tempdir");
            let (server_url, server_handle) = spawn_scripted_server(script);
            Self {
                tempdir,
                server_url,
                server_handle: Some(server_handle),
            }
        }

        /// Runs the CLI with the given arguments, automatically setting the required
        /// environment variables.
        ///
        /// On success, it returns the process output and a vec of requests the server received.
        /// On failure, it panics with detailed output from the CLI and the server.
        pub fn run_cli_and_assert(mut self, args: &[&str]) -> (Output, Vec<String>) {
            let output = {
                let mut cmd = Command::new(env!("CARGO_BIN_EXE_steadystate"));
                cmd.env("STEADYSTATE_CONFIG_DIR", self.tempdir.path());
                cmd.env("STEADYSTATE_BACKEND", &self.server_url);
                cmd.args(args);
                cmd.output().expect("run steadystate cli")
            };

            let requests = self.server_handle.take().unwrap().join().unwrap();

            if !output.status.success() {
                eprintln!("=== CLI STDOUT ===\n{}", String::from_utf8_lossy(&output.stdout));
                eprintln!("=== CLI STDERR ===\n{}", String::from_utf8_lossy(&output.stderr));
                eprintln!("=== SERVER REQUESTS ===");
                for (i, r) in requests.iter().enumerate() {
                    eprintln!("--- Request {} ---\n{}\n", i, r);
                }
                panic!("CLI failed unexpectedly");
            }

            (output, requests)
        }

        /// Helper to write a session.json file within the test's temp directory.
        pub fn create_session(&self, login: &str, jwt: &str, jwt_exp: Option<u64>) {
            let service_dir = self.tempdir.path().join("steadystate");
            fs::create_dir_all(&service_dir).expect("create service dir");
            let session_path = service_dir.join("session.json");
            let session = json!({ "login": login, "jwt": jwt, "jwt_exp": jwt_exp });
            fs::write(&session_path, serde_json::to_vec_pretty(&session).unwrap())
                .expect("write session file");
        }

        /// Helper to create a session file with a valid (future) expiry.
        pub fn create_future_session(&self) {
            let future = std::time::SystemTime::now()
                .checked_add(Duration::from_secs(3600))
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            self.create_session("tester", "test-jwt", Some(future));
        }

        /// Helper to create a session file with an expired JWT.
        pub fn create_expired_session(&self) {
            let expired = std::time::SystemTime::now()
                .checked_sub(Duration::from_secs(10))
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            self.create_session("tester", "expired-jwt", Some(expired));
        }

        /// Helper to set a password in the keyring for the given user.
        pub fn set_keyring_password(&self, username: &str, password: &str) {
            keyring::Entry::new("steadystate", username)
                .unwrap()
                .set_password(password)
                .unwrap();
        }
    }

    /// Spawns a simple TCP server that serves a predefined sequence of responses.
    fn spawn_scripted_server(
        responses: Vec<MockResponse>,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind scripted server");
        let addr = listener.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept connection");
                let mut buffer = Vec::new();

                // Simple loop to read a full HTTP request based on Content-Length.
                loop {
                    let mut chunk = [0u8; 1024];
                    let n = stream.read(&mut chunk).unwrap();
                    if n == 0 { break; }
                    buffer.extend_from_slice(&chunk[..n]);
                    if full_request_length(&buffer).is_some() { break; }
                }

                requests.push(String::from_utf8_lossy(&buffer).to_string());
                stream.write_all(response.into_http_string().as_bytes()).unwrap();
            }
            requests
        });

        (format!("http://{}", addr), handle)
    }

    /// Utility to find the total length of an HTTP request in a buffer.
    fn full_request_length(buffer: &[u8]) -> Option<usize> {
        let end = buffer.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
        let headers_str = std::str::from_utf8(&buffer[..end]).ok()?;
        let content_length = headers_str
            .lines()
            .find_map(|line| line.to_lowercase().strip_prefix("content-length:")?.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let total = end + content_length;
        if buffer.len() >= total { Some(total) } else { None }
    }
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

use helpers::{MockResponse, TestHarness};
use serde_json::json;

#[test]
fn up_handles_401_then_refreshes_then_succeeds() {
    let script = vec![
        MockResponse::Unauthorized,
        MockResponse::Json(json!({ "jwt": "new-jwt-123" })),
        MockResponse::Json(json!({ "id": "session-999", "ssh_url": "ssh://after-refresh" })),
    ];
    let harness = TestHarness::new(script);
    harness.create_future_session();
    harness.set_keyring_password("tester", "refresh-abc");

    let (output, requests) = harness.run_cli_and_assert(&["up", "https://github.com/example/repo"]);

    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("POST /sessions"));
    assert!(requests[1].starts_with("POST /auth/refresh"));
    assert!(requests[2].starts_with("POST /sessions"));

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("session-999"));
}

#[test]
fn up_forces_refresh_when_jwt_expired() {
    let script = vec![
        MockResponse::Json(json!({ "jwt": "fresh-jwt-321" })),
        MockResponse::Json(json!({ "id": "session-expired", "ssh_url": "ssh://expired.example" })),
    ];
    let harness = TestHarness::new(script);
    harness.create_expired_session();
    harness.set_keyring_password("tester", "refresh-token-xyz");

    let (_, requests) = harness.run_cli_and_assert(&["up", "https://github.com/example/repo"]);

    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("POST /auth/refresh"));
    assert!(requests[1].starts_with("POST /sessions"));
}

#[test]
fn logout_removes_session_and_revokes_refresh() {
    let script = vec![MockResponse::Ok];
    let harness = TestHarness::new(script);
    harness.create_future_session();
    harness.set_keyring_password("tester", "refresh-to-revoke");

    let (_, requests) = harness.run_cli_and_assert(&["logout"]);

    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("POST /auth/revoke"));

    // Session file removed
    let session_path = harness.tempdir.path().join("steadystate/session.json");
    assert!(!session_path.exists(), "Session file was not removed");

    // Keychain token removed
    let res = keyring::Entry::new("steadystate", "tester").unwrap().get_password();
    assert!(res.is_err(), "Keyring entry was not removed");
}
