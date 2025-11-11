// cli/tests/auth_integration.rs

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::time::Duration;
use tempfile::TempDir;

// Using a module to encapsulate all the test infrastructure.
mod helpers {
    use super::*;
    use serde_json::json;

    /// Pre-scripted responses our tiny mock backend returns.
    pub enum MockResponse {
        /// 200 OK with a JSON body.
        Json(serde_json::Value),
        /// 401 Unauthorized with empty body.
        Unauthorized,
        /// 200 OK with empty body.
        Ok,
    }

    impl MockResponse {
        fn into_http_string(self) -> String {
            match self {
                MockResponse::Json(val) => {
                    let body = serde_json::to_string(&val).unwrap();
                    format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: application/json\r\n\
                         Connection: close\r\n\
                         Content-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    )
                }
                MockResponse::Unauthorized => {
                    "HTTP/1.1 401 Unauthorized\r\n\
                     Connection: close\r\n\
                     Content-Length: 0\r\n\r\n"
                        .to_string()
                }
                MockResponse::Ok => {
                    "HTTP/1.1 200 OK\r\n\
                     Connection: close\r\n\
                     Content-Length: 0\r\n\r\n"
                        .to_string()
                }
            }
        }
    }

    /// Test harness that spins a scripted server and gives you a temp config dir.
    pub struct TestHarness {
        pub tempdir: TempDir,
        server_url: String,
        server_handle: Option<std::thread::JoinHandle<Vec<String>>>,
    }

    impl TestHarness {
        pub fn new(script: Vec<MockResponse>) -> Self {
            let tempdir = TempDir::new().expect("create tempdir");
            let (server_url, server_handle) = spawn_scripted_server(script);
            Self {
                tempdir,
                server_url,
                server_handle: Some(server_handle),
            }
        }

        /// Run the CLI once. On failure, dumps stdout/stderr and the captured requests.
        pub fn run_cli_and_assert(&mut self, args: &[&str]) -> (Output, Vec<String>) {
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

        /// Write a session.json in our isolated config dir.
        pub fn create_session(&self, login: &str, jwt: &str, jwt_exp: Option<u64>) {
            let service_dir = self.tempdir.path().join("steadystate");
            fs::create_dir_all(&service_dir).expect("create service dir");
            let session_path = service_dir.join("session.json");
            let session = json!({ "login": login, "jwt": jwt, "jwt_exp": jwt_exp });
            fs::write(&session_path, serde_json::to_vec_pretty(&session).unwrap())
                .expect("write session file");
        }

        pub fn create_future_session(&self) {
            let future = std::time::SystemTime::now()
                .checked_add(Duration::from_secs(3600))
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            self.create_session("tester", "test-jwt", Some(future));
        }

        pub fn create_expired_session(&self) {
            let expired = std::time::SystemTime::now()
                .checked_sub(Duration::from_secs(10))
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            self.create_session("tester", "expired-jwt", Some(expired));
        }

        pub fn set_keyring_password(&self, username: &str, password: &str) {
            keyring::Entry::new("steadystate", username)
                .unwrap()
                .set_password(password)
                .unwrap();
        }
    }

    /// Minimal scripted HTTP/1.1 server.
    ///
    /// IMPORTANT: it only reads until the end of headers, then replies and closes.
    /// This avoids any dependency on request body framing or Expect: 100-continue.
    fn spawn_scripted_server(
        responses: Vec<MockResponse>,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind scripted server");
        let addr = listener.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let mut requests = Vec::new();

            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept connection");

                // Avoid infinite waits if client does something odd.
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("set read timeout");

                // Read only headers.
                let mut buffer = Vec::new();
                loop {
                    let mut chunk = [0u8; 1024];
                    match stream.read(&mut chunk) {
                        Ok(0) => break, // connection closed
                        Ok(n) => {
                            buffer.extend_from_slice(&chunk[..n]);
                            if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                                break; // end of headers
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            // No more data in time; treat what we have as the request.
                            break;
                        }
                        Err(e) => panic!("read request error: {e:?}"),
                    }
                }

                requests.push(String::from_utf8_lossy(&buffer).to_string());

                // Respond per script and close.
                let resp = response.into_http_string();
                stream.write_all(resp.as_bytes()).expect("write response");
                // Drop the stream here; Connection: close ensures the client won’t reuse it.
            }

            requests
        });

        (format!("http://{}", addr), handle)
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
        // First attempt -> 401
        MockResponse::Unauthorized,
        // Refresh request -> returns new JWT
        MockResponse::Json(json!({ "jwt": "new-jwt-123" })),
        // Second attempt -> success
        MockResponse::Json(json!({ "id": "session-999", "ssh_url": "ssh://after-refresh" })),
    ];
    let mut harness = TestHarness::new(script);
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
        // Proactive refresh because JWT is expired
        MockResponse::Json(json!({ "jwt": "fresh-jwt-321" })),
        // Then the actual /sessions call succeeds
        MockResponse::Json(json!({ "id": "session-expired", "ssh_url": "ssh://expired.example" })),
    ];
    let mut harness = TestHarness::new(script);
    harness.create_expired_session();
    harness.set_keyring_password("tester", "refresh-token-xyz");

    let (_, requests) = harness.run_cli_and_assert(&["up", "https://github.com/example/repo"]);

    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("POST /auth/refresh"));
    assert!(requests[1].starts_with("POST /sessions"));
}

#[test]
fn logout_removes_session_and_revokes_refresh() {
    // logout only needs one backend hit, /auth/revoke
    let script = vec![MockResponse::Ok];
    let mut harness = TestHarness::new(script);
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
