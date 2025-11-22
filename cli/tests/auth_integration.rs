#![cfg(not(target_os = "macos"))]

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

    pub enum MockResponse {
        Json(serde_json::Value),
        Unauthorized,
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

    pub struct TestHarness {
        pub tempdir: TempDir,
        pub server_url: String, // Made public for direct use in failure tests
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

        pub fn run_cli_and_assert_success(&mut self, args: &[&str]) -> (Output, Vec<String>) {
            let output = self.run_cli(args);
            let requests = self.join_server();

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

        pub fn run_cli(&self, args: &[&str]) -> Output {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_steadystate"));
            cmd.env("STEADYSTATE_CONFIG_DIR", self.tempdir.path());
            cmd.env("STEADYSTATE_BACKEND", &self.server_url);
            cmd.args(args);
            cmd.output().expect("run steadystate cli")
        }

        pub fn join_server(&mut self) -> Vec<String> {
            self.server_handle.take().unwrap().join().unwrap()
        }

        pub fn create_session(&self, login: &str, jwt: &str, jwt_exp: Option<u64>) {
            let dir = self.tempdir.path().join("steadystate");
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join("session.json");
            let session = json!({ "login": login, "jwt": jwt, "jwt_exp": jwt_exp });
            fs::write(path, serde_json::to_vec_pretty(&session).unwrap()).unwrap();
        }

        pub fn create_future_session(&self) {
            let exp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600;
            self.create_session("tester", "test-jwt", Some(exp));
        }

        pub fn create_expired_session(&self) {
            let exp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - 10;
            self.create_session("tester", "expired-jwt", Some(exp));
        }

        pub fn set_keyring_password(&self, username: &str, password: &str) {
            keyring::Entry::new("steadystate", username).unwrap().set_password(password).unwrap();
        }
    }

    /// Minimal, robust, "headers-only" mock server.
    fn spawn_scripted_server(
        responses: Vec<MockResponse>,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let mut reqs = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut buf = vec![0; 1024]; // Simple buffer is enough for headers
                if let Ok(n) = stream.read(&mut buf) {
                    reqs.push(String::from_utf8_lossy(&buf[..n]).to_string());
                }
                let resp = response.into_http_string();
                stream.write_all(resp.as_bytes()).unwrap();
            }
            reqs
        });

        (format!("http://{}", addr), handle)
    }
}

// ---------------------------------------------------------------------------
// NEW, CORRECTED INTEGRATION TESTS
// ---------------------------------------------------------------------------

use helpers::{MockResponse, TestHarness};
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

    let (out, reqs) = harness.run_cli_and_assert_success(&["up", "https://github.com/example/repo", "--env=noenv"]);

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
    let output = harness.run_cli(&["up", "https://github.com/example/repo", "--env=noenv"]);
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
    let res = keyring::Entry::new("steadystate", "tester").unwrap().get_password();
    assert!(res.is_err());
}
