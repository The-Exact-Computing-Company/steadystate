#![cfg(not(target_os = "macos"))]

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::time::Duration;
use tempfile::TempDir;
use serde_json::json;

// Copied helpers to avoid dependency issues and allow modification
mod helpers {
    use super::*;

    pub enum MockResponse {
        Json(serde_json::Value),
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
        pub server_url: String,
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

        pub fn run_cli_no_keyring(&self, args: &[&str]) -> Output {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_steadystate"));
            cmd.env("STEADYSTATE_CONFIG_DIR", self.tempdir.path());
            cmd.env("STEADYSTATE_BACKEND", &self.server_url);
            // IMPORTANT: Do NOT set STEADYSTATE_KEYRING_DIR
            // Set NO_KEYRING to force fallback
            cmd.env("STEADYSTATE_NO_KEYRING", "1");
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

        pub fn set_fallback_token(&self, token: &str) {
            let dir = self.tempdir.path().join("steadystate");
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join("credentials");
            fs::write(path, token).unwrap();
        }

        pub fn fallback_token_exists(&self) -> bool {
            self.tempdir.path().join("steadystate/credentials").exists()
        }
    }

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
                let mut buf = vec![0; 1024];
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

use helpers::{MockResponse, TestHarness};

#[test]
fn logout_with_no_keyring_removes_fallback_file() {
    let script = vec![MockResponse::Ok];
    let mut harness = TestHarness::new(script);
    harness.create_future_session();
    harness.set_fallback_token("token-in-file");

    let output = harness.run_cli_no_keyring(&["logout"]);
    
    if !output.status.success() {
        eprintln!("STDOUT: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("STDERR: {}", String::from_utf8_lossy(&output.stderr));
        panic!("CLI failed");
    }

    let reqs = harness.join_server();
    assert_eq!(reqs.len(), 1);
    assert!(reqs[0].contains("token-in-file")); // Verify it read the token from file
    assert!(!harness.fallback_token_exists()); // Verify it deleted the file
}

#[test]
fn refresh_with_no_keyring_uses_fallback_file() {
    let script = vec![MockResponse::Json(json!({ "jwt": "new-jwt" }))];
    let mut harness = TestHarness::new(script);
    // Create session but with expired JWT to force refresh? 
    // Or just run `refresh` command explicitly.
    harness.create_future_session();
    harness.set_fallback_token("file-refresh-token");

    let output = harness.run_cli_no_keyring(&["refresh"]);

    if !output.status.success() {
        eprintln!("STDOUT: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("STDERR: {}", String::from_utf8_lossy(&output.stderr));
        panic!("CLI failed");
    }

    let reqs = harness.join_server();
    assert_eq!(reqs.len(), 1);
    assert!(reqs[0].contains("file-refresh-token"));
}
