use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::time::Duration;
use tempfile::TempDir;
use serde_json::json;

pub enum MockResponse {
    Json(serde_json::Value),
    Unauthorized,
    Ok,
    Custom(String), // For custom bodies
}

impl MockResponse {
    pub fn into_http_string(self) -> String {
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
            MockResponse::Custom(body) => {
                format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/json\r\n\
                     Connection: close\r\n\
                     Content-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
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

    /// Create a harness without a server (for tests that don't need backend)
    pub fn new_no_server() -> Self {
        let tempdir = TempDir::new().expect("create tempdir");
        Self {
            tempdir,
            server_url: "http://localhost:0".to_string(), // Dummy URL
            server_handle: None,
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
        // Set mock keyring dir
        cmd.env("STEADYSTATE_KEYRING_DIR", self.tempdir.path());
        cmd.args(args);
        cmd.output().expect("run steadystate cli")
    }

    pub fn join_server(&mut self) -> Vec<String> {
        if let Some(handle) = self.server_handle.take() {
            handle.join().unwrap()
        } else {
            Vec::new()
        }
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
        // Use mock keyring file
        let path = self.tempdir.path().join(format!("{}.keyring", username));
        fs::write(path, password).unwrap();
    }
    
    pub fn get_keyring_password(&self, username: &str) -> std::io::Result<String> {
        let path = self.tempdir.path().join(format!("{}.keyring", username));
        fs::read_to_string(path)
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
