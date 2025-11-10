use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Output;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::TempDir;

// ---------------- Utility helpers ----------------

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

// ---------------- Mock Server ----------------

struct MockServer {
    addr: String,
    handle: Option<std::thread::JoinHandle<()>>,
    listener: Option<TcpListener>,
}

impl MockServer {
    fn new<F>(handler: F) -> Self
    where
        F: Fn(String, &mut TcpStream) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let listener_clone = listener.try_clone().unwrap();

        let handle = std::thread::spawn(move || {
            for incoming in listener_clone.incoming() {
                match incoming {
                    Ok(mut stream) => {
                        let req = read_full_request(&mut stream);
                        handler(req, &mut stream);
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            addr: format!("http://{}", addr),
            handle: Some(handle),
            listener: Some(listener),
        }
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(listener) = self.listener.take() {
            drop(listener);
        }
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}

fn read_full_request(stream: &mut TcpStream) -> String {
    let mut buf = vec![0u8; 4096];
    let mut collected = Vec::new();
    stream.set_read_timeout(Some(std::time::Duration::from_millis(200))).unwrap();

    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                collected.extend_from_slice(&buf[..n]);
                if collected.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    String::from_utf8_lossy(&collected).to_string()
}

// ---------------- TESTS ----------------

#[test]
fn up_handles_401_then_refreshes_then_succeeds() {
    let td = TempDir::new().unwrap();

    let setup_res =
        run_cli(None, &[], &["test-setup-keychain", "me", "MY_REFRESH_TOKEN"]);
    assert!(setup_res.status.success(), "Failed to set up keychain");

    write_session(&td, "me", "OLD_JWT", Some(5_000_000_000));

    let call_counter = Arc::new(AtomicUsize::new(0));

    let mock_server = MockServer::new(move |req, stream| {
        let call = call_counter.fetch_add(1, Ordering::SeqCst);
        let req_lower = req.to_lowercase();

        match call {
            0 => {
                assert!(
                    req_lower.starts_with("post /sessions"),
                    "Expected /sessions, got: {}",
                    req
                );
                assert!(
                    req_lower.contains("authorization: bearer old_jwt"),
                    "Expected OLD_JWT in Authorization header, got: {}",
                    req
                );
                let resp = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
                stream.write_all(resp.as_bytes()).unwrap();
            }
            1 => {
                assert!(
                    req_lower.starts_with("post /auth/refresh"),
                    "Expected /auth/refresh, got: {}",
                    req
                );
                let body = r#"{"jwt":"NEW_JWT"}"#;
                let resp =
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
                stream.write_all(resp.as_bytes()).unwrap();
            }
            2 => {
                assert!(
                    req_lower.starts_with("post /sessions"),
                    "Expected retry to /sessions, got: {}",
 
