use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
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

// --- Mock Server ---

struct MockServer {
    addr: String,
    handle: Option<std::thread::JoinHandle<()>>,
    _listener: TcpListener,
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
            for stream in listener_clone.incoming() {
                match stream {
                    Ok(mut stream) => {
                        // Set a short timeout to prevent hanging
                        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
                        
                        match read_full_request(&mut stream) {
                            Ok(req) => {
                                eprintln!("Server received request: {}", &req[..req.len().min(200)]);
                                handler(req, &mut stream);
                                let _ = stream.flush();
                            }
                            Err(e) => {
                                eprintln!("Failed to read request: {}", e);
                            }
                        }
                        // Important: shutdown the stream
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            addr: format!("http://{}", addr),
            handle: Some(handle),
            _listener: listener,
        }
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn read_full_request(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = [0u8; 8192];
    let mut out = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut header_end_pos: Option<usize> = None;
    
    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                // Connection closed
                break;
            }
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                
                // Look for end of headers if we haven't found it yet
                if header_end_pos.is_none() {
                    if let Some(pos) = out.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end_pos = Some(pos);
                        
                        // Parse Content-Length
                        let headers = String::from_utf8_lossy(&out[..pos]);
                        for line in headers.lines() {
                            let lower = line.to_lowercase();
                            if lower.starts_with("content-length:") {
                                if let Some(len_str) = line.split(':').nth(1) {
                                    content_length = len_str.trim().parse().ok();
                                }
                            }
                        }
                    }
                }
                
                // Check if we have the complete request
                if let Some(header_end) = header_end_pos {
                    let body_start = header_end + 4;
                    let body_received = out.len() - body_start;
                    
                    match content_length {
                        Some(expected) => {
                            if body_received >= expected {
                                // We have everything
                                break;
                            }
                        }
                        None => {
                            // No Content-Length header, headers are complete, we're done
                            break;
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || 
                      e.kind() == std::io::ErrorKind::TimedOut => {
                // Timeout
                if header_end_pos.is_some() {
                    // We at least got headers, return what we have
                    break;
                }
                return Err(e);
            }
            Err(e) => return Err(e),
        }
    }
    
    Ok(String::from_utf8_lossy(&out).to_string())
}

fn send_response(stream: &mut TcpStream, status_code: u16, status_text: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_code,
        status_text,
        body.len(),
        body
    );
    eprintln!("Server sending response: {} {}", status_code, status_text);
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
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
        move |req, stream| {
            let call = call_counter.fetch_add(1, Ordering::SeqCst);
            eprintln!("Handling request #{}", call);
            match call {
                0 => {
                    assert!(req.starts_with("POST /sessions"), "Expected /sessions, got: {}", req);
                    assert!(req.to_lowercase().contains("bearer old_jwt"));
                    send_response(stream, 401, "Unauthorized", "");
                }
                1 => {
                    assert!(req.starts_with("POST /auth/refresh"), "Expected /auth/refresh, got: {}", req);
                    send_response(stream, 200, "OK", r#"{"jwt":"NEW_JWT"}"#);
                }
                2 => {
                    assert!(req.starts_with("POST /sessions"), "Expected retry to /sessions, got: {}", req);
                    assert!(req.to_lowercase().contains("bearer new_jwt"));
                    send_response(stream, 200, "OK", r#"{"id":"abc","ssh_url":"ssh://ok"}"#);
                }
                _ => panic!("Unexpected request number {}", call),
            }
        }
    });

    eprintln!("Running CLI command...");
    let out = run_cli(
        Some(&td),
        &[("STEADYSTATE_BACKEND", mock_server.addr.clone())],
        &["up", "https://github.com/x/y"],
    );

    eprintln!("CLI stdout: {}", String::from_utf8_lossy(&out.stdout));
    eprintln!("CLI stderr: {}", String::from_utf8_lossy(&out.stderr));
    
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
        move |req, stream| {
            let call = call_counter.fetch_add(1, Ordering::SeqCst);
            match call {
                0 => {
                    assert!(req.starts_with("POST /auth/refresh"), "Expected /auth/refresh, got: {}", req);
                    send_response(stream, 200, "OK", r#"{"jwt":"FRESH"}"#);
                }
                1 => {
                    assert!(req.starts_with("POST /sessions"), "Expected /sessions, got: {}", req);
                    assert!(req.to_lowercase().contains("bearer fresh"));
                    send_response(stream, 200, "OK", r#"{"id":"abc","ssh_url":"ssh://ok"}"#);
                }
                _ => panic!("Unexpected request number {}", call),
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

    let mock_server = MockServer::new(|req, stream| {
        assert!(req.starts_with("POST /auth/revoke"), "Expected /auth/revoke, got {}", req);
        send_response(stream, 200, "OK", "");
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
