use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use std::process::ExitStatus;
use std::os::unix::process::ExitStatusExt;
use anyhow::Result;
use async_trait::async_trait;
use tokio::io::AsyncRead;

use crate::compute::local_provider::{CommandExecutor, LocalComputeProvider};
use crate::compute::ComputeProvider;
use crate::models::{Session, SessionRequest, SessionState};

#[derive(Debug, Clone)]
struct MockCommandCall {
    cmd: String,
    args: Vec<String>,
}

#[derive(Debug, Clone)]
struct MockCommandExecutor {
    calls: Arc<Mutex<Vec<MockCommandCall>>>,
    // Map of command -> (exit_code, stdout)
    responses: Arc<Mutex<Vec<(String, i32, String)>>>,
}

impl MockCommandExecutor {
    fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn add_response(&self, cmd_contains: &str, exit_code: i32, stdout: &str) {
        self.responses.lock().unwrap().push((cmd_contains.to_string(), exit_code, stdout.to_string()));
    }

    fn get_calls(&self) -> Vec<MockCommandCall> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl CommandExecutor for MockCommandExecutor {
    async fn run_status(&self, cmd: &str, args: &[&str]) -> Result<ExitStatus> {
        self.calls.lock().unwrap().push(MockCommandCall {
            cmd: cmd.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        });

        // Simple matching logic for now
        let responses = self.responses.lock().unwrap();
        for (contains, code, _) in responses.iter() {
            if cmd.contains(contains) || args.iter().any(|a| a.contains(contains)) {
                return Ok(ExitStatus::from_raw(*code));
            }
        }

        // Default success
        Ok(ExitStatus::from_raw(0))
    }

    async fn run_capture(&self, cmd: &str, args: &[&str]) -> Result<(u32, Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncRead + Unpin + Send>)> {
        self.calls.lock().unwrap().push(MockCommandCall {
            cmd: cmd.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        });

        let responses = self.responses.lock().unwrap();
        let mut stdout_content = String::new();
        
        for (contains, _, stdout) in responses.iter() {
            if cmd.contains(contains) || args.iter().any(|a| a.contains(contains)) {
                stdout_content = stdout.clone();
                break;
            }
        }

        Ok((1234, Box::new(std::io::Cursor::new(stdout_content)), Box::new(std::io::Cursor::new(""))))
    }

    async fn run_shell(&self, script: &str) -> Result<ExitStatus> {
        self.calls.lock().unwrap().push(MockCommandCall {
            cmd: "sh".to_string(),
            args: vec!["-c".to_string(), script.to_string()],
        });

        let responses = self.responses.lock().unwrap();
        for (contains, code, _) in responses.iter() {
            if script.contains(contains) {
                return Ok(ExitStatus::from_raw(*code));
            }
        }

        Ok(ExitStatus::from_raw(0))
    }
}

#[tokio::test]
async fn test_start_session_success() {
    let executor = Box::new(MockCommandExecutor::new());
    // Mock upterm output
    executor.add_response("upterm", 0, "Invite: ssh://user@host:22\n");

    let provider = LocalComputeProvider::new_with_executor(
        PathBuf::from("/tmp/flake"),
        executor.clone()
    );

    let mut session = Session {
        id: "test-session".into(),
        _repo_url: "https://github.com/user/repo".into(),
        _branch: None,
        _environment: None,
        compute_provider: "local".into(),
        _creator_login: "user1".into(),
        state: SessionState::Provisioning,
        endpoint: None,
        _created_at: std::time::SystemTime::now(),
        updated_at: std::time::SystemTime::now(),
        error_message: None,
    };

    let request = SessionRequest {
        repo_url: "https://github.com/user/repo".into(),
        branch: None,
        environment: None,
        provider_config: None,
        allowed_users: None,
        public: false,
        mode: Some("pair".to_string()),
    };

    provider.start_session(&mut session, &request).await.unwrap();

    assert!(matches!(session.state, SessionState::Running));
    assert_eq!(session.endpoint, Some("Invite: ssh://user@host:22".to_string()));

    let calls = executor.get_calls();
    // Verify sequence: check nix, (maybe install lix), clone, upterm
    // 1. check nix (sh -c command -v nix)
    // 2. clone repo (git clone ...)
    // 3. upterm (sh -c ... upterm ...)
    
    // Note: ensure_nix_installed checks for nix. If it returns success (default in mock), it skips install.
    
    assert!(calls.iter().any(|c| c.args.iter().any(|a| a.contains("command -v nix"))));
    assert!(calls.iter().any(|c| c.cmd == "git" && c.args[0] == "clone"));
    assert!(calls.iter().any(|c| c.args.iter().any(|a| a.contains("--authorized-keys"))));
}

#[tokio::test]
async fn test_terminate_session() {
    let executor = Box::new(MockCommandExecutor::new());
    let provider = LocalComputeProvider::new_with_executor(
        PathBuf::from("/tmp/flake"),
        executor.clone()
    );

    // Manually inject a session into state (this is tricky because state is private/internal)
    // But we can start a session first to populate state.
    
    // Mock upterm output for start_session
    executor.add_response("upterm", 0, "Invite: ssh://user@host:22\n");

    let mut session = Session {
        id: "test-session-kill".into(),
        _repo_url: "repo".into(),
        _branch: None,
        _environment: None,
        compute_provider: "local".into(),
        _creator_login: "user1".into(),
        state: SessionState::Provisioning,
        endpoint: None,
        _created_at: std::time::SystemTime::now(),
        updated_at: std::time::SystemTime::now(),
        error_message: None,
    };
    let request = SessionRequest { 
        repo_url: "repo".into(),
        branch: None,
        environment: None,
        provider_config: None,
        allowed_users: None,
        public: false,
        mode: Some("pair".to_string()),
    };
    
    provider.start_session(&mut session, &request).await.unwrap();

    // Now terminate
    provider.terminate_session(&session).await.unwrap();

    let calls = executor.get_calls();
    assert!(calls.iter().any(|c| c.args.iter().any(|a| a.contains("kill -TERM"))));
}

#[tokio::test]
async fn test_capture_upterm_invite_parsing() {
    let output = "=== BFO1HH1SZDG28RVDWPAM
Command:                bash
Force Command:          n/a
Host:                   ssh://uptermd.upterm.dev:22
Authorized Keys:        n/a
SSH Session:            ssh BFO1HH1sZDg28RvdWpam:MTc4MTFlNDBjZTk0ZTgudm0udXB0ZXJtLmludGVrbmFsOjIyMjI=@uptermd.upterm.dev

Run 'upterm session current' to display this screen again
";
    let cursor = Box::new(std::io::Cursor::new(output));
    let result = crate::compute::local_provider::capture_upterm_invite(cursor).await;
    assert!(result.is_ok());
    let (pid, invite, _remaining) = result.unwrap();
    assert_eq!(pid, None);
    assert_eq!(invite, "ssh BFO1HH1sZDg28RvdWpam:MTc4MTFlNDBjZTk0ZTgudm0udXB0ZXJtLmludGVrbmFsOjIyMjI=@uptermd.upterm.dev");
}

#[tokio::test]
async fn test_capture_upterm_invite_parsing_new_format() {
    let output = "
│ Command:         │ bash -c echo 'Session started'; sleep 30             │
│ Force Command:   │ n/a                                                  │
│ Host:            │ ssh://uptermd.upterm.dev:22                          │
│ Authorized Keys: │ /tmp/secure_keys_direct/authorized_keys:             │
│                  │ - SHA256:z6jj++GQTO4xVebN4yTQXD5msN1o1XncTqPzK+Cy4rk │
│                  │                                                      │
│ ➤ SSH Command:   │ ssh FYjNpo96BizkITTpFfco@uptermd.upterm.dev          │
└──────────────────┴──────────────────────────────────────────────────────┘
";
    let cursor = Box::new(std::io::Cursor::new(output));
    let result = crate::compute::local_provider::capture_upterm_invite(cursor).await;
    assert!(result.is_ok());
    let (pid, invite, _remaining) = result.unwrap();
    assert_eq!(pid, None);
    assert_eq!(invite, "ssh FYjNpo96BizkITTpFfco@uptermd.upterm.dev");
}

#[tokio::test]
async fn test_start_session_git_failure() {
    let executor = Box::new(MockCommandExecutor::new());
    // Mock git clone failure
    executor.add_response("git", 1, "fatal: repository not found");

    let provider = LocalComputeProvider::new_with_executor(
        PathBuf::from("/tmp/flake"),
        executor.clone()
    );

    let mut session = Session {
        id: "test-session-git-fail".into(),
        _repo_url: "https://github.com/user/repo".into(),
        _branch: None,
        _environment: None,
        compute_provider: "local".into(),
        _creator_login: "user1".into(),
        state: SessionState::Provisioning,
        endpoint: None,
        _created_at: std::time::SystemTime::now(),
        updated_at: std::time::SystemTime::now(),
        error_message: None,
    };

    let request = SessionRequest {
        repo_url: "https://github.com/user/repo".into(),
        branch: None,
        environment: None,
        provider_config: None,
        allowed_users: None,
        public: false,
        mode: Some("pair".to_string()),
    };

    let result = provider.start_session(&mut session, &request).await;
    assert!(result.is_err());
    // The provider does not update state on failure (caller does), so it should remain Provisioning
    assert!(matches!(session.state, SessionState::Provisioning));
}

#[tokio::test]
async fn test_start_session_upterm_failure() {
    let executor = Box::new(MockCommandExecutor::new());
    // Mock upterm failure (non-zero exit code)
    executor.add_response("upterm", 1, "Error: failed to start session");

    let provider = LocalComputeProvider::new_with_executor(
        PathBuf::from("/tmp/flake"),
        executor.clone()
    );

    let mut session = Session {
        id: "test-session-upterm-fail".into(),
        _repo_url: "https://github.com/user/repo".into(),
        _branch: None,
        _environment: None,
        compute_provider: "local".into(),
        _creator_login: "user1".into(),
        state: SessionState::Provisioning,
        endpoint: None,
        _created_at: std::time::SystemTime::now(),
        updated_at: std::time::SystemTime::now(),
        error_message: None,
    };

    let request = SessionRequest {
        repo_url: "https://github.com/user/repo".into(),
        branch: None,
        environment: None,
        provider_config: None,
        allowed_users: None,
        public: false,
        mode: Some("pair".to_string()),
    };

    let result = provider.start_session(&mut session, &request).await;
    assert!(result.is_err());
    assert!(matches!(session.state, SessionState::Provisioning));
}

#[tokio::test]
async fn test_start_session_nix_failure() {
    let executor = Box::new(MockCommandExecutor::new());
    // Mock nix check failure
    executor.add_response("command -v nix", 1, "");
    // And mock installer failure too, otherwise it tries to install
    executor.add_response("sh", 1, "Installer failed"); 

    let provider = LocalComputeProvider::new_with_executor(
        PathBuf::from("/tmp/flake"),
        executor.clone()
    );

    let mut session = Session {
        id: "test-session-nix-fail".into(),
        _repo_url: "https://github.com/user/repo".into(),
        _branch: None,
        _environment: None,
        compute_provider: "local".into(),
        _creator_login: "user1".into(),
        state: SessionState::Provisioning,
        endpoint: None,
        _created_at: std::time::SystemTime::now(),
        updated_at: std::time::SystemTime::now(),
        error_message: None,
    };

    let request = SessionRequest {
        repo_url: "https://github.com/user/repo".into(),
        branch: None,
        environment: None,
        provider_config: None,
        allowed_users: None,
        public: false,
        mode: Some("pair".to_string()),
    };

    let result = provider.start_session(&mut session, &request).await;
    assert!(result.is_err());
    assert!(matches!(session.state, SessionState::Provisioning));
}
