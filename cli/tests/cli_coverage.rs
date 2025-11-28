mod common;
use common::{MockResponse, TestHarness};

#[test]
fn whoami_displays_human_output_when_logged_in() {
    let harness = TestHarness::new_no_server();
    harness.create_session("test-user", "unused", None);

    let output = harness.run_cli(&["whoami"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Logged in as: test-user"));
    assert!(!stdout.contains("\"logged_in\""));
}

#[test]
fn whoami_displays_json_when_logged_in() {
    let harness = TestHarness::new_no_server();
    harness.create_session("json-user", "unused", Some(1_234_567));

    let output = harness.run_cli(&["whoami", "--json"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("parse json");
    assert_eq!(value["logged_in"], true);
    assert_eq!(value["login"], "json-user");
    assert_eq!(value["jwt_expires_at"], 1_234_567);
}

#[test]
fn whoami_reports_missing_session_plain_text() {
    let harness = TestHarness::new_no_server();

    let output = harness.run_cli(&["whoami"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("No active session found. Run 'steadystate login' first."));
}

#[test]
fn whoami_reports_missing_session_json() {
    let harness = TestHarness::new_no_server();

    let output = harness.run_cli(&["whoami", "--json"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("parse json");
    assert_eq!(value["logged_in"], false);
    assert!(value["login"].is_null());
    assert!(value["jwt_expires_at"].is_null());
}

#[test]
fn version_flag_prints_version() {
    let harness = TestHarness::new_no_server();
    let output = harness.run_cli(&["--version"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("SteadyState CLI version"));
}

#[test]
fn running_without_subcommand_prints_help() {
    let harness = TestHarness::new_no_server();
    let output = harness.run_cli(&[]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("SteadyState CLI — Exact reproducible dev envs"));
}

#[test]
fn up_rejects_invalid_repository_url() {
    let harness = TestHarness::new_no_server();
    harness.create_session("tester", "jwt", Some(4_000_000_000));

    let output = harness.run_cli(&["up", "not-a-url", "--env=noenv"]);
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Invalid repository URL"));
}

#[test]
fn up_prints_human_output_on_success() {
    let response = r#"{"id":"session-123","state":"Running","endpoint":"ssh://example.com","message":null,"compute_provider":"local"}"#.to_string();
    let script = vec![MockResponse::Custom(response)];
    let mut harness = TestHarness::new(script);
    harness.create_future_session();

    let (output, reqs) = harness.run_cli_and_assert_success(&["up", "https://example.com/repo.git", "--env=noenv", "--mode=pair"]);
    
    assert_eq!(reqs.len(), 1);
    assert!(reqs[0].starts_with("POST /sessions"));
    assert!(reqs[0].to_lowercase().contains("authorization: bearer test-jwt"));

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("✅ Session created: session-123"));
    assert!(stdout.contains("SSH: ssh://example.com"));
}

#[test]
fn up_prints_json_on_success() {
    let response = r#"{"id":"session-456","state":"Running","endpoint":"ssh://json.example.com","message":null,"compute_provider":"local"}"#.to_string();
    let script = vec![MockResponse::Custom(response)];
    let mut harness = TestHarness::new(script);
    harness.create_future_session();

    let (output, reqs) = harness.run_cli_and_assert_success(&["up", "https://example.com/repo.git", "--env=noenv", "--json", "--mode=pair"]);

    assert_eq!(reqs.len(), 1);
    assert!(reqs[0].starts_with("POST /sessions"));
    assert!(reqs[0].to_lowercase().contains("authorization: bearer test-jwt"));

    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("parse json");
    assert_eq!(value["id"], "session-456");
    assert_eq!(value["endpoint"], "ssh://json.example.com");
}
