use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::thread;
use chrono::{DateTime, Local, TimeZone};
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    cursor,
    style::{Color, Print, ResetColor, SetForegroundColor, Stylize},
};
use std::io::{stdout, Write};

pub fn watch() -> Result<()> {
    // Setup TUI
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, cursor::Hide)?;

    // Ensure cleanup on panic/exit
    let result = run_dashboard(&mut stdout);

    // Cleanup
    execute!(stdout, cursor::Show, LeaveAlternateScreen)?;
    disable_raw_mode()?;

    result
}

fn run_dashboard(stdout: &mut std::io::Stdout) -> Result<()> {
    let repo_root = std::env::var("REPO_ROOT").unwrap_or_else(|_| ".".to_string());
    let sync_log_path = Path::new(&repo_root).join("sync-log");
    let active_users_path = Path::new(&repo_root).join("active-users");
    
    // Get session info
    let session_id = std::env::var("SESSION_ID").unwrap_or_else(|_| "unknown".to_string());
    let current_user = std::env::var("STEADYSTATE_USERNAME").ok();
    
    // Determine worktree path for current user
    let worktree_path = if let Some(user) = &current_user {
        let path = Path::new(&repo_root).join("worktrees").join(user);
        if path.exists() {
            Some(path)
        } else {
            None
        }
    } else {
        None
    };

    let mut last_status_msg = String::new();
    let mut status_msg_time = std::time::Instant::now();

    loop {
        // 1. Draw UI
        draw_ui(stdout, &session_id, &repo_root, &sync_log_path, &active_users_path, &current_user, &worktree_path, &last_status_msg)?;

        // Clear status message after 3 seconds
        if status_msg_time.elapsed() > Duration::from_secs(3) {
            last_status_msg.clear();
        }

        // 2. Handle Input
        if event::poll(Duration::from_millis(500))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    
                    KeyCode::Char('s') => {
                        if let Some(path) = &worktree_path {
                            last_status_msg = "Syncing...".to_string();
                            status_msg_time = std::time::Instant::now();
                            draw_ui(stdout, &session_id, &repo_root, &sync_log_path, &active_users_path, &current_user, &worktree_path, &last_status_msg)?;
                            
                            match run_command("sync", path) {
                                Ok(_) => last_status_msg = "Sync complete!".to_string(),
                                Err(e) => last_status_msg = format!("Sync failed: {}", e),
                            }
                        } else {
                            last_status_msg = "No worktree found for current user".to_string();
                        }
                        status_msg_time = std::time::Instant::now();
                    }
                    
                    KeyCode::Char('p') => {
                        if let Some(path) = &worktree_path {
                            last_status_msg = "Publishing...".to_string();
                            status_msg_time = std::time::Instant::now();
                            draw_ui(stdout, &session_id, &repo_root, &sync_log_path, &active_users_path, &current_user, &worktree_path, &last_status_msg)?;
                            
                            match run_command("publish", path) {
                                Ok(_) => last_status_msg = "Publish complete!".to_string(),
                                Err(e) => last_status_msg = format!("Publish failed: {}", e),
                            }
                        } else {
                            last_status_msg = "No worktree found for current user".to_string();
                        }
                        status_msg_time = std::time::Instant::now();
                    }

                    KeyCode::Char('d') => {
                        if let Some(path) = &worktree_path {
                            // Diff is interactive/output heavy, so we need to temporarily leave TUI
                            execute!(stdout, LeaveAlternateScreen, cursor::Show)?;
                            disable_raw_mode()?;
                            
                            println!("Running diff...");
                            let _ = std::process::Command::new("steadystate")
                                .arg("diff")
                                .current_dir(path)
                                .status();
                                
                            println!("\nPress Enter to return to dashboard...");
                            let _ = std::io::stdin().read_line(&mut String::new());
                            
                            enable_raw_mode()?;
                            execute!(stdout, EnterAlternateScreen, cursor::Hide)?;
                        } else {
                            last_status_msg = "No worktree found for current user".to_string();
                            status_msg_time = std::time::Instant::now();
                        }
                    }

                    KeyCode::Char('c') => {
                        if let Some(path) = &worktree_path {
                            last_status_msg = "Prompting for file...".to_string();
                            status_msg_time = std::time::Instant::now();
                            draw_ui(stdout, &session_id, &repo_root, &sync_log_path, &active_users_path, &current_user, &worktree_path, &last_status_msg)?;

                            // Temporarily leave TUI to prompt for input
                            execute!(stdout, LeaveAlternateScreen, cursor::Show)?;
                            disable_raw_mode()?;
                            
                            print!("Enter file to credit: ");
                            stdout.flush()?;
                            
                            let mut filename = String::new();
                            std::io::stdin().read_line(&mut filename)?;
                            let filename = filename.trim();
                            
                            if !filename.is_empty() {
                                println!("Running credit on {}...", filename);
                                
                                // Use sh -c to pipe to less for paging
                                let status = std::process::Command::new("sh")
                                    .arg("-c")
                                    .arg(format!("steadystate credit {} | less", filename))
                                    .current_dir(path)
                                    .status();
                                    
                                match status {
                                    Ok(s) => {
                                        if s.success() {
                                            last_status_msg = format!("Credit successful for {}!", filename);
                                        } else {
                                            last_status_msg = format!("Credit failed for {}", filename);
                                        }
                                    }
                                    Err(e) => {
                                        last_status_msg = format!("Credit command error: {}", e);
                                    }
                                }
                                
                                println!("\nPress Enter to return to dashboard...");
                                let _ = std::io::stdin().read_line(&mut String::new());
                            } else {
                                last_status_msg = "Credit cancelled.".to_string();
                            }

                            // Restore TUI
                            enable_raw_mode()?;
                            execute!(stdout, EnterAlternateScreen, cursor::Hide)?;
                        } else {
                            last_status_msg = "No worktree found for current user".to_string();
                        }
                        status_msg_time = std::time::Instant::now();
                    }
                    
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

fn run_command(cmd: &str, cwd: &Path) -> Result<()> {
    let output = std::process::Command::new("steadystate")
        .arg(cmd)
        .current_dir(cwd)
        .output()?;
        
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("{}", err.trim()));
    }
    Ok(())
}

fn draw_ui(
    stdout: &mut std::io::Stdout,
    session_id: &str,
    repo_root: &str,
    sync_log_path: &Path,
    active_users_path: &Path,
    current_user: &Option<String>,
    worktree_path: &Option<PathBuf>,
    status_msg: &str,
) -> Result<()> {
    use std::io::Write; // Add this line for `write!` macro
    execute!(stdout, cursor::MoveTo(0, 0), crossterm::terminal::Clear(crossterm::terminal::ClearType::All))?;
    
    // Header
    execute!(stdout, SetForegroundColor(Color::Cyan))?;
    write!(stdout, "SteadyState Dashboard\r\n")?;
    execute!(stdout, ResetColor)?;
    
    // Read session info
    let session_info_path = Path::new(repo_root).join("session-info.json");
    let mut magic_link = None;
    let mut ssh_url = None;
    let mut repo_name = std::env::var("REPO_NAME").ok();

    if session_info_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&session_info_path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                magic_link = json.get("magic_link").and_then(|v| v.as_str()).map(|s| s.to_string());
                ssh_url = json.get("ssh_url").and_then(|v| v.as_str()).map(|s| s.to_string());
                if repo_name.is_none() {
                    repo_name = json.get("repo_name").and_then(|v| v.as_str()).map(|s| s.to_string());
                }
            }
        }
    }

    write!(stdout, "Session ID: {}\r\n", session_id)?;
    if let Some(repo) = repo_name {
        write!(stdout, "Repository: {}\r\n", repo)?;
    }
    if let Some(link) = magic_link {
        write!(stdout, "Join with:       steadystate join \"{}\"\r\n", link)?;
    }
    if let Some(ssh) = ssh_url {
        if let Ok(url) = url::Url::parse(&ssh) {
             let user = url.username();
             let host = url.host_str().unwrap_or("localhost");
             let port = url.port().unwrap_or(22);
             write!(stdout, "To join with ssh: ssh {}@{} -p {}\r\n", user, host, port)?;
        } else {
             write!(stdout, "To join with ssh: {}\r\n", ssh)?;
        }
    }
    write!(stdout, "--------------------------------------------------------------------------------\r\n")?;
    
    if let Some(user) = current_user {
        write!(stdout, "User:       {}", user)?;
        if worktree_path.is_some() {
            execute!(stdout, SetForegroundColor(Color::Green))?;
            write!(stdout, " (Connected)\r\n")?;
        } else {
            execute!(stdout, SetForegroundColor(Color::Yellow))?;
            write!(stdout, " (Observer - No worktree)\r\n")?;
        }
        execute!(stdout, ResetColor)?;
    } else {
        write!(stdout, "User:       (Anonymous Observer)\r\n")?;
    }
    
    write!(stdout, "--------------------------------------------------------------------------------\r\n")?;

    // Connected Users
    write!(stdout, "Connected Users:\r\n")?;
    if active_users_path.exists() {
        if let Ok(content) = std::fs::read_to_string(active_users_path) {
            let mut users: Vec<&str> = content.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
            users.sort();
            users.dedup();
            for user in users {
                write!(stdout, "  • {}\r\n", user)?;
            }
        }
    }
    write!(stdout, "\r\n")?;

    // Activity Log
    write!(stdout, "Recent Activity:\r\n")?;
    if sync_log_path.exists() {
        let content = std::fs::read_to_string(sync_log_path).unwrap_or_default();
        let lines: Vec<&str> = content.lines().collect();
        // Show more lines since each event might take multiple lines now
        let start = if lines.len() > 20 { lines.len() - 20 } else { 0 };
        
        for line in &lines[start..] {
            // Try to parse as JSON first (new format)
            if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
                if let (Some(ts), Some(user)) = (entry.get("timestamp").and_then(|v| v.as_u64()), entry.get("user").and_then(|v| v.as_str())) {
                    let dt: DateTime<Local> = Local.timestamp_opt(ts as i64, 0).single().unwrap_or_default();
                    execute!(stdout, SetForegroundColor(Color::Cyan))?;
                    write!(stdout, "  [{}] {} synced\r\n", dt.format("%H:%M:%S"), user)?;
                    execute!(stdout, ResetColor)?;
                    
                    if let Some(changes) = entry.get("changes").and_then(|v| v.as_array()) {
                        for change in changes {
                            if let (Some(file), Some(lines)) = (change.get("file").and_then(|v| v.as_str()), change.get("lines").and_then(|v| v.as_str())) {
                                // DarkGrey is often invisible on dark themes. Use default color.
                                execute!(stdout, ResetColor)?; 
                                write!(stdout, "      - {} {}\r\n", file, lines)?;
                            }
                        }
                    }
                }
            } else {
                // Fallback to legacy format: timestamp user
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(ts) = parts[0].parse::<i64>() {
                        let dt: DateTime<Local> = Local.timestamp_opt(ts, 0).single().unwrap_or_default();
                        write!(stdout, "  [{}] {} synced\r\n", dt.format("%H:%M:%S"), parts[1])?;
                    } else {
                        write!(stdout, "  {}\r\n", line)?;
                    }
                } else {
                    write!(stdout, "  {}\r\n", line)?;
                }
            }
        }
    }
    
    // Footer / Controls
    let (_, rows) = crossterm::terminal::size()?;
    execute!(stdout, cursor::MoveTo(0, rows - 4))?;
    write!(stdout, "--------------------------------------------------------------------------------\r\n")?;
    
    if !status_msg.is_empty() {
        execute!(stdout, SetForegroundColor(Color::Yellow))?;
        write!(stdout, "Status: {}\r\n", status_msg)?;
        execute!(stdout, ResetColor)?;
    } else {
        write!(stdout, "\r\n")?;
    }
    
    execute!(stdout, SetForegroundColor(Color::DarkGrey))?;
    write!(stdout, "Controls: ")?;
    execute!(stdout, ResetColor)?;
    
    if worktree_path.is_some() {
        write!(stdout, "[s] Sync  [p] Publish  [d] Diff  [c] Credit  ")?;
    }
    write!(stdout, "[q] Quit\r\n")?;

    Ok(())
}
