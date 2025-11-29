use anyhow::{Context, Result};
use std::path::Path;
use std::time::Duration;
use std::thread;
use chrono::{DateTime, Local, TimeZone};

pub fn watch() -> Result<()> {
    // Clear screen
    print!("\x1B[2J\x1B[1;1H");
    
    let repo_root = std::env::var("REPO_ROOT").unwrap_or_else(|_| "..".to_string());
    let sync_log_path = Path::new(&repo_root).join("sync-log");
    let active_users_path = Path::new(&repo_root).join("active-users");
    
    // Get session info (from env or path)
    let session_id = std::env::var("SESSION_ID").unwrap_or_else(|_| "unknown".to_string());
    // Try to get repo name from git remote or just dir name
    let repo_name = std::env::current_dir()
        .map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // Wait for file to exist
    while !sync_log_path.exists() {
        println!("Waiting for sync-log at {}...", sync_log_path.display());
        thread::sleep(Duration::from_secs(1));
    }

    let _file = std::fs::File::open(&sync_log_path).context("Failed to open sync-log")?;
    
    // Seek to end initially to only show new events? 
    // Actually for dashboard we might want to show last few events.
    // Let's read last 10 lines.
    // For simplicity, let's just read from start or seek to end - 1000 bytes?
    // Let's just tail from now for the "Activity" stream, but maybe print last few lines first.
    
    // Actually, let's implement a loop that redraws every second.
    // It's easier than complex async IO for now.
    
    loop {
        // 1. Read connected users
        let mut connected_users = Vec::new();
        if active_users_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&active_users_path) {
                for line in content.lines() {
                    if !line.trim().is_empty() {
                        connected_users.push(line.trim().to_string());
                    }
                }
            }
        }
        // Deduplicate
        connected_users.sort();
        connected_users.dedup();

        // 2. Read last N lines of sync log
        // Re-open to get fresh content or just seek?
        // If we want to show a scrolling log, we should keep the file open.
        // But we also want to redraw the header.
        
        // Let's clear screen and redraw header
        print!("\x1B[2J\x1B[1;1H");
        
        // Try to get repo name from env first (set by wrapper.sh)
        let display_repo_name = std::env::var("REPO_NAME").unwrap_or(repo_name.clone());

        println!("SteadyState Session: {}", session_id);
        // Try to read session-info.json
        let session_info_path = Path::new(&repo_root).join("session-info.json");
        if session_info_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&session_info_path) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(link) = json.get("magic_link").and_then(|v| v.as_str()) {
                        println!("Join: steadystate join \"{}\"", link);
                    }
                    if let Some(ssh_url) = json.get("ssh_url").and_then(|v| v.as_str()) {
                        println!("SSH:  {}", ssh_url);
                    }
                }
            }
        } else if let Ok(link) = std::env::var("MAGIC_LINK") {
             println!("Magic Link: {}", link);
        }
        println!("Repo: {}", display_repo_name);
        println!("-------------------------------------------------------------------------------------------------");
        println!();
        println!("Connected users:");
        if connected_users.is_empty() {
            println!("  (none)");
        } else {
            for user in &connected_users {
                println!("  • {}", user);
            }
        }
        println!();
        println!("Activity (tailing sync-log):");
        
        // Read last 10 lines
        // This is inefficient but fine for a prototype
        let content = std::fs::read_to_string(&sync_log_path).unwrap_or_default();
        let lines: Vec<&str> = content.lines().collect();
        let start = if lines.len() > 10 { lines.len() - 10 } else { 0 };
        
        for line in &lines[start..] {
            // Parse timestamp
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                // Format: timestamp user
                if let Ok(ts) = parts[0].parse::<i64>() {
                    let dt: DateTime<Local> = Local.timestamp_opt(ts, 0).unwrap();
                    println!("  [{}] {} synced", dt.format("%H:%M:%S"), parts[1]);
                } else {
                    println!("  [{}] {} synced", parts[0], parts[1]);
                }
            } else {
                println!("  {}", line);
            }
        }
        
        println!();
        println!("Watching for changes... (Ctrl+C to exit)");
        
        thread::sleep(Duration::from_secs(2));
    }
}
