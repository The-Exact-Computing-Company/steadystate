use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use std::fs::OpenOptions;
use std::io::Write;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use notify::{RecommendedWatcher, RecursiveMode, Watcher, Event as NotifyEvent};
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the session root directory
    #[arg(short, long)]
    session_root: PathBuf,
}

#[derive(Debug, Clone)]
struct FileEvent {
    user: String,
    path: PathBuf,
    event_type: FileEventType,
}

#[derive(Debug, Clone)]
enum FileEventType {
    Opened,
    Modified,
    Saved,
}

struct EventDaemon {
    session_root: PathBuf,
    activity_log: PathBuf,
    debounce_map: HashMap<PathBuf, std::time::Instant>,
}

impl EventDaemon {
    fn new(session_root: PathBuf) -> Self {
        let activity_log = session_root.join("activity-log");
        Self {
            session_root,
            activity_log,
            debounce_map: HashMap::new(),
        }
    }

    async fn run(&mut self) -> Result<()> {
        let (tx, mut rx) = mpsc::channel(100);
        
        // Initial discovery of workspaces
        let workspaces = self.discover_workspaces()?;
        let mut _watchers = Vec::new(); // Keep watchers alive
        
        for (user, workspace) in workspaces {
            tracing::info!("Watching workspace for user: {}", user);
            let watcher = self.watch_workspace(&user, &workspace, tx.clone())?;
            _watchers.push(watcher);
        }
        
        // TODO: Watch for new user directories appearing?
        // For now, we assume users are created before daemon starts or we restart daemon?
        // Actually, users are created when they SSH in.
        // So we should watch the session_root for new directories too.
        
        let _root_tx = tx.clone();
        let _root_session = self.session_root.clone();
        let mut root_watcher = notify::recommended_watcher(move |res: notify::Result<NotifyEvent>| {
            if let Ok(event) = res {
                if let notify::event::EventKind::Create(_) = event.kind {
                    for path in event.paths {
                        if path.is_dir() {
                            // Check if it looks like a user workspace (has .git?)
                            // Or just assume any new dir is a user workspace?
                            // Let's just signal a "NewWorkspace" event and handle it in the loop?
                            // For simplicity, we might just poll or restart.
                            // But let's stick to the plan: watch existing.
                            // If we need dynamic watching, we'd need a control channel to add watchers.
                        }
                    }
                }
            }
        })?;
        root_watcher.watch(&self.session_root, RecursiveMode::NonRecursive)?;
        
        tracing::info!("Event daemon started for session: {}", self.session_root.display());

        while let Some(event) = rx.recv().await {
            self.process_file_event(event).await?;
        }
        
        Ok(())
    }
    
    fn discover_workspaces(&self) -> Result<Vec<(String, PathBuf)>> {
        let mut workspaces = Vec::new();
        
        for entry in std::fs::read_dir(&self.session_root)? {
            let entry = entry?;
            let path = entry.path();
            
            if !path.is_dir() { continue; }
            
            let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
            
            // Skip system dirs
            if name.starts_with('.') || name == "git-repo" || name == "canonical" || name == "bin" {
                continue;
            }
            
            // Check if it has .git (valid workspace)
            if path.join(".git").exists() {
                workspaces.push((name, path));
            }
        }
        
        Ok(workspaces)
    }

    fn watch_workspace(
        &self,
        user: &str,
        workspace: &Path,
        tx: mpsc::Sender<FileEvent>,
    ) -> Result<RecommendedWatcher> {
        let user_id = user.to_string();
        let workspace_path = workspace.to_path_buf();
        
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<NotifyEvent>| {
            if let Ok(event) = res {
                for path in &event.paths {
                    if !should_track(path) {
                        continue;
                    }
                    
                    let rel_path = match path.strip_prefix(&workspace_path) {
                        Ok(p) => p.to_path_buf(),
                        Err(_) => continue,
                    };
                    
                    let event_type = match event.kind {
                        notify::event::EventKind::Access(notify::event::AccessKind::Open(_)) => FileEventType::Opened,
                        notify::event::EventKind::Modify(notify::event::ModifyKind::Data(_)) => FileEventType::Modified,
                        notify::event::EventKind::Access(notify::event::AccessKind::Close(notify::event::AccessMode::Write)) => FileEventType::Saved,
                        _ => continue,
                    };
                    
                    let file_event = FileEvent {
                        user: user_id.clone(),
                        path: rel_path,
                        event_type,
                    };
                    
                    let _ = tx.blocking_send(file_event);
                }
            }
        })?;
        
        watcher.watch(workspace, RecursiveMode::Recursive)?;
        Ok(watcher)
    }
    
    async fn process_file_event(&mut self, event: FileEvent) -> Result<()> {
        // Debounce
        let key = event.path.clone(); // Simple debounce by path
        let now = std::time::Instant::now();
        
        if let Some(last) = self.debounce_map.get(&key) {
            if now.duration_since(*last) < Duration::from_millis(500) {
                return Ok(());
            }
        }
        self.debounce_map.insert(key, now);
        
        let action = match event.event_type {
            FileEventType::Opened => format!("editing:{}", event.path.display()),
            FileEventType::Modified => return Ok(()), // Don't log every modification, wait for save
            FileEventType::Saved => format!("saved:{}", event.path.display()),
        };
        
        self.log_activity(&event.user, &action).await?;
        
        Ok(())
    }
    
    async fn log_activity(&self, user: &str, action: &str) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.activity_log)?;
            
        let log_line = format!(
            "{},{},{}\n",
            Utc::now().to_rfc3339(),
            user,
            action
        );
        
        file.write_all(log_line.as_bytes())?;
        // file.sync_all()?; // Async write might be better but std::fs is blocking.
        // Since this is a separate binary, blocking IO is fine for now.
        
        Ok(())
    }
}

fn should_track(path: &Path) -> bool {
    // Basic filtering
    let s = path.to_string_lossy();
    !s.contains("/.git/") && 
    !s.contains("/target/") && 
    !s.contains("/node_modules/") &&
    !s.ends_with('~')
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    let args = Args::parse();
    
    if !args.session_root.exists() {
        return Err(anyhow::anyhow!("Session root does not exist: {}", args.session_root.display()));
    }
    
    let mut daemon = EventDaemon::new(args.session_root);
    daemon.run().await?;
    
    Ok(())
}
