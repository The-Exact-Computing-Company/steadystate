use anyhow::{Context, Result};
use std::process::Command;
use std::path::Path;
use std::io::Write;
use std::fs;
use std::time::SystemTime;
use serde::{Deserialize, Serialize};
use crate::merge;
use walkdir::WalkDir;
use fs2::FileExt;

#[derive(Serialize, Deserialize)]
struct WorktreeMeta {
    session_branch: String,
    last_synced_commit: String,
}

pub fn sync() -> Result<()> {
    println!("Syncing changes (Y-CRDT)...");

    // 1. Determine paths
    let repo_root = std::env::var("REPO_ROOT").unwrap_or_else(|_| "../..".to_string());
    // Resolve repo_root relative to current dir if it's relative
    let repo_root_path = if Path::new(&repo_root).is_absolute() {
        Path::new(&repo_root).to_path_buf()
    } else {
        std::env::current_dir()?.join(&repo_root).canonicalize().unwrap_or_else(|_| Path::new(&repo_root).to_path_buf())
    };
    
    let canonical_path = repo_root_path.join("canonical");
    
    let worktree_path = std::env::current_dir().context("Failed to get current dir")?;
    let meta_dir = worktree_path.join(".worktree");
    let meta_path = meta_dir.join("steadystate.json");

    // 2. Load metadata
    if !meta_path.exists() {
        return Err(anyhow::anyhow!("Metadata file not found at {}. Session not initialized correctly.", meta_path.display()));
    }
    
    let content = fs::read_to_string(&meta_path).context("Failed to read metadata")?;
    let meta: WorktreeMeta = serde_json::from_str(&content).context("Failed to parse metadata")?;
    
    let base_commit = meta.last_synced_commit;
    let session_branch = meta.session_branch;

    println!("Base commit: {}", base_commit);
    println!("Session branch: {}", session_branch);

    // Scope the lock so it is released before push
    {
        // Lock canonical to prevent concurrent syncs
        let _lock = lock_canonical(&canonical_path)?;

        // 3. Fetch latest changes BEFORE materializing
        println!("Fetching latest changes...");
        let fetch_status = Command::new("git")
            .arg("-C")
            .arg(&canonical_path)
            .args(&["fetch", "origin", &session_branch])
            .status()
            .context("Failed to fetch from origin")?;
        
        if !fetch_status.success() {
            return Err(anyhow::anyhow!("git fetch failed"));
        }

        // Use origin/session_branch as canonical ref
        let canonical_ref = format!("origin/{}", session_branch);
        
        // Verify the ref exists
        let verify_status = Command::new("git")
            .arg("-C")
            .arg(&canonical_path)
            .args(&["rev-parse", "--verify", &canonical_ref])
            .status()?;
        
        if !verify_status.success() {
            return Err(anyhow::anyhow!(
                "Remote branch {} does not exist. Has the session been initialized?",
                canonical_ref
            ));
        }

        // CRITICAL FIX: Reset local branch to match remote
        println!("Updating local branch to match remote...");
        let reset_status = Command::new("git")
            .arg("-C")
            .arg(&canonical_path)
            .args(&["reset", "--hard", &canonical_ref])
            .status()
            .context("Failed to reset local branch")?;

        if !reset_status.success() {
            return Err(anyhow::anyhow!("Failed to reset to remote branch"));
        }

        // 4. Materialize trees
        println!("Materializing trees...");
        let base_tree = merge::materialize_git_tree(&canonical_path, &base_commit).context("Failed to materialize base tree")?;
        
        let canonical_tree = merge::materialize_git_tree(&canonical_path, &canonical_ref).context("Failed to materialize canonical tree")?;
        
        let local_tree = merge::materialize_fs_tree(&worktree_path).context("Failed to materialize local tree")?;

        // Check for changes before merging
        println!("Detecting changes...");
        let local_changed = local_tree.files.len() != base_tree.files.len() 
            || local_tree.files.iter().any(|(k, v)| base_tree.files.get(k) != Some(v));
        let remote_changed = canonical_tree.files.len() != base_tree.files.len()
            || canonical_tree.files.iter().any(|(k, v)| base_tree.files.get(k) != Some(v));

        if !local_changed && !remote_changed {
            println!("No changes detected. Already up to date.");
            return Ok(());
        }

        if local_changed && !remote_changed {
            println!("Only local changes detected.");
        } else if !local_changed && remote_changed {
            println!("Only remote changes detected.");
        } else {
            println!("Both local and remote changes detected. Merging...");
        }

        // 5. Merge
        println!("Merging...");
        let merged_tree = merge::merge_trees(&base_tree, &local_tree, &canonical_tree).context("Merge failed")?;

        // 6. Apply to canonical with safety checks and backup
        println!("Creating safety backup...");
        let backup_ref = format!("refs/backups/sync-{}", 
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        
        let current_head = get_git_head(&canonical_path)?;
        Command::new("git")
            .arg("-C")
            .arg(&canonical_path)
            .args(&["update-ref", &backup_ref, &current_head])
            .status()
            .context("Failed to create backup ref")?;

        println!("Applying to canonical...");
        if let Err(e) = apply_tree_to_canonical(&canonical_path, &merged_tree, &session_branch) {
            eprintln!("❌ Failed to apply tree: {}", e);
            eprintln!("🔄 Attempting recovery from backup...");
            
            // Restore from backup
            let reset_status = Command::new("git")
                .arg("-C")
                .arg(&canonical_path)
                .args(&["reset", "--hard", &backup_ref])
                .status();
                
            match reset_status {
                Ok(status) if status.success() => {
                    return Err(anyhow::anyhow!(
                        "Sync failed but successfully restored previous state. Error: {}", 
                        e
                    ));
                }
                _ => {
                    return Err(anyhow::anyhow!(
                        "Sync failed AND recovery failed! Manual intervention required. \
                         Backup ref: {}. Original error: {}",
                        backup_ref,
                        e
                    ));
                }
            }
        }

        // 7. Commit
        println!("Committing...");
        if let Err(e) = commit_changes(&canonical_path, &session_branch) {
            eprintln!("❌ Failed to commit: {}", e);
            eprintln!("🔄 Attempting recovery from backup...");
            
            // Restore from backup
            Command::new("git")
                .arg("-C")
                .arg(&canonical_path)
                .args(&["reset", "--hard", &backup_ref])
                .status()?;
                
            return Err(anyhow::anyhow!("Commit failed, restored previous state. Error: {}", e));
        }

        // Clean up backup
        Command::new("git")
            .arg("-C")
            .arg(&canonical_path)
            .args(&["update-ref", "-d", &backup_ref])
            .status()
            .ok();

        // 8. Update metadata IMMEDIATELY after commit
        let new_head = get_git_head(&canonical_path)?;
        let new_meta = WorktreeMeta { 
            session_branch: session_branch.clone(),
            last_synced_commit: new_head 
        };
        fs::create_dir_all(&meta_dir)?;
        fs::write(&meta_path, serde_json::to_string_pretty(&new_meta)?)?;
    } // Lock released here

    // 9. Push (without lock)
    println!("Pushing to remote...");
    let push_status = Command::new("git")
        .arg("-C")
        .arg(&canonical_path)
        .args(&["push", "origin", &session_branch])
        .status()?;
        
    if !push_status.success() { 
        eprintln!("⚠️  Warning: Push failed. Your changes are committed locally but not synced to remote.");
        eprintln!("   You can manually push from: {}", canonical_path.display());
        eprintln!("   Run: cd {} && git push origin {}", canonical_path.display(), session_branch);
    }

    // 10. Reset local worktree
    println!("Refreshing worktree...");
    sync_worktree_from_canonical(&canonical_path, &worktree_path)?;

    // 11. Update sync-log
    let sync_log_path = repo_root_path.join("sync-log");
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    let timestamp = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
        
    append_to_sync_log(&sync_log_path, &user, timestamp)?;

    println!("✅ Sync complete!");
    Ok(())
}

fn commit_changes(repo_path: &Path, _branch: &str) -> Result<()> {
    let status = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .args(&["add", "-A"])
        .status()?;
    
    if !status.success() { return Err(anyhow::anyhow!("git add failed")); }

    let diff_status = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .args(&["diff", "--cached", "--quiet"])
        .status()?;

    if !diff_status.success() {
        let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
        let msg = format!("sync: SteadyState session by {}", user);
        
        let commit_status = Command::new("git")
            .arg("-C")
            .arg(repo_path)
            .args(&["commit", "-m", &msg, "--author", "SteadyState Bot <bot@steadystate.dev>"])
            .status()?;
            
        if !commit_status.success() { return Err(anyhow::anyhow!("git commit failed")); }
    }
    
    Ok(())
}

fn append_to_sync_log(log_path: &Path, user: &str, timestamp: u64) -> Result<()> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .context("Failed to open sync-log")?;
    
    // Lock for append
    file.lock_exclusive()
        .context("Failed to lock sync-log")?;
    
    let log_entry = format!("{} {}\n", timestamp, user);
    (&file).write_all(log_entry.as_bytes())
        .context("Failed to write to sync-log")?;
    
    FileExt::unlock(&file).ok();
    Ok(())
}

fn get_git_head(repo_path: &Path) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .args(&["rev-parse", "HEAD"])
        .output()?;
    if !output.status.success() { return Err(anyhow::anyhow!("git rev-parse HEAD failed")); }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// WARNING: This function is DESTRUCTIVE.
/// It deletes all files in `repo_path` (except .git) and replaces them with `tree`.
/// This is intended for the ephemeral `canonical` repository used in sessions.
fn apply_tree_to_canonical(
    repo_path: &Path,
    tree: &crate::merge::TreeSnapshot,
    expected_branch: &str,
) -> Result<()> {
    // Safety check 1: Must have .git
    let git_dir = repo_path.join(".git");
    if !git_dir.exists() {
        return Err(anyhow::anyhow!(
            "Safety check failed: {} is not a git repository",
            repo_path.display()
        ));
    }
    
    // Safety check 2: Must end with /canonical
    if !repo_path.ends_with("canonical") {
        return Err(anyhow::anyhow!(
            "Safety check failed: {} does not end with 'canonical'. \
             This function should only be used on ephemeral canonical repos.",
            repo_path.display()
        ));
    }
    
    // Safety check 3: Verify we're on the expected branch
    let current_branch_output = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .args(&["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .context("Failed to get current branch")?;
    
    if !current_branch_output.status.success() {
        return Err(anyhow::anyhow!("Failed to determine current branch"));
    }
    
    let current_branch = String::from_utf8_lossy(&current_branch_output.stdout).trim().to_string();
    if current_branch != expected_branch {
        return Err(anyhow::anyhow!(
            "Safety check failed: Expected branch '{}' but on '{}'. \
             Refusing to apply tree to wrong branch.",
            expected_branch,
            current_branch
        ));
    }
    
    // Safety check 4: Verify working tree is clean - REMOVED as redundant after reset --hard
    // We just performed a hard reset to the remote branch, so the working tree is guaranteed clean.
    
    // All safety checks passed - proceed with deletion
    tracing::info!("Applying tree to {} (passed all safety checks)", repo_path.display());
    
    // Delete everything except .git
    for entry in fs::read_dir(repo_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.file_name().unwrap() == ".git" { 
            continue; 
        }
        
        if path.is_dir() {
            fs::remove_dir_all(&path)
                .with_context(|| format!("Failed to remove directory {}", path.display()))?;
        } else {
            fs::remove_file(&path)
                .with_context(|| format!("Failed to remove file {}", path.display()))?;
        }
    }

    // Write merged files
    for (rel_path, content) in &tree.files {
        let full_path = repo_path.join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {}", parent.display()))?;
        }
        fs::write(&full_path, content)
            .with_context(|| format!("Failed to write file {}", full_path.display()))?;
    }
    
    Ok(())
}

fn sync_worktree_from_canonical(canonical_path: &Path, worktree_path: &Path) -> Result<()> {
    // 1. Clear worktree (except .worktree and .git if it exists)
    for entry in WalkDir::new(worktree_path).min_depth(1).max_depth(1).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        let name = path.file_name().unwrap().to_string_lossy();
        if name == ".worktree" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            fs::remove_dir_all(path)?;
        } else {
            fs::remove_file(path)?;
        }
    }

    // 2. Copy from canonical (except .git)
    for entry in WalkDir::new(canonical_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        
        let rel_path = path.strip_prefix(canonical_path)?;
        let rel_path_str = rel_path.to_string_lossy();
        
        if rel_path_str.starts_with(".git") || rel_path_str.contains("/.git/") {
            continue;
        }

        let dest_path = worktree_path.join(rel_path);
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(path, dest_path)?;
    }

    Ok(())
}

fn lock_canonical(repo_path: &Path) -> Result<std::fs::File> {
    use fs2::FileExt;
    let lock_path = repo_path.join(".steadystate.lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&lock_path)
        .context("Failed to open lock file")?;
    
    file.lock_exclusive().context("Failed to acquire lock")?;
    Ok(file)
}
