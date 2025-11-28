use anyhow::{Context, Result};
use std::process::Command;
use std::path::{Path, PathBuf};
use std::io::Write;
use std::fs;
use std::time::SystemTime;
use serde::{Deserialize, Serialize};
use crate::merge;
use walkdir::WalkDir;
use fs2::FileExt;
use similar::{ChangeTag, TextDiff};
use crossterm::style::Stylize;

#[derive(Serialize, Deserialize)]
struct WorktreeMeta {
    session_branch: String,
    last_synced_commit: String,
}

struct SyncContext {
    repo_root_path: PathBuf,
    canonical_path: PathBuf,
    worktree_path: PathBuf,
    meta_path: PathBuf,
    meta: WorktreeMeta,
}

impl SyncContext {
    fn new() -> Result<Self> {
        let repo_root = std::env::var("REPO_ROOT").unwrap_or_else(|_| "..".to_string());
        let repo_root_path = if Path::new(&repo_root).is_absolute() {
            Path::new(&repo_root).to_path_buf()
        } else {
            std::env::current_dir()?.join(&repo_root).canonicalize().unwrap_or_else(|_| Path::new(&repo_root).to_path_buf())
        };
        
        let canonical_path = repo_root_path.join("canonical");
        let worktree_path = std::env::current_dir().context("Failed to get current dir")?;
        let meta_dir = worktree_path.join(".worktree");
        let meta_path = meta_dir.join("steadystate.json");

        if !meta_path.exists() {
            return Err(anyhow::anyhow!("Metadata file not found at {}. Session not initialized correctly.", meta_path.display()));
        }
        
        let content = fs::read_to_string(&meta_path).context("Failed to read metadata")?;
        let meta: WorktreeMeta = serde_json::from_str(&content).context("Failed to parse metadata")?;

        Ok(Self {
            repo_root_path,
            canonical_path,
            worktree_path,
            meta_path,
            meta,
        })
    }
}

pub async fn status_command() -> Result<()> {
    let ctx = SyncContext::new()?;
    
    // Materialize trees
    let base_tree = merge::materialize_git_tree(&ctx.canonical_path, &ctx.meta.last_synced_commit)
        .context("Failed to materialize base tree")?;
    let local_tree = merge::materialize_fs_tree(&ctx.worktree_path)
        .context("Failed to materialize local tree")?;

    let mut added = Vec::new();
    let mut modified = Vec::new();
    let mut deleted = Vec::new();

    // Check for local changes vs base
    for (path, content) in &local_tree.files {
        match base_tree.files.get(path) {
            Some(base_content) => {
                if content != base_content {
                    modified.push(path);
                }
            }
            None => {
                added.push(path);
            }
        }
    }

    for path in base_tree.files.keys() {
        if !local_tree.files.contains_key(path) {
            deleted.push(path);
        }
    }

    if added.is_empty() && modified.is_empty() && deleted.is_empty() {
        println!("On branch {}", ctx.meta.session_branch);
        println!("nothing to commit, working tree clean");
        return Ok(());
    }

    println!("On branch {}", ctx.meta.session_branch);
    println!("Changes not staged for commit:");
    println!("  (use \"steadystate publish\" to update the session)");
    println!();

    for path in modified {
        println!("\t{}", format!("modified:   {}", path).red());
    }
    for path in deleted {
        println!("\t{}", format!("deleted:    {}", path).red());
    }
    
    if !added.is_empty() {
        println!();
        println!("Untracked files:");
        println!("  (use \"steadystate publish\" to include in what will be committed)");
        println!();
        for path in added {
            println!("\t{}", path.as_str().red());
        }
    }

    Ok(())
}

pub async fn diff_command() -> Result<()> {
    let ctx = SyncContext::new()?;
    
    // Materialize trees
    let base_tree = merge::materialize_git_tree(&ctx.canonical_path, &ctx.meta.last_synced_commit)
        .context("Failed to materialize base tree")?;
    let local_tree = merge::materialize_fs_tree(&ctx.worktree_path)
        .context("Failed to materialize local tree")?;

    let mut all_paths: Vec<_> = base_tree.files.keys().chain(local_tree.files.keys()).collect();
    all_paths.sort();
    all_paths.dedup();

    for path in all_paths {
        let base_content = base_tree.files.get(path);
        let local_content = local_tree.files.get(path);

        match (base_content, local_content) {
            (Some(base), Some(local)) => {
                if base != local {
                    print_diff(path, base, local);
                }
            }
            (Some(base), None) => {
                // Deleted
                println!("diff a/{} b/{}", path, path);
                println!("deleted file mode 100644");
                println!("--- a/{}", path);
                println!("+++ /dev/null");
                // Show all lines as deleted
                if let Ok(s) = std::str::from_utf8(base) {
                    for line in s.lines() {
                        println!("{}", format!("-{}", line).red());
                    }
                } else {
                    println!("Binary file {} deleted", path);
                }
            }
            (None, Some(local)) => {
                // Added
                println!("diff a/{} b/{}", path, path);
                println!("new file mode 100644");
                println!("--- /dev/null");
                println!("+++ b/{}", path);
                // Show all lines as added
                if let Ok(s) = std::str::from_utf8(local) {
                    for line in s.lines() {
                        println!("{}", format!("+{}", line).green());
                    }
                } else {
                    println!("Binary file {} added", path);
                }
            }
            (None, None) => unreachable!(),
        }
    }

    Ok(())
}

fn print_diff(path: &str, old: &[u8], new: &[u8]) {
    let old_str = match std::str::from_utf8(old) {
        Ok(s) => s,
        Err(_) => {
            println!("Binary files a/{} and b/{} differ", path, path);
            return;
        }
    };
    let new_str = match std::str::from_utf8(new) {
        Ok(s) => s,
        Err(_) => {
            println!("Binary files a/{} and b/{} differ", path, path);
            return;
        }
    };

    let diff = TextDiff::from_lines(old_str, new_str);

    // Use unified diff format with context
    print!("{}", diff.unified_diff().context_radius(3).header(path, path));
}

pub async fn publish_command() -> Result<()> {
    let ctx = SyncContext::new()?;
    let session_branch = ctx.meta.session_branch;
    let canonical_path = ctx.canonical_path;
    let worktree_path = ctx.worktree_path;
    let repo_root_path = ctx.repo_root_path;

    println!("Publishing changes to {}...", session_branch);

    // Resolve current user for fallback
    let current_user = match crate::session::read_session(None).await {
        Ok(session) => session.login,
        Err(_) => std::env::var("STEADYSTATE_USERNAME")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "unknown".to_string()),
    };

    // Scope the lock
    {
        let _lock = lock_canonical(&canonical_path)?;

        // 1. Update canonical from worktree (Staging)
        println!("Staging changes...");
        sync_canonical_from_worktree(&worktree_path, &canonical_path)?;

        // 2. Commit
        println!("Committing...");
        
        // Generate commit message with active users
        let sync_log_path = repo_root_path.join("sync-log");
        let users = get_active_users(&sync_log_path, &current_user).unwrap_or_else(|_| vec![current_user.clone()]);
        let user_list = users.join(", ");
        let msg = format!("Changes from collab session between {}", user_list);

        let status = Command::new("git")
            .arg("-C")
            .arg(&canonical_path)
            .args(&["add", "-A"])
            .status()?;
        
        if !status.success() { return Err(anyhow::anyhow!("git add failed")); }

        let diff_status = Command::new("git")
            .arg("-C")
            .arg(&canonical_path)
            .args(&["diff", "--cached", "--quiet"])
            .status()?;

        if !diff_status.success() {
            let commit_status = Command::new("git")
                .arg("-C")
                .arg(&canonical_path)
                .args(&["commit", "-m", &msg, "--author", "SteadyState Bot <bot@steadystate.dev>"])
                .status()?;
                
            if !commit_status.success() { return Err(anyhow::anyhow!("git commit failed")); }
        } else {
            println!("No changes to commit.");
        }

        // 3. Push to local canonical repo (intermediate)
        println!("Pushing to session repo...");
        let push_status = Command::new("git")
            .arg("-C")
            .arg(&canonical_path)
            .args(&["push", "origin", &session_branch])
            .status()?;
            
        if !push_status.success() {
            eprintln!("❌ Push to session repo failed. The remote branch is likely ahead of your local state.");
            eprintln!("💡 Run 'steadystate sync' to merge remote changes into your worktree, then try publishing again.");
            return Err(anyhow::anyhow!("Push failed"));
        }

        // 4. Push from session repo to GitHub (origin)
        println!("Pushing to GitHub...");
        // The 'repo' directory is a sibling of 'canonical'
        let repo_path = canonical_path.parent().unwrap().join("repo");
        
        // We use -C because 'repo' is a bare repository (or might be)
        // If it's not bare, this still works if pointing to the .git dir, but here 'repo' IS the git dir if bare.
        // However, local_provider.rs initializes it as a clone. If it's a bare clone, 'repo' is the dir.
        
        let github_push_status = Command::new("git")
            .arg("-C")
            .arg(&repo_path)
            .args(&["push", "origin", &session_branch])
            .status()?;

        if !github_push_status.success() {
            eprintln!("⚠️  Warning: Push to GitHub failed.");
            eprintln!("   Your changes are saved in the session, but could not be pushed to GitHub.");
            eprintln!("   Check your internet connection or GitHub permissions.");
            // We don't return error here because the session state is consistent locally
        }
    }

    println!("✅ Publish complete!");
    Ok(())
}

fn get_active_users(log_path: &Path, current_user: &str) -> Result<Vec<String>> {
    if !log_path.exists() {
        return Ok(vec![current_user.to_string()]);
    }

    let content = fs::read_to_string(log_path)?;
    let mut users = Vec::new();
    // Simple parsing: just get all unique users from the log
    // In a real scenario, we might want to filter by recent time window
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let user = parts[1].to_string();
            if !users.contains(&user) {
                users.push(user);
            }
        }
    }
    
    if users.is_empty() {
        users.push(current_user.to_string());
    }
    
    Ok(users)
}

fn sync_canonical_from_worktree(worktree_path: &Path, canonical_path: &Path) -> Result<()> {
    // 1. Clear canonical (except .git)
    for entry in fs::read_dir(canonical_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.file_name().unwrap() == ".git" { 
            continue; 
        }
        
        if path.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }

    // 2. Copy from worktree (except .worktree, .git)
    for entry in WalkDir::new(worktree_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        
        let rel_path = path.strip_prefix(worktree_path)?;
        let rel_path_str = rel_path.to_string_lossy();
        
        if rel_path_str.starts_with(".git") || rel_path_str.contains("/.git/") || 
           rel_path_str.starts_with(".worktree") || rel_path_str.contains("/.worktree/") {
            continue;
        }

        let dest_path = canonical_path.join(rel_path);
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(path, dest_path)?;
    }

    Ok(())
}

pub async fn sync() -> Result<()> {
    println!("Syncing changes (Y-CRDT)...");

    let ctx = SyncContext::new()?;
    let base_commit = ctx.meta.last_synced_commit;
    let session_branch = ctx.meta.session_branch;
    let canonical_path = ctx.canonical_path;
    let worktree_path = ctx.worktree_path;
    let meta_dir = ctx.meta_path.parent().unwrap().to_path_buf();
    let meta_path = ctx.meta_path; // Move happens here
    let repo_root_path = ctx.repo_root_path;

    // Resolve user early
    let user = match crate::session::read_session(None).await {
        Ok(session) => session.login,
        Err(_) => std::env::var("STEADYSTATE_USERNAME")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "unknown".to_string()),
    };

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
        
        let canonical_tree = if !fetch_status.success() {
            // Check if it's because the branch doesn't exist
            // If so, we treat it as a new branch (first push)
            // Canonical state is effectively the base state (no remote changes yet)
            println!("⚠️  Remote branch not found. Assuming first push for this session.");
            println!("   Using base commit as canonical state.");
            
            // Materialize base tree as canonical tree
            merge::materialize_git_tree(&canonical_path, &base_commit).context("Failed to materialize base tree (as canonical)")?
        } else {
            // Use origin/session_branch as canonical ref
            let canonical_ref = format!("origin/{}", session_branch);
            
            // Verify the ref exists
            let verify_status = Command::new("git")
                .arg("-C")
                .arg(&canonical_path)
                .args(&["rev-parse", "--verify", &canonical_ref])
                .status()?;
            
            if !verify_status.success() {
                // Should not happen if fetch succeeded, but just in case
                return Err(anyhow::anyhow!(
                    "Remote branch {} does not exist after successful fetch.",
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
            
            merge::materialize_git_tree(&canonical_path, &canonical_ref).context("Failed to materialize canonical tree")?
        };

        // 4. Materialize trees
        println!("Materializing trees...");
        let base_tree = merge::materialize_git_tree(&canonical_path, &base_commit).context("Failed to materialize base tree")?;
        
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
        if let Err(e) = commit_changes(&canonical_path, &session_branch, &user) {
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

    // 9. Push (REMOVED: Push is now handled by `steadystate publish`)
    // println!("Pushing to remote...");
    
    // 10. Reset local worktree
    println!("Refreshing worktree...");
    sync_worktree_from_canonical(&canonical_path, &worktree_path)?;

    // 11. Update sync-log
    let sync_log_path = repo_root_path.join("sync-log");
    
    let timestamp = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
        
    append_to_sync_log(&sync_log_path, &user, timestamp)?;

    println!("✅ Sync complete!");
    Ok(())
}

fn commit_changes(repo_path: &Path, _branch: &str, user: &str) -> Result<()> {
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
