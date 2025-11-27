use anyhow::{Context, Result};
use std::process::Command;
use std::path::Path;
use std::io::Write;
use std::fs;
use serde::{Deserialize, Serialize};
use crate::merge;
use walkdir::WalkDir;

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
    
    // Lock canonical to prevent concurrent syncs
    let _lock = lock_canonical(&canonical_path)?;

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

    // 3. Materialize trees
    println!("Materializing trees...");
    let base_tree = merge::materialize_git_tree(&canonical_path, &base_commit).context("Failed to materialize base tree")?;
    
    // Canonical HEAD (should be on session branch)
    let canonical_head = get_git_head(&canonical_path)?;
    let canonical_tree = merge::materialize_git_tree(&canonical_path, &canonical_head).context("Failed to materialize canonical tree")?;
    
    let local_tree = merge::materialize_fs_tree(&worktree_path).context("Failed to materialize local tree")?;

    // 4. Merge
    println!("Merging...");
    let merged_tree = merge::merge_trees(&base_tree, &local_tree, &canonical_tree).context("Merge failed")?;

    // 5. Write merged result to canonical
    println!("Applying to canonical...");
    apply_tree_to_canonical(&canonical_path, &merged_tree)?;

    // 6. Commit and Push
    println!("Committing...");
    let status = Command::new("git")
        .arg("-C")
        .arg(&canonical_path)
        .args(&["add", "-A"])
        .status()?;
    
    if !status.success() { return Err(anyhow::anyhow!("git add failed")); }

    // Check if anything changed
    let diff_status = Command::new("git")
        .arg("-C")
        .arg(&canonical_path)
        .args(&["diff", "--cached", "--quiet"])
        .status()?;

    if !diff_status.success() { // Exit code 1 means differences found (good)
        let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
        let msg = format!("sync: SteadyState session by {}", user);
        
        let commit_status = Command::new("git")
            .arg("-C")
            .arg(&canonical_path)
            .args(&["commit", "-m", &msg, "--author", "SteadyState Bot <bot@steadystate.dev>"])
            .status()?;
            
        if !commit_status.success() { return Err(anyhow::anyhow!("git commit failed")); }
        
        let push_status = Command::new("git")
            .arg("-C")
            .arg(&canonical_path)
            .args(&["push", "origin", &session_branch])
            .status()?;
            
        if !push_status.success() { return Err(anyhow::anyhow!("git push failed")); }
    } else {
        println!("No changes to commit.");
    }

    // 7. Reset local worktree
    println!("Refreshing worktree...");
    // Fetch from canonical (origin)
    // Note: We are running git fetch inside canonical to ensure it has latest from origin (though we just pushed to it)
    // Actually, we want to update the worktree to match what is now in canonical.
    // Since worktree is NOT a git repo (in Model A), we just copy files from canonical.
    
    sync_worktree_from_canonical(&canonical_path, &worktree_path)?;

    // 8. Update metadata
    let new_head = get_git_head(&canonical_path)?;
    let new_meta = WorktreeMeta { 
        session_branch: session_branch.clone(),
        last_synced_commit: new_head 
    };
    fs::create_dir_all(&meta_dir)?;
    fs::write(&meta_path, serde_json::to_string_pretty(&new_meta)?)?;

    // 9. Update sync-log
    let sync_log_path = repo_root_path.join("sync-log");
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
        
    let log_entry = format!("{} {}\n", timestamp, user);
    
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&sync_log_path) 
    {
        let _ = file.write_all(log_entry.as_bytes());
    }

    println!("✅ Sync complete!");
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
fn apply_tree_to_canonical(repo_path: &Path, tree: &crate::merge::TreeSnapshot) -> Result<()> {
    // Safety check
    if !repo_path.ends_with("canonical") {
        // It might be absolute path ending in canonical
        // Just check if it has a .git dir
        if !repo_path.join(".git").exists() {
             return Err(anyhow::anyhow!("Safety check failed: {} does not look like a git repo", repo_path.display()));
        }
    }
    
    // Delete everything except .git
    for entry in fs::read_dir(repo_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.file_name().unwrap() == ".git" { continue; }
        if path.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }

    // Write files
    for (rel_path, content) in &tree.files {
        let full_path = repo_path.join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(full_path, content)?;
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
