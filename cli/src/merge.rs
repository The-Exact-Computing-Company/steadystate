use anyhow::{anyhow, Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use yrs::{Doc, Text, Transact, GetString, ReadTxn}; // Added ReadTxn
use yrs::updates::decoder::Decode; // Added Decode
use similar::{ChangeTag, TextDiff};
use walkdir::WalkDir;

pub type FilePath = String;
pub type FileContent = Vec<u8>;

#[derive(Debug, Clone)]
pub struct TreeSnapshot {
    pub files: HashMap<FilePath, FileContent>,
}

impl TreeSnapshot {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
        }
    }

    pub fn get(&self, path: &str) -> Option<&FileContent> {
        self.files.get(path)
    }
}

/// Materialize a tree from a Git commit in a repository.
pub fn materialize_git_tree(repo_path: &Path, commit_hash: &str) -> Result<TreeSnapshot> {
    let mut snapshot = TreeSnapshot::new();

    // 1. List all files in the commit
    // git ls-tree -r --name-only <commit>
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .args(&["ls-tree", "-r", "--name-only", commit_hash])
        .output()
        .context("Failed to run git ls-tree")?;

    if !output.status.success() {
        return Err(anyhow!("git ls-tree failed"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let files: Vec<&str> = stdout.lines().collect();

    // 2. Read content for each file
    // Optimization: Use git cat-file --batch for larger repos, but loop is fine for MVP
    for file_path in files {
        if file_path.trim().is_empty() {
            continue;
        }

        let content_output = Command::new("git")
            .arg("-C")
            .arg(repo_path)
            .args(&["show", &format!("{}:{}", commit_hash, file_path)])
            .output()
            .context(format!("Failed to read file {} from git", file_path))?;

        if content_output.status.success() {
            snapshot.files.insert(file_path.to_string(), content_output.stdout);
        }
    }

    Ok(snapshot)
}

/// Materialize a tree from the filesystem (worktree).
pub fn materialize_fs_tree(root_path: &Path) -> Result<TreeSnapshot> {
    let mut snapshot = TreeSnapshot::new();

    for entry in WalkDir::new(root_path).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        
        // Skip .git, .worktree, etc.
        let rel_path = path.strip_prefix(root_path)?;
        let rel_path_str = rel_path.to_string_lossy();

        if rel_path_str.starts_with(".git") || rel_path_str.starts_with(".worktree") || rel_path_str.contains("/.git/") {
            continue;
        }

        let content = std::fs::read(path)?;
        snapshot.files.insert(rel_path_str.to_string(), content);
    }

    Ok(snapshot)
}

#[derive(Debug)]
enum Presence<'a> {
    Missing,
    Binary(&'a [u8]),
    Text(String),
}

fn looks_binary(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if bytes.len() > 1024 * 1024 {
        // 1 MB threshold: treat as "too big for CRDT"
        return true;
    }

    let mut non_text = 0usize;
    for &b in bytes.iter().take(4096) {
        if b == 0 {
            return true; // NUL in first 4k → binary
        }
        if (b < 0x09) || (b > 0x0D && b < 0x20) {
            non_text += 1;
        }
    }

    non_text as f64 / bytes.len().min(4096) as f64 > 0.30
}

fn classify(content: Option<&Vec<u8>>) -> Presence<'_> {
    match content {
        None => Presence::Missing,
        Some(bytes) => {
            if looks_binary(bytes) {
                Presence::Binary(bytes)
            } else {
                Presence::Text(String::from_utf8_lossy(bytes).to_string())
            }
        }
    }
}

/// Merge three trees using Yjs CRDT logic.
pub fn merge_trees(
    base: &TreeSnapshot,
    local: &TreeSnapshot,
    canonical: &TreeSnapshot,
) -> Result<TreeSnapshot> {
    let mut merged = TreeSnapshot::new();
    let debug_merge = std::env::var("STEADYSTATE_DEBUG_MERGE").is_ok();

    // Union of all file paths
    let mut all_files = HashSet::new();
    all_files.extend(base.files.keys());
    all_files.extend(local.files.keys());
    all_files.extend(canonical.files.keys());

    for path in all_files {
        let base_content = base.files.get(path);
        let local_content = local.files.get(path);
        let canon_content = canonical.files.get(path);

        let b = classify(base_content);
        let l = classify(local_content);
        let c = classify(canon_content);

        if debug_merge {
            tracing::info!(
                "Merge check for {}: Base={:?}, Local={:?}, Canon={:?}",
                path,
                base_content.map(|v| v.len()),
                local_content.map(|v| v.len()),
                canon_content.map(|v| v.len())
            );
        }

        // If both local and canonical explicitly delete → delete in merged
        if matches!(l, Presence::Missing) && matches!(c, Presence::Missing) {
            continue; // removed from merged.files
        }

        match (b, l, c) {
            (Presence::Text(base_text), Presence::Text(local_text), Presence::Text(canon_text)) => {
                // All three are text -> CRDT merge
                let merged_text = merge_file_yjs(&base_text, &local_text, &canon_text)?;
                merged.files.insert(path.clone(), merged_text.into_bytes());
            }
            (_b_state, _l_state, _c_state) => {
                // Binary or mixed or deleted (but not both deleted)
                
                // Helper to get bytes from state, defaulting to empty if missing/text (though text should be handled above if all text)
                // Actually, if we are here, at least one is NOT text (or missing).
                // But we need bytes for binary merge.
                let _get_bytes = |state: Presence, _original: Option<&Vec<u8>>| -> Vec<u8> {
                    match state {
                        Presence::Binary(b) => b.to_vec(),
                        Presence::Text(s) => s.into_bytes(),
                        Presence::Missing => vec![],
                    }
                };

                // We need the original bytes for comparison to avoid re-encoding text if possible, 
                // but for simplicity let's use the Presence data or original content.
                let base_bytes = base_content.cloned().unwrap_or_default();
                let local_bytes = local_content.cloned().unwrap_or_default();
                let canon_bytes = canon_content.cloned().unwrap_or_default();

                // Binary merge strategy: Canonical wins if both changed, else take the changed one.
                if local_bytes != base_bytes && canon_bytes == base_bytes {
                    // Only local changed
                    if local_content.is_some() {
                        merged.files.insert(path.clone(), local_bytes);
                    }
                } else if canon_bytes != base_bytes && local_bytes == base_bytes {
                    // Only canonical changed
                    if canon_content.is_some() {
                        merged.files.insert(path.clone(), canon_bytes);
                    }
                } else {
                    // Both changed or identical
                    // Prefer canonical
                    if canon_content.is_some() {
                        merged.files.insert(path.clone(), canon_bytes);
                    }
                }
            }
        }
    }

    Ok(merged)
}

fn build_base_update(base: &str) -> Result<Vec<u8>> {
    let doc = Doc::new();
    let txt = doc.get_or_insert_text("content");
    {
        let mut txn = doc.transact_mut();
        txt.insert(&mut txn, 0, base);
    }
    Ok(doc.transact().encode_state_as_update_v1(&yrs::StateVector::default()))
}

fn build_side_update(base_update: &[u8], base: &str, side: &str) -> Result<Vec<u8>> {
    let doc = Doc::new();
    {
        let mut txn = doc.transact_mut();
        let upd = yrs::Update::decode_v1(base_update)?;
        txn.apply_update(upd);
    }
    let txt = doc.get_or_insert_text("content");

    // Line-level diff
    let diff = TextDiff::from_lines(base, side);
    {
        let mut txn = doc.transact_mut();
        let mut pos = 0;
        
        for change in diff.iter_all_changes() {
            match change.tag() {
                ChangeTag::Equal => {
                    pos += change.value().chars().count() as u32;
                }
                ChangeTag::Delete => {
                    let len = change.value().chars().count() as u32;
                    txt.remove_range(&mut txn, pos, len);
                }
                ChangeTag::Insert => {
                    txt.insert(&mut txn, pos, change.value());
                    pos += change.value().chars().count() as u32;
                }
            }
        }
    }

    Ok(doc.transact().encode_state_as_update_v1(&yrs::StateVector::default()))
}

fn merge_updates(local_update: &[u8], canonical_update: &[u8]) -> Result<String> {
    let doc = Doc::new();
    let txt = doc.get_or_insert_text("content");
    {
        let mut txn = doc.transact_mut();
        txn.apply_update(yrs::Update::decode_v1(local_update)?);
        txn.apply_update(yrs::Update::decode_v1(canonical_update)?);
    }
    Ok(txt.get_string(&doc.transact()))
}

/// Perform a 3-way merge of text using Yrs.
pub fn merge_file_yjs(base: &str, local: &str, canonical: &str) -> Result<String> {
    let base_update = build_base_update(base)?;
    let local_u = build_side_update(&base_update, base, local)?;
    let canon_u = build_side_update(&base_update, base, canonical)?;
    
    if std::env::var("STEADYSTATE_DEBUG_MERGE").is_ok() {
        tracing::info!(
            "merge_file_yjs: local_update={} bytes, canon_update={} bytes",
            local_u.len(),
            canon_u.len()
        );
    }

    merge_updates(&local_u, &canon_u)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Definitions for test variables:
    // - base: The common ancestor content (last known synced state).
    // - alice: Represents the local user's changes (passed as 'local').
    // - bob: Represents the other user's changes (passed as 'canonical').

    #[test]
    fn test_merge_no_conflict() {
        let base = "Hello World";
        let alice = "Hello World!"; // Alice added "!"
        let bob = "Hello World";    // Bob made no changes
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        // Merged: "Hello World!"
        assert_eq!(merged, "Hello World!");
    }

    #[test]
    fn test_merge_non_conflicting() {
        let base = "Hello World";
        let alice = "Hello World!"; // Alice added "!"
        let bob = "Hello World?";   // Bob added "?"
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        // Merged: "Hello World!?" or "Hello World?!" (order depends on CRDT)
        // Order depends on Yjs internals but should contain both
        assert!(merged.contains("!"));
        assert!(merged.contains("?"));
    }

    #[test]
    fn test_merge_deletion() {
        let base = "Hello World";
        let alice = "Hello";        // Alice deleted " World"
        let bob = "Hello World";    // Bob unchanged
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        // Merged: "Hello"
        assert_eq!(merged, "Hello");
    }

    #[test]
    fn test_merge_concurrent_insert() {
        let base = "";
        let alice = "A"; // Alice inserted "A"
        let bob = "B";   // Bob inserted "B"
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        // Merged: "AB" or "BA"
        assert!(merged == "AB" || merged == "BA");
    }
    
    #[test]
    fn test_merge_mixed_edit() {
        let base = "Line1\nLine2\nLine3";
        let alice = "Line1\nLine2 Modified\nLine3";   // Alice modified Line 2
        let bob = "Line1\nLine2\nLine3 Modified";     // Bob modified Line 3
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        // Merged:
        // Line1
        // Line2 Modified
        // Line3 Modified
        assert!(merged.contains("Line2 Modified"));
        assert!(merged.contains("Line3 Modified"));
    }

    #[test]
    fn test_classify_binary() {
        let binary_data = vec![0, 1, 2, 3];
        let presence = classify(Some(&binary_data));
        assert!(matches!(presence, Presence::Binary(_)));
    }

    #[test]
    fn test_classify_text() {
        let text_data = "Hello World".as_bytes().to_vec();
        let presence = classify(Some(&text_data));
        assert!(matches!(presence, Presence::Text(_)));
    }
}
