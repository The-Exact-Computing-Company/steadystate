//! # Merge Engine
//!
//! This module implements a 3-way merge for text files using a diff3-style algorithm.
//!
//! ## How It Works
//!
//! For each file, we perform a token-level (word-level) 3-way merge:
//! 1. Tokenize base, local, and canonical into words (preserving whitespace)
//! 2. Walk through tokens comparing all three versions
//! 3. Apply standard 3-way merge rules at the token level
//!
//! ## Merge Rules
//!
//! For each token position:
//! - All three match → keep the token
//! - Only local changed → use local's version
//! - Only canonical changed → use canonical's version  
//! - Both changed to same thing → use that
//! - Both changed differently → keep both (conflict preserved)
//!
//! ## Important Behavior
//!
//! - **Non-overlapping edits**: Merge cleanly (e.g., "Tom→Herwig" + "pizza→hamburger")
//! - **Same word edited by both**: Both versions preserved (no garbling)
//! - **Binary files**: >1MB or containing NUL bytes treated as binary
//!   Binary conflicts require manual resolution
//! - **Deletions**: Honored when the other side is unchanged

use anyhow::{anyhow, Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;
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

/// Check if a file should be ignored by the sync engine.
fn is_ignored(path: &str) -> bool {
    let path = Path::new(path);
    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    
    // Ignore list
    file_name == ".viminfo" ||
    file_name == ".DS_Store" ||
    file_name == "Thumbs.db" ||
    file_name.ends_with(".swp") ||
    file_name.ends_with('~') ||
    path.components().any(|c| c.as_os_str() == ".git" || c.as_os_str() == ".worktree")
}

/// Materialize a tree from a Git commit in a repository.
pub fn materialize_git_tree(repo_path: &Path, commit_hash: &str) -> Result<TreeSnapshot> {
    let mut snapshot = TreeSnapshot::new();

    let output = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .args(["ls-tree", "-r", "--name-only", commit_hash])
        .output()
        .context("Failed to run git ls-tree")?;

    if !output.status.success() {
        return Err(anyhow!("git ls-tree failed"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let files: Vec<&str> = stdout.lines().collect();

    for file_path in files {
        if file_path.trim().is_empty() {
            continue;
        }

        if is_ignored(file_path) {
            continue;
        }

        let content_output = Command::new("git")
            .arg("-C")
            .arg(repo_path)
            .args(["show", &format!("{}:{}", commit_hash, file_path)])
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
    let mut file_count = 0;
    let start = std::time::Instant::now();
    
    use std::io::Write;

    for entry in WalkDir::new(root_path).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_symlink() {
            continue;
        }

        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        let rel_path = path.strip_prefix(root_path)?;
        let rel_path_str = rel_path.to_string_lossy();

        if is_ignored(&rel_path_str) {
            continue;
        }

        let content = std::fs::read(path)?;
        snapshot.files.insert(rel_path_str.to_string(), content);

        file_count += 1;
        if file_count % 1000 == 0 {
            eprint!("\rScanning files: {}", file_count);
            std::io::stderr().flush().ok();
        }
    }

    if file_count > 0 {
        eprintln!("\rScanned {} files in {:?}", file_count, start.elapsed());
    }

    Ok(snapshot)
}

#[derive(Debug)]
enum Presence<'a> {
    Missing,
    Binary(&'a [u8]),
    Text(String),
}

/// Heuristically detect if a file should be treated as binary.
fn looks_binary(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    
    if bytes.len() > 1024 * 1024 {
        return true;
    }

    let mut non_text = 0usize;
    for &b in bytes.iter().take(4096) {
        if b == 0 {
            return true;
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
                return Presence::Binary(bytes);
            }
            match String::from_utf8(bytes.to_vec()) {
                Ok(s) => Presence::Text(s),
                Err(_) => Presence::Binary(bytes),
            }
        }
    }
}

/// Merge three trees.
pub fn merge_trees(
    base: &TreeSnapshot,
    local: &TreeSnapshot,
    canonical: &TreeSnapshot,
) -> Result<TreeSnapshot> {
    let mut merged = TreeSnapshot::new();
    let debug_merge = std::env::var("STEADYSTATE_DEBUG_MERGE").is_ok();

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

        if matches!(l, Presence::Missing) && matches!(c, Presence::Missing) {
            continue;
        }

        match (b, l, c) {
            (Presence::Text(base_text), Presence::Text(local_text), Presence::Text(canon_text)) => {
                let merged_text = merge_file_yjs(&base_text, &local_text, &canon_text)?;
                merged.files.insert(path.clone(), merged_text.into_bytes());
            }
            (_b_state, _l_state, _c_state) => {
                let base_bytes = base_content.cloned().unwrap_or_default();
                let local_bytes = local_content.cloned().unwrap_or_default();
                let canon_bytes = canon_content.cloned().unwrap_or_default();

                let local_changed = local_bytes != base_bytes;
                let canon_changed = canon_bytes != base_bytes;

                if local_changed && canon_changed {
                    if local_bytes == canon_bytes {
                        if canon_content.is_some() {
                            merged.files.insert(path.clone(), canon_bytes);
                        }
                    } else {
                        return Err(anyhow!(
                            "Binary file conflict in '{}': both local and canonical modified. \
                             Local size: {} bytes, Canonical size: {} bytes. \
                             Manual resolution required.",
                            path,
                            local_bytes.len(),
                            canon_bytes.len()
                        ));
                    }
                } else if local_changed {
                    if local_content.is_some() {
                        merged.files.insert(path.clone(), local_bytes);
                    }
                } else if canon_changed {
                    if canon_content.is_some() {
                        merged.files.insert(path.clone(), canon_bytes);
                    }
                } else {
                    if canon_content.is_some() {
                        merged.files.insert(path.clone(), canon_bytes);
                    } else if local_content.is_some() {
                        merged.files.insert(path.clone(), local_bytes);
                    }
                }
            }
        }
    }

    Ok(merged)
}

// ============================================================================
// DIFF3-STYLE TOKEN MERGE
// ============================================================================

/// Tokenize into words, preserving whitespace as separate tokens
fn tokenize(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_whitespace: Option<bool> = None;
    
    for c in s.chars() {
        let is_ws = c.is_whitespace();
        match in_whitespace {
            None => {
                in_whitespace = Some(is_ws);
                current.push(c);
            }
            Some(was_ws) if was_ws == is_ws => {
                current.push(c);
            }
            Some(_) => {
                tokens.push(std::mem::take(&mut current));
                current.push(c);
                in_whitespace = Some(is_ws);
            }
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Join tokens back into a string
fn join_tokens(tokens: &[String]) -> String {
    tokens.concat()
}

/// Perform a 3-way merge of text using diff3-style algorithm.
/// 
/// This function is named `merge_file_yjs` for compatibility with the rest
/// of the codebase, but it uses a simpler diff3 algorithm instead of Yrs CRDT.
pub fn merge_file_yjs(base: &str, local: &str, canonical: &str) -> Result<String> {
    // Fast paths
    if local == base && canonical == base {
        return Ok(base.to_string());
    }
    if local == base {
        return Ok(canonical.to_string());
    }
    if canonical == base {
        return Ok(local.to_string());
    }
    if local == canonical {
        return Ok(local.to_string());
    }

    let base_tokens = tokenize(base);
    let local_tokens = tokenize(local);
    let canon_tokens = tokenize(canonical);
    
    let mut result = Vec::new();
    
    let mut bi = 0; // base index
    let mut li = 0; // local index
    let mut ci = 0; // canonical index
    
    while bi < base_tokens.len() || li < local_tokens.len() || ci < canon_tokens.len() {
        let b = base_tokens.get(bi);
        let l = local_tokens.get(li);
        let c = canon_tokens.get(ci);
        
        match (b, l, c) {
            // All three match - keep it
            (Some(bt), Some(lt), Some(ct)) if bt == lt && lt == ct => {
                result.push(bt.clone());
                bi += 1;
                li += 1;
                ci += 1;
            }
            // Base matches local, canon differs - use canon's change
            (Some(bt), Some(lt), Some(ct)) if bt == lt && lt != ct => {
                result.push(ct.clone());
                bi += 1;
                li += 1;
                ci += 1;
            }
            // Base matches canon, local differs - use local's change
            (Some(bt), Some(lt), Some(ct)) if bt == ct && bt != lt => {
                result.push(lt.clone());
                bi += 1;
                li += 1;
                ci += 1;
            }
            // Local matches canon but differs from base - both made same change
            (Some(_bt), Some(lt), Some(ct)) if lt == ct => {
                result.push(lt.clone());
                bi += 1;
                li += 1;
                ci += 1;
            }
            // All three differ - conflict! Keep both changes
            (Some(_bt), Some(lt), Some(ct)) => {
                result.push(lt.clone());
                result.push(ct.clone());
                bi += 1;
                li += 1;
                ci += 1;
            }
            // Base exhausted, local and canon have more
            (None, Some(lt), Some(ct)) if lt == ct => {
                result.push(lt.clone());
                li += 1;
                ci += 1;
            }
            (None, Some(lt), Some(ct)) => {
                result.push(lt.clone());
                result.push(ct.clone());
                li += 1;
                ci += 1;
            }
            (None, Some(lt), None) => {
                result.push(lt.clone());
                li += 1;
            }
            (None, None, Some(ct)) => {
                result.push(ct.clone());
                ci += 1;
            }
            // Local exhausted
            (Some(bt), None, Some(ct)) if bt == ct => {
                // Local deleted, canon unchanged - delete
                bi += 1;
                ci += 1;
            }
            (Some(_bt), None, Some(ct)) => {
                // Local deleted, canon modified - keep canon's modification
                result.push(ct.clone());
                bi += 1;
                ci += 1;
            }
            (Some(_bt), None, None) => {
                // Both deleted
                bi += 1;
            }
            // Canon exhausted
            (Some(bt), Some(lt), None) if bt == lt => {
                // Canon deleted, local unchanged - delete
                bi += 1;
                li += 1;
            }
            (Some(_bt), Some(lt), None) => {
                // Canon deleted, local modified - keep local's modification
                result.push(lt.clone());
                bi += 1;
                li += 1;
            }
            (None, None, None) => break,
        }
    }
    
    Ok(join_tokens(&result))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Tokenizer Tests ====================

    #[test]
    fn test_tokenize() {
        assert_eq!(tokenize("Hello World"), vec!["Hello", " ", "World"]);
        assert_eq!(tokenize("a  b"), vec!["a", "  ", "b"]);
        assert_eq!(tokenize(""), Vec::<String>::new());
        assert_eq!(tokenize("Let's load the datasets:"), 
                   vec!["Let's", " ", "load", " ", "the", " ", "datasets:"]);
    }

    // ==================== Basic Merge Tests ====================

    #[test]
    fn test_merge_no_conflict() {
        let base = "Hello World";
        let alice = "Hello World!";
        let bob = "Hello World";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        assert_eq!(merged, "Hello World!");
    }

    #[test]
    fn test_merge_no_changes() {
        let base = "Hello World";
        let merged = merge_file_yjs(base, base, base).unwrap();
        assert_eq!(merged, base);
    }

    #[test]
    fn test_merge_same_change_both_sides() {
        let base = "Hello World";
        let changed = "Hello Universe";
        let merged = merge_file_yjs(base, changed, changed).unwrap();
        assert_eq!(merged, changed);
    }

    // ==================== The Original Bug Fix ====================

    #[test]
    fn test_merge_same_line_different_words() {
        // This is the originally reported bug scenario
        let base = "Tom likes pizza";
        let alice = "Herwig likes pizza";
        let bob = "Tom likes hamburger";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        // Should merge cleanly: Herwig + hamburger
        assert_eq!(merged, "Herwig likes hamburger");
    }

    #[test]
    fn test_datasets_example() {
        // The garbled output bug
        let base = "Let's load the datasets:";
        let alice = "Let's load the pizza:";
        let bob = "Let's load the mozzarella:";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        // Should have clean prefix
        assert!(merged.starts_with("Let's load the "));
        // Both changes should appear (conflict)
        assert!(merged.contains("pizza:"));
        assert!(merged.contains("mozzarella:"));
        // Should NOT be garbled
        assert!(!merged.contains("loa"));
        assert!(!merged.contains("thzomm"));
    }

    #[test]
    fn test_merge_multiple_edits_same_line() {
        let base = "The quick brown fox";
        let alice = "The slow brown fox";
        let bob = "The quick brown dog";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        assert_eq!(merged, "The slow brown dog");
    }

    // ==================== Conflict Cases ====================

    #[test]
    fn test_both_edit_same_word() {
        let base = "Hello World";
        let alice = "Hi World";
        let bob = "Hey World";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        // Both changed "Hello" - conflict, keep both
        assert!(merged.contains("Hi"));
        assert!(merged.contains("Hey"));
        assert!(merged.contains("World"));
    }

    // ==================== Deletion Tests ====================

    #[test]
    fn test_merge_deletion() {
        let base = "Hello World";
        let alice = "Hello";
        let bob = "Hello World";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        assert_eq!(merged, "Hello");
    }

    #[test]
    fn test_merge_content_to_empty() {
        let base = "Some content here";
        let alice = "";
        let bob = "";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        assert_eq!(merged, "");
    }

    // ==================== Insertion Tests ====================

    #[test]
    fn test_merge_insertion() {
        let base = "Hello World";
        let alice = "Hello Beautiful World";
        let bob = "Hello World";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        assert_eq!(merged, "Hello Beautiful World");
    }

    #[test]
    fn test_merge_concurrent_insert_empty_base() {
        let base = "";
        let alice = "A";
        let bob = "B";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        // Both inserted - conflict, keep both
        assert!(merged.contains("A"));
        assert!(merged.contains("B"));
    }

    #[test]
    fn test_empty_file_merge() {
        let base = "";
        let alice = "New content";
        let bob = "";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        assert_eq!(merged, "New content");
    }

    #[test]
    fn test_merge_insert_at_different_positions() {
        let base = "A B C D";
        let alice = "A X B C D";
        let bob = "A B C Y D";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        assert!(merged.contains("X"));
        assert!(merged.contains("Y"));
        assert!(merged.contains("A"));
        assert!(merged.contains("D"));
    }

    // ==================== Multi-Line Tests ====================

    #[test]
    fn test_merge_different_lines() {
        let base = "Line1\nLine2\nLine3";
        let alice = "Line1\nLine2 Modified\nLine3";
        let bob = "Line1\nLine2\nLine3 Modified";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        assert!(merged.contains("Line2 Modified"));
        assert!(merged.contains("Line3 Modified"));
    }

    #[test]
    fn test_both_add_same_content_same_position() {
        let base = "Line 1\nLine 2";
        let alice = "Line 1\nNew Line\nLine 2";
        let bob = "Line 1\nNew Line\nLine 2";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        // Both added identical content - should appear once with diff3
        // (Unlike CRDT which would duplicate)
        assert!(merged.contains("New Line"));
    }

    #[test]
    fn test_both_add_different_content_same_position() {
        let base = "Line 1\nLine 2";
        let alice = "Line 1\nAlice Line\nLine 2";
        let bob = "Line 1\nBob Line\nLine 2";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        assert!(merged.contains("Alice"));
        assert!(merged.contains("Bob"));
    }

    // ==================== Unicode Tests ====================

    #[test]
    fn test_merge_with_emoji() {
        let base = "Hello World";
        let alice = "Hello 👋 World";
        let bob = "Hello World";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        assert!(merged.contains("👋"));
        assert!(merged.contains("Hello"));
        assert!(merged.contains("World"));
    }

    #[test]
    fn test_merge_with_cjk() {
        let base = "Hello World";
        let alice = "Hello 世界";
        let bob = "Hello World";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        assert!(merged.contains("世界"));
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_merge_one_deletes_all_other_adds_word() {
        let base = "Some content";
        let alice = "";
        let bob = "Some content more";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        // Alice deleted base content, Bob added "more"
        // "more" should survive
        assert!(merged.contains("more"));
    }

    #[test]
    fn test_whitespace_preserved() {
        let base = "foo bar";
        let alice = "foo  bar";
        let bob = "foo bar";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        assert!(merged.contains("foo"));
        assert!(merged.contains("bar"));
    }

    // ==================== Binary/Text Classification Tests ====================

    #[test]
    fn test_classify_binary_with_null() {
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

    #[test]
    fn test_classify_missing() {
        let presence = classify(None);
        assert!(matches!(presence, Presence::Missing));
    }

    #[test]
    fn test_large_file_treated_as_binary() {
        let large_text = vec![b'a'; 1024 * 1024 + 1];
        assert!(looks_binary(&large_text));
    }

    // ==================== Tree Merge Tests ====================

    #[test]
    fn test_binary_conflict_detection() {
        let mut base = TreeSnapshot::new();
        let mut local = TreeSnapshot::new();
        let mut canonical = TreeSnapshot::new();
        
        let base_binary = vec![0xFF, 0xD8, 0xFF, 0xE0];
        let local_binary = vec![0xFF, 0xD8, 0xFF, 0xE1];
        let canon_binary = vec![0xFF, 0xD8, 0xFF, 0xE2];
        
        base.files.insert("image.jpg".to_string(), base_binary);
        local.files.insert("image.jpg".to_string(), local_binary);
        canonical.files.insert("image.jpg".to_string(), canon_binary);
        
        let result = merge_trees(&base, &local, &canonical);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Binary file conflict"));
    }

    #[test]
    fn test_binary_same_change_ok() {
        let mut base = TreeSnapshot::new();
        let mut local = TreeSnapshot::new();
        let mut canonical = TreeSnapshot::new();
        
        let base_binary = vec![0xFF, 0xD8];
        let changed_binary = vec![0xFF, 0xD9];
        
        base.files.insert("image.jpg".to_string(), base_binary);
        local.files.insert("image.jpg".to_string(), changed_binary.clone());
        canonical.files.insert("image.jpg".to_string(), changed_binary.clone());
        
        let result = merge_trees(&base, &local, &canonical);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().files.get("image.jpg"), Some(&changed_binary));
    }

    #[test]
    fn test_binary_one_side_changes() {
        let mut base = TreeSnapshot::new();
        let mut local = TreeSnapshot::new();
        let mut canonical = TreeSnapshot::new();
        
        let base_binary = vec![0xFF, 0xD8];
        let changed_binary = vec![0xFF, 0xD9];
        
        base.files.insert("image.jpg".to_string(), base_binary.clone());
        local.files.insert("image.jpg".to_string(), changed_binary.clone());
        canonical.files.insert("image.jpg".to_string(), base_binary);
        
        let result = merge_trees(&base, &local, &canonical);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().files.get("image.jpg"), Some(&changed_binary));
    }

    #[test]
    fn test_file_added_by_one_side() {
        let base = TreeSnapshot::new();
        let mut local = TreeSnapshot::new();
        let canonical = TreeSnapshot::new();
        
        local.files.insert("new.txt".to_string(), b"new content".to_vec());
        
        let result = merge_trees(&base, &local, &canonical).unwrap();
        assert!(result.files.contains_key("new.txt"));
    }

    #[test]
    fn test_file_deleted_by_both() {
        let mut base = TreeSnapshot::new();
        let local = TreeSnapshot::new();
        let canonical = TreeSnapshot::new();
        
        base.files.insert("old.txt".to_string(), b"old content".to_vec());
        
        let result = merge_trees(&base, &local, &canonical).unwrap();
        assert!(!result.files.contains_key("old.txt"));
    }

    #[test]
    fn test_file_deleted_by_one_modified_by_other_is_conflict() {
        let mut base = TreeSnapshot::new();
        let local = TreeSnapshot::new();
        let mut canonical = TreeSnapshot::new();
        
        base.files.insert("file.txt".to_string(), b"original".to_vec());
        canonical.files.insert("file.txt".to_string(), b"modified".to_vec());
        
        let result = merge_trees(&base, &local, &canonical);
        assert!(result.is_err());
    }

    #[test]
    fn test_file_deleted_by_one_unchanged_by_other() {
        let mut base = TreeSnapshot::new();
        let local = TreeSnapshot::new();
        let mut canonical = TreeSnapshot::new();
        
        base.files.insert("file.txt".to_string(), b"original".to_vec());
        canonical.files.insert("file.txt".to_string(), b"original".to_vec());
        
        let result = merge_trees(&base, &local, &canonical).unwrap();
        assert!(!result.files.contains_key("file.txt"));
    }

    // ==================== Ignore Pattern Tests ====================

    #[test]
    fn test_is_ignored() {
        assert!(is_ignored(".viminfo"));
        assert!(is_ignored(".DS_Store"));
        assert!(is_ignored("foo.swp"));
        assert!(is_ignored("foo.txt~"));
        assert!(is_ignored(".git/config"));
        assert!(is_ignored(".worktree/steadystate.json"));
        
        assert!(!is_ignored("foo.txt"));
        assert!(!is_ignored("src/main.rs"));
        assert!(!is_ignored(".gitignore"));
    }

    // ==================== Filesystem Tests ====================

    #[cfg(unix)]
    #[test]
    fn test_symlinks_are_ignored() {
        use std::os::unix::fs::symlink;
        
        let temp = tempfile::tempdir().unwrap();
        let temp_path = temp.path();
        
        std::fs::write(temp_path.join("real.txt"), "content").unwrap();
        symlink(temp_path.join("real.txt"), temp_path.join("link.txt")).unwrap();
        
        let snapshot = materialize_fs_tree(temp_path).unwrap();
        
        assert!(snapshot.files.contains_key("real.txt"));
        assert!(!snapshot.files.contains_key("link.txt"));
    }
}
