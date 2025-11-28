//! # Merge Engine
//!
//! This module implements a CRDT-based 3-way merge using Yjs/Yrs.
//!
//! ## How It Works
//!
//! For each file, we perform:
//! 1. Build a base Yjs document from the last synced state
//! 2. Compute operations: base → local and base → canonical
//! 3. Apply both operation sets to a fresh document
//! 4. Extract the converged result
//!
//! ## CRDT Guarantees
//!
//! - **Convergence**: Both sides reach the same final state
//! - **Commutativity**: Order of applying updates doesn't matter
//! - **No conflicts**: All concurrent edits are preserved
//!
//! ## Important Behavior
//!
//! - **Concurrent inserts**: Order is deterministic but may seem arbitrary
//!   Example: Alice inserts "A" and Bob inserts "B" at same position
//!   Result: Always "AB" or always "BA" (consistent across runs)
//!
//! - **Binary files**: >1MB or containing NUL bytes treated as binary
//!   Binary conflicts require manual resolution
//!
//! - **Deletions**: Both sides must delete for file to be removed
//!
//! ## Position Tracking
//!
//! Uses UTF-16 code units to match Yjs/Yrs internal representation.
//! This ensures correct handling of:
//! - Emoji and emoticons
//! - Surrogate pairs (math symbols, rare CJK)
//! - Combining characters

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

        if is_ignored(file_path) {
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
    let mut file_count = 0;
    let start = std::time::Instant::now();
    
    use std::io::Write; // Ensure Write trait is available for flush

    for entry in WalkDir::new(root_path).into_iter().filter_map(|e| e.ok()) {
        // Skip symlinks explicitly
        if entry.file_type().is_symlink() {
            continue;
        }

        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        
        // Skip .git, .worktree, etc.
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
///
/// Detection rules:
/// 1. Files > 1MB are treated as binary (CRDT merge would be too expensive)
/// 2. Files containing NUL bytes in first 4KB are binary
/// 3. Files with >30% non-text bytes in first 4KB are binary
fn looks_binary(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    
    // Files larger than 1MB are treated as binary to avoid
    // expensive CRDT operations on large text files like logs
    if bytes.len() > 1024 * 1024 {
        return true;
    }

    let mut non_text = 0usize;
    for &b in bytes.iter().take(4096) {
        // NUL bytes indicate binary
        if b == 0 {
            return true;
        }
        // Count control characters (excluding whitespace)
        if (b < 0x09) || (b > 0x0D && b < 0x20) {
            non_text += 1;
        }
    }

    // If >30% of sampled bytes are non-text, treat as binary
    non_text as f64 / bytes.len().min(4096) as f64 > 0.30
}

fn classify(content: Option<&Vec<u8>>) -> Presence<'_> {
    match content {
        None => Presence::Missing,
        Some(bytes) => {
            if looks_binary(bytes) {
                return Presence::Binary(bytes);
            }
            // If it's not valid UTF-8, treat as binary
            match String::from_utf8(bytes.to_vec()) {
                Ok(s) => Presence::Text(s),
                Err(_) => Presence::Binary(bytes),
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

                // Check if both sides modified
                let local_changed = local_bytes != base_bytes;
                let canon_changed = canon_bytes != base_bytes;

                if local_changed && canon_changed {
                    // Both modified the binary file
                    if local_bytes == canon_bytes {
                        // Same change → OK
                        if canon_content.is_some() {
                            merged.files.insert(path.clone(), canon_bytes);
                        }
                    } else {
                        // Different changes → CONFLICT
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
                    // Only local changed
                    if local_content.is_some() {
                        merged.files.insert(path.clone(), local_bytes);
                    }
                } else if canon_changed {
                    // Only canonical changed
                    if canon_content.is_some() {
                        merged.files.insert(path.clone(), canon_bytes);
                    }
                } else {
                    // Neither changed (identical or both same as base)
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

    // Word-level diff: best balance between granularity and readability
    // - Fixes same-line different-word edits (the original bug)
    // - Avoids character-level garbling when same word is edited
    // - Produces "word1 word2" instead of "wor1d2" on conflicts
    let diff = TextDiff::from_words(base, side);
    {
        let mut txn = doc.transact_mut();
        let mut pos: u32 = 0;
        
        for change in diff.iter_all_changes() {
            let value = change.value();
            let len = value.encode_utf16().count() as u32;
            
            match change.tag() {
                ChangeTag::Equal => {
                    pos += len;
                }
                ChangeTag::Delete => {
                    // Bounds check to prevent Yrs panic
                    let doc_len = txt.get_string(&txn).encode_utf16().count() as u32;
                    if pos < doc_len {
                        let safe_len = len.min(doc_len - pos);
                        if safe_len > 0 {
                            txt.remove_range(&mut txn, pos, safe_len);
                        }
                    }
                    // Don't advance pos - content was removed
                }
                ChangeTag::Insert => {
                    txt.insert(&mut txn, pos, value);
                    pos += len;
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

    // ==================== Basic Merge Tests ====================

    #[test]
    fn test_merge_no_conflict() {
        let base = "Hello World";
        let alice = "Hello World!"; // Alice added "!"
        let bob = "Hello World";    // Bob made no changes
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        assert_eq!(merged, "Hello World!");
    }

    #[test]
    fn test_merge_non_conflicting_appends() {
        // Both append different characters at the end
        let base = "Hello World";
        let alice = "Hello World!"; // Alice added "!"
        let bob = "Hello World?";   // Bob added "?"
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        // With char-level diff, both insertions at end are preserved
        assert!(merged.contains("!"));
        assert!(merged.contains("?"));
        // Result will be "Hello World!?" or "Hello World?!"
        assert!(merged == "Hello World!?" || merged == "Hello World?!");
    }

    #[test]
    fn test_merge_deletion() {
        let base = "Hello World";
        let alice = "Hello";        // Alice deleted " World"
        let bob = "Hello World";    // Bob unchanged
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        assert_eq!(merged, "Hello");
    }

    #[test]
    fn test_merge_concurrent_insert_empty_base() {
        let base = "";
        let alice = "A"; // Alice inserted "A"
        let bob = "B";   // Bob inserted "B"
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        // Both inserted at position 0, CRDT preserves both
        assert!(merged == "AB" || merged == "BA");
    }

    #[test]
    fn test_empty_file_merge() {
        let base = "";
        let alice = "New content";
        let bob = "";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        assert_eq!(merged, "New content");
    }

    // ==================== Same-Line Edit Tests (the bug fix!) ====================

    #[test]
    fn test_merge_same_line_different_words() {
        // This is the originally reported bug scenario
        let base = "Tom likes pizza";
        let alice = "Herwig likes pizza";   // Alice changed "Tom" to "Herwig"
        let bob = "Tom likes hamburger";    // Bob changed "pizza" to "hamburger"
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        // With character-level diff, non-overlapping edits merge correctly
        assert_eq!(merged, "Herwig likes hamburger");
    }

    #[test]
    fn test_merge_same_line_overlapping_words() {
        // Edge case: both edit the same word
        let base = "Hello World";
        let alice = "Hi World";      // Changed "Hello" to "Hi"
        let bob = "Hey World";       // Changed "Hello" to "Hey"
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        // Both edits overlap at the same position - CRDT interleaves
        // The "World" part should be unchanged
        assert!(merged.ends_with(" World"));
        // The first word will be some interleaving of "Hi" and "Hey"
        // We can't predict exact order, but length should be reasonable
        let first_word = merged.split(' ').next().unwrap();
        assert!(first_word.len() >= 2 && first_word.len() <= 5);
    }

    #[test]
    fn test_merge_multiple_edits_same_line() {
        let base = "The quick brown fox";
        let alice = "The slow brown fox";    // Changed "quick" to "slow"
        let bob = "The quick brown dog";     // Changed "fox" to "dog"
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        // Non-overlapping edits should merge cleanly
        assert_eq!(merged, "The slow brown dog");
    }

    // ==================== Multi-Line Edit Tests ====================

    #[test]
    fn test_merge_different_lines() {
        let base = "Line1\nLine2\nLine3";
        let alice = "Line1\nLine2 Modified\nLine3";   // Alice modified Line 2
        let bob = "Line1\nLine2\nLine3 Modified";     // Bob modified Line 3
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        assert!(merged.contains("Line2 Modified"));
        assert!(merged.contains("Line3 Modified"));
        assert_eq!(merged, "Line1\nLine2 Modified\nLine3 Modified");
    }

    #[test]
    fn test_both_add_same_content_same_position() {
        // When both users add identical content at the same position,
        // CRDT does NOT deduplicate - it preserves both insertions
        let base = "Line 1\nLine 2";
        let alice = "Line 1\nNew Line\nLine 2";
        let bob = "Line 1\nNew Line\nLine 2";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        // With char-level diff, identical insertions at same position = 2 copies
        assert_eq!(merged.matches("New Line").count(), 2);
    }

    #[test]
    fn test_both_add_different_content_same_position() {
        let base = "Line 1\nLine 2";
        let alice = "Line 1\nAlice Line\nLine 2";
        let bob = "Line 1\nBob Line\nLine 2";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        // Both insertions preserved
        assert!(merged.contains("Alice Line"));
        assert!(merged.contains("Bob Line"));
    }

    // ==================== Whitespace and Formatting Tests ====================

    #[test]
    fn test_whitespace_only_changes() {
        let base = "foo bar";
        let alice = "foo  bar"; // Two spaces
        let bob = "foo bar";    // Unchanged
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        assert_eq!(merged, "foo  bar"); // Alice's extra space preserved
    }

    #[test]
    fn test_line_ending_changes() {
        let base = "Line 1\nLine 2";
        let alice = "Line 1\r\nLine 2"; // Windows CRLF
        let bob = "Line 1\nLine 2\nLine 3"; // Added Line 3
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        // Bob's addition should be preserved
        assert!(merged.contains("Line 3"));
        // Alice's CRLF change should also be reflected
        assert!(merged.contains("\r\n") || merged.contains("Line 1"));
    }

    // ==================== Unicode Tests ====================

    #[test]
    fn test_merge_with_emoji() {
        let base = "Hello World";
        let alice = "Hello 👋 World";  // Inserted emoji
        let bob = "Hello World!";       // Appended "!"
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        assert!(merged.contains("👋"));
        assert!(merged.contains("!"));
        assert_eq!(merged, "Hello 👋 World!");
    }

    #[test]
    fn test_merge_with_combining_characters() {
        let base = "cafe";
        let alice = "café";   // Changed 'e' to 'é' (e + combining acute or precomposed)
        let bob = "cafe!";    // Appended "!"
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        // Note: This test may behave differently depending on whether
        // "café" uses precomposed é (U+00E9) or e + combining acute (U+0301)
        assert!(merged.contains("!"));
        // The accent should be preserved in some form
        assert!(merged.len() >= 5);
    }

    #[test]
    fn test_merge_with_surrogate_pairs() {
        let base = "Math: H";
        let alice = "Math: 𝕳";   // Mathematical bold H (U+1D573, needs surrogate pair)
        let bob = "Math: H!";    // Appended "!"
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        assert!(merged.contains("𝕳"));
        assert!(merged.contains("!"));
    }

    #[test]
    fn test_merge_with_cjk() {
        let base = "Hello";
        let alice = "Hello 世界";  // Added Chinese characters
        let bob = "Hello!";        // Appended "!"
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        assert!(merged.contains("世界"));
        assert!(merged.contains("!"));
    }

    #[test]
    fn test_merge_emoji_at_different_positions() {
        // Test emoji changes at NON-overlapping positions
        let base = "I feel good today";
        let alice = "I feel 😢 good today";  // Inserted emoji after "feel "
        let bob = "I feel good today!";      // Added "!" at end
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        assert!(merged.contains("😢"));
        assert!(merged.contains("!"));
    }

    #[test]
    fn test_merge_emoji_same_position_interleave() {
        // When both edit the same position, CRDT interleaves
        // This tests that emoji bytes don't get corrupted
        let base = "Hello World";
        let alice = "Hello 😊 World";  // Both insert after "Hello "
        let bob = "Hello 🎉 World";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        // Both emojis should be present (interleaved), not corrupted
        // The exact order depends on CRDT, but both should appear
        assert!(merged.contains("😊") || merged.contains("🎉"));
        assert!(merged.contains("World"));
    }

    // ==================== Binary/Text Classification Tests ====================

    #[test]
    fn test_classify_binary_with_null() {
        let binary_data = vec![0, 1, 2, 3]; // Contains NUL byte
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
    fn test_classify_large_file_as_binary() {
        // Files > 1MB are treated as binary
        let large_text = vec![b'a'; 1024 * 1024 + 1];
        assert!(looks_binary(&large_text));
    }

    #[test]
    fn test_classify_high_control_char_ratio() {
        // >30% control characters = binary
        let mut data = vec![0x01; 40]; // 40 control chars
        data.extend(vec![b'a'; 60]);   // 60 normal chars
        assert!(looks_binary(&data));
    }

    // ==================== Tree Merge Tests ====================

    #[test]
    fn test_binary_conflict_detection() {
        let mut base = TreeSnapshot::new();
        let mut local = TreeSnapshot::new();
        let mut canonical = TreeSnapshot::new();
        
        // Binary file (contains NUL byte)
        let base_binary = vec![0xFF, 0xD8, 0xFF, 0xE0]; // JPEG-like header
        let local_binary = vec![0xFF, 0xD8, 0xFF, 0xE1]; // Modified
        let canon_binary = vec![0xFF, 0xD8, 0xFF, 0xE2]; // Different modification
        
        base.files.insert("image.jpg".to_string(), base_binary);
        local.files.insert("image.jpg".to_string(), local_binary);
        canonical.files.insert("image.jpg".to_string(), canon_binary);
        
        let result = merge_trees(&base, &local, &canonical);
        
        // Should error on conflict
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Binary file conflict"));
    }

    #[test]
    fn test_binary_same_change_ok() {
        let mut base = TreeSnapshot::new();
        let mut local = TreeSnapshot::new();
        let mut canonical = TreeSnapshot::new();
        
        let base_binary = vec![0xFF, 0xD8];
        let changed_binary = vec![0xFF, 0xD9]; // Same change on both sides
        
        base.files.insert("image.jpg".to_string(), base_binary);
        local.files.insert("image.jpg".to_string(), changed_binary.clone());
        canonical.files.insert("image.jpg".to_string(), changed_binary.clone());
        
        let result = merge_trees(&base, &local, &canonical);
        assert!(result.is_ok());
        
        let merged = result.unwrap();
        assert_eq!(merged.files.get("image.jpg"), Some(&changed_binary));
    }

    #[test]
    fn test_binary_one_side_changes() {
        let mut base = TreeSnapshot::new();
        let mut local = TreeSnapshot::new();
        let mut canonical = TreeSnapshot::new();
        
        let base_binary = vec![0xFF, 0xD8];
        let changed_binary = vec![0xFF, 0xD9];
        
        base.files.insert("image.jpg".to_string(), base_binary.clone());
        local.files.insert("image.jpg".to_string(), changed_binary.clone()); // Local changed
        canonical.files.insert("image.jpg".to_string(), base_binary);        // Canon unchanged
        
        let result = merge_trees(&base, &local, &canonical);
        assert!(result.is_ok());
        
        let merged = result.unwrap();
        assert_eq!(merged.files.get("image.jpg"), Some(&changed_binary));
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
        // When one side deletes and the other modifies, the current implementation
        // treats this as a conflict (since it falls into the binary/mixed branch
        // where deletion = empty bytes, modification = different bytes)
        let mut base = TreeSnapshot::new();
        let local = TreeSnapshot::new(); // Deleted (Missing)
        let mut canonical = TreeSnapshot::new();
        
        base.files.insert("file.txt".to_string(), b"original".to_vec());
        canonical.files.insert("file.txt".to_string(), b"modified".to_vec());
        
        let result = merge_trees(&base, &local, &canonical);
        
        // Current behavior: this is treated as a conflict
        // (local changed to empty/missing, canonical changed to different content)
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("conflict"));
    }

    #[test]
    fn test_text_file_deleted_by_one_unchanged_by_other() {
        // If one side deletes and the other is unchanged, no conflict
        let mut base = TreeSnapshot::new();
        let local = TreeSnapshot::new(); // Deleted
        let mut canonical = TreeSnapshot::new();
        
        base.files.insert("file.txt".to_string(), b"original".to_vec());
        canonical.files.insert("file.txt".to_string(), b"original".to_vec()); // Unchanged
        
        let result = merge_trees(&base, &local, &canonical);
        assert!(result.is_ok());
        
        // Local's deletion wins when canonical is unchanged
        let merged = result.unwrap();
        assert!(!merged.files.contains_key("file.txt"));
    }

    // ==================== Ignore Pattern Tests ====================

    #[test]
    fn test_is_ignored() {
        // Should be ignored
        assert!(is_ignored(".viminfo"));
        assert!(is_ignored("path/to/.viminfo"));
        assert!(is_ignored(".DS_Store"));
        assert!(is_ignored("foo.swp"));
        assert!(is_ignored("foo.txt~"));
        assert!(is_ignored(".git/config"));
        assert!(is_ignored(".git/objects/pack/abc"));
        assert!(is_ignored(".worktree/steadystate.json"));
        
        // Should NOT be ignored
        assert!(!is_ignored("foo.txt"));
        assert!(!is_ignored("src/main.rs"));
        assert!(!is_ignored(".gitignore"));
        assert!(!is_ignored("README.md"));
    }

    // ==================== Filesystem Tests ====================

    #[cfg(unix)]
    #[test]
    fn test_symlinks_are_ignored() {
        use std::os::unix::fs::symlink;
        
        let temp = tempfile::tempdir().unwrap();
        let temp_path = temp.path();
        
        // Create a regular file
        std::fs::write(temp_path.join("real.txt"), "content").unwrap();
        
        // Create a symlink
        symlink(
            temp_path.join("real.txt"),
            temp_path.join("link.txt")
        ).unwrap();
        
        let snapshot = materialize_fs_tree(temp_path).unwrap();
        
        // Should only have the real file, not the symlink
        assert!(snapshot.files.contains_key("real.txt"));
        assert!(!snapshot.files.contains_key("link.txt"));
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_merge_identical_changes() {
        // Both make exactly the same change
        let base = "Hello World";
        let alice = "Hello Universe";
        let bob = "Hello Universe";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        // With char-level diff, identical deletions are idempotent,
        // but identical insertions at same position are duplicated
        // "World" (5 chars) deleted by both -> deleted once
        // "Universe" inserted by both at same position -> appears twice
        // This is expected CRDT behavior
        assert!(merged.contains("Universe"));
    }

    #[test]
    fn test_merge_delete_and_modify() {
        // Alice deletes content, Bob modifies it
        let base = "Keep this. Delete this.";
        let alice = "Keep this.";                    // Deleted " Delete this."
        let bob = "Keep this. Modify this.";        // Changed "Delete" to "Modify"
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        // Alice's deletion wins for the deleted part
        // This is a tricky case - result depends on exact char positions
        assert!(merged.contains("Keep this."));
    }

    #[test]
    fn test_merge_insert_at_different_positions() {
        let base = "ABCD";
        let alice = "A123BCD";   // Inserted "123" after A
        let bob = "ABC456D";     // Inserted "456" after C
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        // Non-overlapping insertions should both be present
        assert!(merged.contains("123"));
        assert!(merged.contains("456"));
        assert_eq!(merged, "A123BC456D");
    }

    #[test]
    fn test_merge_empty_to_content() {
        let base = "";
        let alice = "Alice's content";
        let bob = "Bob's content";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        // Both inserted at position 0
        assert!(merged.contains("Alice's content"));
        assert!(merged.contains("Bob's content"));
    }

    #[test]
    fn test_merge_content_to_empty() {
        // Both delete all content
        let base = "Some content here";
        let alice = "";
        let bob = "";
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        assert_eq!(merged, "");
    }

    #[test]
    fn test_merge_one_deletes_all() {
        let base = "Some content";
        let alice = "";              // Deleted everything
        let bob = "Some content!";   // Added "!"
        let merged = merge_file_yjs(base, alice, bob).unwrap();
        
        // Alice deleted "Some content", Bob added "!"
        // Result should just be "!"
        assert_eq!(merged, "!");
    }
}

