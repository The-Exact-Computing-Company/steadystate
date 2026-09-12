use crate::compute::traits::RemoteExecutor;
use anyhow::Result;
use std::path::Path;

/// Default flake providing the `t` binary.
/// Override with `TLANG_FLAKE_URL`.
pub fn tlang_flake_url() -> String {
    std::env::var("TLANG_FLAKE_URL").unwrap_or_else(|_| "github:b-rodrigues/tlang".to_string())
}

/// True if the repo contains a `tproject.toml`.
pub async fn has_tproject(executor: &dyn RemoteExecutor, repo_path: &Path) -> Result<bool> {
    executor.exists(&repo_path.join("tproject.toml")).await
}

/// Extract `[t].min_version` from a tproject.toml body, if present.
/// Minimal hand parser to avoid a new TOML dependency.
pub fn parse_min_version(content: &str) -> Option<String> {
    let mut in_t_section = false;
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_t_section = t == "[t]";
            continue;
        }
        if in_t_section && t.starts_with("min_version")
            && let Some((_, v)) = t.split_once('=') {
                let v = v.trim().trim_matches(|c| c == '"' || c == '\'').trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
    }
    None
}

/// Ensure `nix` is available on the target executor host.
pub async fn ensure_nix(executor: &dyn RemoteExecutor) -> Result<()> {
    let out = executor.exec("nix", &["--version"]).await;
    match out {
        Ok(o) if o.exit_status.success() => Ok(()),
        _ => Err(anyhow::anyhow!(
            "nix is required for tproject.toml environments but was not found. Install nix via the Determinate installer (https://github.com/DeterminateSystems/nix-installer) and retry."
        )),
    }
}

/// Command prefix that guarantees `t` is available via `nix shell`.
/// Returns e.g. `nix shell --accept-flake-config github:b-rodrigues/tlang -c t`.
pub fn t_shell_prefix() -> String {
    format!("nix shell --accept-flake-config {} -c t", tlang_flake_url())
}

/// Parse the first `X.Y[.Z]` numeric version found in `s`.
/// Accepts outputs like `t 0.55.0`, `0.55.0`, `v0.55`.
pub fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let mut nums = Vec::new();
    let mut cur = String::new();
    let flush = |cur: &mut String, nums: &mut Vec<u64>| {
        if !cur.is_empty() {
            if let Ok(n) = cur.parse::<u64>() {
                nums.push(n);
            }
            cur.clear();
        }
    };
    for c in s.chars() {
        if c.is_ascii_digit() {
            cur.push(c);
        } else if c == '.' && !cur.is_empty() {
            flush(&mut cur, &mut nums);
            // Peek-style handling: a '.' only separates if digits follow;
            // trailing '.' is ignored by the final flush logic below.
        } else {
            flush(&mut cur, &mut nums);
            if nums.len() >= 3 {
                break;
            }
        }
    }
    flush(&mut cur, &mut nums);
    match nums.as_slice() {
        [maj, min, patch, ..] => Some((*maj, *min, *patch)),
        [maj, min] => Some((*maj, *min, 0)),
        _ => None,
    }
}

/// Verify the installed `t` satisfies the project's `[t].min_version`.
/// Non-fatal: warns on mismatch or unparseable versions, since `t` is
/// fetched unpinned and is usually newer than the minimum.
pub async fn check_min_version(executor: &dyn RemoteExecutor, repo_path: &Path) -> Result<()> {
    let raw = match executor.read_file(&repo_path.join("tproject.toml")).await {
        Ok(b) => b,
        Err(_) => return Ok(()),
    };
    let content = String::from_utf8_lossy(&raw);
    let Some(min_s) = parse_min_version(&content) else {
        return Ok(());
    };
    let Some(min_v) = parse_version(&min_s) else {
        return Ok(());
    };
    let script = format!("t --version || {} --version", t_shell_prefix());
    let out = executor.exec_shell(&script).await?;
    if !out.exit_status.success() {
        tracing::warn!(
            "Could not determine `t` version; project requires >= {}",
            min_s
        );
        return Ok(());
    }
    match parse_version(&out.stdout) {
        Some(installed) if installed < min_v => {
            tracing::warn!(
                "`t` version {:?} is older than project minimum {} — `t update` output may differ",
                installed,
                min_s
            );
        }
        Some(installed) => {
            tracing::info!("`t` version {:?} satisfies minimum {}", installed, min_s);
        }
        None => {
            tracing::warn!(
                "Unparseable `t --version` output; project requires >= {}",
                min_s
            );
        }
    }
    Ok(())
}

/// Run `t update` in `repo_path` so `flake.nix`/`flake.lock` are regenerated
/// from `tproject.toml` before `nix develop`.
/// If `t` is not on PATH, falls back to `nix shell <tlang> -c t update`.
pub async fn t_update(executor: &dyn RemoteExecutor, repo_path: &Path) -> Result<()> {
    let dir = repo_path.to_string_lossy().to_string();
    // Quote path for shell.
    let q = format!("'{}'", dir.replace('\'', "'\\''"));
    let script = format!(
        "cd {q} && (t update || {prefix} update)",
        prefix = t_shell_prefix()
    );
    let out = executor.exec_shell(&script).await?;
    if out.exit_status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "`t update` failed in {}: {}\n{}",
            dir,
            out.stdout,
            out.stderr
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_min_version() {
        let toml = "[project]\nname = \"x\"\n\n[t]\nmin_version = \"0.55.0\"\n";
        assert_eq!(parse_min_version(toml).as_deref(), Some("0.55.0"));
        assert_eq!(parse_min_version("[project]\nname=\"x\"\n"), None);
    }

    #[test]
    fn test_t_shell_prefix() {
        let p = t_shell_prefix();
        assert!(p.contains("nix shell"));
        assert!(p.ends_with("-c t"));
    }

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("t 0.55.0"), Some((0, 55, 0)));
        assert_eq!(parse_version("0.53.3"), Some((0, 53, 3)));
        assert_eq!(parse_version("v1.10"), Some((1, 10, 0)));
        assert_eq!(parse_version("version 2.4.1 (rev abc)"), Some((2, 4, 1)));
        assert_eq!(parse_version("no version here"), None);
        assert_eq!(parse_version(""), None);
        // Ordering: tuple comparison drives the minimum-version check.
        assert!((0, 54, 0) < (0, 55, 0));
        assert!((0, 55, 0) >= (0, 55, 0));
    }
}
