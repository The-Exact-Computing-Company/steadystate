use std::path::Path;
use anyhow::Result;
use crate::compute::traits::RemoteExecutor;

/// Default flake providing the `t` binary.
/// Override with `TLANG_FLAKE_URL`.
pub fn tlang_flake_url() -> String {
    std::env::var("TLANG_FLAKE_URL")
        .unwrap_or_else(|_| "github:b-rodrigues/tlang".to_string())
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
        if in_t_section && t.starts_with("min_version") {
            if let Some((_, v)) = t.split_once('=') {
                let v = v.trim().trim_matches(|c| c == '"' || c == '\'').trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
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
    format!(
        "nix shell --accept-flake-config {} -c t",
        tlang_flake_url()
    )
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
        Err(anyhow::anyhow!("`t update` failed in {}: {}\n{}", dir, out.stdout, out.stderr))
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
}
