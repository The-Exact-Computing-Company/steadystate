use crate::compute::traits::{BoxedAsyncRead, CommandOutput, RemoteExecutor};
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::path::Path;

/// SSH-backed [`RemoteExecutor`] for Hetzner (or any) remote hosts.
/// Shells out to the system `ssh`/`scp` binaries so no extra SSH crates are needed.
#[derive(Debug, Clone)]
pub struct SshExecutor {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub identity_file: Option<String>,
    pub strict_host_checking: bool,
}

impl SshExecutor {
    pub fn new(host: String, port: u16, user: String) -> Self {
        Self {
            host,
            port,
            user,
            identity_file: None,
            strict_host_checking: false,
        }
    }

    fn base_args(&self) -> Vec<String> {
        let mut args = vec![
            "-p".to_string(),
            self.port.to_string(),
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            "-o".to_string(),
            "ConnectTimeout=10".to_string(),
        ];
        if self.strict_host_checking {
            args.extend(["-o".to_string(), "StrictHostKeyChecking=yes".to_string()]);
        } else {
            args.extend([
                "-o".to_string(),
                "StrictHostKeyChecking=no".to_string(),
                "-o".to_string(),
                "UserKnownHostsFile=/dev/null".to_string(),
                "-o".to_string(),
                "LogLevel=ERROR".to_string(),
            ]);
        }
        if let Some(key) = &self.identity_file {
            args.extend(["-i".to_string(), key.clone()]);
        }
        args
    }

    fn target(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    fn shell_quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

#[async_trait]
impl RemoteExecutor for SshExecutor {
    async fn exec(&self, cmd: &str, args: &[&str]) -> Result<CommandOutput> {
        let remote = std::iter::once(cmd.to_string())
            .chain(args.iter().map(|a| Self::shell_quote(a)))
            .collect::<Vec<_>>()
            .join(" ");
        self.exec_shell(&remote).await
    }

    async fn exec_streaming(
        &self,
        _cmd: &str,
        _args: &[&str],
    ) -> Result<(u32, BoxedAsyncRead, BoxedAsyncRead)> {
        Err(anyhow::anyhow!(
            "streaming exec not supported over SshExecutor; use exec/exec_shell with nohup instead"
        ))
    }

    async fn exec_shell(&self, script: &str) -> Result<CommandOutput> {
        let mut cmd = tokio::process::Command::new("ssh");
        for a in self.base_args() {
            cmd.arg(a);
        }
        cmd.arg(self.target());
        cmd.arg("--");
        cmd.arg(script);
        let out = cmd.output().await.context("failed to run ssh")?;
        Ok(CommandOutput {
            exit_status: out.status,
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        })
    }

    async fn upload_file(&self, local: &Path, remote: &Path) -> Result<()> {
        let mut cmd = tokio::process::Command::new("scp");
        cmd.arg("-P").arg(self.port.to_string());
        cmd.arg("-o").arg("BatchMode=yes");
        if !self.strict_host_checking {
            cmd.arg("-o").arg("StrictHostKeyChecking=no");
            cmd.arg("-o").arg("UserKnownHostsFile=/dev/null");
        }
        if let Some(key) = &self.identity_file {
            cmd.arg("-i").arg(key);
        }
        cmd.arg(local);
        cmd.arg(format!("{}:{}", self.target(), remote.display()));
        let st = cmd.status().await.context("failed to run scp upload")?;
        if st.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("scp upload failed"))
        }
    }

    async fn download_file(&self, remote: &Path, local: &Path) -> Result<()> {
        let mut cmd = tokio::process::Command::new("scp");
        cmd.arg("-P").arg(self.port.to_string());
        cmd.arg("-o").arg("BatchMode=yes");
        if !self.strict_host_checking {
            cmd.arg("-o").arg("StrictHostKeyChecking=no");
            cmd.arg("-o").arg("UserKnownHostsFile=/dev/null");
        }
        if let Some(key) = &self.identity_file {
            cmd.arg("-i").arg(key);
        }
        cmd.arg(format!("{}:{}", self.target(), remote.display()));
        cmd.arg(local);
        let st = cmd.status().await.context("failed to run scp download")?;
        if st.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("scp download failed"))
        }
    }

    async fn write_file(&self, path: &Path, content: &[u8], mode: u32) -> Result<()> {
        // base64 round-trip to avoid quoting issues.
        use base64_like_encode::encode;
        let b64 = encode(content);
        let script = format!(
            "mkdir -p {dir} && echo {b64} | base64 -d > {path} && chmod {mode:o} {path}",
            dir = Self::shell_quote(
                &path
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| "/tmp".to_string())
            ),
            path = Self::shell_quote(&path.to_string_lossy()),
            mode = mode,
        );
        let out = self.exec_shell(&script).await?;
        if out.exit_status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("remote write_file failed: {}", out.stderr))
        }
    }

    async fn read_file(&self, path: &Path) -> Result<Vec<u8>> {
        let script = format!("base64 < {}", Self::shell_quote(&path.to_string_lossy()));
        let out = self.exec_shell(&script).await?;
        if !out.exit_status.success() {
            return Err(anyhow::anyhow!("remote read_file failed: {}", out.stderr));
        }
        let trimmed: String = out.stdout.chars().filter(|c| !c.is_whitespace()).collect();
        decode_base64(&trimmed)
    }

    async fn mkdir_p(&self, path: &Path, mode: u32) -> Result<()> {
        let script = format!(
            "mkdir -p {} && chmod {:o} {}",
            Self::shell_quote(&path.to_string_lossy()),
            mode,
            Self::shell_quote(&path.to_string_lossy())
        );
        let out = self.exec_shell(&script).await?;
        if out.exit_status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("remote mkdir failed: {}", out.stderr))
        }
    }

    async fn exists(&self, path: &Path) -> Result<bool> {
        let script = format!("test -e {}", Self::shell_quote(&path.to_string_lossy()));
        let out = self.exec_shell(&script).await?;
        Ok(out.exit_status.success())
    }

    async fn remove_all(&self, path: &Path) -> Result<()> {
        let script = format!("rm -rf {}", Self::shell_quote(&path.to_string_lossy()));
        let out = self.exec_shell(&script).await?;
        if out.exit_status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("remote rm failed: {}", out.stderr))
        }
    }

    async fn set_permissions(&self, path: &Path, mode: u32) -> Result<()> {
        let script = format!(
            "chmod {:o} {}",
            mode,
            Self::shell_quote(&path.to_string_lossy())
        );
        let out = self.exec_shell(&script).await?;
        if out.exit_status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("remote chmod failed: {}", out.stderr))
        }
    }
}

mod base64_like_encode {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    pub fn encode(data: &[u8]) -> String {
        let mut s = String::new();
        for chunk in data.chunks(3) {
            let mut n: u32 = 0;
            for (i, &b) in chunk.iter().enumerate() {
                n |= (b as u32) << (16 - 8 * i);
            }
            let pad = 3 - chunk.len();
            for i in 0..4 - pad {
                let idx = ((n >> (18 - 6 * i)) & 0x3f) as usize;
                s.push(ALPH[idx] as char);
            }
            for _ in 0..pad {
                s.push('=');
            }
        }
        s
    }
}

fn decode_base64(s: &str) -> Result<Vec<u8>> {
    fn val(c: u8) -> Result<u32> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => Err(anyhow::anyhow!("invalid base64 char")),
        }
    }
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(anyhow::anyhow!("invalid base64 length"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        for i in 0..3 - pad {
            out.push(((n >> (16 - 8 * i)) & 0xff) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_and_defaults() {
        let ex = SshExecutor::new("1.2.3.4".to_string(), 22, "root".to_string());
        assert_eq!(ex.target(), "root@1.2.3.4");
        assert!(ex.identity_file.is_none());
        assert!(!ex.strict_host_checking);
    }

    #[test]
    fn test_base_args_non_interactive() {
        let ex = SshExecutor::new("host".to_string(), 2222, "steady".to_string());
        let args = ex.base_args().join(" ");
        assert!(args.contains("-p 2222"));
        assert!(args.contains("BatchMode=yes"));
        assert!(args.contains("StrictHostKeyChecking=no"));
        assert!(!args.contains("-i "));
    }

    #[test]
    fn test_base_args_strict_with_key() {
        let mut ex = SshExecutor::new("host".to_string(), 22, "steady".to_string());
        ex.strict_host_checking = true;
        ex.identity_file = Some("/tmp/id".to_string());
        let args = ex.base_args().join(" ");
        assert!(args.contains("StrictHostKeyChecking=yes"));
        assert!(args.contains("-i /tmp/id"));
    }

    #[test]
    fn test_shell_quote() {
        assert_eq!(SshExecutor::shell_quote("plain"), "'plain'");
        assert_eq!(SshExecutor::shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn test_base64_round_trip() {
        for data in [
            &b""[..],
            b"hi".as_slice(),
            b"hello world".as_slice(),
            &[0u8, 1, 2, 250, 255],
        ] {
            let enc = base64_like_encode::encode(data);
            let dec = decode_base64(&enc).unwrap();
            assert_eq!(dec, data);
        }
    }

    #[test]
    fn test_decode_base64_rejects_garbage() {
        assert!(decode_base64("!!!").is_err());
        assert!(decode_base64("abc").is_err());
    }
}
