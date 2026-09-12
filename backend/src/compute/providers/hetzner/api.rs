use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct HetznerConfig {
    pub token: String,
    pub server_type: String,
    pub image: String,
    pub location: String,
    pub ssh_key_name: Option<String>,
}

impl HetznerConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            token: std::env::var("HCLOUD_TOKEN")
                .context("HCLOUD_TOKEN must be set for hetzner provider")?,
            server_type: std::env::var("HCLOUD_SERVER_TYPE").unwrap_or_else(|_| "cx23".to_string()),
            image: std::env::var("HCLOUD_IMAGE").unwrap_or_else(|_| "ubuntu-24.04".to_string()),
            location: std::env::var("HCLOUD_LOCATION").unwrap_or_else(|_| "nbg1".to_string()),
            ssh_key_name: std::env::var("HCLOUD_SSH_KEY").ok(),
        })
    }

    pub fn available() -> bool {
        std::env::var("HCLOUD_TOKEN").is_ok()
    }
}

#[derive(Debug, Serialize)]
struct CreateServerReq<'a> {
    name: &'a str,
    server_type: &'a str,
    image: &'a str,
    location: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct CreateServerResp {
    server: HServer,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HServer {
    pub id: u64,
    pub name: String,
    pub status: String,
    pub public_net: HPublicNet,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HPublicNet {
    pub ipv4: HIpv4,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HIpv4 {
    pub ip: String,
}

#[derive(Debug, Deserialize)]
struct GetServerResp {
    server: HServer,
}

#[derive(Debug, Clone)]
pub struct HetznerApi {
    http: Client,
    token: String,
}

impl HetznerApi {
    pub fn new(http: Client, token: String) -> Self {
        Self { http, token }
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("https://api.hetzner.cloud/v1{}", path))
            .bearer_auth(&self.token)
            .header("Content-Type", "application/json")
    }

    pub async fn create_server(
        &self,
        name: &str,
        cfg: &HetznerConfig,
        user_data: Option<String>,
    ) -> Result<HServer> {
        let body = CreateServerReq {
            name,
            server_type: &cfg.server_type,
            image: &cfg.image,
            location: &cfg.location,
            ssh_keys: cfg.ssh_key_name.clone().map(|k| vec![k]),
            user_data,
            labels: Some(
                [("steadystate".to_string(), "session".to_string())]
                    .into_iter()
                    .collect(),
            ),
        };
        let resp = self
            .req(reqwest::Method::POST, "/servers")
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            let txt = resp.text().await.unwrap_or_default();
            return Err(anyhow!("hcloud create server failed: {}", txt));
        }
        let out: CreateServerResp = resp.json().await.context("decode hcloud create response")?;
        Ok(out.server)
    }

    pub async fn get_server(&self, id: u64) -> Result<HServer> {
        let resp = self
            .req(reqwest::Method::GET, &format!("/servers/{}", id))
            .send()
            .await?;
        if !resp.status().is_success() {
            let txt = resp.text().await.unwrap_or_default();
            return Err(anyhow!("hcloud get server failed: {}", txt));
        }
        let out: GetServerResp = resp.json().await.context("decode hcloud get response")?;
        Ok(out.server)
    }

    pub async fn delete_server(&self, id: u64) -> Result<()> {
        let resp = self
            .req(reqwest::Method::DELETE, &format!("/servers/{}", id))
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let txt = resp.text().await.unwrap_or_default();
            Err(anyhow!("hcloud delete server failed: {}", txt))
        }
    }

    /// Poll until server is running and has a public IPv4, up to ~5 min.
    pub async fn wait_running(&self, id: u64) -> Result<HServer> {
        for _ in 0..60 {
            let s = self.get_server(id).await?;
            if s.status == "running" && !s.public_net.ipv4.ip.is_empty() {
                return Ok(s);
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        Err(anyhow!(
            "timed out waiting for hcloud server {} to be running",
            id
        ))
    }
}

/// Cloud-init that installs nix (multi-user), git, sshd and creates the session user.
pub fn cloud_init_script(ssh_user: &str) -> String {
    format!(
        r#"#cloud-config
packages: [curl, git, openssh-server, sudo, tmux]
users:
  - name: {user}
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
runcmd:
  - systemctl enable --now ssh
  - "curl -L https://github.com/DeterminateSystems/nix-installer/releases/latest/download/nix-installer-x86_64-linux -o /tmp/nix-installer && chmod +x /tmp/nix-installer && /tmp/nix-installer install --no-confirm || true"
"#,
        user = ssh_user
    )
}

#[cfg(test)]
mod tests {
    use super::super::provider::HetznerComputeProvider;
    use super::*;
    use crate::compute::ComputeProvider;
    use crate::state::lock_test_env;

    async fn with_env(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
        let _guard = lock_test_env().await;
        let mut saved = Vec::new();
        for (k, v) in vars {
            saved.push((k.to_string(), std::env::var(k).ok()));
            // SAFETY: serialized by the shared test-env lock.
            unsafe {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
        f();
        for (k, old) in saved {
            // SAFETY: still holding the shared lock.
            unsafe {
                match old {
                    Some(val) => std::env::set_var(&k, val),
                    None => std::env::remove_var(&k),
                }
            }
        }
    }

    #[tokio::test]
    async fn test_config_requires_token() {
        with_env(&[("HCLOUD_TOKEN", None)], || {
            assert!(HetznerConfig::from_env().is_err());
            assert!(!HetznerConfig::available());
        })
        .await;
    }

    #[tokio::test]
    async fn test_config_defaults() {
        with_env(
            &[
                ("HCLOUD_TOKEN", Some("test-token")),
                ("HCLOUD_SERVER_TYPE", None),
                ("HCLOUD_IMAGE", None),
                ("HCLOUD_LOCATION", None),
                ("HCLOUD_SSH_KEY", None),
            ],
            || {
                let cfg = HetznerConfig::from_env().unwrap();
                assert_eq!(cfg.token, "test-token");
                assert_eq!(cfg.server_type, "cx23");
                assert_eq!(cfg.image, "ubuntu-24.04");
                assert_eq!(cfg.location, "nbg1");
                assert!(cfg.ssh_key_name.is_none());
                assert!(HetznerConfig::available());
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_config_overrides() {
        with_env(
            &[
                ("HCLOUD_TOKEN", Some("tok")),
                ("HCLOUD_SERVER_TYPE", Some("cax21")),
                ("HCLOUD_IMAGE", Some("debian-12")),
                ("HCLOUD_LOCATION", Some("fsn1")),
                ("HCLOUD_SSH_KEY", Some("my-key")),
            ],
            || {
                let cfg = HetznerConfig::from_env().unwrap();
                assert_eq!(cfg.server_type, "cax21");
                assert_eq!(cfg.image, "debian-12");
                assert_eq!(cfg.location, "fsn1");
                assert_eq!(cfg.ssh_key_name.as_deref(), Some("my-key"));
            },
        )
        .await;
    }

    #[test]
    fn test_cloud_init_script() {
        let script = cloud_init_script("steadystate");
        assert!(script.starts_with("#cloud-config"));
        assert!(script.contains("name: steadystate"));
        assert!(script.contains("openssh-server"));
        assert!(script.contains("tmux"));
        assert!(script.contains("nix-installer"));
        // Must not hard-fail cloud-init if nix install fails (idempotent reruns).
        assert!(script.contains("|| true"));
    }

    #[tokio::test]
    async fn test_provider_identity_and_capabilities() {
        with_env(&[("HCLOUD_TOKEN", Some("test-token"))], || {
            let p = HetznerComputeProvider::from_env(reqwest::Client::new()).unwrap();
            assert_eq!(p.id(), "hetzner");
            let caps = p.capabilities();
            assert!(caps.supports_collab_mode);
            assert!(caps.supports_pair_mode);
            assert!(
                caps.supported_environments
                    .contains(&"tproject".to_string())
            );
            assert!(caps.supported_environments.contains(&"auto".to_string()));
        })
        .await;
    }
}
