use anyhow::{Result, Context, anyhow};
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
            token: std::env::var("HCLOUD_TOKEN").context("HCLOUD_TOKEN must be set for hetzner provider")?,
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
            labels: Some([("steadystate".to_string(), "session".to_string())].into_iter().collect()),
        };
        let resp = self.req(reqwest::Method::POST, "/servers").json(&body).send().await?;
        if !resp.status().is_success() {
            let txt = resp.text().await.unwrap_or_default();
            return Err(anyhow!("hcloud create server failed: {}", txt));
        }
        let out: CreateServerResp = resp.json().await.context("decode hcloud create response")?;
        Ok(out.server)
    }

    pub async fn get_server(&self, id: u64) -> Result<HServer> {
        let resp = self.req(reqwest::Method::GET, &format!("/servers/{}", id)).send().await?;
        if !resp.status().is_success() {
            let txt = resp.text().await.unwrap_or_default();
            return Err(anyhow!("hcloud get server failed: {}", txt));
        }
        let out: GetServerResp = resp.json().await.context("decode hcloud get response")?;
        Ok(out.server)
    }

    pub async fn delete_server(&self, id: u64) -> Result<()> {
        let resp = self.req(reqwest::Method::DELETE, &format!("/servers/{}", id)).send().await?;
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
        Err(anyhow!("timed out waiting for hcloud server {} to be running", id))
    }
}

/// Cloud-init that installs nix (multi-user), git, sshd and creates the session user.
pub fn cloud_init_script(ssh_user: &str) -> String {
    format!(
        r#"#cloud-config
packages: [curl, git, openssh-server, sudo]
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
