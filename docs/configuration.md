# NAME

**steadystate configuration** - environment variables and settings

# DESCRIPTION

SteadyState is configured primarily through environment variables. This page documents all available configuration options for both the CLI and backend server.

# CLI CONFIGURATION

## STEADYSTATE_BACKEND

URL of the SteadyState backend server.

```
export STEADYSTATE_BACKEND="http://localhost:8080"
```

**Default:** `http://localhost:8080`

## STEADYSTATE_USERNAME

Override the username for sync operations. Primarily used internally by the session wrapper.

```
export STEADYSTATE_USERNAME="brodrigues"
```

**Default:** Derived from authenticated session or system `$USER`

## STEADYSTATE_DEBUG_MERGE

Enable verbose merge debugging output.

```
export STEADYSTATE_DEBUG_MERGE=1
```

When set, the merge engine will log detailed information about each file being merged, including tree sizes and merge decisions.

**Default:** Unset (disabled)

## STEADYSTATE_CONFIG_DIR

Override the directory where SteadyState stores configuration and session files.

```
export STEADYSTATE_CONFIG_DIR="/path/to/config"
```

**Default:** `~/.config/steadystate` (Linux), `~/Library/Application Support/steadystate` (macOS)

# BACKEND CONFIGURATION

## Required Variables

### GITHUB_CLIENT_ID

GitHub OAuth application client ID.

```
export GITHUB_CLIENT_ID="Iv1.abc123..."
```

Obtain this from your GitHub OAuth App settings.

### GITHUB_CLIENT_SECRET

GitHub OAuth application client secret.

```
export GITHUB_CLIENT_SECRET="secret123..."
```

**Security:** Keep this value secret. Do not commit to version control.

### JWT_SECRET

Secret key for signing JWT tokens.

```
export JWT_SECRET="$(openssl rand -base64 32)"
```

Generate a random 32+ byte string. All backend instances must share the same secret.

**Security:** Keep this value secret. Rotate periodically.

## Optional Variables

### PORT

Port for the backend HTTP server.

```
export PORT=8080
```

**Default:** `8080`

### STEADYSTATE_EXTERNAL_HOST

Public hostname or IP address for SSH connections.

```
export STEADYSTATE_EXTERNAL_HOST="192.168.1.100"
export STEADYSTATE_EXTERNAL_HOST="steadystate.example.com"
```

**Default:** Auto-detected local IP address

This is included in magic links and must be reachable by collaborators.

### STEADYSTATE_SSH_USER

System user for SSH session connections.

```
export STEADYSTATE_SSH_USER="steadystate"
```

**Default:** `steadystate`

This user must exist on the system and have appropriate permissions.

### STEADYSTATE_PROVIDER

Default compute provider for new sessions. Overrides per session with
`steadystate up --provider=...`.

```
export STEADYSTATE_PROVIDER="local"
```

**Default:** `local`

### STEADYSTATE_DB_PATH

SQLite file used for sessions and refresh tokens.

```
export STEADYSTATE_DB_PATH="$HOME/.steadystate/steadystate.db"
```

**Default:** `~/.steadystate/steadystate.db`

### TLANG_FLAKE_URL

Flake providing the `t` binary for `tproject.toml` environments.

```
export TLANG_FLAKE_URL="github:b-rodrigues/tlang"
```

**Default:** `github:b-rodrigues/tlang`

### HCLOUD_TOKEN

Hetzner Cloud API token. Required for the `hetzner` compute provider;
without it the backend serves `local` sessions only.

```
export HCLOUD_TOKEN="your-hetzner-token"
```

**Default:** Unset (hetzner provider disabled)

### HCLOUD_SERVER_TYPE / HCLOUD_IMAGE / HCLOUD_LOCATION / HCLOUD_SSH_KEY / HCLOUD_SSH_IDENTITY

Hetzner server shape and access (all optional):

```
export HCLOUD_SERVER_TYPE="cx23"
export HCLOUD_IMAGE="ubuntu-24.04"
export HCLOUD_LOCATION="nbg1"
export HCLOUD_SSH_KEY="your-uploaded-ssh-key-name"
export HCLOUD_SSH_IDENTITY="$HOME/.ssh/id_ed25519"
```

**Defaults:** `cx23` / `ubuntu-24.04` / `nbg1` / unset / unset

### OIDC_ISSUER / OIDC_CLIENT_ID / OIDC_CLIENT_SECRET

Enterprise SSO via generic OpenID Connect. `OIDC_ISSUER` is a full
`https://...` URL or a preset (`google`, `entra:{tenant}`, `okta:{domain}`).

```
export OIDC_ISSUER="entra:common"
export OIDC_CLIENT_ID="your-client-id"
export OIDC_CLIENT_SECRET="your-client-secret"
```

**Defaults:** Unset (OIDC provider disabled; `/auth/oidc/*` answers 503)

### OIDC_SCOPES / OIDC_LOGIN_CLAIM

Optional OIDC tuning: space-separated scopes and the userinfo claim used
as the SteadyState login (`preferred_username` → `email` → `sub` fallback
when unset).

```
export OIDC_SCOPES="openid profile email"
export OIDC_LOGIN_CLAIM="preferred_username"
```

**Defaults:** `"openid profile email"` / `"preferred_username"`

### GITLAB_URL

GitLab instance base URL for PAT login and session forge operations
(SSH keys, project members).

```
export GITLAB_URL="https://git.example.com"
```

**Default:** `https://gitlab.com`

### STEADYSTATE_DEFAULT_SESSION_TTL_SECS

Default session lifetime. Sessions past expiry are terminated automatically
by the reaper (every 60s). Applies from creation — idle time is not tracked.

```
export STEADYSTATE_DEFAULT_SESSION_TTL_SECS=172800
```

**Default:** `172800` (48h)

### STEADYSTATE_MAX_SESSION_TTL_SECS

Upper bound for `--ttl` requests (clamped, not rejected). `0` disables the cap.

```
export STEADYSTATE_MAX_SESSION_TTL_SECS=604800
```

**Default:** `604800` (7 days)

### STEADYSTATE_MAX_SESSIONS_PER_USER

Max live (`Provisioning`/`Running`) sessions per user. Over-cap creates get
`429 Too Many Requests`. `0` disables the limit.

```
export STEADYSTATE_MAX_SESSIONS_PER_USER=5
```

**Default:** `5`

### RATE_LIMIT_TOKEN_PER_MIN / RATE_LIMIT_AUTH_PER_MIN / RATE_LIMIT_DEFAULT_PER_MIN

Per-IP rate limits (requests/minute) for `POST /auth/token`, the device
flow (`/auth/device`, `/auth/poll`), and the remaining auth routes
(`refresh`, `revoke`, `me`). `0` disables a tier.

```
export RATE_LIMIT_TOKEN_PER_MIN=5
export RATE_LIMIT_AUTH_PER_MIN=30
export RATE_LIMIT_DEFAULT_PER_MIN=120
```

**Defaults:** `5` / `30` / `120`

Over-limit responses are `429` with a JSON `{"error": ...}` body and a
`Retry-After` header. Keys are peer IPs: behind a reverse proxy every
client shares the proxy's IP unless the proxy setup is adjusted.

### RUST_LOG

Control logging verbosity.

```
export RUST_LOG=info
export RUST_LOG=steadystate=debug
export RUST_LOG=steadystate::compute=trace
```

**Default:** `info`

# SESSION ENVIRONMENT

Inside a collaboration session, the following variables are set automatically:

| Variable | Description |
|----------|-------------|
| `REPO_ROOT` | Path to session root directory |
| `SESSION_ID` | Unique session identifier |
| `STEADYSTATE_USERNAME` | GitHub username of connected user |
| `USER_WORKSPACE` | Path to user's worktree |
| `CANONICAL_REPO` | Path to canonical repository |
| `REPO_NAME` | Name of the repository (used by dashboard) |

# FILES

## ~/.config/steadystate/session.json

Stores the current authentication session:

```json
{
  "login": "username",
  "jwt": "eyJ...",
  "jwt_exp": 1699999999
}
```

**Permissions:** `0600` (user read/write only)

## ~/.config/steadystate/refresh_token

Stores the refresh token for automatic re-authentication.

**Permissions:** `0600`

## /tmp/steadystate-*-known_hosts

Temporary SSH known_hosts files created for session connections. Automatically cleaned up.

# SYSTEMD CONFIGURATION

Example systemd service file for the backend:

```ini
[Unit]
Description=SteadyState Backend
After=network.target

[Service]
Type=simple
User=steadystate
Group=steadystate
WorkingDirectory=/opt/steadystate
ExecStart=/opt/steadystate/steadystate-backend
Restart=always
RestartSec=5

Environment=GITHUB_CLIENT_ID=Iv1.abc123
Environment=GITHUB_CLIENT_SECRET=secret123
Environment=JWT_SECRET=your-secret-here
Environment=PORT=8080
Environment=STEADYSTATE_EXTERNAL_HOST=your-server.com
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

# NIXOS CONFIGURATION

Example NixOS module:

```nix
{ config, pkgs, ... }:

{
  users.users.steadystate = {
    isNormalUser = true;
    home = "/home/steadystate";
    shell = pkgs.bash;
  };

  systemd.services.steadystate = {
    description = "SteadyState Backend";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    
    environment = {
      GITHUB_CLIENT_ID = "Iv1.abc123";
      PORT = "8080";
      STEADYSTATE_EXTERNAL_HOST = "your-server.com";
      RUST_LOG = "info";
    };
    
    serviceConfig = {
      Type = "simple";
      User = "steadystate";
      ExecStart = "${pkgs.steadystate}/bin/steadystate-backend";
      Restart = "always";
      RestartSec = 5;
      
      # Load secrets from file
      EnvironmentFile = "/run/secrets/steadystate";
    };
  };

  networking.firewall.allowedTCPPorts = [ 8080 ];
  networking.firewall.allowedTCPPortRanges = [
    { from = 20000; to = 28000; }  # Hetzner session SSH (local sessions use ephemeral ports)
  ];
}
```

# SEE ALSO

**steadystate**(1), **systemd.service**(5)
