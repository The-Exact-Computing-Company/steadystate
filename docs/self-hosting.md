# Self-Hosting Setup

## Prerequisites

- Linux server (Ubuntu 22.04+ recommended) or NixOS
- Rust toolchain (1.75+)
- Git
- GitHub OAuth App credentials

## 1. Create a GitHub OAuth App

1. Go to **GitHub → Settings → Developer settings → OAuth Apps → New OAuth App**
2. Fill in:
    - **Application name**: `SteadyState` (or your preferred name)
    - **Homepage URL**: `http://your-server:8080`
    - **Authorization callback URL**: `http://your-server:8080/auth/callback` (required by GitHub, unused: login uses the OAuth device flow, no browser redirect)
3. Note your **Client ID** and generate a **Client Secret**

## 2. Clone and Build

```bash
# Clone the repository
git clone https://github.com/your-org/steadystate.git
cd steadystate

# Build the backend and CLI
cargo build --release

# The binaries will be in target/release/
# - steadystate-backend (the server)
# - steadystate (the CLI)
```

## 3. Configure the Backend

Create a configuration file or set environment variables:

```bash
# Required
export GITHUB_CLIENT_ID="your_github_client_id"
export GITHUB_CLIENT_SECRET="your_github_client_secret"
export JWT_SECRET="$(openssl rand -base64 32)"

# Optional
export PORT=8080
export STEADYSTATE_EXTERNAL_HOST="your-server-ip-or-hostname"
export STEADYSTATE_SSH_USER="steadystate"  # System user for SSH sessions
export STEADYSTATE_PROVIDER="local"        # Default compute provider
export TLANG_FLAKE_URL="github:b-rodrigues/tlang"  # Flake providing the `t` binary
```

### Hetzner Cloud provider (optional)

To let users provision sessions on Hetzner Cloud with
`steadystate up --provider=hetzner ...`, set:

```bash
export HCLOUD_TOKEN="your_hetzner_cloud_api_token"
# Optional (defaults shown)
export HCLOUD_SERVER_TYPE="cx23"
export HCLOUD_IMAGE="ubuntu-24.04"
export HCLOUD_LOCATION="nbg1"
export HCLOUD_SSH_KEY="your-uploaded-ssh-key-name"
export HCLOUD_SSH_IDENTITY="$HOME/.ssh/id_ed25519"  # Key used for provisioned hosts
```

Without `HCLOUD_TOKEN` the backend serves `local` sessions only and
rejects `--provider=hetzner` by falling back to the default provider.

## 4. Create the SteadyState System User

For collaboration sessions, SteadyState needs a dedicated system user:

```bash
# Create the user
sudo useradd -m -s /bin/bash steadystate

# Ensure the user can run the CLI
sudo cp target/release/steadystate /usr/local/bin/
```

On **NixOS**, add to your configuration:

```nix
users.users.steadystate = {
  isNormalUser = true;
  home = "/home/steadystate";
  shell = pkgs.bash;
};
```

## 5. Start the Backend

```bash
# Run the backend
./target/release/steadystate-backend

# Or with systemd (recommended for production)
sudo systemctl start steadystate
```

The backend will start on port 8080 (or your configured `PORT`).

## 6. Firewall Configuration

Ensure these ports are accessible:

| Port | Purpose |
|------|---------|
| 8080 | Backend API |
| ephemeral high ports | Local sessions bind an OS-assigned port per session |
| 20000-28000 | Hetzner sessions listen on a deterministic high port per session |

```bash
# UFW example
sudo ufw allow 8080/tcp
sudo ufw allow 20000:28000/tcp  # hetzner session SSH; local sessions use ephemeral ports
```

## 7. Serving a Team from One VM

This is the standard "job VM" setup: the backend runs on a machine at work
(e.g. `devbox.corp`), sessions live on that machine, and teammates connect
from their laptops over the (trusted) office network or VPN.

### On the VM

1. Follow steps 1–5 above. Use a stable address for SSH links:
   ```bash
   export STEADYSTATE_EXTERNAL_HOST="devbox.corp"
   ```
   Without it, the backend falls back to its auto-detected LAN IP, which is
   fine on a flat office network but wrong behind NAT.
2. Open the firewall for the API plus session SSH (see §6). Local sessions
   each bind an OS-assigned ephemeral port; Hetzner sessions use `20000–28000`.
3. Keep the backend running with systemd (see `configuration.md` for a unit
   file) so sessions survive logouts. Session records and refresh tokens are
   stored in SQLite (`~/.steadystate/steadystate.db` by default,
   `STEADYSTATE_DB_PATH` to override), so a backend restart keeps the session
   list — but live SSH handles do not survive a restart.

### On each laptop

```bash
# Point the CLI at the team server (default is http://localhost:8080)
export STEADYSTATE_BACKEND="http://devbox.corp:8080"

# One-time login (GitHub device flow, works from anywhere)
steadystate login
steadystate whoami

# Host a session on the VM
steadystate up --env=auto --mode=collab https://github.com/org/repo
# Share the printed magic link, e.g.:
steadystate join "steadystate://collab/abc123?ssh=...&host_key=..."

# Collaborator prerequisites: a GitHub account with an SSH key uploaded,
# plus repo access (or be listed in --allow=user1,user2)
```

Traffic here is plain HTTP + SSH. That is fine on a trusted LAN/VPN but not
on open Wi-Fi — see §8.

## 8. Locking It Down

### Option A: SSH tunnels (no open ports except 22)

Keep the firewall closed except SSH, and tunnel everything through it:

```bash
# Terminal 1: forward the API
ssh -N -L 8080:localhost:8080 you@devbox.corp

# Terminal 2: point the CLI at the tunnel
export STEADYSTATE_BACKEND="http://localhost:8080"
steadystate login
steadystate up --env=auto --mode=collab https://github.com/org/repo
```

Session SSH then also goes through a tunnel. If the magic link says
`ssh://steady@devbox.corp:45678`, forward that port too:

```bash
ssh -N -L 45678:localhost:45678 you@devbox.corp
# then connect as if it were local (host-key check still applies)
ssh steady@localhost -p 45678
```

Or skip per-port forwarding with a jump host (`ssh -J you@devbox.corp`)
if the VM can route to itself — the session ports only need to be reachable
from the VM.

### Option B: TLS reverse proxy

Put Caddy or nginx in front of `localhost:8080` and point
`STEADYSTATE_BACKEND` at `https://devbox.corp`. Native TLS in the backend
is deliberately out of scope; the proxy also lets you restrict `/auth/*`
or add client certs without touching SteadyState.

### What the server never sees

Your GitHub password or PAT never touches the backend: login is an OAuth
device flow between your browser and GitHub. The backend only ever holds a
short-lived JWT, a refresh token, and (transiently) the OAuth access token
used to fetch your public SSH keys and clone private repos.
