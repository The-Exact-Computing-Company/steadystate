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
   - **Homepage URL**: `http://your-server:3000`
   - **Authorization callback URL**: `http://your-server:3000/auth/callback`
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
export STEADYSTATE_PORT=3000
export STEADYSTATE_EXTERNAL_HOST="your-server-ip-or-hostname"
export STEADYSTATE_SSH_USER="steadystate"  # System user for SSH sessions
```

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

The backend will start on port 3000 (or your configured port).

## 6. Firewall Configuration

Ensure these ports are accessible:

| Port | Purpose |
|------|---------|
| 3000 | Backend API |
| 2000-3000 | SSH sessions (dynamic range) |

```bash
# UFW example
sudo ufw allow 3000/tcp
sudo ufw allow 2000:3000/tcp
```
