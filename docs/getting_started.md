# Getting Started with SteadyState

SteadyState is a real-time collaboration tool for data science and development projects. It enables multiple users to work on the same codebase simultaneously with automatic conflict-free merging.

## Table of Contents

1. [Self-Hosting Setup](#self-hosting-setup)
2. [Authentication](#authentication)
3. [Creating a Session](#creating-a-session)
4. [Joining a Session](#joining-a-session)
5. [The Dashboard](#the-dashboard)
6. [Working with Changes](#working-with-changes)
7. [Workflow Example](#workflow-example)
8. [Troubleshooting](#troubleshooting)

---

## Self-Hosting Setup

### Prerequisites

- Linux server (Ubuntu 22.04+ recommended) or NixOS
- Rust toolchain (1.75+)
- Git
- GitHub OAuth App credentials

### 1. Create a GitHub OAuth App

1. Go to **GitHub → Settings → Developer settings → OAuth Apps → New OAuth App**
2. Fill in:
   - **Application name**: `SteadyState` (or your preferred name)
   - **Homepage URL**: `http://your-server:3000`
   - **Authorization callback URL**: `http://your-server:3000/auth/callback`
3. Note your **Client ID** and generate a **Client Secret**

### 2. Clone and Build

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

### 3. Configure the Backend

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

### 4. Create the SteadyState System User

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

### 5. Start the Backend

```bash
# Run the backend
./target/release/steadystate-backend

# Or with systemd (recommended for production)
sudo systemctl start steadystate
```

The backend will start on port 3000 (or your configured port).

### 6. Firewall Configuration

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

---

## Authentication

### First-Time Login

SteadyState uses GitHub for authentication via the device flow (no browser redirect needed).

```bash
# Point CLI to your backend
export STEADYSTATE_BACKEND_URL="http://your-server:3000"

# Login with GitHub
steadystate login
```

You'll see:

```
🔐 Starting GitHub device authentication...

Please visit: https://github.com/login/device
And enter code: ABCD-1234

Waiting for authorization...
```

1. Open the URL in your browser
2. Enter the code shown
3. Authorize the SteadyState app
4. The CLI will automatically detect authorization:

```
✅ Logged in as brodrigues
```

### Verify Login

```bash
steadystate whoami
# Output: brodrigues
```

### Logout

```bash
steadystate logout
# Output: Logged out (local tokens removed).
```

---

## Creating a Session

The **session host** creates a collaboration session using `steadystate up`.

### Basic Usage

```bash
# Create a collaboration session for a GitHub repository
steadystate up --mode=collab https://github.com/username/repository
```

### Options

| Option | Description |
|--------|-------------|
| `--mode=collab` | Enable collaboration mode (required for multi-user) |
| `--branch=NAME` | Start from a specific branch (default: main) |
| `--allow=user1,user2` | Restrict access to specific GitHub users |

### Example

```bash
steadystate up --mode=collab --branch=feature-analysis https://github.com/b-rodrigues/housing
```

Output:

```
Creating session...
✅ Session ready!

📋 Share this magic link with collaborators:
   steadystate join "steadystate://collab/a1b2c3d4?ssh=ssh%3A%2F%2Fsteadystate%40192.168.1.100%3A2847&host_key=ssh-ed25519%20AAAAC3..."

Launching dashboard...
```

The host is automatically connected to the dashboard.

---

## Joining a Session

Collaborators join using the magic link shared by the host.

### Join a Session

```bash
steadystate join "steadystate://collab/a1b2c3d4?ssh=ssh%3A%2F%2Fsteadystate%40192.168.1.100%3A2847&host_key=ssh-ed25519%20AAAAC3..."
```

> **Important**: Quote the entire URL to prevent shell interpretation of special characters.

Output:

```
Connecting to session...
Creating workspace for rap4all...

╔════════════════════════════════════════════════════════════╗
║         Welcome to SteadyState Collaboration Mode          ║
╚════════════════════════════════════════════════════════════╝

Commands:
  steadystate sync      - Sync your changes
  steadystate diff      - Show changes
  steadystate status    - Check status

rap4all@session:~/housing$
```

You now have your own worktree with the repository files. Edit files as normal using your preferred editor (vim, nano, VS Code remote, etc.).

---

## The Dashboard

The dashboard provides a real-time view of session activity.

### Opening the Dashboard

**As host** (automatically opened after `up`):
The dashboard launches automatically.

**As collaborator or observer**:
```bash
steadystate dashboard "steadystate://collab/a1b2c3d4?ssh=..."
# Or use the alias
steadystate dash "steadystate://collab/a1b2c3d4?ssh=..."
```

### Dashboard Interface
 
 ```
 SteadyState Dashboard
 Session ID: a1b2c3d4
 Repository: housing
 Join with:       steadystate join "steadystate://collab/a1b2c3d4?ssh=..."
 To join with ssh: ssh steadystate@192.168.1.100 -p 2847
 --------------------------------------------------------------------------------
 User:       brodrigues (Connected)
 --------------------------------------------------------------------------------
 Connected Users:
   • brodrigues
   • rap4all
 
 Recent Activity:
   [14:32:05] brodrigues synced
       - analysis.R 10:12
       - data/housing.csv 1:50
   [14:35:22] rap4all synced
       - analysis.R 25:30
   [14:38:01] brodrigues synced
       - analysis.R 45:52
 
 --------------------------------------------------------------------------------
 Status: Sync complete!
 
 Controls: [s] Sync  [p] Publish  [d] Diff  [c] Credit  [q] Quit
 ```
 
 ### Dashboard Controls
 
 | Key | Action |
 |-----|--------|
 | `s` | Run `steadystate sync` - sync your changes with collaborators |
 | `p` | Run `steadystate publish` - push changes to GitHub |
 | `d` | Run `steadystate diff` - view your local changes |
 | `c` | Run `steadystate credit` - view git blame for a file |
 | `q` or `Esc` | Exit dashboard |
 | `Ctrl+C` | Exit dashboard |

---

## Working with Changes

### Check Status

See what files you've modified:

```bash
steadystate status
```

Output:

```
On branch steadystate/a1b2c3d4
Changes not staged for commit:
  (use "steadystate publish" to update the session)

        modified:   analysis.R
        modified:   README.md

Untracked files:
  (use "steadystate publish" to include in what will be committed)

        new_script.R
```

### View Diff

See exactly what changed:

```bash
steadystate diff
```

Output:

```diff
--- analysis.R
+++ analysis.R
@@ -10,7 +10,7 @@
 # Load data
-data <- read.csv("data.csv")
+data <- read.csv("housing.csv")

@@ -25,6 +25,9 @@
 # Analysis
+# Added by rap4all: filter outliers
+data <- data[data$price < 1000000, ]
+
 model <- lm(price ~ sqft + bedrooms, data = data)
```

### Check Credit
 
 See who last modified specific lines in a file (git blame):
 
 ```bash
 steadystate credit analysis.R
 ```
 
 The output is piped to `less` for easy scrolling. Press `q` to exit.
 
 Output:
 ```
 ^abc123 (brodrigues 2023-10-27 14:32:05 +0200 10) data <- read.csv("housing.csv")
 e4f5g6h (rap4all    2023-10-27 14:35:22 +0200 25) data <- data[data$price < 1000000, ]
 ```
 
 **Note:** Commits from `steadystate sync` are authored by the user who ran the sync, so credit is accurately attributed.

### Sync Changes

**This is the core collaboration command.** Sync does three things:

1. **Fetches** changes from other collaborators
2. **Merges** their changes with yours (conflict-free 3-way merge)
3. **Pushes** your merged changes so others can see them

```bash
steadystate sync
```

Output:

```
Syncing changes (Y-CRDT)...
Base commit: abc123
Session branch: steadystate/a1b2c3d4
Fetching latest changes...
Updating local branch to match remote...
Materializing trees...
Detecting changes...
Both local and remote changes detected. Merging...
Merging...
Creating safety backup...
Applying to canonical...
Committing...
Pushing to session repo...
Refreshing worktree...
✅ Sync complete!
```

**When to sync:**
- Before starting work (get latest changes)
- After making changes (share with collaborators)
- Periodically during long editing sessions
- When the dashboard shows others have synced

### Publish to GitHub

When you're ready to push changes back to the original GitHub repository:

```bash
steadystate publish
```

Output:

```
Publishing changes to steadystate/a1b2c3d4...
Staging changes...
Committing...
Pushing to session repo...
Pushing to GitHub...
✅ Publish complete!
```

This pushes the session branch to GitHub, where you can create a Pull Request.

---

## Workflow Example

Here's a typical collaboration workflow:

### Host (brodrigues)

```bash
# 1. Create session
steadystate up --mode=collab https://github.com/b-rodrigues/housing

# 2. Share the magic link with rap4all via Slack/email

# 3. Work on analysis.R lines 1-50
vim analysis.R

# 4. Sync changes
steadystate sync
```

### Collaborator (rap4all)

```bash
# 1. Join the session
steadystate join "steadystate://collab/..."

# 2. Sync to get brodrigues' latest changes
steadystate sync

# 3. Work on analysis.R lines 51-100 (different section)
vim analysis.R

# 4. Sync changes
steadystate sync
# rap4all's changes are now merged with brodrigues' changes
```

### Both Users

```bash
# Keep syncing periodically
steadystate sync

# When done, publish to GitHub
steadystate publish
```

### After the Session

On GitHub:
1. Navigate to the repository
2. You'll see a new branch: `steadystate/a1b2c3d4`
3. Create a Pull Request to merge into `main`
4. Review the combined changes from all collaborators
5. Merge the PR

---

## Troubleshooting

### "Permission denied (publickey)"

**Cause**: Your SSH key isn't authorized for the session.

**Solution**: 
- Ensure you're logged in: `steadystate whoami`
- Ensure your GitHub account has SSH keys configured
- Check that you're a collaborator on the repository

### "Push failed - please sync again"

**Cause**: Another collaborator pushed while you were syncing.

**Solution**: Just run `steadystate sync` again. The system will fetch their changes, merge, and retry.

### "Connection refused"

**Cause**: The session host's machine isn't reachable.

**Solutions**:
- Verify you're on the same network (or have routing)
- Check firewall allows the SSH port
- Verify the host's backend is running

### "Magic link missing SSH URL"

**Cause**: Malformed or incomplete magic link.

**Solution**: Ask the host to share the complete magic link again.

### Dashboard shows "Observer - No worktree"

**Cause**: You opened the dashboard without joining the session first.

**Solution**: Use `steadystate join` to create your worktree, then use the dashboard.

### Merge produces unexpected results

**Cause**: Both users edited the exact same text (same word/token).

**Note**: SteadyState uses an additive merge strategy. If two users replace the same word with different values, both replacements are kept. This is by design to avoid data loss.

**Best practice**: Coordinate with collaborators to work on different sections of files when possible.

---

## Command Reference

| Command | Description |
|---------|-------------|
| `steadystate login` | Authenticate with GitHub |
| `steadystate logout` | Clear local credentials |
| `steadystate whoami` | Show current user |
| `steadystate up --mode=collab <repo>` | Create a collaboration session |
| `steadystate join "<magic_link>"` | Join an existing session |
| `steadystate dashboard "<magic_link>"` | Open session dashboard (alias: `dash`) |
| `steadystate sync` | Sync changes with collaborators |
| `steadystate status` | Show local changes |
| `steadystate diff` | Show detailed diff |
| `steadystate credit <file>` | Show line-by-line credit (git blame) |
| `steadystate publish` | Push changes to GitHub |
| `steadystate watch` | Open dashboard (when inside session) |

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `STEADYSTATE_BACKEND_URL` | Backend server URL | `http://localhost:3000` |
| `STEADYSTATE_EXTERNAL_HOST` | Public hostname/IP for SSH | Auto-detected |
| `STEADYSTATE_SSH_USER` | System user for sessions | `steadystate` |
| `STEADYSTATE_DEBUG_MERGE` | Enable merge debugging | (unset) |

---

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/your-org/steadystate/issues)
- **Documentation**: [docs.steadystate.dev](https://docs.steadystate.dev)

Happy collaborating! 🚀
