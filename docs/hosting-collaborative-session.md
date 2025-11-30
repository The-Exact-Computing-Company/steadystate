# Hosting a Collaborative Session

SteadyState's **Collaboration Mode** allows multiple developers to work on the same codebase simultaneously using a shared workspace and conflict-free merging.

## Prerequisites

- You must be logged in (`steadystate login`).
- You must have a running SteadyState backend (or access to one).

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

## Joining a Session

Collaborators join using the magic link shared by the host.

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

## Working with Changes

### Check Status

See what files you've modified:

```bash
steadystate status
```

### View Diff

See exactly what changed:

```bash
steadystate diff
```

### Check Credit

See who last modified specific lines in a file (git blame):

```bash
steadystate credit analysis.R
```

The output is piped to `less` for easy scrolling. Press `q` to exit.

**Note:** Commits from `steadystate sync` are authored by the user who ran the sync, so credit is accurately attributed.

### Sync Changes

**This is the core collaboration command.** Sync does three things:

1. **Fetches** changes from other collaborators
2. **Merges** their changes with yours (conflict-free 3-way merge)
3. **Pushes** your merged changes so others can see them

```bash
steadystate sync
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

This pushes the session branch to GitHub, where you can create a Pull Request.

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
