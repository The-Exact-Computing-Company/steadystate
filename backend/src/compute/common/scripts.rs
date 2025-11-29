use std::collections::HashMap;

/// Template engine for shell scripts
pub struct ScriptTemplate {
    template: String,
}

impl ScriptTemplate {
    pub fn new(template: &str) -> Self {
        Self {
            template: template.to_string(),
        }
    }
    
    pub fn render(&self, vars: &HashMap<&str, &str>) -> String {
        let mut result = self.template.clone();
        for (key, value) in vars {
            result = result.replace(&format!("{{{{{}}}}}", key), value);
        }
        result
    }
}

/// Generate the collab mode wrapper script
pub fn collab_wrapper_script() -> ScriptTemplate {
    ScriptTemplate::new(r#"#!/usr/bin/env bash
set -e

USER_ID="$1"
export REPO_ROOT="{{session_root}}"
export PATH="$REPO_ROOT/bin:$PATH"
ACTIVE_USERS_FILE="$REPO_ROOT/active-users"
ACTIVITY_LOG="$REPO_ROOT/activity-log"
SYNC_LOG="$REPO_ROOT/sync-log"
export ACTIVITY_LOG
export SYNC_LOG
export SESSION_ROOT="$REPO_ROOT"
export SESSION_ID="{{session_id}}"
export REPO_NAME="{{repo_name}}"

# Add user to active-users
echo "$USER_ID" >> "$ACTIVE_USERS_FILE"

# Cleanup function
cleanup() {
    if [ -f "$ACTIVE_USERS_FILE" ]; then
        grep -v "^$USER_ID$" "$ACTIVE_USERS_FILE" > "$ACTIVE_USERS_FILE.tmp" 2>/dev/null || true
        mv "$ACTIVE_USERS_FILE.tmp" "$ACTIVE_USERS_FILE" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Create worktree if not exists
WORKTREE="$REPO_ROOT/worktrees/$USER_ID"
if [ ! -d "$WORKTREE" ]; then
    echo "Creating workspace for $USER_ID..."
    mkdir -p "$REPO_ROOT/worktrees"
    git clone --branch {{branch_name}} "$REPO_ROOT/canonical" "$WORKTREE"
    cd "$WORKTREE"
    git remote rename origin canonical
    git config user.name "$USER_ID"
    git config user.email "$USER_ID@steadystate.local"

    # Initialize metadata for sync
    mkdir -p .worktree
    HEAD_COMMIT=$(git rev-parse HEAD)
    echo "{\"session_branch\": \"{{branch_name}}\", \"last_synced_commit\": \"$HEAD_COMMIT\"}" > .worktree/steadystate.json
fi

export HOME="$WORKTREE"
export USER_WORKSPACE="$WORKTREE"
export CANONICAL_REPO="$REPO_ROOT/canonical"

cd "$WORKTREE" || exit 1

# Welcome message
cat << 'WELCOME'
╔════════════════════════════════════════════════════════════╗
║         Welcome to SteadyState Collaboration Mode          ║
╚════════════════════════════════════════════════════════════╝

Commands:
  steadystate sync      - Sync your changes
  steadystate diff      - Show changes
  steadystate status    - Check status

WELCOME

if [ -n "$SSH_ORIGINAL_COMMAND" ]; then
    exec bash -c "$SSH_ORIGINAL_COMMAND"
else
    exec bash -l
fi
"#)
}

/// Generate the sync script
pub fn sync_script() -> ScriptTemplate {
    ScriptTemplate::new(r#"#!/bin/bash
set -e

USER_ID="${STEADYSTATE_USERNAME:-${USER:-unknown}}"
WORKSPACE="${USER_WORKSPACE:-$PWD}"
SESSION_ROOT="${SESSION_ROOT:-$(dirname "$WORKSPACE")}"
CANONICAL="${CANONICAL_REPO:-$SESSION_ROOT/canonical}"
SYNC_LOG="${SYNC_LOG:-$SESSION_ROOT/sync-log}"

log_activity() {
    local action="$1"
    if [ -f "$SYNC_LOG" ]; then
        echo "$(date -Iseconds),$USER_ID,$action" >> "$SYNC_LOG"
    fi
}

echo "Syncing changes..."
log_activity "syncing"

cd "$WORKSPACE"

if [ -n "$(git status --porcelain)" ]; then
    git add -A
    git commit -m "Auto-sync by $USER_ID" --author "$USER_ID <$USER_ID@steadystate.local>"
    echo "✓ Recorded your changes"
    log_activity "recorded"
fi

echo "Pulling changes from collaborators..."
if ! git pull --rebase canonical HEAD >/dev/null 2>&1; then
    echo "Warning: Pull failed (conflict?), checking..."
fi

if [ -f .git/rebase-merge/git-rebase-todo ] || [ -d .git/rebase-apply ]; then
    echo ""
    echo "⚠️  MERGE CONFLICTS DETECTED"
    echo "Please resolve conflicts and run 'git rebase --continue'"
    exit 1
fi

if git push canonical HEAD >/dev/null 2>&1; then
    echo "✓ Pushed to canonical repository"
fi

log_activity "synced"
echo ""
echo "✓ Sync complete!"
"#)
}
