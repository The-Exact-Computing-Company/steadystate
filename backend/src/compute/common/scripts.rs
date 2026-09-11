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
LOG_FILE="$REPO_ROOT/setup-$USER_ID.log"
export ACTIVITY_LOG
export SYNC_LOG
export SESSION_ROOT="$REPO_ROOT"
export SESSION_ID="{{session_id}}"
export REPO_NAME="{{repo_name}}"
export STEADYSTATE_USERNAME="$USER_ID"

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

# ============================================================================
# PROGRESS DISPLAY HELPERS
# ============================================================================

# Clear current line and print message
print_status() {
    printf "\r\033[K%s" "$1"
}

print_done() {
    printf "\r\033[K✅ %s\n" "$1"
}

print_progress() {
    printf "\r\033[K⏳ %s" "$1"
}

print_error() {
    printf "\r\033[K❌ %s\n" "$1"
}

# ============================================================================
# WORKSPACE SETUP (with suppressed output)
# ============================================================================

WORKTREE="$REPO_ROOT/worktrees/$USER_ID"

if [ ! -d "$WORKTREE" ]; then
    print_progress "Cloning repository..."
    
    mkdir -p "$REPO_ROOT/worktrees"
    
    # Clone with suppressed output, log errors
    if ! git clone --quiet --branch {{branch_name}} "$REPO_ROOT/canonical" "$WORKTREE" >> "$LOG_FILE" 2>&1; then
        print_error "Failed to clone repository"
        echo "See $LOG_FILE for details"
        exit 1
    fi
    
    cd "$WORKTREE"
    git remote rename origin canonical >> "$LOG_FILE" 2>&1
    git config user.name "$USER_ID"
    git config user.email "$USER_ID@steadystate.local"

    # Initialize metadata for sync
    mkdir -p .worktree
    HEAD_COMMIT=$(git rev-parse HEAD)
    echo "{\"session_branch\": \"{{branch_name}}\", \"last_synced_commit\": \"$HEAD_COMMIT\"}" > .worktree/steadystate.json
    
    print_done "Repository cloned"
fi

export HOME="$WORKTREE"
export USER_WORKSPACE="$WORKTREE"
export CANONICAL_REPO="$REPO_ROOT/canonical"

cd "$WORKTREE" || exit 1

# ============================================================================
# ENVIRONMENT ACTIVATION (with suppressed output)
# ============================================================================

run_in_env() {
    # This function runs a command inside the nix environment
    # Used after environment is built
    case "{{environment}}" in
        noenv|python)
            nix develop "{{flake_path}}" --command "$@"
            ;;
        tproject|auto)
            # tlang project: flake.nix was regenerated via `t update` at provision time.
            # Re-run `t update` defensively (cheap if up to date), then enter dev shell.
            if [ -f "$WORKTREE/tproject.toml" ]; then
                (cd "$WORKTREE" && (t update || nix shell --accept-flake-config github:b-rodrigues/tlang -c t update)) >/dev/null 2>&1 || true
            fi
            if [ -f "$WORKTREE/flake.nix" ]; then
                nix develop "$WORKTREE" --command "$@"
            else
                "$@"
            fi
            ;;
        flake)
            if [ -f "$WORKTREE/flake.nix" ]; then
                nix develop "$WORKTREE" --command "$@"
            else
                "$@"
            fi
            ;;
        legacy-nix)
            if [ -f "$WORKTREE/shell.nix" ]; then
                nix-shell "$WORKTREE/shell.nix" --command "$*"
            elif [ -f "$WORKTREE/default.nix" ]; then
                nix-shell "$WORKTREE/default.nix" --command "$*"
            else
                "$@"
            fi
            ;;
        *)
            "$@"
            ;;
    esac
}

# Build environment if needed (suppress output)
case "{{environment}}" in
    tproject|auto)
        print_progress "Setting up tlang environment (t update)..."
        if [ -f "$WORKTREE/tproject.toml" ]; then
            if ! (cd "$WORKTREE" && (t update || nix shell --accept-flake-config github:b-rodrigues/tlang -c t update)) >> "$LOG_FILE" 2>&1; then
                print_error "Failed to run t update"
                echo "See $LOG_FILE for details"
                exit 1
            fi
        fi
        if [ -f "$WORKTREE/flake.nix" ]; then
            print_progress "Building environment..."
            if ! nix develop "$WORKTREE" --command true >> "$LOG_FILE" 2>&1; then
                print_error "Failed to build environment"
                echo "See $LOG_FILE for details"
                exit 1
            fi
            print_done "Environment ready"
        fi
        ;;
    noenv|python)
        print_progress "Building environment..."
        
        # Build the environment silently, capturing output
        if ! nix develop "{{flake_path}}" --command true >> "$LOG_FILE" 2>&1; then
            print_error "Failed to build environment"
            echo "See $LOG_FILE for details"
            echo ""
            echo "You can try manually with: nix develop {{flake_path}}"
            exit 1
        fi
        
        print_done "Environment ready"
        ;;
    flake)
        if [ -f "$WORKTREE/flake.nix" ]; then
            print_progress "Building environment..."
            
            if ! nix develop "$WORKTREE" --command true >> "$LOG_FILE" 2>&1; then
                print_error "Failed to build environment"
                echo "See $LOG_FILE for details"
                exit 1
            fi
            
            print_done "Environment ready"
        fi
        ;;
    legacy-nix)
        if [ -f "$WORKTREE/shell.nix" ] || [ -f "$WORKTREE/default.nix" ]; then
            print_progress "Building environment..."
            
            NIX_FILE="$WORKTREE/shell.nix"
            [ -f "$NIX_FILE" ] || NIX_FILE="$WORKTREE/default.nix"
            
            if ! nix-shell "$NIX_FILE" --command true >> "$LOG_FILE" 2>&1; then
                print_error "Failed to build environment"
                echo "See $LOG_FILE for details"
                exit 1
            fi
            
            print_done "Environment ready"
        fi
        ;;
esac

echo ""

# ============================================================================
# LAUNCH DASHBOARD OR COMMAND
# ============================================================================

if [ -n "$SSH_ORIGINAL_COMMAND" ]; then
    # User ran a specific command (e.g., ssh user@host "some command")
    run_in_env bash -c "$SSH_ORIGINAL_COMMAND"
else
    # Interactive session - launch dashboard
    run_in_env steadystate dash
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

pub fn pair_wrapper_script() -> ScriptTemplate {
    ScriptTemplate::new(r#"#!/usr/bin/env bash
# Pair mode wrapper - attaches all users to shared tmux session

set -e

SESSION_ROOT="{{session_root}}"
SESSION_ID="{{session_id}}"
REPO_PATH="$SESSION_ROOT/repo"
TMUX_SESSION="pair-${SESSION_ID:0:8}"  # Use first 8 chars of session ID
ENVIRONMENT="{{environment}}"
FLAKE_PATH="{{flake_path}}"

# Log activity
echo "$(date -Iseconds) pair-connect user=$1" >> "$SESSION_ROOT/activity-log"

cd "$REPO_PATH" || exit 1

# Function to start/attach tmux with optional nix environment
start_tmux() {
    # -A: attach if exists, create if not
    # -s: session name
    exec tmux new-session -A -s "$TMUX_SESSION" "$@"
}

case "$ENVIRONMENT" in
    tproject|auto)
        # tlang project: ensure flake is fresh, then enter dev shell with shared tmux
        if [ -f "$REPO_PATH/tproject.toml" ]; then
            (cd "$REPO_PATH" && (t update || nix shell --accept-flake-config github:b-rodrigues/tlang -c t update)) >/dev/null 2>&1 || true
        fi
        if [ -f "$REPO_PATH/flake.nix" ]; then
            exec nix develop "$REPO_PATH" --command tmux new-session -A -s "$TMUX_SESSION"
        else
            exec nix develop "$FLAKE_PATH" --command tmux new-session -A -s "$TMUX_SESSION"
        fi
        ;;
    noenv|python)
        # Wrap tmux in nix develop
        exec nix develop "$FLAKE_PATH" --command tmux new-session -A -s "$TMUX_SESSION"
        ;;
    flake)
        exec nix develop "$REPO_PATH" --command tmux new-session -A -s "$TMUX_SESSION"
        ;;
    legacy-nix)
        if [ -f "$REPO_PATH/shell.nix" ]; then
            exec nix-shell "$REPO_PATH/shell.nix" --command "tmux new-session -A -s $TMUX_SESSION"
        else
            exec nix-shell "$REPO_PATH/default.nix" --command "tmux new-session -A -s $TMUX_SESSION"
        fi
        ;;
    *)
        # No environment, just tmux
        start_tmux
        ;;
esac
"#)
}
