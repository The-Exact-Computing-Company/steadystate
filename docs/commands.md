# NAME

**steadystate commands** - CLI command reference

# AUTHENTICATION COMMANDS

## steadystate login

Authenticate with GitHub using the device flow.

```
steadystate login
```

Opens a device authorization flow. You will be prompted to visit github.com/login/device and enter a code. No browser redirect is required, making this suitable for headless servers and SSH sessions.

For GitLab (no device flow exists), authenticate with a Personal Access Token:

```
steadystate login --provider=gitlab
steadystate login --provider=gitlab --token glpat-xxxx
GITLAB_TOKEN=glpat-xxxx steadystate login --provider=gitlab
```

Without `--token`/`GITLAB_TOKEN`, the CLI prompts for the token with hidden
input. The token needs `read_user` scope (`read_api` additionally for
collaborator lookup in sessions). Which GitLab instance to talk to is a
backend setting (`GITLAB_URL`, default `https://gitlab.com`).

For enterprise SSO (no device flow either), authenticate with OIDC:

```
steadystate login --provider=oidc
steadystate login --provider=oidc --no-browser
```

This opens the IdP login in a browser and captures the redirect on
localhost. With `--no-browser` (headless/SSH sessions), paste the full
redirect URL when prompted instead. The IdP must be configured on the
backend (`OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`); the IdP
side must allowlist `http://127.0.0.1:*` redirect URIs (any port — the CLI
binds an ephemeral one per login).

**Exit Status:**
- 0 on success
- 1 on authentication failure or timeout

## steadystate logout

Remove local authentication tokens.

```
steadystate logout
```

Clears the stored JWT and refresh token. Does not revoke tokens on the server.

## steadystate whoami

Display the currently authenticated user.

```
steadystate whoami
```

**Output:** GitHub username of the authenticated user, or an error if not logged in.

# SESSION COMMANDS

## steadystate up

Create a new collaboration session.

```
steadystate up [OPTIONS] <REPOSITORY>
```

**Arguments:**

`<REPOSITORY>`
:   GitHub repository URL (https or git@)

**Options:**

`--env=<ENV>` (required)
:   Session environment. One of `noenv`, `python`, `flake`, `tproject`, `auto`, `legacy-nix`, `legacy-nix[filename]`. `auto` detects `tproject.toml` first, then `flake.nix`, then `legacy-nix`. `tproject` ensures Nix, runs `t update` to regenerate `flake.nix`, warns if `t` predates `[t].min_version`, then enters `nix develop`.

`--mode=<MODE>` (required)
:   Session mode. `collab` for collaboration mode (isolated worktrees + merge), `pair` for shared-terminal pair programming.

`--provider=<PROVIDER>`
:   Compute provider. `local` (default, runs on the backend host) or `hetzner` (provisions a Hetzner Cloud server; requires `HCLOUD_TOKEN` on the backend).

`--ttl=<DURATION>`
:   Session lifetime, e.g. `12h`, `90m`, `2d`, `3600` (suffixes `s/m/h/d/w`, plain number = seconds). Clamped to the server max; defaults to the server default (48h). Expired sessions are terminated automatically.

`--forge-token=<PAT>`
:   Forge PAT attached to the session for collaborator lookup and token-injected clone. Required for SSO logins (which carry no forge token); falls back to `FORGE_TOKEN` env. The forge (github vs gitlab) is detected from the repository URL.

`--allow=<USERS>`
:   Comma-separated list of GitHub usernames allowed to join. Default: all repository collaborators

**Examples:**

```
steadystate up --env=auto --mode=collab https://github.com/user/repo
steadystate up --env=tproject --mode=collab --provider=hetzner https://github.com/user/repo
steadystate up --env=noenv --mode=pair --allow=alice,bob https://github.com/user/repo
```

## steadystate list

List your sessions.

```
steadystate list
steadystate list --json
```

Shows ID, state, provider, expiry (`in 31h`, `expired`, `never`), idle
time (`now`, `5m`, `2h`, `—` when untracked), and repository. `--json`
dumps the raw array. Only your own sessions appear. Sessions idle past
the server idle timeout are terminated automatically with a
`terminated: idle for ...` message.

## steadystate down

Terminate a session by ID (or magic link).

```
steadystate down abc123
steadystate down "steadystate://collab/abc123?ssh=...&host_key=..."
```

Only the session creator can terminate it (`403` otherwise). Unknown IDs
report "already gone?" instead of failing.

## steadystate join

Join an existing collaboration session.

```
steadystate join "<MAGIC_LINK>"
```

**Arguments:**

`<MAGIC_LINK>`
:   The magic link provided by the session host. Must be quoted to prevent shell interpretation.

The magic link has the format:
```
steadystate://collab/<session_id>?ssh=<ssh_url>&host_key=<public_key>
```

**Example:**

```
steadystate join "steadystate://collab/abc123?ssh=ssh%3A%2F%2Fsteadystate%40192.168.1.100%3A2847&host_key=ssh-ed25519%20AAAA..."
```

## steadystate dashboard

Open the session dashboard without joining.

```
steadystate dashboard "<MAGIC_LINK>"
steadystate dash "<MAGIC_LINK>"
```

Opens a TUI dashboard showing connected users and sync activity. Use this to monitor a session without creating a worktree.

**Aliases:** `dash`

# COLLABORATION COMMANDS

## steadystate sync

Synchronize changes with collaborators.

```
steadystate sync
```

This command:

1. Fetches changes from other collaborators
2. Performs a 3-way merge (base, local, remote)
3. Commits the merged result
4. Pushes to the session repository
5. Updates local worktree

Run this command frequently to stay in sync with collaborators.

**Exit Status:**
- 0 on success
- 1 on merge conflict or push failure (run sync again)

## steadystate publish

Push session changes to GitHub.

```
steadystate publish
```

Pushes the session branch to the original GitHub repository. After publishing, you can create a Pull Request on GitHub to merge changes into the main branch.

## steadystate status

Show local changes.

```
steadystate status
```

Displays files that have been modified, added, or deleted in your worktree compared to the last sync point.

**Output format:**
```
On branch steadystate/abc123
Changes not staged for commit:
        modified:   file.txt
        deleted:    old.txt

Untracked files:
        new.txt
```

## steadystate diff

Show detailed diff of changes.

```
steadystate diff
```

Displays a unified diff of all changes in your worktree. Output is similar to `git diff`.

## steadystate watch

Display the session dashboard (inside session).

```
steadystate watch
```

Opens an interactive TUI dashboard showing:
- Session information
- Connected users
- Recent sync activity with file changes

**Keyboard controls:**
- `s` - Run sync
- `p` - Run publish
- `d` - Show diff
- `c` - Run credit (git blame)
- `q` or `Esc` - Exit

## steadystate credit

Show line-by-line credit (git blame).

```
steadystate credit <FILE>
```

Displays `git blame` output for the specified file, piped to `less` for scrolling. This allows you to see exactly who modified which line.

**Note:** Sync commits are authored by the user who ran the sync, ensuring accurate credit.


# ENVIRONMENT VARIABLES

See **CONFIGURATION(5)** for environment variables that affect command behavior.

# SEE ALSO

**steadystate**(1), **git**(1)
