# SteadyState CLI

The SteadyState CLI manages authentication and development sessions for the SteadyState platform.
It is a standalone binary built from the sources in this directory.

## Installation

```bash
# Clone the repository
git clone https://github.com/exactcomputing/steadystate.git
cd steadystate/cli

# Build with Cargo
cargo install --path .
```

Alternatively, run the CLI directly with `cargo run -- <command>`.

## Commands

| Command | Description |
| --- | --- |
| `steadystate login [--provider=github] [--token ...]` | Start the OAuth device flow and store the resulting session. GitLab uses a PAT: `--token`, `GITLAB_TOKEN`, or hidden prompt (`read_user` scope). |
| `steadystate whoami` | Show the currently authenticated user. Add `--json` for machine-readable output. |
| `steadystate refresh` | Force-refresh the JWT using the stored refresh token. |
| `steadystate logout` | Revoke the refresh token (if possible) and clear local session files. |
| `steadystate up <repo> --env=<ENV> --mode=<MODE> [--provider=<PROVIDER>]` | Create a remote development session for the given repository URL. Add `--json` for structured output. |
| `steadystate --version` or `-v` | Print the CLI version. |

### `up` flags

- `--env`: required. `noenv` (minimal tools), `python` (auto-detected version + uv), `flake` (repo's `flake.nix`), `tproject` (tlang project: `t update` then `nix develop`), `auto` (detect `tproject.toml` > `flake.nix` > `legacy-nix`), `legacy-nix`, `legacy-nix[filename]`.
- `--mode`: required. `collab` (isolated worktrees + merge) or `pair` (shared tmux terminal).
- `--provider`: optional. `local` (default) or `hetzner` (provisions a Hetzner Cloud server; backend needs `HCLOUD_TOKEN`).
- `--ttl`: optional lifetime (`12h`, `90m`, `2d`, …). Clamped to the server max; default 48h. Expired sessions are reaped automatically.
- `--allow`: comma-separated GitHub usernames allowed to join (default: repo collaborators). `--public`: anyone with the link can connect.

```bash
steadystate up --env=auto --mode=collab https://github.com/user/repo
steadystate up --env=tproject --mode=collab --provider=hetzner https://github.com/user/repo
```

## Environment Variables

- `STEADYSTATE_BACKEND` — overrides the API base URL.
  - Defaults to `http://localhost:8080`.
  - Point it at your server, e.g. `STEADYSTATE_BACKEND=http://your-server:8080` (plain HTTP; use an SSH tunnel or TLS proxy on untrusted networks).
- `RUST_LOG` — controls logging (e.g. `RUST_LOG=info` or `RUST_LOG=steadystate=debug`). When set to `debug`, the CLI emits a warning because logs may contain sensitive tokens.
- `STEADYSTATE_CONFIG_DIR` — optional override for the configuration directory (used mainly for testing).

## Troubleshooting

- **Backend unreachable**: Ensure the backend is running and confirm `STEADYSTATE_BACKEND` points to the correct URL.
- **Refresh token expired**: Run `steadystate login` to start a new session.
- **Permission denied writing session file**: The CLI attempts to enforce `0600` permissions. On unusual filesystems manually adjust permissions and retry.
- **Debug logs leaking tokens**: Avoid `RUST_LOG=debug` in production environments; tokens can appear in logs.

For more detailed walkthroughs, see the top-level repository README.

## License
Copyright (C) 2025 The Exact Computing Company

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 3,
as published by the Free Software Foundation.


