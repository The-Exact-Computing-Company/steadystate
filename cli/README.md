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
| `steadystate login` | Start the OAuth device flow and store the resulting session. |
| `steadystate whoami` | Show the currently authenticated user. Add `--json` for machine-readable output. |
| `steadystate refresh` | Force-refresh the JWT using the stored refresh token. |
| `steadystate logout` | Revoke the refresh token (if possible) and clear local session files. |
| `steadystate up <repo>` | Create a remote development session for the given repository URL. Add `--json` for structured output. |
| `steadystate --version` or `-v` | Print the CLI version. |

## Environment Variables

- `STEADYSTATE_BACKEND` — overrides the API base URL.
  - Defaults to `https://localhost:8080` for safety.
  - For local development against a non-TLS backend, export `STEADYSTATE_BACKEND=http://localhost:8080`.
- `RUST_LOG` — controls logging (e.g. `RUST_LOG=info` or `RUST_LOG=steadystate=debug`). When set to `debug`, the CLI emits a warning because logs may contain sensitive tokens.
- `STEADYSTATE_CONFIG_DIR` — optional override for the configuration directory (used mainly for testing).

## Troubleshooting

- **Backend unreachable**: Ensure the backend is running and confirm `STEADYSTATE_BACKEND` points to the correct URL.
- **Refresh token expired**: Run `steadystate login` to start a new session.
- **Permission denied writing session file**: The CLI attempts to enforce `0600` permissions. On unusual filesystems manually adjust permissions and retry.
- **Debug logs leaking tokens**: Avoid `RUST_LOG=debug` in production environments; tokens can appear in logs.

For more detailed walkthroughs, see the top-level repository README.
