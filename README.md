# SteadyState

**SteadyState** is a real-time collaboration tool for codebases. It hosts
ephemeral, reproducible development sessions directly from Git repositories and
uses T through Nix to build the correct environment from the repository's
`tproject.toml`. It consists of two main components:

* **SteadyState CLI** — a Rust-based command-line client used to authenticate,
  launch, and manage sessions.
* **SteadyState Backend** — a Rust/Axum service that handles authentication,
  environment orchestration, and session lifecycle.

The system provides a fast, minimal, transparent way to enter fully configured
collaborative development environments with zero manual setup.

---

## What SteadyState Provides

### 1. Collaborative Access

Each session exposes a multi-user SSH endpoint through an embedded collaboration
layer (using `tmux`). This allows:

* Pair programming
* Live debugging
* Working from any editor (VS Code, Neovim, Emacs, etc.)

Environments ship with [ne](https://github.com/vigna/ne/), the nice editor, for
users who want a minimal in-terminal editor without needing an SSH-aware GUI.

### 2. Reproducible T Environments

SteadyState builds development environments from the repository's
`tproject.toml` using T and Nix:

* `t update` regenerates the Nix flake from the T project definition.
* The session enters the resulting `nix develop` environment.
* `[t].min_version` is checked before entering the shell.

These environments run remotely and are defined declaratively for consistent,
deterministic behavior.

### 3. Ephemeral, On-Demand Sessions

Users can request a fresh environment at any time.
Each session:

* Runs in the cloud (initial target: Hetzner)
* Is short-lived by default
* Automatically cleans up after use
* Provides a complete dev environment without any local dependencies

### 4. Authentication System

The backend implements OAuth Device Flow authentication (GitHub),
PAT login (GitLab), and browser-based OIDC login (enterprise SSO).
The architecture is designed to support:

* GitHub (MVP)
* GitLab (PAT)
* Enterprise identity providers (generic OIDC)

Authentication uses short-lived JWTs with long-lived refresh tokens stored securely by the CLI.

---

## Repository Structure

```
steadystate/
├── cli/            # Rust CLI: authentication, session management
├── backend/        # Rust backend: auth providers, session orchestration
├── common/         # Shared types and utilities (planned)
└── flake.nix       # Reproducible development environment for all components
```

* The **CLI** and **Backend** are independent Rust crates.
* The **flake.nix** provides consistent dev and build tooling across the project.
* A shared crate (`common/`) will consolidate types, JWT logic, and error structures across components.

---

## Design Philosophy

### Minimal local state

Everything needed for development lives in the remote environment.

### Ephemeral by default

Every session starts clean and predictable.

### Transparent and scriptable

SteadyState is a *tool*, not a platform you must commit to.
Both CLI and backend expose simple interfaces that integrate with existing workflows.

### Reproducibility above all

T and Nix are used to define and build environments in a controlled,
deterministic way. SteadyState reads the repository's `tproject.toml`, runs
`t update`, and enters the resulting `nix develop` environment.

### Editor-agnostic collaboration

SSH is the backbone. Bring your own editor, or use `ne`.

### Collaboration Modes

SteadyState supports two distinct modes for collaboration:

#### 1. Pair Programming (`--mode=pair`)
*   **Powered by Tmux**: Creates a shared terminal session.
*   **Shared Terminal**: All users share the same terminal session and file system state.
*   **Ideal for**: Real-time pair programming, debugging, and teaching.

#### 2. Shared Workspace (`--mode=collab`)
*   **Shared Host, Isolated Worktrees**: All users connect to the same compute instance but work in their own isolated Git worktrees.
*   **Canonical Repository**: A central bare repository (`canonical`) acts as the synchronization point.
*   **Conflict-Free Sync Model**:
    *   **Session Branch Isolation**: Each session operates on a dedicated Git branch (`steadystate/collab/<session_id>`), isolating session work from the upstream `main` branch.
    *   **Y-CRDT Merge Engine**: `steadystate sync` uses a Yjs/Yrs-based CRDT merge engine to perform conflict-free 3-way merges (Base, Local, Canonical) for text files. This ensures that concurrent edits from multiple users are merged deterministically without manual conflict resolution.
    *   **Git Integration**: The merged result is committed to the session branch. Users can merge the session branch back to `main` via standard Pull Requests after the session.
*   **Ideal for**: Async collaboration, dividing work on the same feature, and avoiding "it works on my machine" issues.

---

## Components

### CLI

* Handles OAuth device flow login (`login`)
* Shows the authenticated identity (`whoami`)
* Refreshes and revokes tokens
* Creates development sessions (`up`)

### Backend

* Manages authentication via modular providers
* Issues and validates JWTs
* Creates and tracks ephemeral dev sessions
* Provides an API consumed by the CLI

---

## Roadmap

### Authentication

* [x] GitHub OAuth Device Flow
* [x] GitLab PAT login (`POST /auth/token`, `GITLAB_URL` configurable)
* [x] Enterprise SSO (generic OIDC: `POST /auth/oidc/start|complete`, presets for google/entra/okta)

### Sessions

* [x] Local orchestration (`local` provider: pair + collab over ephemeral SSH)
* [x] Hetzner Cloud orchestration (MVP: API-provisioned servers, SSH transport, collab setup reuse — not yet live-tested)
* [x] 48h default expiry with background reaper + per-user live-session cap
* [ ] Optional persistent volumes
* [ ] Resource telemetry and usage reporting
* [ ] Web dashboard

### Environment Handling

* [x] T projects (`tproject.toml` → `t update` → `nix develop`, with `[t].min_version` check)
* [ ] Optional compatibility layers:

  * Pure Nix flakes
  * Python auto-detection (`uv.lock` / `pyproject.toml` / `requirements.txt`)
  * `renv.lock`
  * `environment.yml`
* [ ] Prebuilt environment cache

---

## Contributing

### Requirements

Nix.

### How to

PRs welcome, but make sure unit tests pass (or add required unit tests if you add features).

## License

**CLI:** GNU General Public License v3.0
**Backend:** GNU Affero General Public License v3.0

© 2025 The Exact Computing Company
