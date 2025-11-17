# SteadyState

**SteadyState** is a set of free software tools for creating **reproducible**, **ephemeral**, and
**collaborative** development environments directly from Git repositories. It
consists of two main components:

* **SteadyState CLI** — a Rust-based command-line client used to authenticate,
  launch, and manage sessions.
* **SteadyState Backend** — a Rust/Axum service that handles authentication,
  environment orchestration, and session lifecycle.

The entire system is designed to provide a fast, minimal, transparent way to
enter fully configured cloud developer environments with zero manual setup.

---

## What SteadyState Provides

### 1. Reproducible Environments

SteadyState builds development environments from repository definitions such as:

* `flake.nix`
* `default.nix` / `shell.nix`
* (future) `requirements.txt`, `renv.lock`, `uv.lock`, etc.

These environments run remotely and are defined declaratively for consistent, deterministic behavior.

### 2. Ephemeral, On-Demand Sessions

Users can request a fresh environment at any time.
Each session:

* Runs in the cloud (initial target: Hetzner)
* Is short-lived by default
* Automatically cleans up after use
* Provides a complete dev environment without any local dependencies

### 3. Collaborative Access

Each session exposes a multi-user SSH endpoint through an embedded collaboration
layer (using [Upterm](https://upterm.dev/)). This allows:

* Pair programming
* Live debugging
* Working from any editor (VS Code, Neovim, Emacs, etc.)

Environments ship with [ne](https://github.com/vigna/ne/), the nice editor, for
users who want a minimal in-terminal editor without needing an SSH-aware GUI.

### 4. Authentication System

The backend implements OAuth Device Flow authentication.
The architecture is designed to support:

* GitHub (MVP)
* GitLab (future)
* Orchid (future)
* Enterprise identity providers (future)

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

Nix is used to define and build environments in a controlled, deterministic way.
For non-Nix users, `steadystate` will try to bootstrap the environment from
common lock files.

### Editor-agnostic collaboration

SSH is the backbone. Bring your own editor, or use `ne`.

---

## Components

### CLI

* Handles OAuth device flow login (`login`)
* Shows the authenticated identity (`whoami`)
* Refreshes and revokes tokens
* Creates development sessions (`up`)
* Supports a `--noenv` mode for fast, editor-only sessions

### Backend

* Manages authentication via modular providers
* Issues and validates JWTs
* Creates and tracks ephemeral dev sessions
* Provides an API consumed by the CLI

---

## Roadmap

### Authentication

* [x] GitHub OAuth Device Flow
* [ ] GitLab
* [ ] Orchid
* [ ] Enterprise SSO

### Sessions

* [ ] Hetzner Cloud orchestration
* [ ] Optional persistent volumes
* [ ] Resource telemetry and usage reporting
* [ ] Web dashboard

### Environment Handling

* [x] Pure Nix environments
* [ ] Lightweight compatibility layers:

  * `requirements.txt`
  * `uv.lock`
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

