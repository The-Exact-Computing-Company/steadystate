# SteadyState

This repository contains all components of **SteadyState**, a command-line and backend system for creating reproducible, collaborative computing environments on demand.

SteadyState is developed and maintained by **The Exact Computing Company**.

---

## Overview

SteadyState lets users start a fully configured, remote development environment directly from a Git repository:

```bash
steadystate up https://github.com/user/project
```

This command:

* Provisions a VM in Hetzner Cloud via SteadyState’s backend
* Clones the target repository
* Detects its environment definition (`flake.nix`, `default.nix`, `shell.nix`, `renv.lock`, `uv.lock`)
* Builds it automatically using Nix
* Installs and configures [Upterm](https://github.com/owenthereal/upterm) for collaborative SSH access

Users receive an SSH URL to join the environment — no manual setup, credentials, or Hetzner account required.

---

## Repository Structure

```
steadystate/
├── cli/            # Rust CLI (steadystate)
├── backend/        # Rust backend API
├── common/         # Shared Rust utilities and types
├── flake.nix       # Nix flake for build and development environments
└── README.md
```

* **CLI (`steadystate`)** — user-facing tool for login, launching sessions, and listing active environments
* **Backend** — manages authentication, environment lifecycle, and resource provisioning
* **Common** — shared types, authentication utilities, and network code

---

## Design Goals

### 1. Reproducibility

Every environment is defined declaratively via Nix, ensuring that the same repository always produces the same runtime configuration — from Python and R packages to compilers and LaTeX.

### 2. Collaboration

Real-time, multi-user SSH sessions (via Upterm) enable seamless pair programming and debugging across editors (VS Code, Emacs, Neovim).

### 3. Simplicity

The system follows a Unix philosophy:

* One CLI, one backend, minimal dependencies
* No browser editors, no containers unless explicitly declared
* Everything is transparent and scriptable

### 4. Ephemerality by Default

Each environment is temporary by default. When it stops, all state is discarded — ensuring reproducibility, security, and no hidden drift.

---

## Development

### Prerequisites

* **Nix** (with flakes enabled)
* **Cargo** (optional, included in `nix develop`)
* **Rust toolchain** — automatically provided by the flake

### Setup

```bash
git clone https://github.com/exactcomputing/steadystate.git
cd steadystate
nix develop
```

### Build CLI

```bash
cd cli
cargo build
```

### Run Backend (placeholder)

```bash
cd backend
cargo run
```

### Example Usage

```bash
steadystate login
steadystate up https://github.com/exactcomputing/example-project
```

---

## License

**GNU General Public License v3.0**
© The Exact Computing Company
