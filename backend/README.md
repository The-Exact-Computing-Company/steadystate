# SteadyState Backend

> Authentication and session orchestration service for reproducible cloud
> development environments.

---

## Overview

The **SteadyState Backend** powers the [SteadyState
CLI](https://github.com/steadystate-dev/steadystate) — a tool that lets
developers spin up **reproducible, on-demand development environments** defined
by Nix.

It provides secure authentication via OAuth (starting with **GitHub**, more
coming later) and manages **ephemeral SSH-accessible sessions** in the cloud.

---

## Features

* **GitHub OAuth (Device Flow)** authentication
* **Modular authentication provider architecture** (future: GitLab, Orchid, etc.)
* **JWT + Refresh token** issuing and verification
* **Axum-based REST API**, written in Rust
* **Nix-based dev environment** for reproducible builds
* **Session management skeleton** ready for Hetzner or other cloud backends

---

## Architecture

| Component       | Purpose                                                           |
| --------------- | ----------------------------------------------------------------- |
| `/auth/device`  | Start the OAuth device flow (returns verification URL + code)     |
| `/auth/poll`    | Poll until the user authorizes the device                         |
| `/auth/refresh` | Exchange a refresh token for a new JWT                            |
| `/auth/me`      | Return current user identity from JWT                             |
| `/sessions`     | (WIP) Create reproducible cloud dev environments                  |
| `providers/`    | Modular auth providers (`github.rs`, `gitlab.rs`, `orchid.rs`, …) |
| `storage.rs`    | In-memory token registry (can later use Postgres or Redis)        |
| `jwt.rs`        | JWT encoding and validation                                       |
| `main.rs`       | Axum router and startup logic                                     |

---

## Quick Start

### 1. Clone and enter

```bash
git clone https://github.com/steadystate-dev/backend.git
cd backend
```

### 2. Run in Nix shell

```bash
nix develop
```

### 3. Start the server

```bash
cargo run
```

By default, the API listens on `http://localhost:8080`.

---

## Testing GitHub OAuth (manual)

Start the server, then run:

```bash
curl -X POST http://localhost:8080/auth/device?provider=github
```

You’ll receive a response like:

```json
{
  "device_code": "abcd123",
  "user_code": "ABCD-EFGH",
  "verification_uri": "https://github.com/login/device",
  "interval": 5
}
```

Open the `verification_uri`, enter the `user_code`, and authorize the app.
Then poll:

```bash
curl -X POST http://localhost:8080/auth/poll \
  -H "Content-Type: application/json" \
  -d '{"device_code": "abcd123"}'
```

Once authorized:

```json
{
  "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "f2ec8b73-9dd8-4d23-bb3a-6dc0fa7a6c1a",
  "login": "your-github-username"
}
```

You can validate your token:

```bash
curl -H "Authorization: Bearer <jwt>" http://localhost:8080/auth/me
```

---

## Development

### Requirements

* Nix

### Environment variables

| Name                   | Description                         |
| ---------------------- | ----------------------------------- |
| `GITHUB_CLIENT_ID`     | OAuth client ID for your GitHub app |
| `GITHUB_CLIENT_SECRET` | OAuth client secret                 |
| `JWT_SECRET`           | Symmetric signing key for JWTs      |
| `PORT`                 | Optional, defaults to `8080`        |

### Example `.env` file

```env
GITHUB_CLIENT_ID=gho_xxxxxxx
GITHUB_CLIENT_SECRET=ghs_xxxxxxx
JWT_SECRET=devsecret
PORT=8080
```

Then:

```bash
source .env
cargo run
```

---

## Extending Authentication

The authentication system is **provider-agnostic**.
To add a new provider (e.g., GitLab or Orchid):

1. Create a file in `src/providers/<provider>.rs`
2. Implement the `AuthProvider` trait
3. Register it in `main.rs` under the `/auth/device` dispatcher

Example:

```rust
pub trait AuthProvider {
    fn name(&self) -> &'static str;
    async fn start_device_flow(&self) -> Result<DeviceFlowStart>;
    async fn poll_device_flow(&self, device_code: &str) -> Result<UserIdentity>;
}
```

This allows SteadyState to support new identity providers without changing the CLI.

---

## Roadmap

* [x] GitHub OAuth device flow
* [x] JWT issuance and verification
* [x] `--noenv` and `ne` editor integration for quick pair-programming
* [ ] Persistent refresh token storage (SQLite or Postgres)
* [ ] `/sessions` endpoint (Hetzner VM orchestration)
* [ ] Web dashboard for session management

---

## License

Copyright (C) 2025 The Exact Computing Company

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License version 3,
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.


