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
* **GitLab PAT login** authentication (`POST /auth/token`, `GITLAB_URL` configurable)
* **Modular authentication provider architecture** (GitHub device flow, GitLab PAT, OIDC browser flow)
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
| `/auth/token`   | PAT login for providers without a device flow (GitLab)            |
| `/auth/refresh` | Exchange a refresh token for a new JWT                            |
| `/auth/me`      | Return current user identity from JWT                             |
| `/sessions`     | Create/list/terminate reproducible dev environments (48h TTL, capped per user); `POST /sessions/{id}/extend` extends the lifetime (creator-only, clamped to max) |
| `providers/`    | Modular auth providers (`github.rs`, `gitlab.rs`, `orchid.rs`, …) |
| `storage.rs`    | SQLite persistence for sessions + refresh tokens                  |
| `rate_limit.rs` | Per-IP tiers on auth routes (5/30/120 per min, env-configurable)  |
| `reaper.rs`     | Background expiry enforcement for sessions                        |
| `jwt.rs`        | JWT encoding and validation                                       |
| `main.rs`       | Axum router and startup logic                                     |

Auth routes are rate-limited per client IP and answer `429` with a JSON
error + `Retry-After` header. `GET /sessions/{id}` returns full details
to the session creator and a redacted view (no endpoint/magic link/host
key) to other authenticated users; `DELETE` is creator-only.

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

## GitLab PAT login (manual)

GitLab has no OAuth device flow, so login uses a Personal Access Token
(`read_user` scope; add `read_api` for collaborator lookup):

```bash
curl -X POST http://localhost:8080/auth/token \
  -H "Content-Type: application/json" \
  -d '{"provider": "gitlab", "token": "glpat-xxxx"}'
```

Response shape matches a completed device poll (`jwt`, `refresh_token`, `login`).
For self-managed instances, set `GITLAB_URL` (e.g. `https://git.example.com`).

Sessions work the same afterwards: the CLI sends
`provider_config: {"gitlab": {...}}`, clones are token-injected with the
`oauth2` user, SSH keys come from `{base}/{user}.keys`, and collaborators
from the Projects members API.

---

## Development

### Requirements

* Nix

### Environment variables

| Name                   | Description                                                        |
| ---------------------- | ------------------------------------------------------------------ |
| `GITHUB_CLIENT_ID`     | OAuth client ID for your GitHub app                                |
| `GITHUB_CLIENT_SECRET` | OAuth client secret                                                |
| `GITLAB_URL`           | GitLab instance base URL for PAT login (default `https://gitlab.com`) |
| `JWT_SECRET`           | Symmetric signing key for JWTs                                     |
| `PORT`                 | Optional, defaults to `8080`                                       |
| `STEADYSTATE_PROVIDER` | Default compute provider (`local`); set to `hetzner` if configured |
| `STEADYSTATE_DB_PATH`  | SQLite file for sessions + refresh tokens (default `~/.steadystate/steadystate.db`) |
| `NOENV_FLAKE_PATH`     | Test-only path used by unit/integration tests                      |
| `TLANG_FLAKE_URL`      | Optional flake providing the `t` binary (default `github:b-rodrigues/tlang`) |
| `HCLOUD_TOKEN`         | Hetzner Cloud API token (enables the `hetzner` provider)           |
| `HCLOUD_SERVER_TYPE`   | Optional, defaults to `cx23`                                       |
| `HCLOUD_IMAGE`         | Optional, defaults to `ubuntu-24.04`                               |
| `HCLOUD_LOCATION`      | Optional, defaults to `nbg1`                                       |
| `HCLOUD_SSH_KEY`       | Optional name of an uploaded Hetzner SSH key                       |
| `HCLOUD_SSH_IDENTITY`  | Optional local path to the SSH private key for Hetzner hosts       |

### Sessions

```bash
# T-lang project (tproject.toml -> t update -> nix develop)
steadystate up --env=tproject --mode=collab https://github.com/user/repo

# Explicit provider (requires HCLOUD_TOKEN on the backend for hetzner)
steadystate up --provider=hetzner --env=tproject --mode=collab https://github.com/user/repo
```

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
To add a new provider:

1. Create a file in `src/auth/<provider>.rs`
2. Implement the `AuthProvider` trait (device flow) and/or a dedicated
   route + validation like GitLab PAT (`POST /auth/token`) or OIDC
   (`POST /auth/oidc/start|complete` in `src/auth/oidc.rs`)
3. Register its factory in `register_builtin_providers` (`src/auth/mod.rs`)

Not every provider fits the device flow (GitLab and OIDC don't have one),
so the trait is only one of three supported login shapes. Pick the shape
that matches the IdP rather than forcing the trait.

---

## Roadmap

* [x] GitHub OAuth device flow
* [x] GitLab PAT login + forge integration
* [x] OIDC enterprise SSO (browser + localhost callback)
* [x] JWT issuance and verification
* [x] SQLite persistence for sessions + refresh tokens
* [x] 48h session expiry with reaper + per-user caps
* [x] Local + Hetzner compute providers (pair + collab)
* [x] Creator-only terminate, GET redaction, auth rate limits
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


