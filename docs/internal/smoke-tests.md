# NAME

**steadystate smoke tests** - live verification checklist (things unit tests cannot cover)

# DESCRIPTION

Unit tests (`cargo test --workspace`) cover logic with mocks. Everything
below needs real infrastructure: a VM, a cloud account, a forge account,
or an identity provider. Work through the group that matches what changed;
do the full list before a release.

Conventions used below:

- `BACKEND` = backend base URL, e.g. `http://devbox:8080`
- `REPO` = a small test repository you control on the relevant forge
- Each item states its prerequisites up front; skip groups whose
  prerequisites you don't have

# 0. PREREQUISITES

- [ ] Backend builds from a clean checkout: `nix build .#cli .#backend`
- [ ] `nix flake show` works on the root flake
- [ ] `cargo test --workspace` is green before starting

# 1. LOCAL SESSIONS (no cloud account needed)

- [ ] **Collab round-trip.** `steadystate up --env=tproject --mode=collab REPO`,
      share the magic link, `join` from a second machine/user, both edit,
      both `sync`, `publish`, open the PR. Expect: additive merge, one
      session branch, dashboard shows both users.
- [ ] **Pair round-trip.** `up --env=tproject --mode=pair REPO`, second user
      joins via the magic link, both land in the same `tmux` session
      (type in one terminal, appears in the other), `Ctrl-b d` detaches
      without killing the session.
- [ ] **Restart rehydration.** With sessions live, restart
      `steadystate-backend`. Expect: `list` still shows them (SQLite),
      health reports `Unknown` (live handles don't survive), new sessions
      still provision.

# 2. TPROJECT ENVIRONMENTS (needs a tlang project repo)

- [ ] **T project.** `up --env=tproject --mode=collab` on a repo containing
      `tproject.toml`. Expect: backend runs `t update`, session enters
      `nix develop`, `t --version` works inside.
- [ ] **Pair mode.** Same with `--mode=pair`.
- [ ] **min_version warning.** Point a session at a project whose
      `[t].min_version` is newer than the installed `t`. Expect: session
      still provisions, backend log warns about the version skew.

# 3. HETZNER (needs HCLOUD_TOKEN + SSH key)

Set on the backend: `HCLOUD_TOKEN`, `HCLOUD_SSH_KEY`,
`HCLOUD_SSH_IDENTITY`. Check `hcloud server list` between steps.

- [ ] **Collab provision.** `up --provider=hetzner --env=tproject --mode=collab REPO`.
      Expect: server `steady-<id>` appears, reaches `Running`, magic link
      connects, `sync`/`publish` work, `down` deletes the server.
- [ ] **Pair provision.** Same with `--mode=pair`. Expect:
      `steadystate://pair/...` link, shared `tmux`, `nix develop` active
      inside tmux for `tproject` repos.
- [ ] **T project on a VM.** `--env=tproject` on a repo with `tproject.toml`.
      Expect: `t update` ran, `nix develop` is active, `t --version` works.
- [ ] **Orphan cleanup.** Force a setup failure (e.g. point at a private
      repo the token cannot read). Expect: session goes `Failed`, the
      server is deleted anyway (no `steady-*` leftovers in hcloud).
- [ ] **Health + terminate.** `watch` shows the session; `down` from the
      creator removes the server; `down` from another user gets `403`.

# 4. AUTH

- [ ] **GitHub device flow.** Fresh `STEADYSTATE_CONFIG_DIR`,
      `steadystate login`, complete in browser. Expect: `whoami` shows the
      login, refresh token in keyring, `up` works without `--forge-token`.
- [ ] **GitLab PAT (gitlab.com).** `login --provider=gitlab` with each of:
      `--token`, `GITLAB_TOKEN`, interactive prompt. Expect: `whoami`
      shows the GitLab username with `(via gitlab)`.
- [ ] **GitLab session.** With a GitLab login, `up --env=tproject --mode=collab`
      on a GitLab repo. Expect: clone works, collaborators auto-added from
      project members, SSH keys resolve, `publish` pushes the session branch.
- [ ] **Self-managed GitLab.** Backend with `GITLAB_URL=https://git.example.com`,
      repeat PAT login + session. Expect: same as above against the instance.
- [ ] **OIDC live round-trip.** Backend with `OIDC_ISSUER` (+ client id/secret),
      IdP allowlists `http://127.0.0.1:*`. `login --provider=oidc`.
      Expect: browser flow completes, `whoami` shows `(via oidc)`.
- [ ] **OIDC --no-browser.** Same, with `--no-browser`, pasting the redirect
      URL. Expect: same result (covers headless/SSH laptops).
- [ ] **OIDC + forge bridge.** OIDC login, then `up --env=tproject` on a GitHub
      repo with `--forge-token <PAT>`. Expect: collaborator lookup + push work;
      without the flag they degrade gracefully (explicit `--allow` only).
- [ ] **Rate limits live.** Temporarily set `RATE_LIMIT_TOKEN_PER_MIN=2`,
      fire 3 bad PAT logins. Expect: `401, 401, 429` with JSON body and
      `Retry-After`. Restore defaults afterwards.
- [ ] **GET redaction live.** As creator, `GET /sessions/{id}` shows
      `magic_link`; as another logged-in user, same endpoint hides
      `magic_link`/`endpoint`/`host_public_key` but shows state.

# 5. EXPIRY AND CAPS (fast-forward with env overrides)

Set `STEADYSTATE_DEFAULT_SESSION_TTL_SECS=120`,
`STEADYSTATE_MAX_SESSION_TTL_SECS=300`,
`STEADYSTATE_MAX_SESSIONS_PER_USER=2` on a throwaway backend.

- [ ] **Default expiry.** `up --env=tproject` without `--ttl`. Expect:
      `expires_at` ≈ +120s in `list --json`; ~2 minutes later the reaper
      terminates it (backend log: `Reaper terminated 1 expired session(s)`).
- [ ] **Clamp.** `up --env=tproject --ttl=2d`. Expect: granted ≈ +300s, log
      notes the requested vs granted TTL.
- [ ] **Cap.** Create 2 sessions, third `up` fails. Expect: `429` with the
      "terminate one" message; `down` one, retry succeeds.
- [ ] **Legacy rows.** If you have a pre-expiry `steadystate.db`, start the
      backend with it. Expect: migration adds the column, old sessions load
      with no expiry and are never reaped.

# 6. REMOTE JOB-VM WALKTHROUGH (validates self-hosting.md)

- [ ] **Direct LAN.** Follow `self-hosting.md` §1–§7 verbatim on a fresh VM.
      Note every step that deviates; fix the doc, not your memory.
- [ ] **Tunnel variant.** Close everything but port 22, follow §8 option A
      for API + one session. Expect: login, up, join all work through tunnels.
- [ ] **Two-laptop collab.** Host on laptop A, join from laptop B via magic
      link, sync both ways.

# SEE ALSO

**steadystate-commands**(1) (`commands.md`), **steadystate-configuration**(1)
(`configuration.md`), **self-hosting**(7) (`self-hosting.md`)
