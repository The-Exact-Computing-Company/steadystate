# Architecture

This document provides a high-level overview of the SteadyState monorepo architecture.

## Monorepo Structure

The repository is organized as a monorepo containing three primary components:

- **`backend/`**: A Rust-based backend service responsible for authentication, session management, and orchestration of development environments.
- **`cli/`**: A command-line interface (CLI) application, also written in Rust, that provides a user-facing interface for interacting with the backend.
- **`packages/`**: A directory containing shared crates and libraries used by other components in the monorepo.
  - **`common/`**: A shared crate with common data structures and utilities used by both the `backend` and `cli`.

## Backend Architecture

The `backend` is an Axum-based REST API service written in Rust. It handles user authentication, session orchestration, and compute resource management.

### Key Modules and Functions

#### `main.rs`
The entry point of the application. It sets up the Axum router, initializes the application state, applies middleware (CORS, tracing), and starts the HTTP server.

- **`main()`**: The asynchronous main function that initializes the `AppState` and starts the web server.

#### `state.rs`
Defines the `AppState`, which manages shared resources like the authentication provider registry and token storage. This state is shared across all request handlers.

- **`Config::from_env()`**: Creates a `Config` struct by reading settings from environment variables.
- **`AppState::try_new()`**: Asynchronously initializes the application state, including the HTTP client, JWT keys, compute providers, and auth provider factories.
- **`AppState::register_provider_factory()`**: Registers a new authentication provider factory, making it available for use.
- **`AppState::get_or_create_provider()`**: Retrieves a cached authentication provider or creates a new one using a registered factory. This allows for lazy initialization of providers.
- **`AppState::issue_refresh_token()`**: Generates, stores, and returns a new refresh token for a user.
- **`now()`**: A private helper function that returns the current Unix timestamp in seconds.

#### `jwt.rs`
Handles the creation (encoding) and validation of JSON Web Tokens (JWTs), which are used to secure the API endpoints.

- **`JwtKeys::new()`**: Constructs a new `JwtKeys` instance with a signing key, issuer, and token time-to-live (TTL).
- **`JwtKeys::sign()`**: Creates and signs a new JWT for a given user and provider.
- **`JwtKeys::verify()`**: Validates a JWT's signature and standard claims (like expiry and issuer).
- **`CustomClaims::from_request_parts()`**: An Axum extractor that validates the `Authorization: Bearer` token from request headers and extracts the custom claims.

#### `routes/auth.rs`
Defines the authentication-related API endpoints.

- **`router()`**: Creates and returns the Axum `Router` for all authentication routes (`/device`, `/poll`, `/refresh`, `/revoke`, `/me`).
- **`device_start()`**: The handler for `POST /auth/device`. It initiates the OAuth device flow for a specified provider.
- **`poll()`**: The handler for `POST /auth/poll`. It polls the backend to check if the user has completed the device flow authorization.
- **`refresh()`**: The handler for `POST /auth/refresh`. It exchanges a valid refresh token for a new JWT.
- **`revoke()`**: The handler for `POST /auth/revoke`. It revokes a refresh token, invalidating it for future use.
- **`me()`**: The handler for `GET /auth/me`. It returns the identity of the currently authenticated user based on their JWT.
- **`internal()`**: A private helper function that converts a displayable error into a `(StatusCode, String)` tuple for an HTTP 500 Internal Server Error response.

#### `routes/sessions.rs`
Defines endpoints for managing development sessions.

- **`router()`**: Creates and returns the Axum `Router` for all session-related routes (`/`, `/{id}`).
- **`create_session()`**: The handler for `POST /sessions`. It creates a new session record, returns an `ACCEPTED` status (including a `magic_link` for easy connection), and spawns a background task to provision the session.
- **`get_session_status()`**: The handler for `GET /sessions/{id}`. It returns the current status of a specific session.
- **`terminate_session()`**: The handler for `DELETE /sessions/{id}`. It initiates the termination of a session and returns an `ACCEPTED` status.
- **`run_provisioning()`**: A private background task that handles the logic for provisioning a new compute session using the appropriate `ComputeProvider`. It updates the session state based on the outcome (e.g., to `Running` or `Failed`).

#### `compute/traits.rs`
Defines the core abstractions for compute providers and remote execution.

- **`RemoteExecutor` (trait)**: Abstraction for executing commands, managing files, and handling processes (local or remote).
- **`ComputeProvider` (trait)**: Interface for managing session lifecycle (start, stop, health check).

#### `compute/providers/local/provider.rs`
An implementation of the `ComputeProvider` trait that runs development sessions locally.

- **`LocalComputeProvider::new()`**: Creates a new instance of the local compute provider.
- **`LocalComputeProvider::start_session()`**: Orchestrates session startup, delegating to `setup_collab_mode` or `setup_pair_mode`.
- **`LocalComputeProvider::setup_collab_mode()`**: Initializes a shared workspace for asynchronous collaboration.
- **`LocalComputeProvider::setup_pair_mode()`**: Initializes a pair programming session using `upterm`.
- **`LocalComputeProvider::install_scripts()`**: Copies the `steadystate` binary and installs helper scripts (`steadystate-sync`, `steadystate-wrapper`) into the session.
- **`LocalComputeProvider::launch_sshd()`**: Configures and starts a dedicated `sshd` instance for the session.
    - **SSH User Handling**: Uses `STEADYSTATE_SSH_USER` env var, falls back to `USER` env var, or defaults to "steadystate".
    - **Token Injection**: Injects the GitHub token into the repository's `origin` remote URL to enable passwordless `git push`.

#### `compute/common/git_ops.rs`
Helper struct for performing Git operations via the `RemoteExecutor`.

- **`GitOps::clone()`**: Clones a repository.
- **`GitOps::checkout_new_branch()`**: Creates and checks out a new branch.
- **`GitOps::configure_user()`**: Sets `user.name` and `user.email`.
- **`GitOps::add_remote()`**: Adds a new remote.
- **`GitOps::set_remote_url()`**: Updates the URL of an existing remote (used for token injection).

#### `compute/common/ssh_keys.rs`
Manages SSH keys and `authorized_keys` files.

- **`SshKeyManager::fetch_github_keys()`**: Fetches public keys for a GitHub user.
- **`SshKeyManager::build_authorized_keys()`**: Aggregates keys for the session creator and allowed users.
- **`SshKeyManager::generate_authorized_keys_file()`**: Generates the content for an `authorized_keys` file, optionally with a forced command.

#### `compute/common/sshd.rs`
Manages `sshd` configuration and execution.

- **`SshdConfig::generate()`**: Generates a secure `sshd_config` file.
- **`find_sshd_binary()`**: Locates the `sshd` binary on the system.
- **`generate_host_keys()`**: Generates ephemeral host keys for the session.

## Collaboration Architecture

SteadyState uses a "Shared Workspace" model (`--mode=collab`) to enable seamless asynchronous collaboration on the same compute instance.

### Shared Workspace Structure

When a session is started in `collab` mode, the backend provisions a secure directory structure:

```
~/.steadystate/sessions/<session_id>/
├── canonical/          # Bare Git repository (synchronization point)
├── repo/               # The actual bare repo cloned from GitHub
├── ssh/                # Dedicated SSH daemon configuration and keys
├── bin/                # Session-specific binaries (steadystate, steadystate-sync, wrapper)
├── sync-log            # Log of sync operations
├── activity-log        # Log of user activity
└── session-info.json   # JSON file containing magic link and SSH connection info
```

### Session Initialization

1.  **Canonical Repo**: The backend initializes a bare clone of the target repository in `canonical/`.
2.  **Session Branch**: A dedicated branch `steadystate/collab/<session_id>` is created to isolate session work.
3.  **Environment Setup**:
    *   The `steadystate` CLI binary is copied (or symlinked) into `bin/`.
    *   `sync-log` and `activity-log` files are created to prevent dashboard hangs.
    *   `session-info.json` is written with connection details.
4.  **SSHD Launch**: A custom `sshd` instance is launched on a random high port, configured to:
    *   Use a generated host key.
    *   Authenticate users via their GitHub public keys.
    *   Force all connections to execute a `wrapper.sh` script.

### Magic Links

The backend generates a **Magic Link** (`steadystate://collab/<session_id>?ssh=...&host_key=...`) for every session. This link encodes:

*   **Mode**: `collab`.
*   **Session ID**: The unique identifier for the session.
*   **Connection Details**: The full SSH connection string (user, host, port).
*   **Host Key**: The public host key of the session's SSH server, allowing the CLI to automatically configure `known_hosts` securely.

### Connection & Isolation

When a user connects via SSH (`ssh <user>@host -p <port>`):

1.  **Authentication**: `sshd` authenticates the user using their public key.
2.  **Wrapper Script**: The `wrapper.sh` script is executed:
    *   Identifies the user based on the key used.
    *   Creates a private **Git Worktree** for the user in `.worktree/` (inside the user's home in the session).
    *   Initializes `.worktree/steadystate.json` with metadata required for syncing.
    *   Configures Git identity (user.name, user.email).
    *   Drops the user into a shell inside their worktree.

This ensures that while users share the same compute resources, their file system changes are isolated until they choose to sync.

### Synchronization Workflow

Users synchronize their work using the `steadystate sync` and `steadystate publish` commands.

#### `steadystate sync` (Local Sync)
Synchronizes the user's private worktree with the session's `canonical` repository using a Y-CRDT (Conflict-Free Replicated Data Type) approach:
1.  **Materialize**: Converts both the worktree state and the canonical state into Y-CRDT models.
2.  **Merge**: Merges the two models, resolving conflicts automatically where possible.
3.  **Apply**: Updates the `canonical` repository with the merged state.
4.  **Refresh**: Updates the user's worktree to match the new canonical state.

#### `steadystate publish` (Remote Sync)
Pushes the state of the `canonical` repository to the upstream GitHub repository:
1.  **Sync**: Performs a local sync (canonical <-> worktree).
2.  **Commit**: Creates a commit in the `canonical` repo with the changes.
3.  **Push**: Pushes the session branch to the `origin` remote (GitHub).
    *   **Authentication**: Uses the injected GitHub token in the remote URL to authenticate without user intervention.

## CLI Architecture

The `cli` is a command-line application built with `clap` that serves as the primary user interface for SteadyState. It communicates with the `backend` via a REST API.

### Key Modules and Functions

#### `main.rs`
The entry point for the CLI. It defines the command structure, parses arguments, and dispatches to the appropriate handler.

- **`main()`**: The asynchronous main function that sets up logging, parses CLI commands, creates an HTTP client, and executes the matched subcommand.
- **`whoami()`**: The handler for the `steadystate whoami` command. It reads the local session and prints the current user's login status.
- **`logout()`**: The handler for the `steadystate logout` command. It revokes the refresh token via an API call and deletes local session data.
- **`up()`**: The handler for the `steadystate up` command. It makes an authenticated request to the backend to create a new development session.

#### `auth.rs`
Contains the logic for handling user authentication and making authenticated API calls.

- **`device_login()`**: Orchestrates the entire OAuth device flow from the CLI side, including initiating the flow, polling for completion, and storing the resulting tokens.
- **`perform_refresh()`**: Proactively refreshes the JWT using the stored refresh token. It is called automatically when the JWT is near expiry.
- **`request_with_auth()`**: A generic helper function for making authenticated API requests. It handles reading the session, checking for JWT expiry, performing a refresh if needed, and then sending the request with the `Authorization: Bearer` header.
- **`extract_exp_from_jwt()`**: A utility function to parse a JWT (without verifying its signature) to extract its expiry timestamp.
- **`store_refresh_token()`**: Securely stores a refresh token in the operating system's keychain/keyring.
- **`get_refresh_token()`**: Retrieves a stored refresh token from the keychain.
- **`delete_refresh_token()`**: Deletes a stored refresh token from the keychain.
- **`send_with_retries()`**: A private helper function that wraps an HTTP request, providing a retry mechanism for transient network failures (like timeouts or connection errors).

#### `session.rs`
Manages the local user session file.

- **`Session::new()`**: Creates a new `Session` struct, automatically extracting the expiry timestamp from the provided JWT.
- **`Session::is_near_expiry()`**: Checks if the session's JWT has expired or will expire within a specified time buffer.
- **`get_cfg_dir()`**: Determines the appropriate configuration directory for storing session files, respecting the `STEADYSTATE_CONFIG_DIR` environment variable for overrides.
- **`session_file()`**: Constructs the full path to the `session.json` file.
- **`write_session()`**: Serializes a `Session` struct to JSON and writes it to the session file with secure file permissions (0600 on Unix).
- **`read_session()`**: Reads and deserializes the `Session` struct from the session file.
- **`remove_session()`**: Deletes the session file from the disk.

#### `notify.rs` (Dashboard)
Implements the `steadystate watch` dashboard.

- **`watch()`**: The main loop for the dashboard.
    - Connects via SSH to the session.
    - Tails `sync-log` and `activity-log` to display real-time updates.
    - Reads `session-info.json` to display the magic link and join command.
    - Displays connected users and recent activity with human-readable timestamps.

#### `sync.rs`
Implements the synchronization logic (`sync`, `publish`, `status`, `diff`).

- **`sync()`**: Orchestrates the local synchronization process (Materialize -> Merge -> Apply -> Refresh).
- **`publish_command()`**: Orchestrates the remote publish process (Sync -> Commit -> Push).
- **`status_command()`**: Shows the status of the local worktree relative to the canonical repo.
- **`diff_command()`**: Shows the diff between the local worktree and the canonical repo.
- **`apply_tree_to_canonical()`**: Destructively updates the canonical repo with the merged state (with safety checks).
- **`sync_worktree_from_canonical()`**: Updates the user's worktree to match the canonical repo.

#### `merge.rs`
Implements the Y-CRDT based merge engine.

- **`materialize_git_tree()`**: Reads a Git tree into a `TreeSnapshot`.
- **`materialize_fs_tree()`**: Reads a filesystem directory into a `TreeSnapshot`.
- **`merge_trees()`**: Performs a 3-way merge of two `TreeSnapshot`s against a base.
- **`merge_file_yjs()`**: Performs a 3-way text merge using the `yrs` crate (Yjs for Rust).

## Shared Code (`packages/common`)

The `packages/common` crate is intended to hold shared data structures, utilities, and business logic that is common to both the `backend` and `cli` applications. This helps to reduce code duplication and ensure consistency between the two components.

Currently, this crate is a placeholder and does not contain any shared code.

## CLI-Backend Interaction

The `cli` and `backend` communicate over a REST API. The `cli` acts as the client, making HTTP requests to the `backend` service to perform actions.

### Authentication Flow (`steadystate login`)

1.  **Device Flow Request**: The `cli` sends a `POST` request to the `backend`'s `/auth/device` endpoint.
2.  **User Authorization**: The `backend` responds with a `verification_uri` and `user_code`, which the `cli` displays to the user. The user authorizes the application in their browser.
3.  **Polling**: The `cli` polls the `backend`'s `/auth/poll` endpoint until the user completes authorization.
4.  **Token Issuance**: The `backend` returns a JWT and a refresh token.
5.  **Secure Storage**: The `cli` stores the refresh token in the system keychain and saves the JWT in a local session file.

### Authenticated API Calls (`steadystate up`)

1.  The `cli` reads the JWT from the session file.
2.  If the JWT is expired, the `cli` uses the refresh token to request a new one from the `/auth/refresh` endpoint.
3.  The `cli` sends the API request (e.g., to `/sessions`) with the valid JWT in the `Authorization: Bearer <token>` header.
4.  The `backend` validates the JWT and processes the request.
