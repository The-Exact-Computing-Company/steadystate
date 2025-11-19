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
- **`create_session()`**: The handler for `POST /sessions`. It creates a new session record, returns an `ACCEPTED` status, and spawns a background task to provision the session.
- **`get_session_status()`**: The handler for `GET /sessions/{id}`. It returns the current status of a specific session.
- **`terminate_session()`**: The handler for `DELETE /sessions/{id}`. It initiates the termination of a session and returns an `ACCEPTED` status.
- **`run_provisioning()`**: A private background task that handles the logic for provisioning a new compute session using the appropriate `ComputeProvider`. It updates the session state based on the outcome (e.g., to `Running` or `Failed`).

#### `auth/provider.rs`
Defines the core traits for the modular authentication system.

- **`AuthProvider` (trait)**: An async trait defining the interface for an authentication provider, including methods for starting and polling the device flow.
- **`AuthProviderFactory` (trait)**: An async trait for factories that can build instances of `AuthProvider`.

#### `auth/github.rs`
An implementation of the `AuthProvider` trait for GitHub.

- **`GitHubAuth::new()`**: Creates a new instance of the GitHub authentication provider.
- **`GitHubAuth::start_device_flow()`**: Implements the device flow initiation logic by making a request to GitHub's device code endpoint.
- **`GitHubAuth::poll_device_flow()`**: Implements the polling logic by exchanging the device code for an access token and then fetching the user's identity.
- **`GitHubFactory::build()`**: Implements the factory pattern to build a `GitHubAuth` provider, reading the necessary client ID and secret from the application config.

#### `compute/local_provider.rs`
An implementation of the `ComputeProvider` trait that runs development sessions locally.

- **`LocalComputeProvider::new()`**: Creates a new instance of the local compute provider.
- **`LocalComputeProvider::start_session()`**: Implements the session startup logic, which involves creating a workspace, cloning the user's repository, and launching an `upterm` session within a Nix environment.
- **`LocalComputeProvider::terminate_session()`**: Implements the session termination logic by killing the `upterm` process and cleaning up the workspace directory.
- **`create_workspace()`**: A private method to create a temporary directory for the session's workspace.
- **`nix_shell_command()`**: A private helper to construct a `tokio::process::Command` that runs a given command inside a sourced Nix shell environment.
- **`ensure_nix_installed()`**: A private helper that checks if Nix is installed and, if not, installs it.
- **`clone_repo()`**: A private async function to clone a Git repository into a specified destination.
- **`launch_upterm_in_noenv()`**: A private async function that launches the `upterm` host process inside a `nix develop` shell.
- **`capture_upterm_invite()`**: A private async helper that reads the stdout of the `upterm` process to find and return the SSH invite link.
- **`kill_pid()`**: A private async function to terminate a process by its process ID (PID).

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
