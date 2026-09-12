# NAME

**steadystate** - real-time collaboration for code repositories

# SYNOPSIS

```
steadystate login
steadystate up --env=tproject --mode=pair|collab [--branch=NAME] <repository>
steadystate join "<magic_link>"
steadystate dashboard "<magic_link>"
steadystate sync
steadystate publish
steadystate status
steadystate diff
steadystate whoami
steadystate logout
```

# DESCRIPTION

**SteadyState** enables multiple developers to collaborate on a code repository in real-time. It provides conflict-free merging of concurrent edits using a 3-way merge algorithm, allowing team members to work on the same files simultaneously without merge conflicts.

The system consists of a backend server that manages sessions and a CLI tool that users interact with. Environments are provisioned from the repository's `tproject.toml` using T and Nix. Authentication supports GitHub OAuth, GitLab personal access tokens, and enterprise OIDC.

# DOCUMENTATION

This manual contains the following sections:

**GETTING_STARTED(1)**
:   Installation, self-hosting setup, and first steps

**COMMANDS(1)**
:   Detailed reference for all CLI commands

**CONFIGURATION(5)**
:   Environment variables and configuration options

**ARCHITECTURE(8)**
:   System design and internals

**TROUBLESHOOTING(7)**
:   Common issues and solutions

# QUICK START

1. Login with GitHub:

```
steadystate login
```

2. Create a collaboration session (host):

```
steadystate up --env=tproject --mode=collab https://github.com/user/repo
```

3. Share the magic link with collaborators.

4. Join a session (collaborator):

```
steadystate join "steadystate://collab/..."
```

5. Make edits, then sync:

```
steadystate sync
```

# EXAMPLES

Create a session for a feature branch:

```
steadystate up --env=tproject --mode=collab --branch=feature-x https://github.com/org/repo
```

Open the dashboard to monitor activity:

```
steadystate dash "steadystate://collab/abc123?ssh=..."
```

View local changes before syncing:

```
steadystate diff
```

# SEE ALSO

**git**(1), **ssh**(1)

# AUTHORS

SteadyState is developed by Bruno Rodrigues and contributors.

# BUGS

Report bugs at: https://github.com/b-rodrigues/steadystate/issues
