# Hosting a Pair Programming Session

SteadyState's **Pair Programming Mode** (`--mode=pair`) creates a shared terminal session where multiple users can control the same shell instance in real-time. This is ideal for debugging, teaching, or tight collaboration where you want to see exactly what the other person is typing.

## Prerequisites

- You must be logged in (`steadystate login`).
- You must have a running SteadyState backend.
- `upterm` must be installed on the backend server (SteadyState uses `upterm` for this mode).

## Creating a Session

To start a pair programming session:

```bash
steadystate up --mode=pair <REPOSITORY>
```

### Example

```bash
steadystate up --mode=pair https://github.com/b-rodrigues/housing
```

Output:

```
Creating pair programming session...
✅ Session ready!

📋 Share this magic link with your pair:
   steadystate join "steadystate://pair/abc12345?ssh=..."

Connecting to session...
```

You will be immediately dropped into a shared terminal session inside the repository.

## Joining a Session

Your pair joins using the magic link you shared:

```bash
steadystate join "steadystate://pair/abc12345?ssh=..."
```

Once they join, they will see the same terminal as you. Both of you can type commands, edit files (using terminal editors like vim or nano), and run code.

## Key Differences from Collab Mode

| Feature | Pair Mode (`--mode=pair`) | Collab Mode (`--mode=collab`) |
|---------|---------------------------|-------------------------------|
| **View** | Shared Screen (Same Terminal) | Independent Worktrees |
| **Editing** | One cursor (taking turns) | Parallel editing |
| **Sync** | Instant (same shell) | Explicit (`steadystate sync`) |
| **Use Case** | Debugging, Teaching, Review | Feature development, Data Science |

## Ending the Session

To end the session, simply exit the shell:

```bash
exit
```

This will close the connection for all participants.
