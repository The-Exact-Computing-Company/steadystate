# NAME

**steadystate troubleshooting** - common issues and solutions

# AUTHENTICATION ISSUES

## "Refresh token has expired or been revoked"

**Cause:** Your authentication session has expired.

**Solution:**

```
steadystate logout
steadystate login
```

## Device code expires before authorization

**Cause:** The device code has a 15-minute timeout.

**Solution:** Run `steadystate login` again and complete authorization more quickly.

## "Failed to get user info from GitHub"

**Cause:** Network issue or GitHub API problem.

**Solution:**
1. Check internet connection
2. Verify GitHub status at githubstatus.com
3. Try again in a few minutes

# CONNECTION ISSUES

## "Permission denied (publickey)"

**Cause:** Your SSH key isn't authorized for the session.

**Solutions:**

1. Ensure you're logged in:
   ```
   steadystate whoami
   ```

2. Verify your GitHub account has SSH keys:
   ```
   curl https://github.com/<username>.keys
   ```

3. Ensure you're a collaborator on the repository

4. Ask the session host to re-create the session

## "Connection refused"

**Cause:** Cannot reach the session host.

**Solutions:**

1. Verify you can reach the host:
   ```
   ping <host-ip>
   ```

2. Check the port is correct:
   ```
   nc -zv <host-ip> <port>
   ```

3. Ask the host to check firewall settings:
   ```
   sudo ufw allow <port>/tcp
   ```

4. If on different networks, you may need VPN or port forwarding

## "Host key verification failed"

**Cause:** SSH host key mismatch.

**Solutions:**

1. The magic link may be outdated - ask host for a new one
2. Remove old known_hosts entry:
   ```
   ssh-keygen -R "[host]:port"
   ```

## Connection hangs

**Cause:** Firewall blocking, network timeout, or sshd not running.

**Solutions:**

1. Try with verbose SSH:
   ```
   ssh -v -p <port> user@host
   ```

2. Check if sshd is running (host side):
   ```
   ps aux | grep sshd
   ```

3. Check sshd logs (host side):
   ```
   journalctl -u steadystate -f
   ```

# SYNC ISSUES

## "Push failed - please sync again"

**Cause:** Another collaborator pushed changes while you were syncing.

**Solution:** This is normal in active collaboration. Just run:

```
steadystate sync
```

The second sync will fetch their changes, merge, and push.

## "Binary file conflict"

**Cause:** Two users modified the same binary file (image, PDF, etc.).

**Solution:** Binary files cannot be auto-merged. Coordinate with your collaborator:

1. Decide whose version to keep
2. One user reverts their change
3. Both users sync

## Sync completes but changes don't appear

**Cause:** May be looking at wrong directory or stale worktree.

**Solutions:**

1. Verify you're in the worktree:
   ```
   pwd
   ls -la .worktree/
   ```

2. Check the sync actually pushed:
   ```
   cd ../canonical
   git log -1
   ```

3. Other user should sync:
   ```
   steadystate sync
   ```

## "Metadata file not found"

**Cause:** Not in a SteadyState worktree, or worktree corrupted.

**Solution:**

1. Navigate to your worktree:
   ```
   cd ~/worktrees/<username>
   ```

2. If corrupted, leave and rejoin the session

## Merge produces unexpected results

**Cause:** Both users edited the exact same text.

**Explanation:** SteadyState uses an additive merge strategy. If two users replace the same word with different values, both replacements are kept (canonical first, then local).

**Example:**
```
Base:   "Hello World"
User A: "Hi World"
User B: "Hey World"
Result: "HeyHi World"
```

**Solution:** Coordinate with collaborators to work on different sections. After sync, manually clean up if needed.

# SESSION ISSUES

## "Session not found"

**Cause:** Session expired, terminated, or backend restarted.

**Solution:** Ask the host to create a new session.

## Dashboard shows "Observer - No worktree"

**Cause:** Opened dashboard without joining first.

**Solution:** Use `steadystate join` to create your worktree, then use dashboard.

## Session host cannot see collaborators' changes

**Cause:** Collaborators haven't synced, or sync failed.

**Solution:**

1. Ask collaborators to run `steadystate sync`
2. Host should also run `steadystate sync` to fetch their changes

## Magic link doesn't work

**Cause:** URL encoding issues or incomplete copy.

**Solutions:**

1. Ensure the entire link is quoted:
   ```
   steadystate join "steadystate://collab/...full-link..."
   ```

2. Check for truncation - the link should include `host_key=`

3. Ask host to share via a method that preserves the full URL

# BACKEND ISSUES

## Backend won't start

**Cause:** Missing configuration or port conflict.

**Solutions:**

1. Check required environment variables:
   ```
   echo $GITHUB_CLIENT_ID
   echo $GITHUB_CLIENT_SECRET
   echo $JWT_SECRET
   ```

2. Check port availability:
   ```
   lsof -i :8080
   ```

3. Check logs:
   ```
   RUST_LOG=debug ./steadystate-backend
   ```

## "Address already in use" for SSH

**Cause:** Port conflict with another sshd or service.

**Solution:** The backend binds an OS-assigned ephemeral port per local session (Hetzner sessions use deterministic ports in `20000-28000`). If you see this error, check for a collision with `ss -tlnp` and retry — a fresh port is picked per session.

## GitHub OAuth errors

**Cause:** Misconfigured OAuth app.

**Solutions:**

1. Verify Client ID and Secret are correct
2. Check OAuth app callback URL matches your backend URL
3. Ensure OAuth app is not suspended

# DEBUGGING

## Enable debug logging

```
export RUST_LOG=debug
steadystate sync
```

## Enable merge debugging

```
export STEADYSTATE_DEBUG_MERGE=1
steadystate sync
```

## Check session files

Inside a session:

```
# View session metadata
cat .worktree/steadystate.json

# View sync log
cat ../sync-log

# View active users
cat ../active-users

# Check canonical state
cd ../canonical && git log --oneline -5
```

## Test SSH manually

```
ssh -v -p <port> \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    steadystate@<host>
```

# GETTING HELP

If your issue isn't covered here:

1. Check existing issues: https://github.com/b-rodrigues/steadystate/issues
2. Open a new issue with:
   - SteadyState version
   - Operating system
   - Steps to reproduce
   - Error messages and logs
   - Output of `steadystate whoami`

# SEE ALSO

**steadystate**(1), **ssh**(1), **git**(1)
