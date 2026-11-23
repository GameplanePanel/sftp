# sftp — Specification

How this component works today. The feature design is spec 040 in Gameplane (`specs/040-sftp-access/`); this file follows the code as it lands.

## Purpose

Optional SFTP endpoint, one per cluster, that gives users SFTP access to the files of the game servers they may access, without holding any permission or volume itself. Every login and file operation is sent to the Gameplane API as the signed-in user.

## Responsibilities

- Accept SSH connections, authenticate them through the API, and serve the SFTP subsystem and nothing else.
- Present the servers a user may reach as a folder tree, translate SFTP operations into API file calls, and map API errors to SFTP statuses.
- Close connections whose API session was revoked, cap sessions and transfers per user, and expose Prometheus metrics.

## Non-goals / boundaries

- No shell, exec, port forwarding or SCP (spec 040 FR-004).
- No direct access to game volumes or agents: all file access goes through the Gameplane API.
- No permission decisions: the API's file-access check decides (spec 040 FR-011a).
- No symlinks, hard links or `readlink`; `chown` and truncate-by-attribute are refused.

## Directory & package layout

- `main.go`: entrypoint, subcommand dispatch (`serve`, `version`), flag and environment parsing, wiring, metrics HTTP server.
- `internal/apiclient`: HTTP client for the API: login, session check, server list, and the file routes. Sentinel errors (`ErrNotFound`, `ErrPermission`, ...) map HTTP statuses.
- `internal/sshserver`: SSH listener, authentication callbacks, session registry, revocation loop, idle timeout, host key loading, metrics.
- `internal/vfs`: the per-connection virtual file system (`pkg/sftp` handlers), path translation, read and write streaming, transfer limiter.

## External interface / contracts

### Commands

- `sftp version`: prints the build version.
- `sftp serve [flags]`: runs the endpoint until SIGINT or SIGTERM. A flag overrides its environment variable, and the variable overrides the default.

| Flag | Environment variable | Default | Meaning |
|---|---|---|---|
| `--listen` | `GAMEPLANE_SFTP_LISTEN` | `:2222` | SSH listen address |
| `--host-key` | `GAMEPLANE_SFTP_HOST_KEY` | required | host key file, or a directory of keys (a mounted Secret works; `.pub` and hidden names are skipped) |
| `--api-url` | `GAMEPLANE_SFTP_API_URL` | required | Gameplane API base URL |
| `--service-token-file` | `GAMEPLANE_SFTP_SERVICE_TOKEN_FILE` | required | file holding the service token (`gpsftps_...`) |
| `--ca-file` | `GAMEPLANE_SFTP_CA_FILE` | none | extra PEM CA bundle for the API, added to the system roots |
| `--idle-timeout` | `GAMEPLANE_SFTP_IDLE_TIMEOUT` | `15m` | close a connection with no traffic for this long |
| `--max-sessions-per-user` | `GAMEPLANE_SFTP_MAX_SESSIONS_PER_USER` | `4` | concurrent SSH connections per user |
| `--max-preauth-connections` | `GAMEPLANE_SFTP_MAX_PREAUTH_CONNECTIONS` | `64` | concurrent connections still before authentication; further ones are closed at once |
| `--max-transfers-per-user` | `GAMEPLANE_SFTP_MAX_TRANSFERS_PER_USER` | `8` | concurrent file transfers per user, across connections |
| `--default-namespace` | `GAMEPLANE_SFTP_DEFAULT_NAMESPACE` | `gameplane-games` | namespace shown as `/<server>`; must equal the API's default games namespace |
| `--metrics-addr` | `GAMEPLANE_SFTP_METRICS_ADDR` | `:9102` | address for `/metrics`; empty disables it |

Exit code 2 with a message on stderr for a usage or startup error.

### Login

- Password: the callback sends the full SSH username (including a `+target` suffix), the password and the client address to `POST /sftp/v1/login` with the service token.
- Public key: the SSH layer verifies the signature, then the server logs in through the API with the key's authorized_keys line. Because the SSH library accepts the key before the API is asked, a refused key shows to the client as a connection that closes right after authentication, not as an authentication failure. Documented limitation.
- Every failure is a generic "permission denied" to the client; the cause is only logged at debug level and counted in metrics.
- A login as `user+server` or `user+namespace/server` roots the connection at that server. Otherwise the root lists the user's servers.

### File tree

- Tree login: `/<server>/...` for servers in the default namespace; `/_namespaces/<ns>/<server>/...` for others. The root, `/_namespaces`, `/_namespaces/<ns>` and each server's top folder are read-only virtual directories (create, rename, remove and write are refused). Kubernetes names cannot start with `_`, so `_namespaces` never collides with a server.
- Target login: `/` is the server's root, read-only itself; the server list is fetched only to check write access before a change.
- Write access: `GET /sftp/v1/servers` marks each server with `write`, the API's file-access decision. On a server marked `write: false`, open-for-write, mkdir, rename and remove are refused with permission denied before any request reaches the file routes, so an upload fails when the file is opened. A server without the field is left to the API, which checks every change itself.
- Paths are cleaned before use, so `..` cannot leave a server and no path can reach another server. A rename between servers is refused.
- Dotfiles: any path component starting with `.` is not found for reads and stat, refused for writes, and filtered from listings.
- Reads stream with `Range` requests. Reads a little ahead of the stream skip forward and keep the skipped bytes, because `pkg/sftp` may deliver pipelined reads slightly out of order; a far seek reopens the download.
- Writes stream to `PUT .../files/stream` through one request per open file. The API commits only when the body ends cleanly, so an aborted upload never replaces an existing file. A new or truncated file starts at offset 0. An existing file opened without truncation resumes at the lowest offset of the first chunks (the API copies the existing prefix). Chunks that arrive slightly out of order (bounded to 4 MiB ahead and 16 chunks) are held until the gap fills; a gap that never fills, a write behind the stream, or a chunk beyond the window aborts the upload with an error. Append mode is unsupported. An empty create makes an empty file.
- `chmod` and time changes are accepted as no-ops after checking the path exists; `chown` is refused; truncate by attribute is unsupported. `remove` refuses directories, `rmdir` refuses non-empty ones; the API delete is never recursive. `rename` does not overwrite; `posix-rename@openssh.com` does.
- API errors map to SFTP statuses with fixed messages: not found, permission denied, "file exists", "no space left on server", "file too large", "server busy, try again", "server not available, try again". No URL, token or response body reaches the client.

### Metrics

On `--metrics-addr` at `/metrics` (private registry): `gameplane_sftp_sessions` (gauge), `gameplane_sftp_logins_total{result="ok|denied|error|limit"}`, `gameplane_sftp_revoked_total`, `gameplane_sftp_preauth_rejected_total` (connections closed at once because the pre-auth cap was reached), `gameplane_sftp_bytes_total{direction="read|write"}`.

## Key invariants

- Only session channels with the `sftp` subsystem are served. `shell`, `exec`, `pty-req`, `env`, `x11-req`, agent forwarding and every other request are refused; `direct-tcpip` and other channel types are rejected; global forwarding requests are discarded. Only one SFTP subsystem runs per connection, and a further session channel is accepted, but its requests (including a second `sftp` subsystem) are refused and the channel is closed right after the refusal, so it never sits idle until the idle timeout. A non-`sftp` subsystem, `shell` and `exec` are refused.
- Every authenticated connection is registered by session token. Every 30 seconds the server sends the tokens to `POST /sftp/v1/sessions/check` and closes the connections whose tokens are reported revoked. A failed check keeps the connections (it never fails open into a kill, nor a grant).
- At most `--max-preauth-connections` connections may be before authentication at once (the slot is freed when the handshake and the API login finish). A connection over the cap is closed immediately, before any SSH exchange, and counted in `gameplane_sftp_preauth_rejected_total`.
- An API session the server creates but does not use is ended with `POST /sftp/v1/sessions/end` (service token, body `{"sessionTokens": ["gpsftp_…"]}`): a login refused by the per-user cap (password or key), and a password login whose SSH handshake does not finish. A failed end call is only logged; the session still expires on its own.
- Per-user caps are keyed by the lowercased API user name and enforced after authentication.
- The session token is used only as the bearer for the API calls of its own connection and is never logged. Passwords and keys are never logged.
- Before authentication completes, the handshake has an absolute deadline of `LoginTimeout` (10 s) from accept, so a client that drips bytes cannot hold a pre-auth slot longer; after it, each read or write has the idle-timeout deadline. `MaxAuthTries` is 3.

## Dependencies

`golang.org/x/crypto` (SSH), `github.com/pkg/sftp` (request server), `github.com/prometheus/client_golang` (metrics), and the standard library.

## Security considerations

- Authentication failures are generic (core rule 3); rate limiting of failed logins is done by the API per user and per source address, using the client address this server forwards.
- The service token authorises only login and session checks; file operations use the user's own short-lived session token, which the API restricts to the SFTP routes.
- Host keys must be stable across restarts (mounted from a Secret); they are read through `os.Root`, so a path cannot escape its directory.
- The API URL should be `https`; use `--ca-file` for a private CA.
- The session-end route `POST /sftp/v1/sessions/end` is not yet in the Gameplane API contract (`specs/040-sftp-access/contracts/api.md`). Until the API implements it, the call fails (logged at debug level) and an unused session expires on its own.

## Testing & coverage

Unit tests use in-process SSH clients and an `httptest` fake of the API; none needs a cluster. `main_test.go` covers flag parsing. The gate is `.testcoverage.yml` (total 70).
