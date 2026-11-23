# sftp

> This repository is checked out as the `sftp/` submodule of [GameplanePanel/Gameplane](https://github.com/GameplanePanel/Gameplane). Paths such as `docs/`, `operator/`, `api/`, `charts/` and `web/` below refer to that repository.

The **sftp** component [optional] is Gameplane's SFTP endpoint for game server files. Each cluster can run one. A user connects with any SFTP client (FileZilla, WinSCP, `sftp`) using an SSH key or a generated SFTP password from their Gameplane profile, and sees one folder per game server they may access. Logging in as `<user>+<server>` opens one server directly.

The server holds no permissions and mounts no volumes: every login and file operation is sent to the Gameplane API as that user, so roles, ownership, per-cluster grants and the audit log apply exactly as in the dashboard Files tab.

Status: the server runs (`sftp serve`). The design is spec 040 (`specs/040-sftp-access/` in Gameplane).

## Running

```sh
sftp serve \
  --host-key /etc/sftp/hostkeys \
  --api-url https://gameplane-api.gameplane.svc:8080 \
  --service-token-file /etc/sftp/service-token
```

Every flag has a `GAMEPLANE_SFTP_*` environment variable; the flag wins. Required: `--host-key` (a key file or a directory of keys, kept stable so clients can verify it), `--api-url`, `--service-token-file`. Optional: `--listen` (`:2222`), `--ca-file`, `--idle-timeout` (`15m`), `--max-sessions-per-user` (`4`), `--max-preauth-connections` (`64`, connections still authenticating; more are closed at once), `--max-transfers-per-user` (`8`), `--default-namespace` (`gameplane-games`, must match the API), `--metrics-addr` (`:9102`, empty disables). `sftp version` prints the build version. The full contract is in [`specs.md`](specs.md).

Clients log in as `<user>` to see every server they may access, or as `<user>+<server>` (or `<user>+<namespace>/<server>`) to open one server directly. There is no shell, command execution or port forwarding. Dotfiles are hidden.

Gameplane builds and ships the image and the Helm chart (`sftp.enabled`). Lint, tests, coverage and govulncheck for this module run in this repository's own CI.
