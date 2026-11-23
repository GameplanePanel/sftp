# sftp

> This repository is checked out as the `sftp/` submodule of [GameplanePanel/Gameplane](https://github.com/GameplanePanel/Gameplane). Paths such as `docs/`, `operator/`, `api/`, `charts/` and `web/` below refer to that repository.

The **sftp** component [optional] is Gameplane's SFTP endpoint for game server files. Each cluster can run one. A user connects with any SFTP client (FileZilla, WinSCP, `sftp`) using an SSH key or a generated SFTP password from their Gameplane profile, and sees one folder per game server they may access. Logging in as `<user>+<server>` opens one server directly.

The server holds no permissions and mounts no volumes: every login and file operation is sent to the Gameplane API as that user, so roles, ownership, per-cluster grants and the audit log apply exactly as in the dashboard Files tab.

Status: scaffold. The design is spec 040 (`specs/040-sftp-access/` in Gameplane); this repository grows with its tasks T020 onward.

Gameplane builds and ships the image and the Helm chart (`sftp.enabled`). Lint, tests, coverage and govulncheck for this module run in this repository's own CI.
