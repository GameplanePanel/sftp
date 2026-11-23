# sftp — Specification

How this component works today. The feature design is spec 040 in Gameplane (`specs/040-sftp-access/`); this file follows the code as it lands.

## Purpose

Optional SFTP endpoint, one per cluster, that gives users SFTP access to the files of the game servers they may access, without holding any permission or volume itself.

## Responsibilities

Scaffold only: the binary prints its version (`sftp version`). The SSH server, API client and virtual file system arrive with spec 040 tasks T020–T029.

## Non-goals / boundaries

- No shell, exec, port forwarding or SCP (spec 040 FR-004).
- No direct access to game volumes or agents: all file access goes through the Gameplane API.
- No permission decisions: the API's file-access check decides (spec 040 FR-011a).

## Directory & package layout

- `main.go`: entrypoint and subcommand dispatch.

## External interface / contracts

- `sftp version`: prints the build version.

## Key invariants

None yet beyond the boundaries above.

## Dependencies

Go standard library only.

## Security considerations

Nothing is listened on yet.

## Testing & coverage

`main_test.go` covers `run()`; the gate is `.testcoverage.yml`.
