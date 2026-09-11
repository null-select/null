# null CLI

`null` securely enrolls an agent runtime into the null.select continuity control plane. It exchanges a single-use execution enrollment for a scoped workload credential, stores that credential with owner-only permissions, and requests the runtime's fenced lease.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/null-select/null/main/install.sh | sh
```

The installer supports macOS and Linux on amd64 and arm64, verifies the release SHA-256 checksum, and installs to `/usr/local/bin` when writable or `$HOME/.local/bin` otherwise. Set `NULL_INSTALL_DIR` to select another directory or `NULL_VERSION=v0.1.0` to pin a release.

## Connect

Create an enrollment for an execution in [console.null.select](https://console.null.select), then run the command shown there:

```sh
null connect \
  --server https://console.null.select/connect \
  --provider declared \
  --model your-model \
  --capability-digest <sha256>
```

The CLI prompts for the one-time enrollment token without echoing it. It never accepts organization or project scope from the customer. The resulting workload credential is stored in the operating system's user configuration directory with mode `0600` before the runtime bind request is sent.

Re-running the same command safely retries the saved binding. Use `--re-enroll` only when intentionally replacing the saved enrollment.

## Development

```sh
go test ./...
go test -race ./...
go build ./...
```

This public repository contains only the customer onboarding client. Canonical authority, policy, reconciliation, and database access remain server-side.
