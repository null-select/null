# null CLI

`null` securely enrolls an agent runtime into the null.select continuity control plane. It exchanges a single-use execution enrollment for a scoped workload credential, stores that credential with owner-only permissions, and requests the runtime's fenced lease.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/null-select/null/main/install.sh | sh
```

The installer supports macOS and Linux on amd64 and arm64, verifies the release SHA-256 checksum, prints the version it installed, and installs to `$HOME/.local/bin` without elevated privileges. Set `NULL_INSTALL_DIR` to select another directory or `NULL_VERSION=v0.2.1` to pin a release.

## Connect

Create an enrollment for an execution in [console.null.select](https://console.null.select), then run the command shown there:

```sh
$HOME/.local/bin/null connect \
  --server https://console.null.select/connect \
  --provider declared \
  --model your-model \
  --capability-digest <sha256> \
  --re-enroll
```

The console includes `--re-enroll` whenever it has just issued a fresh one-time secret, so customers never have to infer whether a prior local credential must be replaced. The CLI prompts for that secret without echoing it. It never accepts organization or project scope from the customer. The resulting workload credential is stored in the operating system's user configuration directory with mode `0600` before the runtime bind request is sent.

After binding, keep `null connect` running. It renews the exact workload-owned effect lease every 30 seconds, stops immediately if the runtime is fenced or frozen, and stops safely on Ctrl-C. A transport interruption is retried only while the last confirmed lease is still valid; the CLI never assumes authority after that expiry. Use `--once` only for diagnostics that intentionally leave the lease to expire.

After a successful exchange, rerun the command without `--re-enroll` to retry the saved binding. An expired, otherwise valid credential automatically returns to the enrollment prompt. Malformed or permission-unsafe credential files continue to fail closed.

## Inspect authority

From a second terminal, read the control plane's authenticated view of the saved runtime:

```sh
$HOME/.local/bin/null status
$HOME/.local/bin/null doctor
```

`null status` reports the canonical execution state, local and persisted fencing epochs, lease expiry, unresolved consequential actions, and whether the runtime may perform consequential work. `null doctor` checks the private credential file, authenticated gateway reachability, runtime binding, fencing epoch, effect authority, and continuation hold. A safe recovery hold or fenced runtime is reported as a completed diagnosis rather than disguised as a transport failure. Add `--json` to either command for bounded machine-readable output.

Neither command prints the workload credential or accepts organization/project headers. Tenant and execution scope remain derived by the control plane from the hashed workload credential.

## Protect a GitHub pull-request label

First connect both GitHub Apps from the null.select console to the same non-empty repository selection. Then enroll a fresh execution with the **GitHub pull request labels** capability and keep its `null connect` process running.

From another terminal, submit one stable operation key with the label action:

```sh
$HOME/.local/bin/null github label \
  --owner YOUR_ORG \
  --repo YOUR_REPO \
  --pr 123 \
  --label continuity-verified \
  --idempotency-key ticket-123-label
```

null.select commits the action intent and consumes its single-use permit before the executor contacts GitHub. A confirmed response is independently read back through the separate read-only App. If contact is lost after possible dispatch, the command reports an active continuation hold and the attempt identifier; reconcile it without repeating the effect:

```sh
$HOME/.local/bin/null github observe --attempt ATTEMPT_ID
```

Reuse the original idempotency key when retrying the same client delivery. Do not invent a second key for an uncertain effect: only authoritative reconciliation can determine whether a replacement action is safe.

## Development

```sh
go test ./...
go test -race ./...
go build ./...
```

This public repository contains only the customer onboarding client. Canonical authority, policy, reconciliation, and database access remain server-side.
