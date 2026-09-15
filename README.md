# SimpleSecretsManager (SSM)

**Version 0.0.3** — a small, self-hosted secrets service for Linux homelabs, written in Go.

SSM provides the everyday workflow of storing encrypted secrets centrally and delivering them to machines or Kubernetes. It includes `ssm-server`, an embedded administrative WebUI, and `ssm-agent`. The WebUI keeps the installed version and server lock status in its persistent header.

## What it does

- Manage secret values and revision metadata through the WebUI or `/api/v1/` API. Browsing never fetches values; use **Reveal** or **Copy** explicitly.
- Issue dedicated write credentials for automation, restrict which secrets they can update, optionally allow creation of missing secrets, and revoke access in the WebUI. Updates use a simple bearer-authenticated POST.
- Create agents, grant exact-path or subtree permissions, issue expiring one-time enrollment tokens, and revoke runtime credentials.
- Encrypt values with AES-256-GCM and a random data-encryption key. A separate master key protects that key through envelope encryption. Restarting always locks the server.
- Store records in SQLite or MySQL with tracked, automatic schema migrations.
- Deploy raw values or Go-template output through atomic, symlink-resistant file replacement. Poll metadata first, persist applied revisions, and retry outages and local hooks.
- Authenticate administrators using expiring secure-cookie sessions and CSRF protection. Authenticate agents and Kubernetes using independent bearer credentials over verified TLS.
- Record audit events without secret values or plaintext credentials. Expose liveness and readiness while locked.

Start with **[setup.md](setup.md)** for a complete installation, certificate setup, enrollment, unlock, backup, and Kubernetes walkthrough. Copy-ready units and configuration examples are in [examples](examples).

## Build and test

Requires Go 1.25 or newer; Linux is the supported runtime. SQLite uses a pure-Go driver, so release binaries do not need a C toolchain or system SQLite library.

```sh
make build
./bin/ssm-server -v
./bin/ssm-agent -v
make test
make check
make release
```

`make release` produces Linux amd64 and arm64 archives and `dist/SHA256SUMS`. `VERSION` supplies the build version for both binaries and the embedded WebUI. `make clean` removes build/release output.

SQLite, encryption, authentication, permissions, file publication, enrollment, and HTTPS agent/server integration tests run by default. Real MySQL tests are opt-in and **require a disposable database**:

```sh
MYSQL_TEST_DSN='ssm_test:password@tcp(127.0.0.1:3306)/ssm_test' make test-mysql
```

MySQL tests remove SSM records in that database. Do not point them at an installation you want to keep. See setup.md for an isolated Docker test command.

## Layout

| Directory | Responsibility |
| --- | --- |
| `cmd/ssm-server`, `cmd/ssm-agent` | Configuration, version flags, process lifecycle |
| `internal/security` | Token hashing, path authorization, authenticated/envelope encryption |
| `internal/storage` | Common transactional interface, SQLite/MySQL, migrations |
| `internal/server` | Administrator/agent authentication, API, audit, embedded WebUI |
| `internal/agent` | Enrollment, polling, templates, atomic files, local hooks, state |
| `examples` | Service units, configuration, secret definitions, ESO manifests |

## Scope and operational boundaries

SSM 0.0.3 implements a static secret store and delivery agent. It does not implement Vault's dynamic database credentials, leases, PKI engine, Shamir unseal, or HA coordination. Run one server instance per database; transactions protect record consistency, but each process has its own in-memory lock state.

The master key is your recovery material: losing it makes the encrypted secrets unrecoverable. Keep it outside the server. Metadata, permission rules, and audit records are not encrypted; secret values are. A privileged attacker controlling an unlocked process can access its in-memory data. Disable core dumps and use encrypted swap or disable swap on secret-bearing hosts. Go cannot guarantee removal of every transient copy of a secret from memory.

Destination directories and agent configuration must be controlled by a trusted administrator. Local hooks run with the agent's privileges, retry with at-least-once semantics, and should be idempotent. Secret deletion or access revocation stops future delivery; it deliberately retains existing local files and cannot recall values already distributed.

This is an initial implementation with automated tests, not an independently audited replacement for all Vault/OpenBao deployments.
