# Installing and operating SimpleSecretsManager

This guide installs SSM **0.0.2** on a Linux server and a Linux client using systemd. It assumes you have root access, a DNS name such as `ssm.home.arpa`, and a certificate that clients can verify. Examples use port 8443 and SQLite. The MySQL and Kubernetes sections explain their additional configuration.

The normal sequence is: install binaries, configure TLS, initialize the database once, start the locked server, sign in and unlock, create secrets and an agent identity, then enroll the agent. The service units in `examples/systemd/` require no edits when these paths are used.

## 1. Build and install

Install Go 1.25 or newer on your build host, then run:

```sh
make build
sudo install -m 0755 bin/ssm-server /usr/local/bin/ssm-server
sudo install -m 0755 bin/ssm-agent /usr/local/bin/ssm-agent
sudo install -d -m 0755 /usr/local/share/doc/ssm
sudo install -m 0644 README.md setup.md /usr/local/share/doc/ssm/
ssm-server -v
ssm-agent -v
```

Both commands must print `0.0.2`. You can instead install the binaries from the appropriate `make release` archive. Server and agent hosts need only their respective binary. Building releases requires Go but running them does not.

Create a dedicated server account and private directories:

```sh
sudo useradd --system --home-dir /var/lib/ssm-server --shell /usr/sbin/nologin ssm-server
sudo install -d -m 0700 -o ssm-server -g ssm-server /etc/ssm-server /etc/ssm-server/tls /var/lib/ssm-server
sudo install -m 0600 -o ssm-server -g ssm-server examples/server.yaml /etc/ssm-server/config.yaml
```

If the account already exists, skip `useradd`. Allow inbound TCP 8443 only from your intended administration, agent, and Kubernetes networks.

## 2. Configure certificates

Install a server certificate whose Subject Alternative Name includes the hostname clients will use. `server.crt` should include any intermediate chain certificates; `server.key` is the corresponding private key.

```sh
sudo install -m 0644 -o ssm-server -g ssm-server /path/to/server-fullchain.pem /etc/ssm-server/tls/server.crt
sudo install -m 0600 -o ssm-server -g ssm-server /path/to/server-key.pem /etc/ssm-server/tls/server.key
```

For a private CA, install its root certificate in the administrator browser's trust store and provide it to agents using `ca_file`. There is no insecure TLS verification option. The server has no plaintext HTTP listener and rejects non-TLS API requests. A reverse proxy must use HTTPS to the SSM backend as well; configure it not to log request bodies or Authorization/Cookie headers. Do not place unlock keys or credentials in URLs.

For an isolated lab without an existing CA, you can create one on a trusted workstation with OpenSSL. Keep the CA private key off the SSM server:

```sh
umask 077
openssl req -x509 -newkey rsa:3072 -nodes -days 3650 \
  -keyout lab-ca.key -out lab-ca.crt -subj '/CN=Homelab SSM CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl req -newkey rsa:3072 -nodes -keyout server.key -out server.csr \
  -subj '/CN=ssm.home.arpa'
cat > server.ext <<'EXT'
subjectAltName=DNS:ssm.home.arpa
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EXT
openssl x509 -req -in server.csr -CA lab-ca.crt -CAkey lab-ca.key \
  -CAcreateserial -out server.crt -days 365 -sha256 -extfile server.ext
```

Install `server.crt` and `server.key` using the paths above, distribute only `lab-ca.crt` to clients, and make sure DNS resolves `ssm.home.arpa`. Renew certificates before expiry and restart SSM to load replacements; restart requires another unlock.

## 3. Initialize the database once

Edit `/etc/ssm-server/config.yaml` if needed:

```yaml
listen: ":8443"
storage: sqlite
dsn: /var/lib/ssm-server/ssm.db
tls_cert: /etc/ssm-server/tls/server.crt
tls_key: /etc/ssm-server/tls/server.key
session_ttl: 8h
log_level: info
```

`session_ttl` is an absolute session lifetime, not an idle timeout. Supported log levels are `debug`, `info`, `warn`, and `error`. The database schema is created/migrated automatically and its version recorded in `schema_migrations`. Never run setup against a running server.

Choose a unique administrator password of at least 12 characters and a randomly generated master key of at least 16 characters. A 32-byte random key stored in your password manager is a good choice. **Keep a recovery copy of the master key outside this host.** SSM stores only the wrapped data-encryption key, never the plaintext master key.

The setup and unlock commands read credential files instead of command-line secret arguments. This example uses temporary files in `/run` and hidden terminal input, avoiding shell history and process-list exposure. Run the following in a root Bash shell (`sudo bash`):

```sh
umask 077
install -d -m 0700 -o ssm-server -g ssm-server /run/ssm-bootstrap
read -rsp 'Administrator password: ' ssm_password; echo
printf '%s' "$ssm_password" > /run/ssm-bootstrap/password
unset ssm_password
read -rsp 'Master key (already saved externally): ' ssm_master; echo
printf '%s' "$ssm_master" > /run/ssm-bootstrap/master
unset ssm_master
chown ssm-server:ssm-server /run/ssm-bootstrap/password /run/ssm-bootstrap/master
runuser -u ssm-server -- /usr/local/bin/ssm-server -setup \
  -config /etc/ssm-server/config.yaml -admin admin \
  -password-file /run/ssm-bootstrap/password \
  -master-key-file /run/ssm-bootstrap/master
rm -f /run/ssm-bootstrap/password /run/ssm-bootstrap/master
rmdir /run/ssm-bootstrap
exit
```

Check that setup reports completion before deleting the temporary inputs. Setup refuses an initialized database. It creates the first administrator and encrypted key envelope in one transaction and leaves the server locked. Administrator password hashes use bcrypt; bearer tokens use SHA-256 hashes of cryptographically random 256-bit credentials. The master wrapping key uses scrypt with a random salt. Values and the wrapped DEK use AES-256-GCM with fresh random nonces.

## 4. Start and unlock the server

```sh
sudo install -m 0644 examples/systemd/ssm-server.service /etc/systemd/system/ssm-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now ssm-server
sudo journalctl -u ssm-server -n 30 --no-pager
```

Open `https://ssm.home.arpa:8443`. Sign in with the administrator created during setup. The persistent header shows **SSM v0.0.2** and **LOCKED**. Select **Server & audit**, enter the master key, and choose **Unlock server**. The header changes to **UNLOCKED**. Authentication, agent management, and metadata listings remain available while locked; operations on secret values do not.

For CLI unlock, create mode-0600 temporary password/master files as in the previous step, then run:

```sh
ssm-server -unlock -server https://ssm.home.arpa:8443 \
  -ca-file /path/to/lab-ca.crt -admin admin \
  -password-file /run/ssm-bootstrap/password \
  -master-key-file /run/ssm-bootstrap/master
```

Remove those temporary files afterward. Run the command as the identity that can read them. CLI unlock logs in, obtains a CSRF token, unlocks over HTTPS, and logs out. Unlock bodies and responses are not logged; API responses include `Cache-Control: no-store`.

Use **Lock server** to discard the in-memory DEK. Every restart starts locked. `SIGTERM` and `SIGINT` stop accepting requests, drain in-flight requests, lock the vault, and close the database.

To rotate the master key, use **Change master key** with the current and new keys. This re-wraps the same DEK and leaves stored secret ciphertext unchanged. The old key no longer unlocks the current database; older backups still require their original master key.

## 5. Create secrets and an agent identity

In **Secrets**, create these example paths:

- `servers/web01/database-password`
- `servers/web01/api-token`

Paths are case-sensitive, relative names separated by `/`. Leading/trailing slashes, empty components, `.`/`..`, backslashes, percent signs, control characters, and wildcards in secret names are rejected. The WebUI lists path, revision, creation time, and update time. It retrieves values only when you choose **Reveal** or **Copy**. Close the reveal dialog to clear the displayed value.

In **Agents & permissions**, create an agent named `web01` with this permission:

```text
servers/web01/*
```

Permissions are default-deny. An exact rule grants that one secret; a terminal `/*` grants descendants, including deeper paths. `servers/web01/*` does not grant `servers/web010/password` or the parent `servers/web01`. Agents have read-only access. Administrators can also issue separate write credentials for scoped automated updates, as described below.

In **Enrollment tokens**, select the new agent and generate a token. Expiry is configurable from 1 to 86,400 seconds. Copy it immediately; the plaintext is shown only in the creation response. A token is consumed by successful enrollment. Only one runtime credential can enroll an identity; other outstanding tokens for that identity stop working afterward. You can delete unused tokens.

### Scoped write credentials and curl updates

In **Write credentials**, choose a name such as `certbot-example.com`, enter the
paths it may update (one per line), and select **Create write credential**. Exact
paths and terminal `/*` subtree rules work just like agent permissions. Copy the
token immediately; it is displayed only once. Use **Edit paths** to change its
scope or **Revoke** to permanently disable it. An empty path list denies all
updates. These credentials remain valid until revoked.

Create the target secret through the WebUI first. A write credential can only
update existing secrets: it cannot read their values, create or delete secrets,
enroll agents, unlock SSM, or access administrative endpoints. The server must
be unlocked for an update to succeed. Agent bearer tokens remain read-only.

A simple HTTPS POST updates the value (replace the placeholders):

```sh
curl --fail --silent --show-error \
  --cacert /path/to/lab-ca.crt \
  -H 'Authorization: Bearer YOUR_WRITE_TOKEN' \
  -H 'Content-Type: application/json' \
  --data-binary '{"value":"NEW_SECRET_VALUE"}' \
  https://ssm.home.arpa:8443/api/v1/write/certificates/example.com/fullchain
```

`--data-binary` makes this a POST. No administrator login, cookie, or CSRF token
is needed. The response contains the path, revision, timestamps, and encryption
algorithm, never the value. Repeating an identical value leaves its revision
unchanged. An out-of-scope path returns 403, a missing/deleted secret returns 404,
a revoked/invalid credential returns 401, and a locked server returns 503.

For an unattended hook, keep the token out of command-line arguments and shell
history: put `Authorization: Bearer YOUR_WRITE_TOKEN` in a root-owned mode-0600
file such as `/etc/ssm-writer/authorization.header`. For a PEM certificate, use
`jq --rawfile` to encode newlines correctly instead of interpolating it into JSON:

```sh
jq -n --rawfile value "$RENEWED_LINEAGE/fullchain.pem" '{value: $value}' |
  curl --fail --silent --show-error \
    --cacert /path/to/lab-ca.crt \
    --header @/etc/ssm-writer/authorization.header \
    -H 'Content-Type: application/json' \
    --data-binary @- \
    https://ssm.home.arpa:8443/api/v1/write/certificates/example.com/fullchain
```

The file example requires `jq`; `RENEWED_LINEAGE` is supplied by the deploy-hook
caller. Grant only the paths that hook needs. Separate updates are not an atomic
certificate/key pair; deploy a single combined secret when your application
supports it, or coordinate the receiving application's reload after both files
are ready. Writer identities, permission changes, revocations, and successful or
failed updates are audited without plaintext tokens or values.

Upgrading from 0.0.1 preserves existing secrets and agents. Write credentials use
new record kinds in the existing storage schema, so no SQL migration is needed.

## 6. Install and enroll the agent

On the agent host, install `ssm-agent` in `/usr/local/bin`, then:

```sh
sudo install -d -m 0700 /etc/ssm-agent /etc/ssm-agent/templates /etc/ssm-agent/secrets /var/lib/ssm-agent
sudo install -d -m 0700 /etc/myapp
sudo install -m 0600 examples/agent/config.yaml /etc/ssm-agent/config.yaml
sudo install -m 0600 examples/agent/templates/database.templ /etc/ssm-agent/templates/database.templ
sudo install -m 0600 examples/agent/secrets/database.yaml /etc/ssm-agent/secrets/database.yaml
sudo install -m 0600 examples/agent/secrets/raw.yaml /etc/ssm-agent/secrets/raw.yaml
sudo install -m 0644 /path/to/lab-ca.crt /etc/ssm-agent/ca.crt
```

Edit `/etc/ssm-agent/config.yaml` to set the server origin and one-time enrollment token. Keep the file root-owned and mode 0600. Use a trusted local editor, not a command containing the token in its arguments.

```yaml
server: https://ssm.home.arpa:8443
ca_file: /etc/ssm-agent/ca.crt
enrollment_token: YOUR_ONE_TIME_TOKEN
poll_interval: 30s
state_dir: /var/lib/ssm-agent
templates_dir: /etc/ssm-agent/templates
secrets_dir: /etc/ssm-agent/secrets
log_level: info
```

Install and start the supplied unit unchanged:

```sh
sudo install -m 0644 examples/systemd/ssm-agent.service /etc/systemd/system/ssm-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now ssm-agent
sudo journalctl -u ssm-agent -n 30 --no-pager
sudo stat -c '%a %U:%G %n' /var/lib/ssm-agent/credentials.json /etc/myapp/database.conf /etc/myapp/api-token
```

Enrollment stores a separate runtime credential in `/var/lib/ssm-agent/credentials.json` with mode 0600. The agent stops using the enrollment token, including after restart. Remove the used enrollment token from `config.yaml`; SSM does not rewrite the operator's configuration file.

If enrollment succeeded on the server but its response or local credential write was lost, the one-time token cannot be replayed. Revoke that identity, create a new identity and enrollment token, and enroll again. If a runtime credential is revoked, the agent retains existing files and logs failed polls; it never silently re-enrolls with an old token.

For a one-shot verification, stop the service and use `sudo ssm-agent -once`. A process lock prevents simultaneous agents from sharing the same state directory.

### Definition files and templates

Each `/etc/ssm-agent/secrets/<name>.yaml` defines one delivery:

```yaml
path: servers/web01/database-password
template: database.templ
destination: /etc/myapp/database.conf
owner: root
group: root
mode: "0600"
command: ["/usr/bin/systemctl", "try-restart", "myapp.service"]
command_timeout: 30s
```

Owner/group accept names or numeric IDs; omitted owner/group use the agent process identity for the newly created file. Mode defaults to `0600`; quote octal modes in YAML. Do not enable the sample hook until the referenced application service exists.

The template lives at `/etc/ssm-agent/templates/database.templ`. Templates receive `.Value`, `.Path`, and `.Revision`; unknown fields fail rather than silently producing empty configuration. This is Go's `text/template`, so values are **not** automatically escaped for JSON, shell, INI, or your application's grammar. Choose a suitable template or store an already serialized configuration as the secret value. Server-provided text is template data, never parsed as a template or command.

Omit `template` to write the raw value without adding a newline. Destinations must be clean absolute paths with existing parent directories. SSM rejects symlinks in the destination or any parent, and rejects destinations inside its own configuration/state directories. It does not create arbitrary destination directories for you. Keep parent directories under trusted ownership: an administrator who can rename those directories can redirect where applications look for files.

The agent writes a temporary file in the destination directory, applies ownership and permissions, flushes it, renames it atomically, then flushes the directory. Readers opening the path see a complete old or new file. Applications holding an old file descriptor must reopen it; use a reload/restart hook if needed. Hard-link aliases of the old inode are not updated.

### Polling, failures, and hooks

Every poll first retrieves revision metadata. The agent downloads values only for a changed revision, a changed definition/template, or a missing/modified deployed file. It saves successful revisions and output/configuration fingerprints in `/var/lib/ssm-agent/revisions.json`. An unchanged value does not increment a server revision. Delete/recreate keeps a monotonically increasing revision through an internal tombstone.

Failed HTTP requests, a locked server, failed rendering, and failed file writes leave the deployed value intact and are retried on the next interval. A failed hook leaves the new file deployed and records a pending hook for retry. Hook output is discarded to avoid logging secrets. Commands use a local argv array, without automatic shell expansion, and have a timeout (default 30 seconds). Shutdown cancels HTTP requests and hook process groups while letting a file replacement already in progress complete atomically.

Hook execution is at least once: a crash after command execution but before journal persistence can cause another execution. Use idempotent hooks. Synchronization is atomic per file, not across a group of files. A removed definition, deleted server secret, or revoked permission does not delete the deployed file. Remove old files explicitly when decommissioning applications.

The sample agent service runs as root to support arbitrary destination ownership and local service restarts. It intentionally does not use a private temporary directory or read-only filesystem sandbox that would hide configured destinations. You may harden it further around your actual destination and command requirements.

## 7. Use MySQL instead of SQLite

Provision a dedicated database on MySQL 8.0 or newer (tests use MySQL 8.4). Run database administration separately, then grant the SSM account access only to that database:

```sql
CREATE DATABASE ssm CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE USER 'ssm'@'YOUR_SERVER_ADDRESS' IDENTIFIED BY 'USE_A_UNIQUE_DATABASE_PASSWORD';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX ON ssm.* TO 'ssm'@'YOUR_SERVER_ADDRESS';
```

Set the server configuration before initial setup:

```yaml
storage: mysql
dsn: 'ssm:YOUR_DATABASE_PASSWORD@tcp(db.home.arpa:3306)/ssm?tls=true&timeout=10s&readTimeout=30s&writeTimeout=30s'
```

Use a database certificate verified by the SSM host's system trust store for `tls=true`; install your internal database CA there if needed. A local Unix socket DSN is another option. The server's HTTPS certificate options configure client-facing TLS, not MySQL TLS. Restrict the config file because its DSN contains the database password.

Both engines implement the same transactional storage interface. A database mutex row serializes changes, making one-time token redemption and revision increments atomic. MySQL uses InnoDB and case-sensitive identifier collation. Schema migration 1 is idempotent, records its completed version, and rejects a database from a newer schema version. Back up before any binary upgrade. This version does not provide an automatic SQLite-to-MySQL conversion command.

## 8. Connect Kubernetes External Secrets Operator

Install ESO in your cluster using its upstream instructions. The [official generic webhook provider documentation](https://external-secrets.io/main/provider/webhook/) describes the `SecretStore` webhook, credential labels, and CA options used here. The checked-in example uses `external-secrets.io/v1`; make sure your installed CRDs serve that version.

Create a dedicated SSM agent identity named `k8s-homelab` and grant **only** `k8s/homelab/*`. Generate its one-time enrollment token. This identity is for ESO, so do not share it with a host agent.

Redeem the token using a private JSON request file with contents `{"token":"YOUR_ENROLLMENT_TOKEN"}` and mode 0600. For example, with Python 3 on a trusted workstation:

```sh
umask 077
python3 - <<'PY'
import getpass, json
with open('enrollment.json', 'w') as f:
    json.dump({'token': getpass.getpass('Enrollment token: ')}, f)
PY
curl --fail --silent --show-error --cacert /path/to/lab-ca.crt \
  -H 'Content-Type: application/json' --data-binary @enrollment.json \
  https://ssm.home.arpa:8443/api/v1/enroll > runtime.json
python3 - <<'PY'
import json
with open('runtime.json') as f:
    runtime = json.load(f)
with open('runtime-token', 'w') as f:
    f.write(runtime['token'])
PY
kubectl create namespace apps
kubectl -n apps create secret generic ssm-runtime-credential --from-file=token=runtime-token
kubectl -n apps label secret ssm-runtime-credential external-secrets.io/type=webhook
kubectl -n apps create configmap ssm-ca --from-file=ca.crt=/path/to/lab-ca.crt
rm -f enrollment.json runtime.json runtime-token
kubectl apply -f examples/eso.yaml
```

Check each command succeeds before continuing. If `apps` already exists, skip its creation. Create `k8s/homelab/application-password` in SSM. Then inspect `kubectl -n apps describe externalsecret application-password`. ESO calls the HTTPS endpoint using its dedicated bearer credential and extracts `$.data.value`. Access outside the assigned subtree returns 403. Keep Kubernetes RBAC narrow around the runtime-credential Secret.

The sample `ExternalSecret` retains the Kubernetes Secret if SSM reports the source deleted. A locked server returns 503 so ESO can retry. Rotating a Kubernetes runtime credential means creating/enrolling a replacement identity, updating its Kubernetes Secret, verifying synchronization, and revoking the previous identity. The repository tests the HTTPS response/authentication contract; an actual cluster installation should also verify its ESO reconciliation status.

## 9. API reference

All JSON endpoints begin with `/api/v1/`. Successful operations currently return 200 with JSON. Errors return `{"error":"message"}` and an appropriate status: 400 invalid input, 401 missing/invalid/expired credentials, 403 denied permission or CSRF, 404 missing resource, 405 unsupported method, 409 duplicate secret creation, 429 authentication rate limit, 503 locked/unavailable, or 500 internal failure.

| Method | Endpoint | Authentication / behavior |
| --- | --- | --- |
| GET | `/health` | Public; minimal liveness, available locked |
| GET | `/ready` | Public; 503 when locked or DB unavailable |
| POST | `/login` | `{name,password}`; secure session cookie and CSRF token |
| POST | `/enroll` | `{token}`; consumes one-time token, returns `{id,token}` |
| GET | `/metadata/<path>` | Agent bearer; path, revision, timestamps, algorithm |
| POST | `/write/<path>` | Dedicated write bearer; update existing secret with `{value}` |
| GET | `/secrets/<path>` | Agent bearer; scoped secret value |
| GET | `/admin/session` | Administrator; session information and CSRF token |
| POST | `/admin/logout` | Administrator + CSRF; invalidate session |
| GET | `/admin/status` | Administrator; version and lock status |
| POST | `/admin/unlock` | Administrator + CSRF; `{master}` |
| POST | `/admin/lock` | Administrator + CSRF |
| POST | `/admin/master` | Administrator + CSRF; `{old,new}` master keys |
| GET | `/admin/secrets` | Administrator; metadata-only listing, even locked |
| GET / POST / PUT / DELETE | `/admin/secrets/<path>` | Administrator; read/create/update/delete; writes use `{value}` |
| GET / POST | `/admin/write-credentials` | Administrator; list or create `{name,paths:[...]}`, returning a token once |
| PUT / DELETE | `/admin/write-credentials/<id>` | Administrator; replace `{paths:[...]}` or permanently revoke |
| GET / POST | `/admin/agents` | Administrator; list or create `{name,paths:[...]}` |
| PUT / DELETE | `/admin/agents/<id>` | Administrator; replace `{paths:[...]}` or revoke |
| GET / POST | `/admin/enrollment` | Administrator; list or create `{agent_id,ttl_seconds}` |
| DELETE | `/admin/enrollment/<id>` | Administrator; delete enrollment token |
| GET / POST | `/admin/administrators` | Administrator; list names or create/change `{name,password}` |
| DELETE | `/admin/administrators/<name>` | Administrator; delete another administrator |
| GET | `/admin/audit` | Administrator; audit records |

Table paths are relative to `/api/v1`. All administrative writes require `X-CSRF-Token` from the login/session response and the `ssm_session` cookie. Browser writes are restricted to the same HTTPS origin; cross-origin CORS access is not enabled. Cookie attributes are Secure, HttpOnly, and SameSite=Strict. Password changes invalidate that administrator's sessions. Self-deletion is rejected to avoid removing the last usable administrator accidentally.

Secret read response:

```json
{
  "data": {"value": "example"},
  "path": "servers/web01/api-token",
  "revision": 1,
  "created_at": "2026-09-14T12:00:00Z",
  "updated_at": "2026-09-14T12:00:00Z"
}
```

Metadata responses omit `data` and ciphertext. Values are UTF-8 JSON strings; encode binary material yourself if needed. Requests are limited to roughly 2 MiB and should remain small. Administrators are full managers; per-administrator roles are not implemented. Agent permissions never grant administrative access.

## 10. Monitoring, audit, backup, and recovery

Liveness/readiness checks require TLS trust just like normal clients:

```sh
curl --fail --cacert /path/to/lab-ca.crt https://ssm.home.arpa:8443/api/v1/health
curl --fail --cacert /path/to/lab-ca.crt https://ssm.home.arpa:8443/api/v1/ready
```

Health is available locked; readiness returns 503 locked. Neither exposes secret names, database credentials, or encryption material. An uninitialized database also remains unready until setup and unlock.

Server and agent logs use structured JSON with configurable levels. Audit records in the database capture timestamps, identity, operation, success/failure, secret path where relevant, and the direct peer source address. The server deliberately ignores forwarded source headers; behind a proxy, the source is the proxy. Audit access uses **Server & audit → Load audit records** or `/api/v1/admin/audit`. Request bodies, plaintext bearer credentials, and secret values are excluded. Audit records are not tamper-proof against someone with database write access; export/retain database backups accordingly. Listings and audit retrieval are unpaginated in 0.0.2, so monitor database growth; there is no automatic retention cleanup.

For a simple consistent SQLite backup, stop SSM, copy its entire state directory, then restart and unlock:

```sh
sudo systemctl stop ssm-server
sudo tar -C /var/lib -czf /secure/backup/ssm-server-state.tar.gz ssm-server
sudo systemctl start ssm-server
```

Create and restrict `/secure/backup` before running this example. Include the DB plus WAL/SHM files if present; copying only a live SQLite main database is not sufficient. For MySQL use a consistent database backup such as your normal InnoDB backup procedure. Also back up restricted server configuration and TLS material separately. Store the master key independently from database backups.

To restore, stop SSM, restore the database/state and matching configuration, set the original ownership and restrictive modes, start SSM, and unlock with the master key valid for that backup. Restoring an older database also restores old permissions, runtime credentials, and revisions. Review and revoke stale identities before reconnecting clients. Agents compare revisions for inequality, so a restored lower revision can still redeploy correctly. Existing agent credentials only work if their enrollment existed in the restored database.

To upgrade, back up first, stop the service, replace its binary, and restart. Migrations run before listening. Verify `-v` on both installed binaries and the persistent WebUI version, then unlock. Rollback requires a database backup if a future migration changes the schema incompatibly.

## 11. Development verification

```sh
make check
make release
```

The suite covers path normalization and boundary authorization; encryption, tampering, and envelope rotation; SQLite persistence and migrations; session/CSRF and runtime authentication; enrollment expiration and concurrent redemption; atomic file readers and symlinks; templates and local hook retries; revision behavior; and a TLS agent/server polling integration.

To exercise MySQL too, use a disposable local container:

```sh
docker run --detach --rm --name ssm-mysql-test \
  --publish 127.0.0.2:33316:3306 \
  --env MYSQL_ROOT_PASSWORD=ssm-test-only-password \
  --env MYSQL_DATABASE=ssm_test mysql:8.4
# Wait until the database reports it is ready before running tests.
MYSQL_TEST_DSN='root:ssm-test-only-password@tcp(127.0.0.2:33316)/ssm_test?timeout=5s' make test-mysql
docker stop ssm-mysql-test
```

The database password above is only for the disposable loopback test container. Tests exercise actual MySQL transactions, migrations, and the complete server lifecycle. MySQL-specific tests clearly skip when no DSN is provided; a skipped backend test is not verification of that backend.
