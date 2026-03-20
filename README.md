# SquidKeys Go

SquidKeys is a local-first encrypted secret store for agent systems and adjacent developer tooling. It stores secrets in DuckDB, protects secret payloads with per-record data encryption keys wrapped by versioned KEKs, exposes a small HTTP API, and also ships an MCP server for local agents.

This Go port currently supports:

- Authorization records for OAuth-style tokens and API credentials
- Password records for opaque secret blobs
- Certificate records for X.509 bundles plus private key material
- Git profile manifests that reference other stored records without performing machine-side switching

## What SquidKeys Is

SquidKeys is the storage layer.

It is responsible for:

- Encrypting secret material at rest
- Validating record shapes and cross-record references
- Returning secrets to local callers over HTTP or MCP
- Tracking KEK versions and rewrapping encrypted records

It is not responsible for:

- Choosing the current Git profile
- Editing `git config`
- Rewriting remotes
- Managing `~/.ssh/config`
- Materializing secret refs to files on disk

That split is intentional. A separate switcher such as `gat` should own switching behavior, while SquidKeys owns durable local storage.

## Data Flow Charts

### Secret Storage and Retrieval Flow

This is the core write/read path for authorization, password, and certificate payloads.

```mermaid
flowchart LR
  Caller[Local caller]
  API[HTTP API or MCP tool]
  Validate[Validate input and record shape]
  DEK[Generate per-record DEK]
  Encrypt[Encrypt secret payload with DEK]
  Wrap[Wrap DEK with active KEK]
  DB[(DuckDB)]
  Lookup[Lookup record and metadata]
  Unwrap[Unwrap DEK with stored KEK version]
  Decrypt[Decrypt payload]

  Caller --> API
  API --> Validate
  Validate --> DEK
  DEK --> Encrypt
  DEK --> Wrap
  Encrypt --> DB
  Wrap --> DB

  Caller -->|read request| API
  API --> Lookup
  DB --> Lookup
  Lookup --> Unwrap
  DB --> Unwrap
  Unwrap --> Decrypt
  Decrypt --> API
  API --> Caller
```

### Git Profile Resolution Flow

This shows the split between SquidKeys as storage and the external switcher as the component that changes machine state.

```mermaid
flowchart LR
  Switcher[Switcher app]
  Profiles[Git profile manifest]
  Refs[Secret refs]
  Auth[Authorization record]
  Pwd[Password record]
  Cert[Certificate record]
  Apply[Apply git and ssh config outside SquidKeys]

  Switcher -->|list and fetch| Profiles
  Profiles --> Refs
  Refs --> Auth
  Refs --> Pwd
  Refs --> Cert
  Auth --> Switcher
  Pwd --> Switcher
  Cert --> Switcher
  Switcher --> Apply
```

### KEK Rotation and Rewrap Flow

This is the data path for rotating wrapped DEKs without rewriting plaintext secrets from the caller side.

```mermaid
flowchart TD
  Start[Rewrap request]
  Load[Load records with non-target KEK version]
  Unwrap[Unwrap stored DEK with old KEK]
  Rewrap[Wrap same DEK with target KEK]
  Update[Update wrapped DEK and kek_version]
  Finish[Sync active KEK version]

  Start --> Load
  Load --> Unwrap
  Unwrap --> Rewrap
  Rewrap --> Update
  Update --> Finish
```

## Supported Data Model

### Authorizations

Use authorization records for provider-bound access tokens, refresh tokens, scopes, and expiration times.

Examples:

- OAuth access tokens
- GitHub App or GitLab OAuth-style credentials
- API tokens that naturally belong to a `provider` and optional `account_id`

### Passwords

Use password records for opaque blobs that should be stored as encrypted text.

Examples:

- Personal access tokens
- SSH private keys stored as text
- GPG private key blobs
- Passphrases

### Certificates

Use certificate records for X.509 bundles when you want the certificate chain, private key, and passphrase stored together and you want SquidKeys to derive searchable certificate metadata.

Examples:

- Client certificates
- Signing certificates
- Internal PKI credentials for local automation

### Git Profile Manifests

Use Git profile manifests to describe a Git identity and point at the actual stored secrets required to activate it.

Examples:

- A work GitHub profile
- A personal GitLab profile
- A self-hosted Forgejo profile with custom host and signing settings

Important:

- Git profile manifests are not secret containers.
- They hold metadata plus refs to stored secrets in the same `agent_id`.
- The switcher app resolves those refs and applies host-side configuration.

## Installation

### Requirements

- Go 1.25.x
- A platform supported by `duckdb-go`

### Install From a Release Archive

If you publish packaged binaries, the release helper in `scripts/build-release.sh` produces archives named like:

- `squidkeys-go_0.2.0_linux_amd64.tar.gz`
- `squidkeys-go_0.2.0_darwin_arm64.tar.gz`
- `squidkeys-go_0.2.0_windows_amd64.tar.gz`

Once those archives are attached to a GitHub Release, a manual install looks like this:

```bash
VERSION="0.2.0"
GOOS="linux"
GOARCH="amd64"

curl -L \
  -o "squidkeys-go_${VERSION}_${GOOS}_${GOARCH}.tar.gz" \
  "https://github.com/LynnColeArt/squidkeys-go/releases/download/v${VERSION}/squidkeys-go_${VERSION}_${GOOS}_${GOARCH}.tar.gz"

tar -xzf "squidkeys-go_${VERSION}_${GOOS}_${GOARCH}.tar.gz"
cd "squidkeys-go_${VERSION}_${GOOS}_${GOARCH}"
install -m 0755 squidkeys-api /usr/local/bin/squidkeys-api
install -m 0755 squidkeys-mcp /usr/local/bin/squidkeys-mcp
```

The archive includes:

- `squidkeys-api`
- `squidkeys-mcp`
- `README.md`
- `API_SPEC.md`

### Build From Source

Build the HTTP API binary:

```bash
go build -o bin/squidkeys-api ./cmd/squidkeys-api
```

Build the MCP binary:

```bash
go build -o bin/squidkeys-mcp ./cmd/squidkeys-mcp
```

### Install From a Checkout

Install both commands into your Go bin directory:

```bash
go install ./cmd/squidkeys-api
go install ./cmd/squidkeys-mcp
```

If you want the binaries on your shell path, make sure `$(go env GOPATH)/bin` or your configured `GOBIN` is on `PATH`.

### Build Release Archives Locally

Package the current platform:

```bash
./scripts/build-release.sh
```

Package a small release matrix:

```bash
SQUIDKEYS_RELEASE_TARGETS="linux/amd64 linux/arm64 darwin/arm64 windows/amd64" \
  ./scripts/build-release.sh
```

Write archives to a custom directory:

```bash
SQUIDKEYS_RELEASE_DIR="$PWD/out" ./scripts/build-release.sh
```

The script writes tarballs plus a versioned checksum file into `dist/` by default.

## Configuration

SquidKeys needs a local DB path plus one of the supported KEK configurations.

### Required Secret-Key Configuration

Choose one:

- `KEY_STORE_KEKS_JSON`
- `KEY_STORE_MASTER_KEY`

`KEY_STORE_KEKS_JSON` is preferred. It should be a JSON object of KEK version to URL-safe base64-encoded 32-byte key.

Example:

```bash
export KEY_STORE_KEKS_JSON='{"v1":"REPLACE_WITH_BASE64URL_32_BYTE_KEY"}'
export KEY_STORE_ACTIVE_KEK_VERSION='v1'
```

Legacy single-key mode is still supported:

```bash
export KEY_STORE_MASTER_KEY='REPLACE_WITH_BASE64URL_32_BYTE_KEY'
```

### Useful Environment Variables

- `KEY_STORE_DB_PATH`
- `KEY_STORE_ACTIVE_KEK_VERSION`
- `KEY_STORE_BEARER_TOKEN`
- `KEY_STORE_API_HOST`
- `KEY_STORE_API_PORT`
- `KEY_STORE_MCP_TRANSPORT`

Defaults:

- API host: `127.0.0.1`
- API port: `8080`
- MCP transport: `stdio`
- DB path: `./keystore.duckdb`

## Quick Start

Start the HTTP API:

```bash
export KEY_STORE_MASTER_KEY='REPLACE_WITH_BASE64URL_32_BYTE_KEY'
export KEY_STORE_DB_PATH="$PWD/keystore.duckdb"
go run ./cmd/squidkeys-api
```

In another shell, save a password record:

```bash
curl \
  -X PUT http://127.0.0.1:8080/v1/passwords \
  -H 'Content-Type: application/json' \
  -d '{
    "agent_id": "desktop-agent",
    "name": "github-work-pat",
    "password": "ghp_example_token",
    "metadata": {
      "purpose": "https git auth"
    }
  }'
```

Fetch it back:

```bash
curl http://127.0.0.1:8080/v1/passwords/desktop-agent/github-work-pat
```

## Running the HTTP API

Run directly from source:

```bash
go run ./cmd/squidkeys-api
```

Run a built binary:

```bash
./bin/squidkeys-api
```

If you set `KEY_STORE_BEARER_TOKEN`, send it with requests:

```bash
curl \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  http://127.0.0.1:8080/v1/keys/status
```

## Running the MCP Server

Run directly from source:

```bash
go run ./cmd/squidkeys-mcp
```

Run a built binary:

```bash
./bin/squidkeys-mcp
```

This server currently uses `stdio` transport and is intended to be launched by a local MCP host.

## Illustrative Git Profile Workflow

Here is a practical example of how to use SquidKeys as the storage layer for Git profile switching.

### 1. Store the HTTPS credential

```bash
curl \
  -X PUT http://127.0.0.1:8080/v1/passwords \
  -H 'Content-Type: application/json' \
  -d '{
    "agent_id": "desktop-agent",
    "name": "github-work-pat",
    "password": "ghp_example_token"
  }'
```

### 2. Store the SSH private key as a password blob

```bash
curl \
  -X PUT http://127.0.0.1:8080/v1/passwords \
  -H 'Content-Type: application/json' \
  -d '{
    "agent_id": "desktop-agent",
    "name": "github-work-ssh",
    "password": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----"
  }'
```

### 3. Store the signing certificate bundle

```bash
curl \
  -X PUT http://127.0.0.1:8080/v1/certificates \
  -H 'Content-Type: application/json' \
  -d '{
    "agent_id": "desktop-agent",
    "name": "github-work-signing",
    "certificate_chain_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
    "private_key_pem": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n",
    "private_key_passphrase": "optional-passphrase"
  }'
```

### 4. Store the Git profile manifest

```bash
curl \
  -X PUT http://127.0.0.1:8080/v1/git-profiles \
  -H 'Content-Type: application/json' \
  -d '{
    "agent_id": "desktop-agent",
    "name": "work",
    "platform": "github",
    "host": "github.com",
    "git_username": "workuser",
    "git_email": "work@example.com",
    "preferred_transport": "ssh",
    "https_credential_ref": {
      "record_type": "password",
      "name": "github-work-pat"
    },
    "ssh_identity_ref": {
      "record_type": "password",
      "name": "github-work-ssh"
    },
    "signing_identity_ref": {
      "record_type": "certificate",
      "name": "github-work-signing"
    },
    "signing_format": "x509",
    "repo_matchers": [
      "github.com/work/*"
    ]
  }'
```

### 5. Let the switcher consume the manifest

The separate switcher should:

- list Git profile manifests from SquidKeys
- fetch the selected manifest
- resolve the referenced secret records
- write `git config`, SSH includes, and any helper files it needs
- track which profile is currently active outside of SquidKeys

That keeps the switching logic isolated from secret storage.

## Security Notes

- Secret payloads are encrypted with a per-record DEK wrapped by the active KEK.
- The DB directory is forced to mode `0700` and the DB file to `0600`.
- Authorization expiry parsing rejects naive timestamps and requires explicit RFC3339 offsets or `Z`.
- HTTP bearer auth is optional by design for localhost/local-first usage.
- Git profile manifests are plaintext metadata plus refs. They intentionally do not contain raw secrets.

Certificate limitations:

- PEM certificate chains are supported
- Private keys may be unencrypted PEM or legacy PEM-encrypted PEM blocks
- PKCS#12/PFX is not supported yet
- PKCS#8 `ENCRYPTED PRIVATE KEY` is not supported yet

## API Reference

The full API contract lives in [API_SPEC.md](API_SPEC.md).

High-level HTTP routes:

- `PUT/GET/DELETE /v1/authorizations`
- `PUT/GET/DELETE /v1/passwords`
- `PUT/GET/DELETE /v1/certificates`
- `PUT/GET/LIST/DELETE /v1/git-profiles`
- `GET /v1/keys/status`
- `POST /v1/keys/rewrap`

High-level MCP tools:

- `save_authorization`, `get_authorization`, `delete_authorization`
- `save_password`, `get_password`, `delete_password`
- `save_certificate`, `get_certificate`, `delete_certificate`
- `save_git_profile`, `get_git_profile`, `list_git_profiles`, `delete_git_profile`
- `key_status`, `rewrap_all_records`

## Development and Verification

Run the test suite:

```bash
go test ./...
```

Run the race detector:

```bash
go test -race ./...
```

Run `go vet`:

```bash
go vet ./...
```

Run the Python compatibility harness for the original authorization/password format:

```bash
./scripts/run-python-compat.sh
```

## Project Layout

- `cmd/squidkeys-api`: HTTP server entrypoint
- `cmd/squidkeys-mcp`: MCP server entrypoint
- `scripts/build-release.sh`: local release packaging helper
- `store.go`: encrypted store setup, schema, and KEK rewrap logic
- `api.go`: HTTP handlers
- `mcp.go`: MCP tool handlers
- `certificates.go`: certificate storage and X.509 parsing
- `gitprofiles.go`: Git profile manifest storage and ref validation
- `API_SPEC.md`: API contract
