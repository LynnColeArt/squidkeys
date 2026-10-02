# SquidKeys API Spec

## Purpose

SquidKeys is a local-first storage API for secrets and secret-adjacent manifests.

It stores encrypted records for credentials and certificates, and it stores plaintext Git profile manifests that reference those records. It does not perform Git profile switching or host configuration changes.

For Git workflows, SquidKeys should be paired with a separate switcher app. SquidKeys stores the profile manifest and backing secrets; the switcher chooses the active profile and applies local machine state.

## Transports

SquidKeys exposes:

- HTTP endpoints
- MCP tools

The HTTP and MCP surfaces mirror the same logical record model.

## Authentication

HTTP bearer auth is optional.

- If `KEY_STORE_BEARER_TOKEN` is unset, requests are accepted without an `Authorization` header.
- If `KEY_STORE_BEARER_TOKEN` is set, send `Authorization: Bearer <token>`.

The opt-in organization HTTP mode is enabled by
`KEY_STORE_ORG_AUTH_POLICY_PATH`; it cannot be combined with the legacy token.
The version-1 policy names admin principals and reader principals with exact
`record_type`/`agent_id`/`name` grants (or `provider` and `account_id` for
authorizations). Tokens are verified against SHA-256 digests from the policy;
readers cannot write, delete, list git profiles, or access key endpoints.
Authorization GET requests from readers must explicitly include `account_id`.
In this mode all audit actors are derived from the verified principal, never
from the request body or `actor` query. Policy changes require restart.
Non-loopback API binding additionally requires a TLS certificate/key.
`GET /health` remains public. See README for deployment limitations.

MCP authentication depends on the host process that launches the server.

## Common Behavior

- Base path: `/v1`
- Content type: `application/json`
- Maximum JSON request body: 1 MiB
- Error payload:

```json
{
  "detail": "human-readable error"
}
```

Other shared rules:

- Authorization expiry timestamps must be RFC3339 with an explicit offset or `Z`.
- Git profile secret refs are validated on save and must point to an existing stored record in the same `agent_id`.
- Git profile manifests are metadata records. They are not encrypted because they do not contain secret payloads.

## Core Record Types

### Authorization

Secret payloads:

- `access_token`
- `refresh_token`

Searchable/plaintext fields:

- `agent_id`
- `provider`
- `account_id`
- `scopes`
- `token_type`
- `expires_at`
- `metadata`
- `kek_version`

### Password

Secret payload:

- `password`

Searchable/plaintext fields:

- `agent_id`
- `name`
- `username`
- `url`
- `metadata`
- `kek_version`

### Certificate

Encrypted payloads:

- `certificate_chain_pem`
- `private_key_pem`
- `private_key_passphrase`

Derived/searchable fields:

- `subject`
- `subject_common_name`
- `issuer`
- `issuer_common_name`
- `serial_number`
- `fingerprint_sha256`
- `not_before`
- `not_after`
- `dns_names`
- `email_addresses`
- `ip_addresses`
- `uris`
- `key_usages`
- `ext_key_usages`
- `is_ca`
- `public_key_algorithm`
- `private_key_algorithm`
- `signature_algorithm`
- `metadata`
- `kek_version`

Current certificate limitations:

- PEM certificate chains are supported
- Private keys may be unencrypted PEM or legacy PEM-encrypted blocks
- PKCS#12/PFX is not supported yet
- PKCS#8 `ENCRYPTED PRIVATE KEY` is not supported yet

### Git Profile Manifest

A Git profile record is a non-secret manifest.

Fields:

- `agent_id`
- `name`
- `platform`
- `host`
- `git_username`
- `git_email`
- `preferred_transport`
- `https_credential_ref`
- `ssh_identity_ref`
- `signing_identity_ref`
- `signing_format`
- `repo_matchers`
- `metadata`
- `created_at`
- `updated_at`

Semantics:

- `preferred_transport` is `ssh` or `https`
- `signing_format` is `ssh`, `gpg`, or `x509`
- SquidKeys does not track the currently active Git profile
- The switcher app is expected to resolve refs and apply host configuration

## Supporting Types

### SecretRef

Used by Git profile manifests to reference an existing stored record.

```json
{
  "record_type": "authorization | password | certificate",
  "name": "required for password and certificate refs",
  "provider": "required for authorization refs",
  "account_id": "optional for authorization refs"
}
```

Rules:

- `authorization` refs use `provider` and optional `account_id`
- `password` refs use `name`
- `certificate` refs use `name`

## HTTP Endpoints

### Health

`GET /health`

Response:

```json
{
  "status": "ok"
}
```

### Authorizations

`PUT /v1/authorizations`

Request:

```json
{
  "agent_id": "agent-a",
  "provider": "discord",
  "account_id": "user-123",
  "access_token": "token",
  "refresh_token": "refresh",
  "token_type": "Bearer",
  "scopes": ["identify"],
  "expires_at": "2026-02-09T10:00:00Z",
  "metadata": {
    "workspace": "primary"
  },
  "actor": "api"
}
```

`GET /v1/authorizations/{agent_id}/{provider}?account_id=<value>&actor=<value>`

`DELETE /v1/authorizations/{agent_id}/{provider}?account_id=<value>&actor=<value>`

### Passwords

`PUT /v1/passwords`

Request:

```json
{
  "agent_id": "agent-a",
  "name": "github-pat",
  "username": "workuser",
  "password": "secret",
  "url": "https://github.com",
  "metadata": {
    "team": "ops"
  },
  "actor": "api"
}
```

`GET /v1/passwords/{agent_id}/{name}?actor=<value>`

`DELETE /v1/passwords/{agent_id}/{name}?actor=<value>`

### Certificates

`PUT /v1/certificates`

Request:

```json
{
  "agent_id": "agent-a",
  "name": "github-work-signing",
  "certificate_chain_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "private_key_pem": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n",
  "private_key_passphrase": "optional-passphrase",
  "metadata": {
    "purpose": "signing"
  },
  "actor": "api"
}
```

`GET /v1/certificates/{agent_id}/{name}?actor=<value>`

`DELETE /v1/certificates/{agent_id}/{name}?actor=<value>`

### Git Profiles

`PUT /v1/git-profiles`

Request:

```json
{
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
  ],
  "metadata": {
    "owner": "ops"
  },
  "actor": "api"
}
```

`GET /v1/git-profiles/{agent_id}/{name}?actor=<value>`

`GET /v1/git-profiles?agent_id=<value>&platform=<value>&actor=<value>`

Returns a JSON array of Git profile manifests.

`DELETE /v1/git-profiles/{agent_id}/{name}?actor=<value>`

### KEK Management

`GET /v1/keys/status`

Response:

```json
{
  "active_kek_version": "v1",
  "loaded_kek_versions": ["v1", "v2"],
  "registered_kek_versions": [
    {
      "kek_version": "v1",
      "is_active": false,
      "created_at": "2026-03-20T00:00:00Z"
    }
  ]
}
```

`POST /v1/keys/rewrap`

Request:

```json
{
  "target_kek_version": "v2",
  "actor": "api"
}
```

Response:

```json
{
  "target_kek_version": "v2",
  "authorizations_rewrapped": 1,
  "passwords_rewrapped": 1,
  "certificates_rewrapped": 1
}
```

## MCP Tools

Authorization tools:

- `save_authorization`
- `get_authorization`
- `delete_authorization`

Password tools:

- `save_password`
- `get_password`
- `delete_password`

Certificate tools:

- `save_certificate`
- `get_certificate`
- `delete_certificate`

Git profile tools:

- `save_git_profile`
- `get_git_profile`
- `list_git_profiles`
- `delete_git_profile`

Key management tools:

- `key_status`
- `rewrap_all_records`

The MCP inputs mirror the HTTP JSON request shapes.

## Git Switching Boundary

SquidKeys stores:

- Git identity metadata
- refs to credentials, SSH identity material, and signing material

The switcher app owns:

- current-profile selection
- writing `git config`
- SSH include/config management
- remote rewriting
- helper-file materialization

This split is part of the design, not an omission.
