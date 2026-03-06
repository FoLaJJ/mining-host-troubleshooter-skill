# Login Methods

Use the least-privileged method that still allows diagnostics.

## 1) Local Shell

Use when physically on host or in a trusted console.

```bash
whoami
hostname
```

## 2) SSH with Private Key File

Preferred for production hosts.

```bash
ssh -i /path/to/id_rsa user@host -p 22
```

Before the first session, verify the remote host key through either:

1. an already trusted `known_hosts` entry, or
2. an out-of-band fingerprint from the asset owner or CMDB.

## 3) SSH with Agent-Loaded Key

Use when the key is managed by `ssh-agent`.

```bash
ssh-add -l
ssh user@host
```

Do not accept unknown host keys automatically.

## 4) SSH Password Authentication

Use only when key auth is unavailable.

```bash
ssh user@host
```

Rules:

1. Never place plaintext passwords in shell command lines if a safer path exists.
2. Prefer environment-variable input or a secure prompt.
3. Do not store plaintext passwords in command history, scripts, or reports.

## 5) SSH via Jump Host

Use for segmented networks.

```bash
ssh -J jump_user@bastion target_user@target_host
```

The target host key still must be pinned or already trusted.

## 6) Public Key Enrollment (When Needed)

If the user explicitly approves key enrollment:

```bash
ssh-copy-id -i <public-key-path>.pub <target_user>@<target_host>
```

Treat this as a change operation and request approval before execution.

## Session Pre-Checks

Before deep diagnostics, verify:

1. Correct target host identity.
2. Host-key trust source: `known_hosts` or pinned fingerprint.
3. Timezone and obvious clock drift.
4. Access scope: read-only, user, sudo, or root.
5. Maintenance constraints and blackout windows.

## Strong Host Identity Pattern

Preferred order:

1. Existing trusted `known_hosts` entry.
2. Out-of-band SHA256 fingerprint provided by the user or asset inventory.
3. Only after trust is established, begin evidence collection.

If the host key is unknown and no trusted fingerprint is provided, stop and ask for a trust source instead of auto-accepting.

## Security and Privacy Rules

1. Never echo private keys.
2. Never paste plaintext passwords or tokens into reports.
3. Public IPs may remain visible in internal reports when needed for traceability.
4. Mask usernames or account names only for external sharing copies when required.
5. Prefer short-lived sessions and log out cleanly.
