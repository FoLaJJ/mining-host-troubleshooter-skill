# Restricted Permissions

Use this when the session does not have root or working sudo.

## First Commands

```bash
whoami
id
sudo -n true >/dev/null 2>&1 && echo sudo_nopasswd=yes || echo sudo_nopasswd=no
```

## What To Prioritize As A Normal User

1. Current user process tree.
2. Current user crontab and startup files.
3. Readable entries under `/proc`.
4. Readable systemd unit files and service metadata.
5. Readable shell histories, home-directory persistence, SSH keys, and suspicious binaries under the current user scope.
6. Socket visibility from `ss` or `netstat` if permitted.

## Required Language

If privileges are weak, say so directly. Example:

`[INCONCLUSIVE: sudo unavailable; some system-wide logs and process owner details may be incomplete]`

Do not imply full host coverage when only user-scope coverage was possible.
