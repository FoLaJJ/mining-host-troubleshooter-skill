# Command Trust Verification

Use this workflow when you suspect command tampering, alias hijacking, or shell-function interception.

## 1) Quick Integrity Preflight

```bash
python scripts/preflight_environment.py
```

Review:

1. command path and realpath
2. alias/function presence
3. world/group writable binary flags
4. package owner lookup

## 2) Manual Verification Commands

For a sensitive command such as `lsattr`:

```bash
type -a lsattr
alias lsattr
command -v lsattr
readlink -f "$(command -v lsattr)"
stat "$(command -v lsattr)"
sha256sum "$(command -v lsattr)"
```

Package ownership:

```bash
dpkg -S "$(command -v lsattr)"      # Debian/Ubuntu
rpm -qf "$(command -v lsattr)"      # RHEL/SUSE
pacman -Qo "$(command -v lsattr)"   # Arch
```

## 3) Bypass Alias/Function Traps

Use one of:

1. absolute path (`/usr/bin/lsattr`)
2. `command lsattr`
3. `\lsattr` (for alias bypass in compatible shells)

If `type -a` shows a shell function before binary path, treat it as suspicious.

## 4) If `lsattr` Is Compromised or Unavailable

1. Treat host as potentially compromised.
2. Continue with read-only evidence collection.
3. Use package verification and trusted baseline comparison.
4. Do not "fix in place" without explicit approval and containment plan.

## 5) Incident Escalation Trigger

Escalate as security incident when:

1. trusted command points outside expected system paths
2. critical binaries are world-writable
3. command hash diverges from approved baseline
4. multiple core utilities show alias/function hijack
