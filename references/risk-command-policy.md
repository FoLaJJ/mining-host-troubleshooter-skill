# Risk Command Policy

This policy enforces business-host safety for the `mining-host-troubleshooter` skill.

## Risk Levels

## `read_only`

- Purpose: observation, evidence gathering, and integrity verification.
- Approval: not required.
- Expected effect: no intended system state change.

Examples:

- `journalctl -n 200`
- `dmesg -T | tail -n 200`
- `nvidia-smi`
- `ps aux`
- `ss -tulpn`
- `sha256sum /usr/bin/lsattr`

## `confirm_required`

This class is split into three approval gates.

### `reversible_change`

- Typical meaning: a state change that is usually reversible with a known rollback path.
- Approval: explicit approval required.
- Examples:
  - temporary GPU power or clock adjustment
  - limited service configuration change with known rollback

### `irreversible_change`

- Typical meaning: a change that can overwrite forensic context or cannot be safely rolled back without backup.
- Approval: explicit approval required.
- Must include backup or rollback preparation.
- Examples:
  - editing `/etc/*`, `*.conf`, `*.service`
  - package install/remove/upgrade
  - changing accounts, passwords, keys, cron, PAM, sudoers, or immutable attributes

### `business_interruption`

- Typical meaning: a change that can stop services, disconnect operators, or alter network reachability.
- Approval: explicit approval required.
- Must include expected disruption window.
- Examples:
  - `systemctl restart/stop/start`
  - `kill`, `pkill`, `killall`
  - `reboot`, `shutdown`
  - firewall or routing changes
  - forced log rotation during active collection
  - `mount` or `umount`

## `blocked`

- Purpose: destructive or clearly unsafe operations.
- Approval: stop by default; require explicit maintenance authorization and separate operational planning.
- Examples:
  - `rm -rf /`
  - `mkfs.*`
  - `dd if=... of=/dev/...`
  - `wipefs`, `fdisk`, `parted`, `sgdisk`
  - `curl ... | bash` / `wget ... | sh`
  - fork bomb payloads
  - firewall flush (`iptables -F`, `nft ... flush`)
  - direct write to `/etc/sudoers`
  - history or log destruction
  - `journalctl --vacuum-*` during live incident review

## Mandatory Confirmation Template

Use this template before a `confirm_required` command:

1. Proposed command(s):
2. Approval gate: `reversible_change` / `irreversible_change` / `business_interruption`
3. Why needed (linked to evidence):
4. Expected impact:
5. Side effects and risk:
6. Rollback plan:
7. Expected disruption window:
8. `Reply approve to continue or cancel.`

## Rollback Discipline

1. Back up configs before editing.
2. Snapshot current service status before disruptive actions.
3. Preserve command logs for audit.
4. Re-check service health, hashrate, and connectivity after rollback.

## Command Trust Prerequisite

Before executing sensitive diagnostics:

1. run `python scripts/preflight_environment.py`
2. if alias or function hijack is detected, prefer absolute paths
3. if command binary hash or path trust is suspicious, escalate as part of the incident rather than silently trusting the command
