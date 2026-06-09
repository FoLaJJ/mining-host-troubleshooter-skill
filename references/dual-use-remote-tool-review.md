# Dual-Use Remote Tool Review

Use this when remote-control software such as Sunlogin, ToDesk, AnyDesk, RustDesk, TeamViewer, or similar tooling appears during a case and the authorization story is unclear.

## Core Rule

These tools are dual-use.

Their presence may reflect normal operations, pre-existing admin tooling, shadow IT, or attacker-enabled remote access.

Do not decide which story is true from the tool name alone.

## Default Classification

1. installed package or binary presence = `observed_fact`
2. running process or service presence = `observed_fact`
3. configured auto-start or persistence path = `observed_fact`
4. suspicious or unauthorized use = usually `inference`
5. attacker remote control through the tool = only with stronger corroboration

## Neutral First Questions

Ask these before escalating:

1. Is this host role one where remote-control software might legitimately exist?
2. Is the tool in an expected path, package source, or service name?
3. Does the runtime account match normal operations?
4. Do timestamps align with the suspected incident window?
5. Is there evidence of abnormal startup, replacement, sideloading, or user-context abuse?

## Evidence That Can Raise Suspicion

Treat these as supporting signals, not standalone proof:

1. remote-control binary or service appears on a host where it is not expected
2. path, hash, owner, unit file, or config differs from known-good expectations
3. startup entries or service fragments were added near the intrusion timeline
4. the tool runs under an unusual account or from a user-writable path
5. authentication, privesc, malware drop-path, or persistence evidence overlaps with the tool timeline
6. the named tool is present, but the binary path or service name is slightly different in a way that suggests masquerading

## Evidence That Should Hold Conclusions Back

These keep the result neutral or `inconclusive` unless stronger support exists:

1. only package presence is known
2. only a process name match is known
3. the host belongs to an environment where remote support tools are common
4. no supporting auth, startup, path, or timeline anomaly is visible
5. authorization status cannot be verified from host evidence alone

## Useful Read-Only Cross-Checks

1. process name vs `/proc/<pid>/exe` vs command line
2. service `ExecStart` vs actual runtime parent and child processes
3. package ownership vs on-disk path
4. startup metadata vs incident timeline
5. auth evidence vs declared operator story
6. host role vs expected software inventory

## Output Rules

Prefer wording like:

1. `Observed remote-control software presence`
2. `Observed remote-control runtime`
3. `Authorization could not be determined from host evidence alone`
4. `Suspicious use remains inconclusive because`
5. `Existing remote-control software may have been leveraged, but the current evidence does not confirm that reconstruction`

Avoid wording like:

1. `The attacker used Sunlogin`
2. `ToDesk proves remote takeover`
3. `AnyDesk was present, therefore compromise is confirmed`
4. `The tool is legitimate, therefore it is unrelated`

## Decision Boundary

Use this progression:

1. `observed presence`
2. `observed runtime`
3. `inconclusive suspicious use`
4. `plausible attacker use`
5. `confirmed attacker use`

Stay at the lowest level the evidence supports.
