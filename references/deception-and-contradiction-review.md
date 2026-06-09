# Deception and Contradiction Review

Use this when the host may contain misleading artifacts, partially deleted logs, command pollution, or intentionally planted noise.

## Goal

Do not ask "is this line suspicious" in isolation.

Ask whether multiple independent sources agree.

## Primary Cross-Checks

1. Authentication lines in `journalctl` vs primary auth logs vs `wtmp`/`btmp`/`lastlog`
2. Shell command resolution vs absolute-path candidates under trusted prefixes
3. Process list vs `/proc/<pid>/exe` vs on-disk hash
4. Service `ExecStart` vs actual runtime parent/child process view
5. Claimed network exposure vs socket table vs route visibility
6. Missing primary logs vs surviving logging pipeline metadata

## Deception Signals

Treat these as risk signals, not automatic proof:

1. Critical command resolves outside `/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`, `/usr/local/bin`
2. Shell function or alias shadows a core collection command
3. Authentication failures appear in one source only, with no surviving corroboration
4. Primary auth logs are absent while journald or `btmp` still shows activity
5. `accepted` or `failed` login stories conflict with current privilege scope or host timeline
6. A binary name looks normal, but its path, hash, owner, or startup path differs

## Reporting Rule

When contradiction signals exist, the report must:

1. state the contradiction explicitly
2. list the evidence IDs behind each side
3. lower confidence where reconstruction depends on a weak source
4. avoid turning contradiction into attribution

## Output Language

Prefer wording like:

1. `cross-source gap observed`
2. `surviving sources do not fully corroborate`
3. `command trust conflict observed`
4. `scene reconstruction confidence reduced by contradiction signals`
