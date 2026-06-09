# Second-Pass Review

Use this file when the skill has already collected and enriched evidence, and is about to generate the first formal report.

The goal of the second pass is not to create new facts. It is to stop overstatement, keep open gaps visible, and force a closure check before the report is allowed to sound confident.

## Why This Exists

Host-only evidence is often enough to prove that something suspicious happened, but not enough to close:

1. whether an accepted login was truly authorized
2. whether missing logs are real loss or just the wrong distro expectation
3. whether a startup line is malicious or only vendor-managed baseline
4. whether a vulnerable version means exposure only or actual exploit use
5. whether the visible timeline is broad enough to support the story being told

The first report must already carry these checks, so later human review is mostly evidence-guided validation, not a fresh rewrite.

## Mandatory Gates

Do not finalize the report until all gates below have been checked.

### 1. Accepted Access Re-Review

Ask:

1. Could this accepted source simply be the current investigation session?
2. Could it be a recurring admin source visible across the host window?
3. Is there mixed auth evidence from the same source, such as both accepted and failed attempts?
4. Does the host have enough evidence to prove authorization?

Rule:

1. Accepted access alone is not attacker control.
2. If authorization cannot be proven, say so explicitly.

### 2. Distro-Aware Log Layout Re-Review

Ask:

1. Is this Ubuntu/Debian, or RHEL/CentOS/Rocky/Alma?
2. Are the allegedly missing logs actually expected on this distro?
3. Is the host mainly using journald instead of the file path being judged?

Rule:

1. Wrong-path expectations must be removed from risk counts.
2. Real expected-log loss stays visible and lowers confidence.

### 3. Timeline Re-Review

Ask:

1. Is there a usable UTC-normalized sequence?
2. Is the visible time window wide enough to support the claimed ingress story?
3. Are the visible timestamps only near collection time, or do they actually cover earlier activity?

Rule:

1. If the timeline window is narrow, say so and require time-window expansion.
2. Do not present a clean attack chain when the timeline is thin.

### 4. Persistence Surface Re-Review

Ask:

1. Are the hits only vendor-managed startup lines?
2. Are they only account metadata or identity surfaces such as `authorized_keys` or shell profiles?
3. Do any lines still look high-signal, such as `/tmp`, `/dev/shm`, pipe-to-shell, policy weakening, or privileged preload hooks?

Rule:

1. Vendor or baseline-only surfaces do not independently prove foothold.
2. Keep high-signal startup or privileged-policy lines visible for direct analyst review.

### 5. Local Priv-Esc Re-Review

Ask:

1. Is the host only exposed, or is there real evidence of use?
2. Is passwordless sudo visible, making ordinary admin access a competing explanation?
3. Is there a plausible user-to-root path supported by surrounding evidence?

Rule:

1. Exposure is not exploitation.
2. `plausible` is allowed when surrounding evidence supports it.
3. `confirmed` requires stronger direct evidence.

### 6. Scope Closure Re-Review

Ask:

1. Can the requested scope be closed from host evidence alone?
2. Which non-host or cross-host pivots are still required?
3. Are there unresolved contradictions that block stronger attribution?

Common pivots:

1. bastion / VPN / IdP / jump-host authentication logs
2. firewall / NAT / proxy / DNS / SIEM telemetry
3. Kubernetes audit logs and container registry history
4. cloud audit trails and metadata-access telemetry
5. peer hosts, bastions, management nodes, and internal source-IP pivots
6. package backport records or admin change history for local-privesc review

Rule:

1. If a pivot is still required, put it in the report.
2. Do not hide open gaps because the scene "looks bad enough."

## Output Contract

The second pass should leave behind:

1. status of each gate
2. downgraded findings where required
3. open gaps that still block stronger closure
4. explicit external or cross-host pivots
5. closure notes that explain what still needs corroboration

## Safe Wording

Prefer:

1. `accepted access observed, authorization unconfirmed`
2. `log layout consistent with detected distro family`
3. `timeline window remains narrow`
4. `persistence review dominated by vendor-managed or baseline surfaces`
5. `local-privesc exposure present, exploit use unconfirmed`
6. `external corroboration still required before stronger attribution`

Avoid:

1. `accepted login proves attacker access`
2. `missing /var/log/secure proves log deletion on Ubuntu`
3. `authorized_keys hit proves persistence`
4. `vulnerable version proves local privilege escalation happened`
5. `host-only evidence fully closes ingress path` when key pivots remain open
