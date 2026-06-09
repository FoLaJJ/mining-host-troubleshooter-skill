# Harness Discipline

Use this file when the model needs extra guardrails to stay evidence-bound, especially when capability is limited, logs are missing, or the host may contain misleading artifacts.

## Goal

Keep the workflow read-only, factual, and conservative in primary conclusions without discarding useful weak clues.

## Non-Negotiables

1. Default to read-only evidence collection.
2. Reconstruct from surviving evidence, not intuition.
3. Prefer a narrower true statement over a broader speculative statement.
4. If evidence is insufficient, say `inconclusive`.
5. If two explanations remain viable, keep both visible or state why one is weaker.
6. Do not promote a clue into a conclusion only because it matches a familiar attack story.

## Claim Ladder

Use this order and do not skip levels:

1. `observed_fact`: directly shown by artifact content, command output, metadata, or hashable files.
2. `inference`: a supported connection between observed facts.
3. `attribution`: a higher-risk explanation about attacker intent, exploitation path, or ownership.

Promotion rules:

1. Do not jump from keyword hit to `attribution`.
2. Do not jump from vulnerable package or kernel version to confirmed exploitation.
3. Do not jump from missing logs to confirmed log tampering.
4. Do not jump from a familiar process name to confirmed miner identity unless path, hash, runtime, or config support it.
5. Do not jump from a suspicious IP to attacker attribution unless the evidence chain supports that mapping.

## Primary Conclusions Gate

Main findings, leadership summaries, management summaries, and answer-first sections should include only claims that satisfy all of the following:

1. concrete `evidence_ids`
2. visible `claim_type`
3. explicit `confidence_reason`
4. wording that still holds if one weak source is removed
5. no unresolved contradiction that would materially change the conclusion

If any item fails, downgrade the statement to `inconclusive` or move it to investigative leads.

## Investigative Leads Gate

Weak clues are allowed, but they must stay out of the main narrative unless they clear the primary gate.

For each weak clue:

1. say what was observed
2. say why it matters
3. say what is missing for confirmation
4. keep `status` or wording aligned to `inconclusive`
5. link supporting and counter-evidence IDs when available

Preferred pattern:

1. `Observed clue`
2. `Why relevant`
3. `Why not yet confirmed`
4. `Evidence IDs`

## Missing Logs and Visibility Loss

When logs are missing, deleted, empty, or inconsistent:

1. state visibility loss first
2. check distro-specific log expectations before implying tampering
3. pivot to fallback evidence
4. lower confidence where fallback evidence is the only support
5. keep "log tampering plausible" separate from "log tampering confirmed"

Safe wording:

1. `primary auth logs unavailable for expected path`
2. `scene visibility reduced`
3. `surviving fallback evidence indicates`
4. `log tampering remains inconclusive`

## Command Trust and Polluted Output

If a collection command may be polluted, aliased, wrapped, or replaced:

1. do not rely on that output alone
2. verify command resolution and real path first
3. prefer trusted absolute paths where possible
4. cross-check with `/proc`, package ownership, hashes, or another independent source
5. mark confidence down when a conclusion depends on untrusted command output

Do not treat a single suspicious command path as proof that all host output is fake.

## Dual-Use Remote-Control Tools

Treat remote-control software such as Sunlogin, ToDesk, AnyDesk, RustDesk, and TeamViewer as dual-use tools.

Default stance:

1. tool presence is `observed_fact`
2. tool runtime is `observed_fact`
3. suspicious or unauthorized use is usually `inference`
4. attacker control through the tool is not `confirmed` without stronger evidence

Do not escalate based on the vendor name alone.

Allowed upgrade path:

1. start with presence, path, owner, service/unit name, startup method, and timestamps
2. check whether host role and request context make the tool expected
3. look for abnormal path, hash, parent process, account, startup changes, or timeline overlap with intrusion evidence
4. if authorization cannot be determined, say so explicitly
5. keep the conclusion `inconclusive` unless multiple sources support unauthorized use

Do not let these shortcuts appear in output:

1. `Sunlogin was found, therefore the host was remotely controlled by an attacker`
2. `ToDesk is installed, therefore the machine was breached`
3. `The tool is legitimate, therefore it is unrelated`

## Vulnerability Exposure and Local Privilege Escalation

Use conservative wording for sudo, `CopyFail`, `DirtyFrag`, and related exposure review:

1. `exposed`: vulnerable version or configuration state is present
2. `plausible`: exposure plus surrounding evidence makes local privesc a credible explanation
3. `confirmed`: only when direct exploitation evidence exists

If vulnerable versions are present and root-scope effects appear after user-scope access, it is reasonable to say `local privilege escalation plausible`, but not `confirmed` without stronger evidence.

## Small Differences Matter

Preserve small differences that change interpretation:

1. same name, different path
2. same path, different hash
3. same unit name, different `ExecStart`
4. same account, different key material
5. same process family, different wallet, pool, proxy, or thread count
6. same login story, different surviving source support

Do not compress these differences away in the first summary.

## Contradiction Handling

When two sources disagree:

1. name the contradiction explicitly
2. list both evidence sides
3. state which side is stronger and why
4. lower confidence if the contradiction cannot be resolved
5. keep attribution claims out of the contradiction gap

Safe wording:

1. `cross-source gap observed`
2. `surviving sources do not fully corroborate`
3. `scene reconstruction confidence reduced`

## Output Checklist

Before finalizing any report or answer, verify:

1. the requested focus is visible
2. the read-only boundary is visible
3. distro and kernel identity were established early
4. main conclusions have `evidence_ids`
5. weak clues are separated from main conclusions
6. exposure is not described as exploitation without direct support
7. missing logs are not described as tampering without corroboration
8. contradiction signals are explicit where they affect confidence
9. command-trust concerns are explicit where they affect confidence
10. dual-use remote-control tools are kept neutral unless abnormal use is evidenced
11. unknowns and collection limits are stated plainly

## Second-Pass Self-Review Gate

Do not finalize the first report until this second-pass gate is complete.

Required checks:

1. Re-check whether the current accepted-login sources could simply be the active investigation session or recurring administration.
2. Re-check whether the distro-specific log layout makes any "missing log" finding non-applicable.
3. Re-check whether the recovered timeline is wide enough and normalized enough to support the story being told.
4. Re-check whether current persistence lines are only vendor-managed, baseline, or identity-surface lines rather than true foothold indicators.
5. Re-check whether local-privesc evidence is only exposure, not confirmed use.
6. Re-check which external or cross-host pivots are still required before stronger attribution or closure.

Output rule:

1. If the second pass downgrades a claim, keep the downgrade.
2. If the second pass leaves open gaps, show them explicitly in the report.
3. Do not hide open gaps just because the overall scene still looks suspicious.

## Anti-Patterns

Do not do the following:

1. write a clean attacker story when the evidence is fragmented
2. hide weak sources behind decisive wording
3. merge confirmed findings and speculative leads into one bullet
4. let appendix clues redefine the executive summary
5. use vulnerability names as shorthand for confirmed attacker behavior
6. assume the most dramatic explanation is the correct one
