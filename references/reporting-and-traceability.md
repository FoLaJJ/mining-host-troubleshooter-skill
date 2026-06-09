# Reporting and Traceability

Use this file when writing or reviewing reports from this skill.

## Core Rule

Reports exist to explain what the evidence supports, what it does not support, and how the current reconstruction was derived.

They do not exist to sound decisive.

## Minimum Report Contract

Every report should state:

1. requested investigation focus
2. host identity, distro/kernel identity, and observation window
3. read-only collection scope
4. evidence-backed findings
5. timeline normalized to UTC when possible
6. traceability status for source IPs or note why traceability is incomplete
7. log survivability status
8. persistence, runtime, and file/hash correlation
9. local-privesc exposure review result if collected
10. unknowns, gaps, and confidence limits

## Truth-Reconstruction Rules

When reconstructing the likely attacker path:

1. start from observed facts
2. connect them with explicit inferences
3. show counter-evidence or missing evidence
4. avoid skipping from keyword hits to attribution
5. keep vulnerable package/kernel status separate from confirmed exploitation
6. keep missing logs separate from confirmed log tampering unless the evidence supports tampering

## Evidence Discipline

1. Prefer evidence IDs over paraphrase-only claims.
2. Keep hashes, paths, process IDs, service names, pool endpoints, wallet fragments, and timestamps when they materially support the conclusion.
3. Call out small differences that materially change interpretation.
4. If two explanations remain possible, say so.

## Primary Conclusions vs Investigative Leads

Keep the report split mentally, even if the final format is compact:

1. primary conclusions are for claims that clear the evidence gate
2. investigative leads are for weak clues that still matter but remain unconfirmed
3. do not let investigative leads bleed into executive wording

Primary conclusions should carry:

1. `claim_type`
2. `confidence_reason`
3. linked `evidence_ids`
4. wording that survives removal of one weak source

Investigative leads should carry:

1. what was observed
2. why it matters
3. why it remains `inconclusive`
4. supporting and counter-evidence when available

## Dual-Use Remote Tools

When software such as Sunlogin, ToDesk, AnyDesk, RustDesk, or TeamViewer appears:

1. record presence and runtime as observed software facts first
2. do not assume either legitimacy or compromise from the tool name alone
3. keep `authorized use unknown` separate from `unauthorized use suspected`
4. if the tool may have been used by the attacker, explain which extra evidence supports that concern
5. if the tool may simply be part of normal operations, say that this remains possible

## Language Rules

Use phrases like:

1. `Observed`
2. `Evidence indicates`
3. `This supports`
4. `This remains inconclusive because`
5. `A local privilege-escalation path is plausible because`

Avoid phrases like:

1. `Definitely`
2. `Certainly`
3. `The attacker must have`
4. `This proves exploitation` when only exposure is known
5. `Logs were clearly deleted by the attacker` when only visibility loss is known
6. `The attacker used ToDesk/Sunlogin/AnyDesk` when only software presence or runtime was observed

## Internal vs External Copies

1. Internal copies keep traceable IPs and host-level details visible by default.
2. External copies may use redaction, but redaction must not change the meaning of the evidence chain.
3. If redaction removes a key value, say that it was redacted rather than silently omitting it.
