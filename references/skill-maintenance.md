# Skill Maintenance

Maintain this repository as a reusable troubleshooting skill, not as an ad-hoc script folder.

## Required Workflow

1. Use the installed `skill-creator` skill when creating or updating this skill.
2. Keep `SKILL.md` as the operating contract and update supporting references/scripts around it.
3. Re-run validation after every meaningful edit.
4. Re-run `python scripts/audit_example_placeholders.py` before publishing or reinstalling.
5. Keep generated evidence under `reports/` out of version control.

## Maintainer Checklist

1. Read `C:/Users/admin/.codex/skills/.system/skill-creator/SKILL.md` before structural changes.
2. If workflow or capabilities change, update both `README.md` and `README.en.md`.
3. If UI-facing behavior changes, verify `agents/openai.yaml` is still accurate.
4. If install behavior changes, keep `package.json` and `scripts/install-skill.mjs` aligned.
5. Run:
   - `python C:/Users/admin/.codex/skills/.system/skill-creator/scripts/quick_validate.py <skill-dir>`
   - `python scripts/audit_example_placeholders.py`
6. Keep `SKILL.md` short and high-signal. For this skill, treat roughly 80-160 lines as the normal target and move detail into `references/` when it grows beyond that without a strong reason.
7. Do not publish real case bundles, raw reports, or sensitive artifacts with the skill.

## Repository Hygiene

1. Keep `reports/.gitkeep` only; delete generated case bundles before publish.
2. Prefer deterministic scripts for repeatable tasks.
3. Keep documentation concise and operational.
4. Keep examples placeholder-based and avoid concrete host identifiers in README/references unless they are explicitly marked as live evidence examples.
