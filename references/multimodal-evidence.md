# Multimodal Evidence

Use this when the user provides screenshots, pasted logs, config fragments, or other non-command evidence.

## Rules

1. Treat uploaded screenshots and pasted text as user-supplied evidence, not as proof of hidden context.
2. Only describe what is actually visible.
3. If OCR or image reading is uncertain, mark it explicitly with `[OCR-UNCERTAIN: ...]`.
4. If an image shows only part of a command or config, ask for the raw text or full file before making stronger claims.
5. If the user uploads a file, prefer quoting the visible filename, hash, and relevant lines rather than paraphrasing loosely.
6. Never infer cropped, hidden, or off-screen content.

## Evidence Integration

When incorporating user-supplied evidence into a case summary, label it clearly as one of:

1. `user-uploaded screenshot`
2. `user-pasted log excerpt`
3. `user-provided config snippet`
4. `live command artifact`

Keep these categories separate from live-collected shell evidence.
