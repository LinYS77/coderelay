# Extractor golden fixtures

`extractor_golden.json` is the language-neutral contract shared by Python 0.3 and Go.

Each case contains:

- extractor settings or a named settings profile;
- `now` and optional `not_before` timestamps;
- bounded provider-neutral messages, including UID ordering metadata;
- the expected six-digit ASCII code, no-match result, or `AMBIGUOUS_CODE`.

Python is the export oracle. Regenerate or verify the expected outcomes with:

```bash
python scripts/export-extractor-golden.py
python scripts/export-extractor-golden.py --check
```

Both `tests/test_extractor_golden.py` and `internal/extractor/golden_test.go` consume this exact JSON file. Real credentials, mailbox contents, and verification codes from live accounts must never be added here.
