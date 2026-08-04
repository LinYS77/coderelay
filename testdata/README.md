# Extractor golden fixtures

`extractor_golden.json` is the frozen, language-neutral extractor contract used by the Go implementation.

Each case contains:

- a settings profile;
- `now` and optional `not_before` timestamps;
- messages with provider sequence/UID metadata;
- the expected six-digit ASCII code or public error code.

The original 48 expected outcomes were frozen after the Phase 4 differential gate reached zero mismatches. Case 49 is an explicitly reviewed extension for Japanese `検証コード` messages; it preserves the ASCII six-digit output and ambiguity rules. The retired implementation and exporter are intentionally not retained; any further contract change requires an explicit fixture review plus the Go golden, unit, race, and fuzz gates.

Run:

```bash
go test -count=1 ./internal/extractor
```
