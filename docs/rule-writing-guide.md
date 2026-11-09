# Rule Writing Guide

Rules live under `rules/` or `rules/community/`.

Recommended YARA metadata:

```yara
meta:
    severity = "high"
    description = "What this rule detects"
    author = "community"
```

Guidelines:

- Keep rules static and deterministic.
- Prefer precise strings over broad keywords.
- Include `severity` as `info`, `low`, `medium`, `high`, or `critical`.
- Avoid rules that match common clean documents without context.
- Test with `miyomacro rules validate` when `engines/yara/yara.exe` is installed.
- Community rules should explain expected false positives.
