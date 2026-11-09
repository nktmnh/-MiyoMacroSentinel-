# Analyst Guide

Use the executive summary for quick triage, then validate each finding by evidence, location, and severity. URLs and domains are defanged by default. Copy original IOCs only when needed and inside an analyst workflow.

High-value pivots:

- Macro auto-exec plus command keywords.
- External Office relationships and templates.
- Hidden Unicode in filenames or URLs.
- PDF `/OpenAction`, `/JavaScript`, or `/Launch`.
- CSV formulas with `HYPERLINK`, `WEBSERVICE`, command text, or external links.
- Archive zip-slip, nested suspicious files, or executable-like entries.

Static analysis does not confirm malware. Escalate High/Critical samples for deeper controlled analysis.
