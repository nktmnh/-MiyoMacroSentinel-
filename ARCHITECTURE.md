# Architecture

MiyoMacroSentinel uses a layered .NET 8 WPF architecture.

## Projects

- `MiyoMacroSentinel.App`: WPF/MVVM desktop shell, bilingual UI, drag/drop, settings, history, reports, quarantine, rule manager.
- `MiyoMacroSentinel.Core`: shared models, file triage, hashing, magic-byte detection, hidden Unicode scanner, IOC extractor, static decoder, risk scoring, settings, safe logging.
- `MiyoMacroSentinel.Parsers`: OpenXML, OLE, macro keyword analysis, PDF, RTF, CSV/TXT, ZIP archive scanning, main `DocumentScanService`.
- `MiyoMacroSentinel.Rules`: optional local YARA sidecar integration and rule listing/validation.
- `MiyoMacroSentinel.Reports`: JSON/HTML/CSV export, SQLite scan history, quarantine copy/restore/delete.
- `MiyoMacroSentinel.Cli`: command-line scanner.
- `MiyoMacroSentinel.Tests`: unit, integration, report/history, and stability tests.

## Scan Pipeline

1. File triage and metadata.
2. Hashing with SHA256/SHA1/MD5.
3. Magic-byte file type detection.
4. Format parser.
5. Macro detection and static macro keyword analysis.
6. Hidden Unicode scan.
7. IOC extraction and defanging.
8. Static decoding.
9. Optional YARA matching.
10. Transparent risk scoring.
11. Report/history persistence.

## Safety Boundaries

- Macros are parsed as bytes/strings only.
- Office is never automated or launched for analysis.
- Archive extraction uses isolated temp folders, path checks, recursion limits, and extracted-size limits.
- Parser exceptions are converted into findings so malformed files do not crash the app.
- Sensitive document content is truncated before evidence/report/log display.
