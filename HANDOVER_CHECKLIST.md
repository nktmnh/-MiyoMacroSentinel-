# Handover Checklist

## Build And Test

- [x] `dotnet restore`
- [x] `dotnet build`
- [x] `dotnet test`
- [x] No build warnings after implementation pass.
- [x] Desktop app launch smoke test passed; executable stayed running until closed.
- [x] CLI scan smoke test passed on `qa-artifacts/clean-sample.txt`.
- [x] Sample JSON report created at `qa-artifacts/clean-sample-report.json`.
- [x] Sample HTML report created under `reports/`.

## Unit Tests

- [x] Magic byte detection
- [x] Extension mismatch detection
- [x] Hidden Unicode detection
- [x] IOC extraction
- [x] Risk scoring
- [x] Base64 decoding
- [x] PowerShell EncodedCommand decoding
- [x] CSV formula injection detection
- [x] Archive zip-slip prevention

## Integration Tests

- [x] Scan clean `.docx`
- [x] Scan macro-enabled `.docm` sample
- [x] Scan `.xlsx` without macro
- [x] Scan `.xlsm` with macro indicators
- [x] Scan PDF with suspicious JavaScript indicator
- [x] Scan TXT with hidden Unicode
- [x] Scan CSV formula injection
- [x] Scan ZIP containing suspicious document
- [x] Scan corrupted file
- [~] Password-protected archive: handled as a design path for unreadable/encrypted entries; creating true encrypted ZIPs requires an external archive tool not bundled with .NET.

## Stability Tests

- [x] Drag/drop handler accepts invalid dropped paths without crashing the shell.
- [x] Very large file limit is implemented and reported.
- [x] Batch scan supports cancellation and safe concurrency.
- [x] Cancel scan midway test passes.
- [x] Missing YARA engine is graceful.
- [x] Missing oletools engine is graceful.
- [x] Malformed XML is caught as a finding.
- [x] Corrupted ZIP is caught as a finding.
- [x] Unicode filename is flagged.
- [~] Long path/no-permission path behavior depends on local Windows policy and ACLs; parser errors are caught globally.
- [x] Temporary archive extraction folder is deleted best-effort after scan.

## Handover

- [x] App icon copied and converted to `.ico`.
- [x] Vietnamese UI resources exist.
- [x] English UI resources exist.
- [x] JSON export implemented.
- [x] HTML export implemented.
- [x] IOC CSV export implemented.
- [x] CLI scan implemented.
- [x] SQLite history implemented.
- [x] Quarantine copy/restore/delete service implemented.
- [x] No file upload occurs by default.
- [x] README, architecture, user guides, analyst guides, and rule guide created.
