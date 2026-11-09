# MiyoMacroSentinel

MiyoMacroSentinel is a privacy-first Windows desktop security scanner for defensive document triage. It scans locally for suspicious Office macros, hidden Unicode, phishing links, embedded objects, external Office relationships, PDF actions, CSV formula injection, archive tricks, and IOC artifacts.

Author: nktmnh

## English

### Who Should Use It

SOC analysts, cybersecurity students, Office users, and community document-safety reviewers.

### Safety Notes

- Macros are never executed.
- Suspicious documents are never opened with Microsoft Office for analysis.
- Files are not uploaded by default.
- Results use risk language such as Clean, Low, Medium, High, and Critical instead of claiming malware confirmation.

### Supported Files

`.doc`, `.xls`, `.ppt`, `.dot`, `.xlt`, `.pps`, `.docx`, `.xlsx`, `.pptx`, `.docm`, `.xlsm`, `.pptm`, `.dotm`, `.xltm`, `.ppsm`, `.pdf`, `.rtf`, `.txt`, `.csv`, `.html`, `.xml`, `.odt`, `.ods`, `.odp`, `.zip`, `.rar`, `.7z`.

### Run the Desktop App

```powershell
dotnet run --project src\MiyoMacroSentinel.App\MiyoMacroSentinel.App.csproj
```

Use **Single File Scan** to drag/drop or browse for a file. Reports are written to the configured local report folder.

### Run the CLI

```powershell
dotnet run --project src\MiyoMacroSentinel.Cli\MiyoMacroSentinel.Cli.csproj -- scan "file.docm"
dotnet run --project src\MiyoMacroSentinel.Cli\MiyoMacroSentinel.Cli.csproj -- scan "file.docm" --json report.json
dotnet run --project src\MiyoMacroSentinel.Cli\MiyoMacroSentinel.Cli.csproj -- scan "folder" --recursive --csv results.csv
dotnet run --project src\MiyoMacroSentinel.Cli\MiyoMacroSentinel.Cli.csproj -- rules validate
dotnet run --project src\MiyoMacroSentinel.Cli\MiyoMacroSentinel.Cli.csproj -- version
```

CLI exit codes: `0` Clean/Low, `1` Medium, `2` High/Critical, `3` scan error.

### Risk Score

Scores run from `0` to `100`: Clean `0-20`, Low `21-40`, Medium `41-60`, High `61-80`, Critical `81-100`. Scores are transparent and based on findings such as macros, auto-exec indicators, command keywords, external relationships, hidden Unicode, PDF actions, CSV formula injection, archive risks, and YARA matches.

### Reports

The app exports JSON, HTML, and IOC CSV reports. Batch scans can export CSV, JSON, and HTML summaries.

### YARA Rules

Place `yara.exe` in `engines/yara/yara.exe`. Add local `.yar` or `.yara` rules under `rules/` or `rules/community/`. The scanner continues safely if YARA is missing.

### Troubleshooting

- Build: run `dotnet restore`, `dotnet build`, `dotnet test`.
- Logs: check `logs/app.log`, `logs/scan.log`, and `logs/error.log` under the app runtime folder.
- Missing YARA/oletools: install optional sidecar tools or leave them disabled.
- Corrupted files: the scanner reports parser errors and continues without crashing.

### Privacy And Limitations

Scanning is local by default. No telemetry or cloud upload is enabled by default. Static analysis cannot prove a file is safe; clean results still require normal sender and business-purpose verification.

## Tiếng Việt

### Công Cụ Này Dành Cho Ai

SOC analyst, sinh viên an toàn thông tin, người dùng Office, và người cần kiểm tra tài liệu cộng đồng.

### Ghi Chú An Toàn

- Không bao giờ chạy macro.
- Không mở tài liệu nghi ngờ bằng Microsoft Office khi phân tích tĩnh.
- Không tải file lên mạng theo mặc định.
- Kết quả dùng mức rủi ro Clean, Low, Medium, High, Critical; không kết luận chắc chắn là malware nếu chưa đủ bằng chứng.

### Cách Quét File

Chạy app desktop rồi vào **Quét một file**, kéo thả file hoặc bấm chọn file. Báo cáo JSON/HTML/CSV IOC được lưu trong thư mục report cục bộ.

### Cách Dùng CLI

```powershell
dotnet run --project src\MiyoMacroSentinel.Cli\MiyoMacroSentinel.Cli.csproj -- scan "file.docm"
dotnet run --project src\MiyoMacroSentinel.Cli\MiyoMacroSentinel.Cli.csproj -- scan "folder" --recursive --csv results.csv
```

### Đọc Điểm Rủi Ro

`0-20` Clean, `21-40` Low, `41-60` Medium, `61-80` High, `81-100` Critical. Điểm đến từ các bằng chứng như macro, auto-exec, PowerShell/cmd, IOC, Unicode ẩn, PDF JavaScript, CSV formula injection, archive đáng ngờ, và YARA.

### Thêm Rule

Đặt rule vào `rules/` hoặc `rules/community/`. Nếu có `yara.exe`, đặt tại `engines/yara/yara.exe`.

### Đóng Góp Cộng Đồng

Rule nên có `meta.severity`, mô tả rõ, không chứa logic nguy hiểm, và ưu tiên giảm false positive. Xem `docs/rule-writing-guide.md`.
