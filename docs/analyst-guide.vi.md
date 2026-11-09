# Hướng Dẫn Analyst

Dùng phần tóm tắt để triage nhanh, sau đó kiểm tra từng phát hiện theo bằng chứng, vị trí, và mức độ. URL/domain được defang theo mặc định. Chỉ copy IOC gốc khi thật sự cần trong workflow phân tích.

Điểm cần ưu tiên:

- Macro auto-exec đi kèm PowerShell/cmd/script engine.
- External relationship/template trong Office.
- Unicode ẩn trong tên file hoặc URL.
- PDF `/OpenAction`, `/JavaScript`, hoặc `/Launch`.
- CSV formula có `HYPERLINK`, `WEBSERVICE`, lệnh, hoặc link ngoài.
- Archive có zip-slip, file nested đáng ngờ, hoặc executable/script.

Phân tích tĩnh không khẳng định chắc chắn malware. File High/Critical nên được phân tích sâu trong môi trường kiểm soát.
