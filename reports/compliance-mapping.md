# Bảng ánh xạ tuân thủ

| Yêu cầu | Kiểm soát | Bằng chứng |
|---|---|---|
| Luật 91/2025 - quyền yêu cầu xóa | Chưa triển khai delete cascade trong phạm vi lab; hệ thống đã có cổng phát hiện và redact PII để giảm rủi ro lộ dữ liệu trong quá trình xử lý. | `agent/pii.py:24`, `agent/pii.py:55` |
| NĐ 356/2025 - hồ sơ xuyên biên giới 60 ngày | DPIA-lite mô tả rõ luồng dữ liệu. Chế độ chấm dùng `--mock`, không gọi model provider bên ngoài; egress chỉ là sink localhost và bị policy deny khi có dữ liệu restricted. | `reports/dpia-lite.md:17`, `agent/policy.py:16`, `reports/ledger.jsonl:23` |
| ASI03 - privilege abuse | Mọi tool call đi qua policy-as-code, có `agent_owner`, `run_id`, `decision`, `reason` và ledger dạng hash-chain để kiểm toán. | `agent/policy.py:16`, `agent/runner.py:47`, `agent/ledger.py:18`, `reports/ledger.jsonl:1` |
| ASI01 - goal hijack | Runner tách trifecta: Run A chỉ tìm ticket, Run B map ticket id sang customer qua `related_tickets`, Run C kiểm soát egress và deny khi có restricted data. | `agent/runner.py:98`, `agent/runner.py:114`, `agent/runner.py:119`, `agent/runner.py:128`, `agent/runner.py:141`, `reports/attack-before.log:1`, `reports/ledger.jsonl:23` |
| ISO 42001 Clause 5-6 | Policy và audit được mã hóa thành control có test tự động để hỗ trợ review. | `tests/test_policy.py:8`, `tests/test_ledger.py:20`, `tests/test_split.py:76` |
