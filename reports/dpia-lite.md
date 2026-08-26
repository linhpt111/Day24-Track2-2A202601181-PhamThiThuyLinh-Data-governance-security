# DPIA-lite

## 1. Dữ liệu gì

Agent chạm vào hai nhóm dữ liệu chính:

- `search_docs`: nội dung ticket trong `corpus/`, có thể chứa customer id, nội dung hỗ trợ khách hàng và payload prompt injection không đáng tin.
- `read_customer`: dữ liệu restricted trong `data/customers.json`, gồm `customer_id`, tên, CCCD, số điện thoại, số tài khoản ngân hàng, email và `related_tickets`.
- `reports/ledger.jsonl`: metadata kiểm toán của tool call, ghi hash của tham số thay vì ghi raw PII vào ledger.

PII gate phát hiện CCCD, số điện thoại, số tài khoản ngân hàng và email tại `agent/pii.py:24`; chức năng redact nằm tại `agent/pii.py:55`.

## 2. Mục đích gì

Mục đích hợp lệ là tổng hợp và đối soát ticket hỗ trợ khách hàng. Agent cần đọc ticket để biết ticket nào liên quan, sau đó Run B chỉ được đọc customer khi ticket id lấy từ tên file map được sang `related_tickets` trong kho dữ liệu tin cậy. Runner không dùng `customer_id` nằm trong free text của attacker để quyết định đọc private data.

Bằng chứng: `agent/runner.py:114`, `agent/runner.py:119`, `agent/runner.py:128`.

## 3. Chảy đi đâu

Trong chế độ chấm điểm `--mock`, dữ liệu không đi sang API model provider bên ngoài. Lab có sink nội bộ `http://localhost:9999`, nhưng egress với restricted data bị policy deny trước khi tool thật được gọi.

Bằng chứng trước containment: `reports/attack-before.log:1` có PII của `KH-000999` ra sink. Bằng chứng sau containment: `reports/attack-after.log` rỗng, và `reports/ledger.jsonl:23` ghi `tool=http_post`, `decision=deny`, `reason=restricted data cannot be used when egress is enabled`.
