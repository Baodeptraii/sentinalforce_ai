# Kiểm chứng bản cập nhật Survey — 12/11/2026

## Kết quả đã kiểm chứng

- Đã triển khai mã nguồn vào `/home/bao/DATN/GUI` và hai file dùng chung trong `/home/bao/DATN/final_template`.
- 76 test Python đạt, không skip. Chạy từ cả `~/DATN` và `~/DATN/GUI` đều đạt.
- 18 test JavaScript đạt bằng Node `v20.20.2` đã có trong `~/.nvm`; không thay Node hệ thống.
- Đã khởi động GUI bằng `start.sh`, đọc `/api/meta` và trang chính qua loopback: đúng root `/home/bao/DATN/GUI`, mode `ai`, model `gemini-3.5-flash-lite`, không có job đang chạy tại thời điểm kiểm tra.
- HTML phục vụ có nút yêu cầu dừng và tải gói bằng chứng. Kiểm thử DOM mô phỏng đạt; không coi đây là kiểm tra bố cục bằng trình duyệt thật.
- Các test tương tác HTTP dùng loopback/fake CALDERA. Không có operation mới trên Windows hoặc request khảo sát DVWA thật trong đợt sửa.
- Không gọi Gemini thật; các test nhiều lượt kiểm tra giao thức bằng client giả lập. Không kết luận chất lượng lựa chọn của model từ test này.
- Không sửa `config.json`, API key, credential gốc, dữ liệu output gốc hoặc cấu hình hệ điều hành.

## Đối chiếu review

| Vấn đề | Cập nhật |
|---|---|
| Deadline CALDERA bỏ sót prepare/API | Deadline từ đầu runner; API có timeout/size limit; cleanup có ngân sách riêng; watchdog và journal khi không xác nhận hoàn nguyên được |
| Mất độ mới và bằng chứng khi bàn giao | `handoff.json` + ZIP có run ID, thời điểm, scope, trạng thái partial và hash; profile giữ 6 nhóm |
| Cổng chưa gọi bị ghi đã kiểm tra | Tách `ports_planned`/`ports_checked`, đếm request thật; kiểm tra các protocol được phép độc lập; ghi body truncation |
| Import/test phụ thuộc cwd và Node 10 | Bootstrap package dùng shared contracts; `tools/verify_offline.py`; chọn Node >=20 có sẵn; fixture lịch sử cố định |
| AI lặp lại tool/cổng | Danh sách tool và source theo trạng thái; loại cổng đã thử; context gồm các kiểm tra còn thiếu; backend vẫn kiểm tra lời gọi |
| Thiếu listener/process của XAMPP | Inventory v3 giữ listener, PID, tên/path process, service; giới hạn và ghi thiếu/cắt ngắn; tham chiếu trong profile |
| DVWA thiếu module/form | Tool đọc module GET sau login được xác minh; lưu metadata form, không value/token; thêm `modules_ref`; auth cấu hình riêng theo IP |
| Thiếu số liệu điều phối | Ghi latency, usage provider hoặc null, tool duration, rejection và nhóm quan sát mới; chưa benchmark chất lượng model thật |
| Vòng đời/khôi phục | Khóa GUI và runner theo IP; intent journal trước PATCH; xử lý mất response; cancel; atomic JSON; công cụ GET-only để reconcile |
| Contract telemetry khác nhau | JSON schema và Pydantic cùng giữ telemetry null trong producer hiện tại; chưa có collector chứng minh ingest |
| UX dễ nhầm readiness | Nhãn và tài liệu phân biệt survey/planning/execution/detection; thời điểm, download ZIP, cancel, metrics và TCP process summary |

## Bằng chứng kiểm thử trên Ubuntu

- `/home/bao/DATN/verification/survey_upgrade_tests.txt`
- `/home/bao/DATN/verification/survey_upgrade_root_tests.txt`
- `/home/bao/DATN/verification/survey_console_20261112.log`

## Backup trước thay đổi

- `/home/bao/DATN/verification/survey_upgrade_backup_20261112T135349Z/`: đợt triển khai đầu, có `manifest.json` và bản cũ của file đã tồn tại.
- `/home/bao/DATN/verification/survey_upgrade_backup_20261112T135616Z/`: bổ sung fixture/replay sau khi phát hiện test lịch sử cần cập nhật cho nhóm TCP listener.
- Các file mới được manifest ghi `old_sha256: null`. Backup không chứa key hoặc credential.
- Khi rollback, dừng GUI nếu đang rảnh; đối chiếu manifest và khôi phục file cũ. Không ghi đè config hoặc outputs. Không chạy lại operation tự động.

## Phần cần xác minh trong lượt lab tiếp theo

1. Chạy một survey endpoint + DVWA qua GUI, quan sát tool lựa chọn trong timeline.
2. Kiểm tra ability v3 chạy bằng PowerShell trên Windows và profile có listener/process tương ứng.
3. Kiểm tra Gemini chấp nhận danh sách tool thay đổi theo lượt và có thể chọn `inspect_dvwa_modules` khi cần.
4. Kiểm tra metadata form/module thực tế; nếu thiếu credential hoặc không đọc được thì giữ unknown.
5. Tải ZIP, đối chiếu `handoff.json`, `report.json`, `metrics.json` và evidence.

Chưa kiểm chứng khả năng ingest/detection Wazuh; đây là bước riêng. Chưa xây backend Scenario/RAG. Chưa có benchmark nhiều lần chứng minh AI tốt hơn baseline scripts.

## Bản staging

- Bản chuẩn triển khai là `~/DATN/GUI`, không phải `~/DATN/.survey-upgrade-20261112/GUI`.
- Có bản sao phụ `.secrets/dvwa.json` và thư mục `backups` được lấy cùng staging lúc đầu; chúng không nằm trong manifest triển khai hay gói bàn giao evidence. Không chia sẻ toàn bộ thư mục staging.
- Lệnh dọn các bản sao phụ trên Windows bị cơ chế tự động chặn (`blocked by policy`), nên chưa xóa. Bản staging Ubuntu được giới hạn quyền truy cập thư mục 0700 và file credential 0600.
- Có thể dọn thủ công các bản sao phụ tại `E:\Study\DATN\implementation\survey_upgrade_20261112\GUI\.secrets`, `...\GUI\backups` và bản staging tương ứng trên Ubuntu. Không xóa `.secrets` trong bản GUI chính đang sử dụng.
