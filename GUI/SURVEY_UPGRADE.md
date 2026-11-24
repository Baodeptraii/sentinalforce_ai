# Survey Agent — bản cập nhật 12/11/2026

## Phạm vi

- Bản chính: `GUI`; dependency dùng chung: `final_template`.
- Hoàn thiện Survey Windows + web/DVWA. Scenario và Flow vẫn là bản xem trước/mô phỏng.
- Không đổi API key, credential, HTTP-only scope của máy lab hoặc cấu hình Windows/CALDERA.
- Không yêu cầu ART, Wazuh hoặc Sysmon làm điều kiện cần. Telemetry chưa kiểm chứng vẫn `null`.

## Chạy

```bash
cd GUI
./start.sh
```

- Mở `http://127.0.0.1:8765`.
- Nhập IP, chọn phạm vi, kiểm tra điều kiện, chạy khảo sát.
- GUI chỉ cho một instance hoạt động. Runner có khóa riêng theo IP để tránh hai lượt đổi group đồng thời.
- Nút **Yêu cầu dừng khảo sát** yêu cầu dừng hợp tác. Lệnh đã giao cho Sandcat không thể thu hồi tức thì; phải kiểm tra journal nếu cleanup thất bại.

## AI làm gì

- Chọn tool từ danh sách còn phù hợp với scope và bằng chứng đã có.
- Chọn kiểm tra web ban đầu hoặc cổng listener chưa thử nhưng đã nằm trong allowlist.
- Khi có bằng chứng đăng nhập DVWA, có thể chọn `inspect_dvwa_modules` để đọc trang module và metadata form.
- Nhận bản tóm tắt ngắn, danh sách kiểm tra còn thiếu và kết quả lỗi; không nhận HTML, password hoặc cookie.
- Không được tự tạo shell command, thay IP/port, mở rộng scope, cài đặt hay sửa cấu hình.
- Pydantic và code tạo profile từ evidence. Lời văn model không trở thành dữ kiện.
- `metrics.json` ghi request, thời gian, token provider thực sự trả, tool bị từ chối và số nhóm quan sát mới. Đây không phải điểm đo trí thông minh hay độ chính xác.

## Dữ liệu đầu ra

- `target_profile.json`: giữ 6 nhóm `id`, `os`, `address`, `services`, `capabilities`, `telemetry`.
- Inventory v3 gồm listener, PID, tên/path tiến trình và dịch vụ đang chạy; đọc tối đa 256 listener và 256 service, có số lượng và thông báo cắt ngắn.
- Profile giữ listener và tham chiếu bằng chứng; inventory chi tiết nằm trong `02_endpoint.json`.
- Web phân biệt cổng dự kiến và cổng thực sự thử; ghi request, HTTP status, redirect, lỗi và cắt ngắn body.
- DVWA ghi dấu hiệu logout, token có/không và option security được chọn. Không lưu token/value của form.
- `modules_ref` tham chiếu metadata module/form, không suy luận module có thể khai thác được.
- `handoff.json`: run ID, scope, thời điểm, trạng thái partial, thông tin thiếu và SHA-256 của evidence.
- **Tải hồ sơ + bằng chứng (.zip)** để bàn giao cho bước Scenario. Tải JSON riêng vẫn được, nhưng thiếu ngữ cảnh độ mới và evidence.
- Phiên DVWA chỉ được xác minh tại thời điểm survey. Khảo sát lại khi môi trường thay đổi; luôn preflight trước thực thi kịch bản.

## Giới hạn và cấu hình

- `web_scope_by_target`/`web_scope` quyết định scheme/port được phép. `web_initial_ports` tùy chọn chọn tập cổng thử đầu tiên; nếu không đặt, dùng `web_ports`. Cổng phát hiện không tự mở rộng scope.
- `dvwa_auth_by_target`: map IP → cấu hình `enabled`, `base_url`, `credentials_file`. Nếu có registry, không fallback credential của máy khác. Cấu hình `dvwa_auth` cũ vẫn hoạt động và kiểm tra base URL khớp IP.
- `max_dvwa_modules` mặc định 12, tối đa 20. Chỉ GET đường dẫn module directory lấy từ index đã đăng nhập; không submit form tấn công. Nếu hết thời gian, giữ kết quả một phần.
- Endpoint dùng ability/adversary v3 mới, không ghi đè v2 đã đăng ký. Lần survey tiếp theo sẽ đăng ký qua API như trước.
- Runner tính deadline trước prepare/API, có tối đa 20 giây cleanup; watchdog dự phòng cho tiến trình con bị treo. HTTP read có giới hạn byte và kiểm tra deadline giữa các lần đọc; một socket call đang chờ có thể vượt deadline theo timeout request.
- Cancel trong lúc chờ model/HTTP có hiệu lực ở checkpoint tiếp theo; không tuyên bố dừng tức thì.
- JSON schema telemetry thống nhất với producer hiện tại: chỉ `null` khi chưa có tool kiểm chứng ingest. Khi xây backend xác minh telemetry, cần nâng contract có evidence tương ứng.

## Khôi phục lượt bị gián đoạn

- Đọc `outputs/<run_id>/caldera/summary.json`: `original_group`, `temporary_group`, `operation_id`, `group_restored`, `cleanup_required`.
- GUI chặn lượt mới cùng mục tiêu nếu journal chưa xác nhận cleanup.
- Kiểm tra và xử lý operation/group trong CALDERA khi cần. Sau đó chạy:

```bash
.venv/bin/python tools/reconcile.py <run_id>
```

- Script chỉ GET CALDERA, xác minh group đã trở lại và không còn operation chưa kết thúc, rồi cập nhật journal local. Không tự resume/pause operation hoặc thay group.
- Không xóa bằng chứng để vượt qua kiểm tra.

## Kiểm thử

```bash
cd GUI
.venv/bin/python tools/verify_offline.py
```

- Chạy unittest Python và Node test. Chọn Node >=20 đã có trong PATH hoặc `~/.nvm/versions/node`; không dùng Node 10 hệ thống và không tự cài thêm.
- Test dùng fake CALDERA, fake LLM, HTTP loopback và fixture; không gửi request vào victim hoặc gọi Gemini trả phí.
- Các test bảo vệ: scope, target override, dữ kiện giả, callback nhiều lượt, hết budget, group PATCH mất response, cancel, file/hash handoff, form không rò value, HTTP/HTTPS và schema.
- Chưa dùng kết quả offline để kết luận độ chính xác của Gemini, khả năng thực thi PowerShell v3 trên VM hoặc ingest Wazuh. Chạy một lượt survey thực sau khi khởi động lại GUI để xác minh các phần đó trong lab.

## Bàn giao và phần tiếp theo

- Giữ cả `GUI/` và `final_template/` khi chuyển máy; không chỉ chép `app.py`.
- Không đưa `.secrets`, `config.json`, `.venv`, `outputs` hoặc backup vào gói mã nguồn chia sẻ.
- Benchmark nhiều lượt Gemini và backend Scenario/RAG/Wazuh nằm ngoài bản cập nhật này. Test offline chứng minh ranh giới điều phối, không chứng minh AI luôn chọn tối ưu.
