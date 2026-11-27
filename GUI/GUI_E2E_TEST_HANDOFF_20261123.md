# Kiểm thử GUI thực tế — 23/11/2026

## Kết luận

**PARTIAL / BLOCKED ở Scenario parse. Chưa đạt end-to-end execution → telemetry report.** Thao tác khảo sát, chuyển profile, sinh kịch bản, tìm kho và reload được thực hiện trong Firefox headless thật, qua Marionette điều khiển DOM của http://localhost:8765. Không dùng fake backend để tuyên bố đạt. Export được kiểm tra thêm bằng HTTP trên link GUI.

## Lượt kiểm thử

- Target: 192.168.1.150 / PTIT / Sandcat datnptit.
- Survey: `1e9a0b45f1a04faa9349e89701ebed8e`, 11:01:42–11:02:10 giờ Bangkok.
- Scenario: `ca33fb72b6b04620a7ade7d2c97d35da`.
- Yêu cầu scenario: một bước process discovery chỉ đọc bằng tasklist; không file write/delete, không dừng process, không payload/máy khác.
- Đã chạy operation khảo sát thật qua luồng Survey được người dùng yêu cầu; không chạy scenario operation vì chưa có plan hợp lệ.

## Kết quả từng bước

| Bước | Kết quả | Bằng chứng |
|---|---|---|
| Mở GUI Firefox | PASS | Trang/DOM tải thật |
| Nhập IP và kiểm tra điều kiện | PASS | Đúng target/paw, CALDERA xác thực, Elevated, endpoint không bận |
| Bấm bắt đầu Survey endpoint + web | PASS có unknown | Model 5 lượt chọn collect_endpoint, probe_web, probe_dvwa, inspect_dvwa_modules, finish_survey; trạng thái completed_with_unknowns |
| Kết quả Survey | PASS | PTIT/Windows/PowerShell/Apache/DVWA; session DVWA xác minh; Wazuh ingestion vẫn unknown |
| Export profile/bundle | PASS HTTP | ZIP 64.990 byte, 31 entries, integrity đạt; profile endpoint trả JSON |
| Chuyển sang sinh kịch bản | PASS | UI giữ Survey ID và snapshot v2 của lượt mới |
| Sinh 1 bước tasklist | BLOCKED | budget_exceeded tại parse |
| Thực thi plan mới | BLOCKED đúng gate | Nút execution disabled vì chưa có plan hoàn tất |
| Kho kịch bản | PASS | Tìm powershell được 4 mẫu; mở chi tiết Undercover được; không chạy mẫu |
| Kho ability | PASS | Tìm tasklist được 3 bản ghi trong catalog 2.014 bản ghi |
| Reload trang/lịch sử | PASS | Survey mới được lưu, xuất hiện sau reload; không tự tạo lượt mới |
| Thêm plan vào kho / regenerate / xóa / hủy | NOT_TESTED trên plan mới | Không có plan completed; không xóa lịch sử để làm test |
| Scenario execution → correlation/report thật | NOT_TESTED | Phụ thuộc bước sinh plan đang bị chặn |

## Lỗi đã phát hiện

`scenario_outputs/ca33fb72b6b04620a7ade7d2c97d35da/result.json` và `token_metrics.json`:

- `budget_reason=phase_input_limit`.
- `input_tokens_reserved=51595`, `limit=49152`.
- Đây là **ước lượng/reservation**, không phải usage token actual.
- Có một request kind count_tokens, status count_unavailable, error type ValueError; actual usage null, reservation/charge 256 token.
- Không có bằng chứng request generation của Scenario được gửi trong phase parse này; không gọi đây là lỗi Gemini503/quota.
- Survey đã gọi Gemini thành công trong cùng bài thử; điều đó không bảo đảm các lần sau không gặp503.

UI báo “chờ cửa sổ mới hoặc thu hẹp yêu cầu/điều chỉnh budget” cho phase_input_limit. Riêng giới hạn input/phase **không được giải quyết chỉ bằng chờ**; wording này cần sửa để tránh hướng dẫn người dùng resume vô ích.

Survey hoàn tất nhưng bảng lịch sử gần đây còn hiển thị 4 lượt cho đến reload/refresh; reload hiện5 lượt gồm lượt mới. Cần xem lại cơ chế refresh history sau completion.

## Việc sửa tiếp theo

1. Đối chiếu component context của parse trên snapshot này; tìm vì sao yêu cầu ngắn vẫn reserve51.595 token. Tối ưu projection đúng phase, không tăng limit mù quáng hoặc cắt evidence tùy tiện.
2. Điều tra ValueError của count_tokens bằng log đã lọc và mock SDK; giữ null khi count unavailable.
3. Sửa hướng dẫn phase_input_limit trong UI và refresh history sau Survey completion.
4. Sau sửa chạy tiếp từ checkpoint hợp lệ hoặc tạo phiên bản rõ ràng nếu context/version thay đổi; không sửa plan/checkpoint để vượt gate.
5. Khi có plan, review đúng command tasklist và prerequisites, thực thi qua nút confirm, đối chiếu operation/link/source events. API55000 credential còn thiếu là blocker riêng cho execution identity telemetry.

## Artifacts

`review/gui-e2e-20261123/`:

- `survey-running.png` (chụp lúc UI đã chuyển sang kết quả, xem thêm ảnh tên completed).
- `survey-completed.png`.
- `scenario-budget-blocked.png`.
- `scenario-ui-state.json`.
- `checks.json` (profile_ip null do probe đọc key top-level ip không có trong schema; không phải kết luận target thiếu IP; target xác minh bằng UI/preflight/snapshot).

Không thay key/model/budget, không đổi source/validator, không sửa dữ liệu lịch sử. Không restart GUI/host trong bài thử. Bài kiểm thử này phát hiện blocker thực tế; không được dùng để tuyên bố toàn hệ thống đã hoàn thiện.
