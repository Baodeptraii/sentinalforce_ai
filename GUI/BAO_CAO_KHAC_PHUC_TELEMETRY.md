# Kết quả khắc phục Survey Agent

**Hoàn tất kiểm chứng:** 17/11/2026 theo múi giờ Việt Nam. Timestamp artifact trên Ubuntu dùng UTC ngày 16/11/2026.

**Bản triển khai:** `/home/bao/DATN/GUI`, `http://127.0.0.1:8765`.

## Vấn đề và cách sửa

| Vấn đề | Nguyên nhân đã kiểm tra | Cách khắc phục |
|---|---|---|
| Danh sách Running quá dài | UI hiển thị toàn bộ services và listener inventory ngay trong phần chính | Giữ Apache/MySQL, Wazuh, Sysmon, Sandcat và web ở tóm tắt; gom dịch vụ hệ thống/TCP vào mục đóng/mở có số lượng. Không xóa inventory khỏi JSON. |
| Nhiều cảnh báo và thông tin kỹ thuật gây rối | Cảnh báo, metrics và chi tiết hiển thị cùng lúc | Gom cảnh báo/số liệu, bằng chứng telemetry và chi tiết vào mục đóng/mở; lỗi khiến job thất bại vẫn hiển thị riêng. |
| Wazuh đã có log nhưng profile luôn unknown | Producer luôn gán telemetry None; Pydantic và shared schema cũng chỉ chấp nhận None; chưa có collector | Thêm collector endpoint và Wazuh; đồng bộ schema Python, JSON và schema nhúng trong GUI. Chỉ xuất true khi có metadata bằng chứng phù hợp. |
| Chỉ biết Sysmon/Wazuh Running | Inventory chỉ đọc trạng thái dịch vụ | Ability v4 đọc metadata Sysmon ID 1/3, thời gian, record ID và bản ghi Apache access trong cửa sổ 24 giờ. |
| Không biết log đã đến Manager hay chưa | Survey không truy vấn Wazuh | Đọc giới hạn phần cuối alerts/archives qua SSH đã xác minh host key; đối chiếu agent ID 001, hostname và mapping target. Lưu metadata, không lưu raw message/command. |
| Parser bỏ qua timestamp Wazuh | Manager trả offset `+0000`; Python của Manager cần dạng có dấu `:` cho `fromisoformat` | Chuẩn hóa offset và thêm kiểm thử bằng timestamp Wazuh thực tế. |
| Contract sửa nhưng UI upload chưa nhận | `scenario-data.json` có bản sao profile schema | Cập nhật bản sao, giữ kiểm thử so sánh schema để phát hiện lệch lần sau. |
| Sandcat bị untrusted khi chạy lại | Agent đúng endpoint vẫn online nhưng trusted=false | Kiểm tra paw, hostname, IP, platform, executor, last_seen rồi PATCH trusted=true cho đúng agent. Không bỏ kiểm tra trust hay thêm tự động trust mọi máy. |
| Khảo sát module DVWA bị cắt | Budget mặc định 12 trong khi DVWA có 17 module được phát hiện | Đặt max_dvwa_modules=20 theo mức trần code đang hỗ trợ; lượt cuối đọc 17, modules_truncated=false. Chỉ đọc metadata, không submit form tấn công. |

## Kiểm chứng thực tế

- SSH vào Ubuntu Desktop `192.168.73.128`, Windows `192.168.73.130` và Wazuh Manager `192.168.73.129`.
- Windows có Sysmon ID 1/3 và access.log. Wazuh Manager có bản ghi Apache access/error và các Windows Event Channels của agent 001. Cấu hình thu log đã tồn tại; không cần sửa Wazuh hoặc antivirus.
- Chạy một lượt scripts ở staging và hai lượt AI qua HTTP API của GUI chính; lượt AI thứ hai xác nhận thay đổi budget module.
- **Run cuối:** `cf385e27da744f9fb69708e3266691ea`.
- **83 kiểm thử Python + 19 kiểm thử JavaScript đạt**, bao gồm hồi quy identity, scope, timestamp, thiếu evidence, lỗi SSH, cancel và UI đóng/mở. Test chạy lại trên bản triển khai; fake LLM/CALDERA được dùng trong bộ offline, tách khỏi run lab thật.
- Gói handoff qua endpoint download chứa **27 file**; checksum từng evidence đạt và profile download khớp bytes artifact gốc.
- CALDERA đã hoàn nguyên group; `group_restored=true`, `cleanup_required=false`. Không còn job GUI đang chạy lúc nghiệm thu.

Profile cuối:

```json
{
  "process_events": true,
  "network_events": true,
  "web_access_logs": true,
  "wazuh_ingestion": true
}
```

Các giá trị này được xác định bằng code từ evidence, không từ lời LLM. Bước telemetry tự chạy sau vòng khảo sát ở cả hai mode, không tốn thêm request LLM. Trong run cuối, bước telemetry mất khoảng 0,973 giây; vòng AI có 5 request, 6.409 token provider báo cáo và khoảng 5,945 giây chờ model. Đây là số liệu của một lượt, không phải benchmark chất lượng AI.

## File và cấu hình đã thay đổi

- Collector mới: `engine/telemetry.py`, `engine/wazuh_scan.py`, `engine/ssh_askpass.py`.
- Inventory: `engine/survey_windows_basic.ps1`, `engine/runner.py` với ID ability/adversary v4 riêng; không ghi đè ability v3.
- Tích hợp và validation: `engine/survey.py`, `engine/agent.py`, `engine/contracts.py`, `engine/readiness.py`, `engine/evidence_refs.py`, `../final_template/target_profile_schema.json`.
- UI: `static/app.js`, `static/index.html`, `static/scenario-data.json`.
- Kiểm thử: thêm `tests/test_telemetry.py`, cập nhật kiểm thử contract/evidence và DOM.
- `config.json`: thêm cấu hình telemetry có binding target và đặt budget module=20. Credential SSH riêng có quyền 0600, host key được lưu riêng. Giữ các cấu hình/key Gemini, CALDERA và credential DVWA đã có.
- Tài liệu vận hành: `TELEMETRY_UPDATE.md` trong GUI.

Backend mới đã được nạp bằng restart đúng GUI khi không có job chạy. Không restart CALDERA, không sửa dịch vụ Windows/Wazuh và không chạy kịch bản tấn công để tạo kết quả.

## Giới hạn cần đọc đúng

- Run vẫn có trạng thái `completed_with_unknowns` vì **phiên bản DVWA chưa xác minh**. Đây là dữ kiện còn thiếu hợp lệ; không liên quan lỗi ingestion đã sửa.
- `detection_result=not_evaluated`: log đã được nhận không chứng minh SOC phát hiện đúng mọi kịch bản.
- Cửa sổ 24 giờ và phần cuối file có giới hạn; không tìm thấy bản ghi không đồng nghĩa mất log. Counts có thể gồm cùng sự kiện ở alerts và archives, không phải số sự kiện duy nhất hoặc tỷ lệ detection.
- Collector hiện dùng SSH và quyền đọc log Manager của tài khoản lab đã cung cấp. Máy đích khác cần cấu hình binding agent ID/hostname/log path tương ứng; thiếu mapping giữ unknown, không dùng nhầm thông tin máy cũ.
- Cancel trước collector bỏ qua nó; SSH đang chờ có thể cần đến hết timeout tối đa 20 giây. Thời gian collector là ngân sách riêng, nằm ngoài thời gian chờ LLM.
- Đã kiểm tra DOM tự động và HTTP artifact; **chưa kiểm tra bố cục bằng trình duyệt thật**. Tải lại trang bằng Ctrl+F5 để dùng UI mới.
- Không ghi lại profile lịch sử thành true. Các run cũ giữ nguyên bằng chứng và trạng thái của thời điểm đó.

## Đường dẫn và khôi phục

- Output Ubuntu: `/home/bao/DATN/GUI/outputs/cf385e27da744f9fb69708e3266691ea/`.
- Bằng chứng kiểm chứng: `/home/bao/DATN/verification/telemetry_final_verification.json`, `telemetry_deployed_tests.log`.
- Backup riêng: `/home/bao/DATN/verification/telemetry_upgrade_20261116T183335Z/`, gồm manifest/hash, bản cũ của file đã sửa và config riêng. Không chia sẻ `config.private.json`.
- Rollback theo manifest khi GUI không có job: dừng đúng GUI, khôi phục file/config gốc, giữ outputs và CALDERA, rồi dùng `~/DATN/GUI/start.sh`. Không xóa lock để chạy instance thứ hai.

GUI đang chạy; chỉ cần Ctrl+F5 và mở run cuối trong lịch sử để xem kết quả mới.
