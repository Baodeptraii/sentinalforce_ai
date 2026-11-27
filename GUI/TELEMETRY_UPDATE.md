# Cập nhật Survey: kiểm chứng log và thu gọn giao diện

## Cách hoạt động

- Sau phần khảo sát, cả chế độ AI và scripts đều chạy bước kiểm chứng telemetry bằng code xác định. Bước này không gọi thêm LLM.
- Ability inventory v4 đọc metadata của Sysmon Event ID 1/3 trong 24 giờ gần nhất và một phần cuối Apache access.log. Đường dẫn Apache được lấy từ cấu hình localfile Apache của Wazuh Agent trên Windows.
- Collector Wazuh dùng SSH tới Manager, kiểm tra host key đã lưu và đọc giới hạn 8 MiB cuối mỗi file `alerts/alerts.json`, `archives/archives.json`. Chỉ xuất metadata: agent ID/tên, channel/event ID, nguồn và thời gian; không xuất message/command line/raw log.
- Đối chiếu target IP trong cấu hình với agent ID và hostname. Hostname phải khớp Sandcat hiện tại và bản ghi Wazuh. Chỉ chấp nhận timestamp có timezone, trong 24 giờ trước lần kiểm tra và không quá 120 giây ở tương lai.
- Không có bản ghi trong phần đã đọc không chứng minh pipeline lỗi. Mất kết nối, thiếu quyền, sai danh tính hoặc chưa cấu hình đều giữ `null` và có lý do.
- `process_events`, `network_events`, `web_access_logs` có thể được xác minh từ endpoint hoặc Manager. `wazuh_ingestion` chỉ được xác minh từ Manager. Một nguồn được xác minh không có nghĩa mọi nguồn đều ingest hoặc SOC phát hiện mọi kịch bản.
- Bốn trường giữ kiểu boolean/null trong profile sáu nhóm. Evidence gate đối chiếu với `telemetry_evidence.json` trước khi xuất profile/handoff. Pydantic chỉ kiểm tra kiểu; không tự chứng minh sự thật.

## Cấu hình triển khai hiện tại

GUI chính: `/home/bao/DATN/GUI`. Cấu hình `telemetry` trong `config.json` gồm:

```json
{
  "enabled": true,
  "host": "<manager-ip>",
  "username": "<ssh-user>",
  "credentials_file": "/absolute/private/wazuh-manager.json",
  "known_hosts_file": "/absolute/private/wazuh-known-hosts",
  "targets": {
    "<endpoint-ip>": {
      "agent_id": "<wazuh-agent-id>",
      "hostname": "<observed-hostname>",
      "web_log_paths": ["C:\\xampp\\apache\\logs\\access.log"]
    }
  }
}
```

File credential chứa trường `password`, quyền 0600; thư mục riêng 0700. Host key phải được xác minh và lưu trước; collector không tự chấp nhận host key mới. Tài khoản SSH hiện tại cần quyền đọc log qua sudo. Không ghi password vào config public, prompt hoặc output. Helper `engine/ssh_askpass.py` phải có quyền thực thi. Không cần cài thêm thư viện.

Target khác cần mapping riêng đã xác minh; không tái sử dụng binding của máy trước. Config này do quản trị viên cấu hình, không nhận từ LLM hoặc request HTTP. Hiện cấu hình máy lab `192.168.73.130` với Wazuh agent `001`, Manager `192.168.73.129`.

SSH có timeout tổng 20 giây. Bước telemetry có ngân sách riêng sau vòng LLM; thời gian nằm trong `report.telemetry.duration_seconds`, không cộng vào token/model latency. Cancel có hiệu lực trước bước collector; SSH đang chờ có thể cần đến hết timeout.

## Giao diện và kết quả

- Dịch vụ chính hiện ở phần tóm tắt; các dịch vụ Windows khác và TCP inventory nằm trong mục đóng/mở có số lượng.
- Cảnh báo, số liệu điều phối, bằng chứng telemetry và chi tiết kỹ thuật có mục đóng/mở. Lỗi khiến job thất bại vẫn hiển thị riêng.
- `telemetry_evidence.json` có giá trị, lý do, nguồn, thời điểm và thời gian collector. `report.json` chứa phần tương ứng để GUI hiển thị; handoff ZIP kèm evidence và checksum.
- Profile cũ không được viết lại thành đã xác minh. Chạy lượt mới để có collector và evidence mới.
- `max_dvwa_modules` được đặt thành 20 trong lab, vẫn chỉ GET metadata từ link module được phát hiện sau đăng nhập. Không submit form tấn công.
- Phiên bản DVWA chưa có nguồn xác minh vẫn giữ unknown. Metadata module không chứng minh khai thác thành công. `detection_result` vẫn là `not_evaluated`.

## Vận hành

GUI đã được restart sau cập nhật khi không có job hoạt động. Nếu GUI đang chạy, tải lại trang bằng Ctrl+F5; không chạy thêm instance. Nếu đã dừng, dùng `~/DATN/GUI/start.sh`.

Kiểm thử offline bằng `SURVEY_CONFIG_FILE="$PWD/config.example.json" .venv/bin/python tools/verify_offline.py` từ thư mục GUI. Fake LLM/CALDERA được dùng trong test, khác với các run lab được ghi riêng trong báo cáo.

## Khôi phục

Backup triển khai: `/home/bao/DATN/verification/telemetry_upgrade_20261116T183335Z`.

Chỉ rollback khi GUI không chạy job. Dừng đúng process GUI, đối chiếu `manifest.json`, khôi phục từng file có backup và cấu hình từ `config.private.json` (file riêng, không chia sẻ). Các file mới không có backup phải được xử lý theo manifest; không xóa cả project. Giữ nguyên outputs, credential cũ và môi trường CALDERA. Sau đó khởi động lại GUI và kiểm tra root/port. Không dùng xóa lock để vượt qua instance đang chạy.
