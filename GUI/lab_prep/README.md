# Chuẩn bị lab cho 5 case cố định (thực hiện SAU KHI được duyệt)

Các file trong thư mục này là **bước prep ngoài kế hoạch thực thi** — không tự
đưa lên máy `.150` nếu chưa có xác nhận riêng của người dùng.

## Máy .150 (Windows victim)

1. **Tài khoản lab DVWA** — tạo `C:\SOC-Lab\config\dvwa_login.json`, quyền chặt:
   ```json
   {"user": "<tài khoản DVWA lab>", "pwd": "<mật khẩu lab>"}
   ```
   Giá trị lấy từ kênh credential của người dùng, KHÔNG ghi vào source, YAML,
   chat hay báo cáo. File chỉ dùng bởi ability cố định và verifier.
2. **XSS browser verifier** — copy `xss_browser_verifier.ps1` sang
   `C:\SOC-Lab\config\xss_browser_verifier.ps1`. Không sửa nội dung sau khi
   copy; đổi nội dung phải tạo phiên bản mới và cập nhật review.
3. **Kiểm tra Edge headless** — chạy tay một lần:
   `powershell -File C:\SOC-Lab\config\xss_browser_verifier.ps1 -BaseUrl http://192.168.1.150:8080/dvwa -JarPath C:\SOC-Lab\WEB\demo\session.txt -Payload '<script>document.title="XSS_EXEC_MARKER";document.documentElement.setAttribute("data-demo","xss-exec");</script>`
   (cần chạy bước session của WEB-01 trước để có `session.txt`).
4. Không tắt Defender/Sysmon/Wazuh/logging.

## Máy .164 (GUI)

5. `config.json` đã có `demo_receiver` (origin `http://192.168.1.164:18765`,
   cap 8 beacon / 3 exfil / 64 KiB). Runtime catalog và `input/demo_receiver.json`
   cùng origin — lệch nhau sẽ bị preflight chặn.
6. Survey phải chạy với scope chứa `web` cho WEB-01/WEB-02 và còn mới
   (≤3600s) ngay trước khi bấm chạy.

## Reset giữa các lần demo

- EP-02: namespace `C:\SOC-Lab\EP02\demo` — bước cleanup của case tự xóa; nếu
  run giữa chừng fail, xóa tay đúng thư mục đó.
- EP-03: `C:\SOC-Lab\EP03\demo\payload_demo.txt` ghi đè mỗi lần chạy; receipt
  nằm trong `executions/<id>/receiver_receipts.json` phía GUI.
- WEB: `C:\SOC-Lab\WEB\demo\session.txt` và thư mục profile Edge tạm — ghi đè
  mỗi lần chạy session; xóa tay nếu cần.
- Không có bước nào đụng nội dung ngoài các namespace `C:\SOC-Lab\<case>\`.
