# Xác minh phiên DVWA trong Survey Agent

Survey có thể đăng nhập DVWA khi chọn khảo sát DVWA và `dvwa_auth.enabled=true`. Chế độ AI gọi bước này trong `probe_dvwa`, tối đa một lần cho mỗi lượt khảo sát; scripts dùng cùng bộ kiểm tra. Backend sinh Scenario chưa được triển khai trong thay đổi này.

Cấu hình `dvwa_auth` chứa `base_url`, `enabled`, `credentials_file`. Credential file phải nằm ngoài package và được loại khỏi Git. Khi triển khai, giới hạn quyền đọc: Unix dùng file 0600 và thư mục cha 0700; Windows dùng ACL chỉ cấp quyền cho tài khoản chạy GUI. Bộ kiểm tra DVWA đọc credential theo cấu hình nhưng không thay thế kiểm tra quyền triển khai. Không đưa credential vào profile, LLM, artifact hay UI. Cấu hình CALDERA, LLM và lịch sử được giữ. Backup lịch sử nằm trong kho backup riêng, không phát hành cùng package; người vận hành phải giữ đường dẫn kho đó ngoài Git.

Quy trình: GET login lấy CSRF; POST form login một lần với cookie jar; GET index bằng cùng cookie và xác minh đúng đường dẫn cùng dấu hiệu logout; GET security.php đọc option security được chọn. Không POST đổi security level và không chạy payload. Chỉ chấp nhận chuyển hướng cùng origin và các trang login/index/security trong base URL cấu hình. TLS luôn xác minh. Cookie tồn tại trong bộ nhớ suốt phép kiểm tra rồi được xóa.

`session_ready=true` và `capabilities.dvwa_session_ready=true` chỉ khi xác minh thành công. Đây là khả năng đăng nhập tại thời điểm `checked_at`, không bảo đảm một cookie còn sống để dùng ở lượt thực thi sau. `current_security_level` chỉ được điền từ trang security của phiên đã xác minh, có thể là low/medium/high/impossible. Phiên bản và telemetry vẫn null. Không hạ security level tự động. HTTP 200 ở login không đủ xác nhận session; nếu chưa chứng minh được, giữ null và ghi lý do. Lỗi đọc security sau khi xác minh index vẫn giữ bằng chứng đăng nhập đã thành công.

Bằng chứng nằm trong `authentication` của file probe DVWA, gồm thời điểm, đường dẫn kiểm tra, HTTP status, kết quả và loại lỗi; không có cookie/CSRF/mật khẩu. Profile tham chiếu bằng `authentication_ref`. Bộ schema và Pydantic chấp nhận kết quả session/security đã xác minh; profile lịch sử vẫn đọc được. Giao diện hiển thị phiên đã xác minh hoặc chưa xác minh và security level.

Kiểm tra riêng từ thư mục `GUI/`:

```bash
.venv/bin/python -B -m engine.check_dvwa
```

Lệnh chỉ xác minh DVWA bằng cấu hình hiện có, không gọi LLM/CALDERA. Sau khi cập nhật, khởi động lại riêng GUI bằng `./start.sh` từ thư mục `GUI/` để nạp mã nguồn và cấu hình; chọn web + DVWA khi khảo sát.

Kiểm chứng: 56 Python tests (53 đạt, 3 socket tests bị sandbox chặn); 10 bài DOM Survey/Scenario đạt. Fixture kiểm tra CSRF, POST một lần, cookie jar, login 200 không đủ, scope redirect, đọc security và giữ phiên đã xác minh khi đọc security thất bại. Kiểm tra trực tiếp tại môi trường Codex bị `PermissionError`, errno 1, trước phản hồi HTTP; xem `review/dvwa-session-check/verification.json`. Chưa xác minh đăng nhập thực tế trên Windows, chưa kiểm thử browser thật. Không kết luận target lỗi từ giới hạn quyền cục bộ này.
