# Bản sửa phạm vi HTTP và bằng chứng Survey

## Cấu hình đang dùng

Launcher `~/DATN/GUI/start.sh` đặt `SURVEY_CONFIG_FILE` thành `/home/bao/DATN/GUI/config.json`. Trong môi trường kiểm tra không có override biến này; hàm `load_config()` dùng đúng file trên. Không thấy tiến trình GUI trong namespace tiến trình của môi trường kiểm tra, nên không suy đoán một GUI chạy ngoài namespace đã nạp cấu hình mới.

Đã thêm vào config, giữ các trường credential/API/LLM hiện có:

```json
"web_scope_by_target": {
  "192.168.73.130": [{"scheme": "http", "port": 80}]
}
```

Thứ tự ưu tiên: `web_scope_by_target[IP]` → `web_scope` chung → cấu hình cũ `web_ports` (HTTP và HTTPS trên các cổng đó). Map theo IP ghi đè phạm vi chung cho IP đó. Vì vậy danh sách `web_ports` cũ còn các cổng khác không cấp quyền gửi chúng tới `.130`. Có thể cấu hình mục tiêu khác bằng `{"scheme":"https","port":443}` hoặc cổng khác. Danh sách phạm vi rỗng không cho probe mạng web. LLM chỉ chọn tool/source, không được thay allowlist.

`web_scope.py` cung cấp cùng chính sách cho probe công khai và đăng nhập. `survey.py` lọc trước khi tạo request, chặn scheme/port sai ở redirect và link nội bộ; không thử fallback ngoài scope. Nhánh discovered chỉ dùng các cổng listener đã quan sát nằm trong allowlist. `dvwa_session.py` kiểm tra base URL trước khi đọc credential/gửi request; redirect đăng nhập tiếp tục bị giới hạn cùng origin và các trang được cho phép. HTTPS ngoài scope là `out_of_scope`, giá trị verified vẫn null và không tạo cảnh báo cần khắc phục.

## Bằng chứng, limitations và cảnh báo

Nguồn tool được truyền tới normalizer bằng `tool_03_probe_dvwa.json#/data`; nguồn scripts không bọc data dùng tên file thuần. Normalizer tạo `authentication_ref` tương ứng `tool_03_probe_dvwa.json#/data/authentication`. Các observation có tên file, index và pointer tới vị trí trong dữ liệu nguồn. `evidence_refs.py` kiểm tra các evidence/authentication reference trước khi lưu profile mới; từ chối đường dẫn tuyệt đối, traversal và symlink thoát thư mục run. Những tham chiếu tới origin/app trong `web_evidence.json` cũng được phân giải kiểm tra.

`web_limitations.py` tạo mô tả từ kết quả thực tế: probe công khai, bước xác thực chưa cấu hình/thiếu credential/ngoài scope/thất bại, phiên đã xác minh, security level đã đọc hoặc chưa xác minh. Lỗi HTTP xác thực được ghi bằng status code, không ghi response chứa secrets. Không tự gán low. Giữ cảnh báo ingestion chưa kiểm tra. `session_ready=true` chỉ chứng minh khả năng đăng nhập bằng phiên khảo sát tại `checked_at`; cookie bị xóa khi kết thúc kiểm tra và không được hứa còn hiệu lực trong lượt thực thi sau.

`readiness.py`, finalizer AI/scripts loại trùng warnings bằng so sánh chính xác chuỗi, giữ thứ tự. Không gộp các lý do khác nhau. Bốn mục telemetry vẫn riêng biệt trong `missing_information`, đầy đủ field/status/reason/required. UI có một thông báo chung mở rộng ra các trường liên quan; null vẫn là chưa xác minh. Bộ đọc lịch sử loại trùng thông báo khi hiển thị, không ghi lại report gốc. Các lỗi HTTPS của lượt cũ vẫn phản ánh request thực sự đã gửi lúc đó.

Không đổi schema cấp cao, model, wire metadata Gemini, credential hoặc profile lịch sử. Các thay đổi chính: `engine/web_scope.py`, `survey.py`, `agent.py`, `dvwa_session.py`, `web_limitations.py`, `evidence_refs.py`, `readiness.py`, `presentation.py`, `web_history.py`, `final_template/web_profile.py`, `static/app.js`, config và kiểm thử liên quan.

## Replay và kiểm thử

Ví dụ: `review/http-scope-f32a4866f5434e89840a45cb24009eb4/`. Đây là **offline_filtered_replay**, không phải lượt khảo sát live: lấy bằng chứng HTTP:80 từ run gốc, loại 17 bản ghi ngoài chính sách mới trong bản review, chuẩn hóa lại và giữ thời điểm xác thực lịch sử. File tool trong review được ghi nhãn replay; report chứa SHA-256 nguồn và giải thích rõ bản gốc đã gửi request ngoài phạm vi mới. Không làm cho bản gốc trông như đã chạy bằng mã mới. Replay có 2 cảnh báo khác nhau (phiên bản DVWA chưa xác minh và telemetry chưa kiểm tra), các mục chi tiết vẫn đầy đủ.

```bash
cd ~/DATN
GUI/.venv/bin/python -B GUI/tools/review_http_scope.py f32a4866f5434e89840a45cb24009eb4
GUI/.venv/bin/python -B -m unittest discover -s GUI/tests -p 'test_*.py'
node GUI/tests/scenario-ui.test.cjs
node GUI/tests/flow-core.test.cjs
```

Kết quả: 64 Python tests, 61 đạt, 3 bỏ qua do sandbox cấm socket; 11 Survey/Scenario DOM tests và 6 Flow tests đạt. Fixture kiểm tra cả hai tool/hai source, fallback, link/redirect ngoài scope, cấu hình HTTPS cho mục tiêu khác, auth bị chặn trước mạng/credential, JSON Pointer/file tồn tại/traversal/symlink, limitations thành công/thất bại/chưa cấu hình/security level null, telemetry dedup và UI mở rộng. Các bài hồi quy Gemini mock, download và lịch sử cũng đạt. Dòng `Operation: test-op` trong bộ kiểm thử là API giả lập, không chạy operation lab.

Không gọi LLM thật, không gửi request tới victim, không sửa Windows/CALDERA/Wazuh. Chưa kiểm chứng khảo sát live sau sửa hoặc browser layout thật.

## Backup và nạp bản sửa

Workspace không có Git repository. Backup trước thay đổi tại `backups/scope-20261112T040700Z/source.tar.gz`; file `outputs.sha256.json` cùng thư mục dùng để xác nhận 153 file lịch sử giữ nguyên. Backup có cấu hình trước sửa; khi rollback chỉ phục hồi các file liên quan sau đối chiếu, không ghi đè thay đổi mới hoặc outputs.

Nếu GUI đang chạy ở terminal, Ctrl+C tại đúng terminal đó rồi:

```bash
~/DATN/GUI/start.sh
```

Mở http://127.0.0.1:8765. Việc khởi động GUI không tự chạy lại khảo sát; cần lượt mới để kiểm chứng thực tế chính sách HTTP:80.
