# Khảo sát web và profile chuẩn hóa

Cập nhật tiếp theo: [DVWA_SESSION.md](DVWA_SESSION.md) bổ sung xác minh đăng nhập tùy cấu hình. Các mô tả dưới đây về session/security luôn null áp dụng cho khảo sát công khai và bản replay cũ; khảo sát bật xác thực có thể xuất kết quả đã xác minh kèm authentication_ref.

Ứng dụng chính nằm trong `GUI/`, chạy bằng `./start.sh`, mở http://127.0.0.1:8765. Không đổi cấu hình hiện có, model hoặc giao thức Gemini.

## Cấu trúc và bằng chứng

Profile giữ sáu trường cấp cao `id`, `os`, `address`, `services`, `capabilities`, `telemetry`.

- Inventory endpoint tiếp tục nằm trong `services` như trước.
- Mỗi dịch vụ web là một origin HTTP(S): scheme + host + port, dùng `kind: "web"`, `url`, `applications`, `evidence_ref`. Port mặc định 80/443 được lược khỏi URL; scheme và đường dẫn vẫn phân biệt. HTTP 400 chỉ là kết quả probe, không tạo dịch vụ.
- Mỗi ứng dụng nằm trong `applications[]`, có `name`, `base_url`, `application_identified`, `session_ready`, `current_security_level`, `version`, `evidence_ref`. Hiện chỉ nhận diện DVWA/XAMPP từ dấu hiệu phản hồi 2xx; không suy ra phpMyAdmin từ đường dẫn hoặc 403. Với khảo sát công khai và replay cũ, phiên bản, session và security level giữ null; khảo sát bật xác thực có thể ghi `session_ready`, `current_security_level` và `authentication_ref` sau khi xác minh thành công.
- `capabilities.web_reachable` phản ánh đã quan sát phản hồi HTTP(S) đủ căn cứ; `application_identified` là capability tùy chọn, khác với `dvwa_session_ready`. Truy cập trang login không chứng minh đăng nhập.
- `web_evidence.json` giữ mọi request trong `requests`, kết quả URL loại trùng trong `observations`, nguồn file/index, URL ban đầu, chuỗi chuyển hướng, HTTP status, banner, title, lỗi và trạng thái xác minh TLS. `origins` và `applications` trỏ về các observation. `evidence_ref` dùng tên file + JSON pointer, có thể lần tới file tool gốc. Banner Server là thông tin tự công bố, không phải phiên bản hệ điều hành được xác minh.
- Tool artifacts giữ dữ liệu đầy đủ đã thu; probe không lưu HTML, credential hoặc cookie. Tóm tắt gửi LLM chỉ có số lượng, URL đã che dữ liệu nhạy cảm, port, status, application hint, loại lỗi và TLS; tối đa 24 observation, có số lượng bị lược. Metadata tool calling Gemini được giữ nguyên bởi adapter hiện có.

Gom theo origin không gộp HTTP với HTTPS. Loại trùng observation theo URL chuẩn hóa, status và lỗi, vẫn giữ từng request và nguồn. URL có cùng đích qua chuyển hướng có chung observation; các đường dẫn khác nhau vẫn là các observation khác nhau. Hạn chế của bằng chứng cũ được giữ, không tái tạo chuỗi chuyển hướng bị thiếu.

Python normalizer, JSON Schema, Pydantic và bộ đọc Scenario đã cập nhật cùng nhau. Profile lịch sử dạng mỗi URL một service được chuyển trong bộ nhớ khi xem hoặc nhập vào Scenario. File lịch sử và JSON tải xuống giữ nguyên byte gốc; không âm thầm viết lại. `evidence_ref: "#/services"` trong bản chuyển lịch sử tham chiếu danh sách services của file đầu vào cũ; nguồn chi tiết có trong evidence của lượt đó.

## Null và kết quả khảo sát

Null nghĩa là **Chưa xác minh**, không phải false. False chỉ hiển thị **Không** khi có giá trị đó. `missing_information` trong báo cáo mới gồm `field`, `status`, `reason`, `required`:

| status | Ý nghĩa |
| --- | --- |
| `not_checked` | Chưa thực hiện phép kiểm tra thích hợp |
| `check_failed` | Phép kiểm tra/tool chưa xác minh được kết quả; xem bằng chứng |
| `credential_required` | Cần phiên đăng nhập hoặc credential để xác minh; không tự đăng nhập |
| `out_of_scope` | Ngoài lựa chọn khảo sát; không đưa thành cảnh báo cần khắc phục |

`completed_with_unknowns` hợp lệ khi các tool trong phạm vi đã thực hiện xong, dù đích trả lỗi kết nối hoặc các điều kiện tùy chọn chưa xác minh. `partial` khi chưa hoàn tất tool bắt buộc hoặc vòng AI dừng vì lỗi/budget. `tool_errors` phân biệt lỗi công cụ với `failure.stage=model` và lỗi probe của ứng dụng đích. Báo cáo và timeline không suy đoán lý do model quyết định.

Wazuh/Sysmon service đang chạy không xác minh tạo log hoặc ingestion. Không tự điền telemetry. UI tách tóm tắt, URL kỹ thuật và thông tin còn thiếu. HTTPS chưa có bằng chứng không hiển thị thành công. Phiên DVWA hiển thị **DVWA được nhận diện — chưa xác minh đăng nhập** khi chưa bật hoặc chưa đạt kiểm tra xác thực; khi xác minh thành công, UI hiển thị trạng thái session và security level có bằng chứng.

## HTTPS và phạm vi

Probe phân loại `dns`, `timeout`, `refused`, `tls_certificate`, `hostname_mismatch`, `tls_error`, `out_of_scope_redirect`, `redirect_error`, `other`; thông báo giới hạn độ dài và che secrets. Mọi bước chuyển hướng được kiểm tra trước khi gửi request: cùng IP mục tiêu, chỉ cổng trong danh sách probe được phép, HTTP(S), không userinfo. Link nội bộ cũng chịu giới hạn này. Số trang, số cổng và thời gian được giới hạn; không lặp cùng lỗi transport trên nhiều đường dẫn của một origin.

TLS dùng `ssl.create_default_context`, luôn xác minh certificate/hostname. Nếu cần CA riêng, quản trị viên có thể đặt **tùy chọn** `web_ca_file` trong config thành đường dẫn tuyệt đối hoặc `~/...` tới PEM; mặc định dùng trust store sẵn có. Không tự cài CA hoặc tắt verify. HTTP fallback trên cổng 443 được giữ như chẩn đoán; HTTP 400 không chứng minh HTTPS sẵn sàng.

## Replay và kiểm chứng

Chạy offline từ thư mục đồ án, sau khi kích hoạt virtualenv GUI (`source GUI/.venv/bin/activate` trên Unix hoặc `GUI\.venv\Scripts\Activate.ps1` trong PowerShell):

```bash
# Replay fixture offline (Unix):
mkdir -p GUI/outputs
cp -R GUI/tests/fixtures/legacy_run GUI/outputs/legacy_run
# PowerShell tương đương: New-Item -ItemType Directory GUI/outputs -Force; Copy-Item -Recurse GUI/tests/fixtures/legacy_run GUI/outputs/legacy_run
python -B GUI/tools/replay_web.py legacy_run
cd GUI
# Với lượt chạy được phép khác, đặt dữ liệu vào GUI/outputs/<RUN_ID> rồi dùng <RUN_ID> thay legacy_run.
python -B -m unittest discover -s tests -p 'test_*.py'
cd ..
node GUI/tests/scenario-ui.test.cjs
node GUI/tests/flow-core.test.cjs
```

Package không phát hành `GUI/outputs/`; fixture lịch sử đã sanitize nằm tại `GUI/tests/fixtures/legacy_run/` và được dùng bởi test replay. Replay chỉ đọc `outputs/<run-id>` và ghi `review/web-<run-id>`; không chạy GET, LLM, operation hoặc đăng nhập. Kết quả gồm profile, bằng chứng chuẩn hóa, report và comparison có hash nguồn. Không dùng thư mục nguồn làm đích review.

Lượt `f273cfc2e7604db999778e4de0873723`: trước 9 mục dịch vụ; sau 4 mục (Sysmon64, Wazuh, Sandcat, HTTP). HTTP chứa XAMPP `/dashboard/` và DVWA `/dvwa/`. 11 bản ghi gồm 8 phản hồi HTTP và 3 lỗi HTTPS từ log cũ; gom thành 9 observation, giữ 2 bản trùng trong requests. `/phpmyadmin/` 403 và ba URL HTTP 400 trên cổng 443 vẫn có trong bằng chứng, không thành ứng dụng/dịch vụ riêng. Log cũ chỉ lưu lớp `URLError`, nên dùng `legacy_unknown`: không xác định được lỗi CA, hostname hay timeout. URL yêu cầu ban đầu và chuỗi chuyển hướng cũ không được ghi, giữ thiếu thay vì đoán.

Kiểm chứng ngày 2026-11-12 UTC: 50 Python tests, 47 đạt và 3 bỏ qua vì sandbox cấm socket; 10 bài Scenario/Survey DOM và 6 bài Flow đạt. Có fixture TLS certificate/hostname, timeout/refused, DNS, redirect ngoài phạm vi, HTTP400, DVWA login, 403, endpoint-only, LLM summary, tool failure, replay và lịch sử. Các bài Gemini multi-turn mock và tên tải/nội dung file vẫn đạt. Test runner in `Operation: test-op` từ API giả lập; không phải operation lab.

Giới hạn: chưa kiểm tra bố cục bằng trình duyệt thật hoặc probe HTTPS thực tế trong task này. Không gọi API LLM thực; thành công nhiều lượt của lượt gốc là bằng chứng có sẵn do người dùng xác nhận. Không sửa HTTPS trên Windows. Không đổi nội dung JSON tải hoặc cách đặt tên tải; trình duyệt vẫn có thể thêm `(1)` khi tải lại.

## Backup và rollback

Backup trước khi sửa nằm trong kho backup riêng ngoài package này (mã nguồn GUI và final_template, không gồm virtualenv/outputs); kho đó giữ `preserved.json` với SHA-256 cấu hình và toàn bộ kết quả có sẵn. Người vận hành phải ghi đường dẫn kho backup vào hồ sơ triển khai trước khi thay đổi, không commit đường dẫn vào source. Đối chiếu hash sau thay đổi để bảo đảm dữ liệu được giữ.

Để rollback, dùng đường dẫn kho backup đã ghi trong hồ sơ triển khai: dừng riêng GUI, giải nén archive vào thư mục tạm để đối chiếu, rồi phục hồi các file mã nguồn và tài liệu đã sửa từ bản backup. Các file mới hoặc tài liệu được chỉnh của task: `final_template/web_profile.py`, `GUI/engine/readiness.py`, `GUI/engine/web_history.py`, `GUI/tools/replay_web.py`, `GUI/tests/test_web_normalization.py`, `GUI/DVWA_SESSION.md`, `GUI/VERIFICATION.md`, `GUI/WEB_PROFILE.md` và `final_template/README_QUY_CHUAN_DUNG_SAI.md`. Thư mục review nằm ngoài package. Không phục hồi cấu hình hoặc outputs bằng cách ghi đè. Khởi động lại bằng launcher chính sau khi kiểm tra.
