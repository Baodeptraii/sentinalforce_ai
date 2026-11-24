# SOC Console — ứng dụng chính

Source package path is `GUI/`. Run from this directory after creating a local virtual environment and copying `config.example.json` to `config.json`. Do not commit local credentials or runtime output.

## Khởi động

Từ thư mục `GUI/`:

```bash
./start.sh
```

Mở **http://127.0.0.1:8765**. Launcher chọn `GUI/.venv/bin/python`, chuyển về thư mục GUI và cố định `SURVEY_CONFIG_FILE` vào `GUI/config.json`. Có thể truyền `--port 8767` khi kiểm tra một cổng riêng. Chạy launcher không tự tạo operation; chỉ thao tác bắt đầu khảo sát mới gửi công việc.

Môi trường GUI hiện có Python 3.11.17, LangGraph 1.2.20, Pydantic 2.14.3. Dependency nằm trong `pyproject.toml` và `uv.lock`; môi trường CALDERA không được sửa. Nếu cần tái tạo virtualenv, dùng Python 3.11 riêng và cài dependency theo lock bằng uv; không dùng pip của CALDERA.

## Cấu hình

Sửa từng trường trong `config.json`, không thay toàn bộ file:

- `caldera_url`, `key_file`, `allowed_networks`: kết nối/phạm vi CALDERA. `key_file` ở gốc là key **CALDERA**.
- `orchestration_mode`: `ai` hoặc `scripts`. Bản hợp nhất giữ `ai` theo cấu hình đang dùng.
- `llm.base_url`, `llm.model`, `llm.key_file`: cấu hình **LLM riêng**. Model giữ `gemini-3.5-flash-lite`, không đổi model khi lỗi.
- `llm.max_steps`, `max_seconds`, `timeout_seconds`, `max_output_tokens`: giới hạn vòng AI. Không có retry HTTP 400 hoặc tự fallback sang scripts.
- `web_ports`, `web_paths`, `dvwa_paths` và các giới hạn probe giữ cấu hình đã có.

Các biến môi trường đang được hỗ trợ vẫn có tác dụng: `CALDERA_URL`, `CALDERA_KEY_FILE`, `CALDERA_KEY`, `SURVEY_LLM_BASE_URL`, `SURVEY_LLM_MODEL`, `SURVEY_LLM_API_KEY`. Chỉ gửi mode/model và thông tin nhận diện ứng dụng xuống frontend, không gửi key. Không in key vào log.

## Khảo sát và kết quả

Nhập IP, chọn endpoint/web/cả hai và tùy chọn DVWA. Preflight xác minh phạm vi, agent duy nhất còn mới, executor và trạng thái operation. Quyền User chỉ cảnh báo; từng tool vẫn bị giới hạn tham số/phạm vi. Không cài ART hoặc dùng ART làm prerequisite chung.

AI dùng LangGraph để chọn tool trong allowlist: `collect_endpoint`, `probe_web`, `probe_dvwa`, `finish_survey` theo scope. Tool evidence qua Pydantic; profile do code tạo từ bằng chứng. Pydantic không kiểm chứng sự thật của môi trường. Nội dung banner/log là dữ liệu không tin cậy, không là chỉ thị hệ thống.

Các trạng thái hiển thị riêng: đang chạy, hoàn tất, hoàn tất còn thông tin chưa xác minh, một phần, thất bại/bị gián đoạn. `report.json=partial` luôn giữ nhãn một phần kể cả đã có profile. Mỗi lượt có timeline các sự kiện thật được code ghi lại, không có phần trăm tiến độ hoặc lý do LLM tự suy đoán.

Tóm tắt capability/telemetry được tách khỏi JSON/log kỹ thuật có thể mở rộng. Null là **Chưa xác minh**, false là **Không**; trường web/DVWA bị loại khỏi request được ghi **Ngoài phạm vi khảo sát** khi chưa có giá trị quan sát. Wazuh/Sysmon service chạy không chứng minh ingestion.

`outputs/<run-id>/` giữ request, profile, report, evidence, trace và trạng thái. Lỗi sau khi đã thu thập vẫn giữ bằng chứng và xuất profile một phần khi có thể. Các run từ cả hai bản đã giữ, run trùng được so sánh nội dung; không ghi đè im lặng. Refresh chỉ đọc/poll job đang có, không tự tạo operation mới.

### Tải profile

File nội bộ vẫn là `target_profile.json`. Tên tải do `Content-Disposition` tạo từ IP chuẩn hóa, thời điểm UTC đã ghi trong run và **toàn bộ run ID** để tránh cả trường hợp trùng 8 ký tự đầu:

```text
target_profile_192-0-2-10_20261111T085714Z_example.json
```

Tải lại cùng run cho cùng tên, không tạo bản sao mới trên server và trả nguyên byte của JSON đã lưu. Với profile lịch sử legacy, GUI chuẩn hóa trong bộ nhớ khi chuyển sang Scenario; file tải vẫn giữ nội dung bằng chứng gốc. Trình duyệt có thể thêm `(1)` khi tải lại; server không kiểm soát ghi đè trong Downloads.

## Scenario, dataset và màn hình luồng

Giữ các màn hình `#scenario`, `#library`, `#flow`, cùng lịch sử và nút chuyển profile từ khảo sát. Scenario nhận profile chuyển tiếp/tải JSON/chọn sẵn, yêu cầu văn bản và dataset. Kho có 113 adversary, tìm kiếm/lọc/phân trang, xem và tải YAML. Phần sinh kịch bản vẫn là xem **mẫu có sẵn**, chưa có backend AI sinh kịch bản.

`#flow` là mô phỏng riêng: node/đường truyền/inspector/log, chạy/pause/step/reset và ba tình huống. Không phải sự kiện backend realtime, không cấp quyền lab qua nút phê duyệt mô phỏng.

Chuẩn chung ở `../final_template/`; ba nhóm input nghiệp vụ là `user_request`, `target_profile`, `dataset`. Không thêm đầu vào danh mục riêng. Bộ ability đầy đủ và chuẩn hóa liên kết target ID vẫn chờ công việc sau.

## Kiểm tra

Từ thư mục `GUI/`:

```bash
.venv/bin/python tools/verify_offline.py
```

Kiểm tra API LLM **hai lượt**, chỉ tool giả lập, không CALDERA/victim, tối đa 2 request mỗi lần chạy; không retry:

```bash
.venv/bin/python -B -m engine.check_llm
```

Kiểm tra này yêu cầu model gọi tool, gửi lại assistant message có metadata và tool result với đúng call ID, rồi yêu cầu model xác nhận nonce trả về. Nó không đánh giá chất lượng khảo sát hoặc detection SOC.

Trong sandbox của phiên hợp nhất, API thật bị lỗi DNS; chưa xác minh nhiều lượt với Gemini thật. Socket localhost cũng bị chặn nên chưa restart GUI hoặc kiểm tra bố cục laptop bằng trình duyệt thực. Chi tiết backup, rollback và triển khai nội bộ không nằm trong package staging. Không coi test một lượt cũ hoặc mock mới là bằng chứng API thật đã sửa xong.

## Chuẩn hóa khảo sát web

Xem [WEB_PROFILE.md](WEB_PROFILE.md) về dịch vụ theo origin, ứng dụng theo base URL, bằng chứng request riêng, null/readiness và chẩn đoán HTTPS. Giao diện nhóm dịch vụ/ứng dụng và cho mở các URL/lỗi kỹ thuật; DVWA login 200 không xác minh đăng nhập. Profile cũ được đọc tương thích trong Survey/Scenario; JSON lịch sử tải xuống không bị viết lại.

Ví dụ offline và artifact review lịch sử không nằm trong package staging. HTTPS lỗi cần được phân loại bằng evidence riêng; không suy đoán nguyên nhân từ một URLError.

## Xác minh đăng nhập DVWA

Survey đã hỗ trợ đăng nhập bằng credential cấu hình riêng, xác minh index và đọc security level. Xem [DVWA_SESSION.md](DVWA_SESSION.md) và chạy `.venv/bin/python -B -m engine.check_dvwa` từ thư mục GUI để kiểm tra riêng, không chạy CALDERA.

## Phạm vi HTTP

Mỗi mục tiêu chỉ được probe trong `allowed_networks`, cổng và đường dẫn cấu hình. HTTPS ngoài scope không là lỗi. Xem `engine/web_scope.py`, `engine/web_limitations.py` và `tools/replay_web.py` về cấu hình mục tiêu, tham chiếu bằng chứng, giới hạn telemetry và replay offline.
