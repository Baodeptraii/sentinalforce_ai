# Hợp nhất GUI và sửa vòng AI — 11/11/2026

## Trạng thái bàn giao

Mã đã hợp nhất tại `/home/bao/DATN/GUI`; chưa thể xác nhận chạy được API Gemini nhiều lượt hoặc restart GUI trên desktop vì giới hạn môi trường hiện tại. Không coi smoke test một lượt cũ là bằng chứng sửa xong HTTP 400.

## Đã hợp nhất và giữ lại

- Giữ bản chính, Survey scripts, Scenario UI, kho 113 kịch bản, chuyển/tải profile, lịch sử và màn hình Flow mô phỏng.
- Đưa riêng `agent.py`, `llm.py`, `contracts.py`, `check_llm.py`, dependency/lock và test AI từ `~/GUI` sang. Hợp nhất `survey.py` theo từng thay đổi, giữ kiểm tra `final_template`; runner và PowerShell giống nhau nên không thay.
- Cấu hình gốc CALDERA của hai bản giống nhau và được giữ; bổ sung mode AI, `llm` và `dvwa_paths`. `key_file` gốc của CALDERA không bị nhầm với `llm.key_file`. Model giữ `gemini-3.5-flash-lite`.
- Bốn run: `9477a3c129eb49f7b2161eb59eb293a6`, `9f423ae4758742328ad2d2bccc9e4b9e`, `1258e4a1534541a49a17557578bf6c13`, `2de999af2b524923a3f10f7d0091c0fc`. Run trùng `9477…` có cùng tên file và checksum nội dung, nên giữ bản đang có. Hai run AI được nhập riêng; không ghi đè. Checksum toàn bộ lịch sử gốc của cả hai bản không đổi.
- Không có git repository hợp lệ ở workspace/hai GUI (`git status` báo not a git repository); không thể khẳng định working tree sạch. Dùng snapshot/checksum để bảo toàn thay đổi hiện có.
- Không tìm thấy AGENTS.md áp dụng trong các đường dẫn cha hoặc hai GUI đã kiểm tra. Đã đọc toàn bộ rules.md, không xử lý D21/Stuff.

## Lỗi Gemini: điều gì đã xác minh

Run `1258…` lưu tool `collect_endpoint` thành công rồi lỗi HTTP 400 ở lượt model thứ hai. `report.json` là partial, steps=2, stop_reason=llm_error. `ai_trace.json` cũ chỉ còn thông báo HTTP chung; không có raw response lượt đầu hay body lỗi 400. Vì vậy không thể chứng minh provider đã từ chối chính xác vì thiếu thought_signature trong lần chạy này.

**Defect mã nguồn đã xác minh:** adapter cũ chỉ trả lại id/type/function, làm mất các trường mở rộng của tool call. Agent tiếp tục dựng một assistant message mới. Hồi quy wire mock xác nhận bản cũ thiếu metadata bị fixture trả 400; giữ nguyên metadata thì hội thoại tiếp tục hợp lệ. Đây là bằng chứng giao thức offline, không phải xác nhận API thật.

Tài liệu chính thức [OpenAI compatibility của Gemini](https://aistudio.google.com/docs/openai) xác nhận đường Chat Completions đang dùng; đã đối chiếu cả [Function calling](https://aistudio.google.com/docs/function-calling). [Google hướng dẫn thought signatures](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/thinking/thought-signatures) yêu cầu giữ signature cùng function call khi tiếp tục hội thoại; ví dụ Chat Completions đặt signature trong `tool_calls[].extra_content.google.thought_signature`. Thiếu signature bắt buộc có thể trả 400. Đây là căn cứ cho bản sửa và là giả thuyết phù hợp với lỗi lịch sử, chưa phải nguyên nhân thực tế đã chứng minh.

### Bản sửa

- Giữ nguyên tool-call object, id, arguments và metadata provider; replay assistant message tương ứng trong bộ nhớ. Không chuyển SDK/native API vì sửa tại chỗ đáp ứng giao thức, giữ URL/model/dependency đang dùng.
- Không lưu blob signature, reasoning riêng tư hoặc prose model vào ai_trace/profile/UI. Audit chỉ ghi tool/arguments đã kiểm tra, cấu trúc role/call ID và cờ có metadata; không ghi giá trị metadata.
- Giữ tool allowlist, schema tham số, phạm vi mục tiêu, giới hạn số bước/thời gian và retry cũ (không có retry HTTP 400). Không đổi model hoặc fallback sang scripts.
- Lỗi HTTP đọc tối đa 8 KiB body, lấy mã/message hữu ích rồi che key/signature và giới hạn thông báo 1.500 ký tự. Lỗi mạng phân biệt với lỗi HTTP. Report partial ghi stage, lượt model, HTTP status nếu có; giữ profile/evidence đã thu.
- `check_llm` kiểm tra hai lượt qua tool giả lập: gọi tool → gửi result với nonce → model xác nhận nonce. Không gọi runner, CALDERA hoặc victim.
- Pydantic kiểm tra kiểu/cấu trúc. Fact chỉ lấy từ evidence; không coi Pydantic là bằng chứng sự thật hoặc lời model là dữ kiện.

## UX và tải file

Mode/model rõ trên Survey và theo từng run. Phân biệt completed/completed_with_unknowns/partial/failed; trạng thái report thắng state cũ. Timeline dùng event thực hoặc trace lịch sử, không vẽ phần trăm giả và không bịa lý do model.

Tóm tắt dễ đọc có capability, telemetry và dịch vụ; JSON/log đặt trong details. Null khác false và ngoài scope. Ghi rõ Wazuh/Sysmon service running không chứng minh ingestion. POST tạo job được khóa từ lúc bắt đầu gửi; refresh/poll chỉ GET, không tự tạo operation.

Nội bộ giữ `target_profile.json`. Download trả nguyên bytes của artifact, Content-Disposition chứa IP chuẩn hóa, thời điểm run theo UTC và toàn bộ 32 ký tự run ID. Dùng ID đầy đủ để bảo đảm hai ID trùng 8 ký tự đầu vẫn khác tên. Cùng run luôn cùng tên, không tạo bản sao server. Browser vẫn có thể thêm `(1)` khi tải lại.

## Backup và rollback

`/home/bao/DATN/GUI/backups/merge-20261111T090931Z`

Thư mục này có `main-source.tar.gz`, `ai-source-source.tar.gz` và `inventory.json` liệt kê hash mã nguồn/cấu hình/lịch sử. Backup giới hạn quyền đọc; không chứa virtualenv. Artifact lịch sử giữ nguyên tại cả bản nguồn và bản chính; manifest nhập ở `../verification/history_merge.json`.

Rollback mã/config bản chính khi đã dừng đúng process GUI của nó:

```bash
tar -xzf /home/bao/DATN/GUI/backups/merge-20261111T090931Z/main-source.tar.gz -C /home/bao/DATN/GUI
```

Không chạy lệnh trên khi có job đang chạy. Lệnh khôi phục các file đã có trước merge, không xóa các file mới không được tham chiếu và không xóa các run được nhập. Virtualenv không bị thay đổi trong phiên này nên không có dependency cần hạ cấp. Giữ toàn bộ outputs khi rollback.

`~/GUI` không bị sửa/xóa. Đã chuẩn bị `LEGACY_GUI_NOTICE.txt` chỉ rõ đường dẫn chính, nhưng chưa thể đặt ghi chú cạnh bản nguồn vì sandbox chỉ cho ghi `~/DATN` và `/tmp`.

## Điểm khởi động chính

```bash
~/DATN/GUI/start.sh
```

URL: **http://127.0.0.1:8765**. Launcher dùng `/home/bao/DATN/GUI/.venv/bin/python`, CWD `/home/bao/DATN/GUI`, config `/home/bao/DATN/GUI/config.json`. Meta API và hộp Cấu hình kết nối hiển thị app_root/mode/model để kiểm tra đúng bản. Cổng không dùng làm bằng chứng nhận diện.

Process view trong sandbox không thấy được đầy đủ process desktop. Thử server kiểm tra ở cổng riêng 8767 bị PermissionError tại thao tác tạo socket, trước khi bind. Vì chưa xác minh được bản mới chạy, **không dừng bất kỳ GUI cũ, Python hay CALDERA nào**. Chưa thực hiện yêu cầu restart trên desktop; cần chạy lệnh chính từ môi trường có quyền socket và xác minh process bằng executable/CWD trước khi dừng bản cũ.

## Kiểm thử và giới hạn

- 39 test Python: 36 đạt, 3 HTTP integration bỏ qua vì socket bị cấm. Gồm test AI cũ, hồi quy nhiều lượt/metadata/redaction/partial, tải file ổn định nguyên bytes và lịch sử hợp nhất.
- 14 test Node: 14 đạt; có UI partial vẫn tải profile, null/false/ngoài scope và chặn submit kép; giữ Scenario/Library/Flow.
- Kiểm tra cú pháp Python, JavaScript và shell launcher đạt. Runtime GUI hiện có Python 3.11.17, LangGraph 1.2.20, Pydantic 2.14.3; không cài vào Python CALDERA.
- Hai lần chạy check API thật, mỗi lần tối đa hai request (trần tối đa 4/5 request được cho phép), không có lần nào xác minh được nhiều lượt. Lần cuối báo DNS `Temporary failure in name resolution`. Không thử tiếp để tránh gọi lặp vô ích; không có body HTTP 400 mới để đối chiếu trên provider.
- Chưa kiểm tra màn hình laptop bằng browser thật hoặc screenshot vì không mở được preview server. Các test UI dùng DOM fixture và CSS responsive; không coi đó là browser QA.
- Không chạy operation trên victim, kịch bản tấn công, không đổi Wazuh/Windows/antivirus và không sửa môi trường CALDERA.

Log kiểm tra: `../verification/merge_ai_validation.json`, `llm_live_check.json`, `merged_runtime.json`. Nguyên nhân HTTP 400 thật và khả năng API nhiều lượt vẫn **chưa kiểm chứng trực tiếp**.
