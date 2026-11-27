# Survey output v2 — bàn giao cho Scenario

Đã triển khai phía Survey trong GUI. Builder xác định bằng Python, chạy offline, không gọi LLM, không truy cập endpoint. Workflow/prompt/retrieval/validator của Scenario chưa thay đổi: nút chuyển profile vẫn dùng contract legacy. Chưa kiểm chứng chất lượng kế hoạch end-to-end.

## Producer, consumer và điểm mất dữ liệu

- `engine/agent.py::SurveyTools.finalize` và `engine/survey.py::execute` ghi profile/report, web/telemetry evidence và tool records.
- `app.py::work` finalize cả completed/partial/failed/cancelled trong `finally`. Sau handoff legacy, nó xuất snapshot `survey_v2/`. Không yêu cầu profile nếu có kết quả một phần; lỗi export được ghi trong warnings, không phát hành snapshot dang dở.
- `engine/handoff.py` vẫn giữ manifest v1. `/api/jobs/<id>/bundle` ưu tiên snapshot v2 nếu có; run cũ chưa chuyển đổi giữ hành vi cũ. API file hiện có hỗ trợ đường dẫn tương đối `survey_v2/*.json`; danh sách file GUI tự hiện các liên kết này.
- `engine/scenario_bridge.py::provenance` kiểm tra hash evidence nhưng consumer chỉ nhận profile legacy. Các module/forms có trong tool records chưa được workflow Scenario đọc. Chỉ thêm file path vào profile không khắc phục được vấn đề này.

## File map và contract

`engine/survey_output_v2.py` định nghĩa các model Pydantic strict. JSON Schemas tương ứng nằm tại `schemas/survey_v2/`. Phiên bản mới là `schema_version: "2.0"`.

| File trong snapshot/bundle | Nội dung |
| --- | --- |
| `target_profile.json` | Bản sao đã lọc secrets của profile legacy; run nguồn không sửa |
| `target_profile_v2.json` | Target identity, summary theo domain, observation IDs, inventory refs, giới hạn diễn giải |
| `survey_context.json` | Nội dung fact thực tế: endpoint, runner, web, authentication, telemetry; gaps, conflicts, coverage |
| `scenario_handoff.json` | Run/target/scope/time/status, SHA-256 các artifact, mode profile_only/evidence_backed, hướng dẫn consumer |
| `source_manifest.json` | SHA-256 trước chuyển đổi của các file nguồn, chính sách redaction, danh sách loại trừ |
| Các JSON còn lại | Evidence đã lọc secrets, giữ nguyên cấu trúc để JSON Pointer giải được |

Snapshot chứa JSON nguồn trong run, kể cả evidence CALDERA, report, metrics, preflight và tool records. Không nhồi trace hay inventory dài vào context. Inventory đầy đủ ở evidence; listener chỉ gắn process/service có PID tương ứng. Trace/API response giúp truy vết trong bundle, không được coi tự động là fact mục tiêu.

`state.json`, `handoff.json` và artifact v2 cũ không được copy. Logs/binary không được export; vẫn có hash nguồn. Thư mục `survey_v2/` và thư mục tạm bị bỏ qua để tránh tự đóng gói snapshot. Với finalize GUI, state là journal đang tiếp tục cập nhật; hash state là tại thời điểm tạo snapshot. Với chuyển đổi offline, mọi file nguồn phải giữ nguyên suốt chuyển đổi.

Manifest v2 hash các artifact sau redaction, không hash chính nó. `source_manifest.json` được hash bởi manifest v2, không có vòng hash. `evidence_index.json` cũ giữ hash nguồn gốc, không dùng để xác minh bytes đã redaction; consumer dùng `scenario_handoff.json`. Handoff v1 tại run gốc tiếp tục mô tả bytes gốc, không mô tả snapshot đã làm sạch.

## Ngữ nghĩa dữ kiện

- Fact gồm ID ổn định trong snapshot, domain/subject/predicate/value, status, observed_at, time_reason, evidence_refs. Ref có file tương đối, JSON Pointer, SHA-256, source/tool.
- Status: `observed`, `configured`, `inferred`, `unknown`. Agent executor/privilege là metadata CALDERA (`configured`), không chứng minh thực thi tương lai. Capability legacy chỉ `inferred` hoặc `unknown`, có basis.
- Thời gian quan sát lấy từ collected_at/checked_at/event_time/last_seen của nguồn thích hợp. Không dùng giờ export. Thiếu giờ giữ null và gap `missing_time`. Run time có thể lấy từ manifest/state cũ; không biến thành giờ quan sát.
- URL ứng dụng giữ scheme, port, base_path. Module giữ HTTP status, authenticated, form method/action, input name/type và csrf_present. Không tạo endpoint không được quan sát; HTTP 200 không chứng minh khai thác thành công.
- Session chỉ thuộc lần khảo sát; yêu cầu reverify_before_execution. Không suy ra authentication_required từ authenticated=true. Không cấp execution_authorized.
- Telemetry phân biệt local_event và manager_ingestion bằng loại sample; legacy flags/service running không tạo ingestion/detection. Các mức log_source_exists, collection_configuration và detection giữ unknown qua gaps vì chưa có checker chuyên biệt.
- Gaps có reason enum; error/rejected tool, truncation cờ nguồn, module planned nhưng không có observation, missing time, coverage thiếu được ghi rõ. Không tự đặt TTL, không gán stale chỉ vì dữ liệu cũ.
- Nhiều giá trị cùng subject/predicate được giữ trong conflicts, không tự chọn nguồn thắng; có thể là thay đổi theo thời gian.

## Export, validation và ví dụ

Chạy từ `/home/soc/DATN/GUI`, dùng virtualenv sẵn có:

```bash
.venv/bin/python tools/convert_survey_v2.py \
  outputs/8722ef963d82403fb445ed9c0f8e9f05 \
  review/survey-v2-8722 --bundle --example-subject sqli
```

Destination phải chưa tồn tại. Công cụ không ghi đè run gốc hoặc destination. Có thể xuất sang thư mục ngoài run, hoặc trực tiếp một thư mục con của run. Dữ liệu ghi vào staging rồi rename nguyên thư mục sau validation. Nếu nguồn thay đổi trong lúc convert thì từ chối xuất. Không có network I/O.

Artifact mẫu thực tế:

- `review/survey-v2-8722/`: snapshot, 82 observations.
- `review/survey-v2-8722.zip`: bundle có thể chuyển máy.
- `review/survey-v2-8722.example.json`: lọc domain web/authentication và subject chứa sqli; giữ location/session/identity dùng chung. Không gọi Scenario hay chọn ability.
- `review/survey-v2-8722.verification.json`: kết quả kiểm chứng run thật offline.

Ví dụ SQLi giữ URL `http://192.168.1.150:8080/dvwa/`, security level low và session quan sát. Cả sqli/sqli_blind ghi HTTP 200, authenticated=true, form GET, input id/Submit, không sinh search.php. Ref module trỏ vào `tool_04_inspect_dvwa_modules.json#/data/authentication/modules/<index>` với hash bytes đã lọc secrets.

Kiểm tra và lọc bằng Python:

```python
from engine.survey_output_v2 import verify, select_context, checked_ref
ctx = verify('review/survey-v2-8722').model_dump()
sqli = select_context(ctx, domains=['web', 'authentication'], subjects=['sqli'])
for fact in sqli['observations']:
    for ref in fact['evidence_refs']:
        checked_ref('review/survey-v2-8722', ref)
```

## Kiểm thử thực tế

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_survey_output_v2.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
node --test tests/flow-core.test.cjs tests/scenario-ui.test.cjs
```

- 8 tests v2 đạt: forms/auth/secrets, source unchanged, deterministic, relocated ZIP, bad pointer/hash/missing/traversal/symlink, partial/error/truncation/conflicts/missing time, record limit, GUI finalize + bundle v2.
- Toàn bộ Python: 91 tests, 1 failure + 2 subtest errors trong test_web_normalization. Test replay kỳ vọng (11,9), fixture hiện trả (8,6); scripts tests dùng IP ngoài allowed_networks cấu hình host. Đã tái hiện đúng các lỗi này trên bản sao bỏ thay đổi app/handoff của task. Không sửa config hoặc sửa test để che lỗi.
- Node: 19/19 đạt.
- Run thật: kiểm tra mọi ref/hash, schema legacy, sqli/sqli_blind forms, bundle sau giải nén sang thư mục khác; 29 file nguồn có hash không đổi. Không khảo sát live, gọi model, chạy operation hoặc restart dịch vụ.
- Log kết quả: `review/survey-v2-tests.log`, `review/survey-v2-baseline.log`, `review/survey-v2-js.log`.

## Giới hạn và consumer Scenario tiếp theo

Builder ưu tiên cấu trúc đã được producer hiện tại định nghĩa; không tự trích fact từ prose/trace/command tùy ý. Các JSON khác vẫn có trong manifest/evidence để truy vết. Phiên bản ứng dụng không được đoán từ banner. Authentication requirement, cấu hình collection và detection cần checker chuyên biệt nếu muốn có kết luận. Hiện chưa hợp nhất nhiều run hoặc đánh giá freshness liên run.

Giới hạn nguồn JSON 32 MB và context 2.000 facts. Vượt byte limit từ chối export rõ ràng; vượt fact limit ghi gap truncated và giữ nguồn đầy đủ trong bundle. Secrets được lọc theo cấu trúc: cookie/password/token/credentials, form values, URL userinfo/query, raw body/output/command/payload; mẫu credential phổ biến trong chuỗi cũng được lọc. Không coi đây là DLP cho secrets tùy ý nằm trong prose không có nhãn; evidence tự do mới cần bổ sung chính sách trước khi export. Lịch sử gốc không bị redaction tại chỗ.

Consumer tiếp theo cần:

1. Nạp scenario_handoff, verify hashes và toàn bộ ref trong root bundle được phép; không lấy URL từ evidence để tự đọc.
2. Chọn facts theo domain/subject và mục tiêu người dùng, luôn mang theo status/time/ref và gaps/conflicts liên quan. Không chỉ truyền tên file hoặc profile sáu trường.
3. Giữ target_ip từ run identity, validate scope, ngăn dùng endpoint/ability không có bằng chứng hoặc precondition rõ ràng.
4. Phân biệt profile_only/evidence_backed; không nâng inferred/unknown thành observed. Reverify session và runner trước execution; plan_only không cấp quyền.

Rollback: bỏ import/export block v2 trong app.py, nhánh bundle_v2 trong engine/handoff.py và điều kiện hiện nút ZIP v2 trong static/app.js. Các producer/contract legacy không đổi. Chỉ xóa snapshot v2 mới tạo nếu cần; giữ outputs lịch sử.
