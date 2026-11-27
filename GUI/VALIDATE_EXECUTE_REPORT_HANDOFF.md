# Validate → Execution → Expected / Reality

Cập nhật 24/11/2026. Triển khai trên GUI hiện có, không gọi LLM, không tạo operation mới, không sửa Wazuh/collectors/firewall. Không tìm thấy rules.md/AGENTS.md trong hai project ở thời điểm kiểm tra. Service thực tế là **systemctl --user datn-survey.service**, không phải system service. Project không có Git metadata; dùng backup theo file.

## Kết quả và giới hạn

- GUI chuyển sang **Validate kịch bản → Xác nhận thực thi** theo yêu cầu mới. Validate chỉ đọc CALDERA; checkbox/IP không thay thế prerequisite. Reload/GET/export không dispatch.
- Giữ plan lịch sử nguyên vẹn. Thêm `execution_validation_v1` gắn plan hash, binding, survey, source, prerequisite, target, executor, timestamp/expiry và kết quả từng bước. Gate thực tế vẫn là preflight xác định và kiểm tra lại dưới endpoint locks.
- Revalidation `needs_information` hỗ trợ tập inventory Windows tĩnh vốn có parser (tasklist, hostname, systeminfo, ipconfig; Get-Process/Get-Service qua psh), ngoài các nguồn compound đã review/hash trước đó. Phải có source integrity, fresh Survey, trusted/fresh agent, executor đúng và privilege Elevated. Các ID đã ghim revision không được đi đường generic để né revision pin. Không đổi YAML sang ready.
- Thêm expected contract trước dispatch, hash và kiểm tra lại trước đăng ký artifact. Historical report ghi rõ `historical_reconstruction_from_preflight`, không giả vờ đã có expectation trước execution cũ. Technique lịch sử chỉ lấy từ YAML khớp SHA-256 đã ghim.
- Indexer vẫn được query khi API55000 thiếu credential; nếu thiếu binding lịch sử thì chỉ có **candidate counts**, không nhận là correlated. API hiện thiếu credential; không thử lại dashboard credential.
- UI/report JSON/Markdown có expected/reality theo bước, numerator/denominator, unique techniques, thời gian và token/request có nguồn. Không có universal behavior verifier: hành vi giữ unknown/not_verified.
- Không hỗ trợ mọi ability CALDERA: dynamic facts, payload/parser/dependency/cleanup, secrets và shell chưa có adapter vẫn bị chặn. Chưa bổ sung form nhập tham số: chưa có type/binding adapter đủ căn cứ cho những nguồn đó; không nhận chuỗi shell qua UI. Không có rule baseline đáng tin nên alert expectation mặc định not_defined.

## Kiến trúc và API

`Scenario/source → deterministic preflight → execution_validation.json + execution_expected.json → explicit confirm → existing locked controller → record → bounded Wazuh collection → normalization/dedup/correlation → report cache → GUI/export`.

- `POST /api/scenarios/<job>/execute` body `{}`: Validate/preview, không dispatch. API cũ `start_on_click` được giữ tương thích cho tập inventory đã kiểm soát; GUI mới không gửi cờ đó.
- `POST /api/executions/<id>/confirm`: giữ xác nhận IP/hash, TTL và idempotency. Worker kiểm tra fresh binding dưới hai khóa endpoint trước POST đầu tiên. Journal POST intent, stop/reconcile/group restore giữ nguyên.
- `GET /api/executions/<id>/files/execution_validation.json` và `execution_expected.json`: artifact allowlist.
- GET `/api/executions/<id>/telemetry`, `/telemetry/report.json`, `/telemetry/report.md`: local cache, không gọi upstream.
- POST `/telemetry/refresh`: collection có thread/file lock, cooldown, deadline/page/event/byte bounds. CLI dùng cùng service: `.venv/bin/python -B tools/replay_execution_report.py <execution-id> --refresh`. Bỏ `--refresh` chỉ đọc cache.
- Restart collection requery đúng window lịch sử và dedup, không dùng now-1h. Scroll snapshot `_doc`, tối đa pages/events/deadline cấu hình cũ; không lưu token scroll lâu dài. Đây là replay hữu hạn + dedup, không cam kết cursor tiếp tục trên snapshot cũ sau restart.
- `telemetry_reports/<id>/expected.json`, `snapshot-<ns>.json`, `events.json`, `telemetry_state.json`, `report.json`, `report.md`. Snapshots giữ bằng chứng các lần refresh trong phiên bản mới, không xóa theo retention mới.

## Blocker taxonomy và điều tra

| Nguồn | Phân loại | Cần gì / vì sao giữ |
|---|---|---|
| execution_context: source hash/provenance/checkpoint | execution_required | Đối chiếu source thật, revision và plan/checkpoint; bỏ sẽ mất đảm bảo lệnh nguồn |
| preflight: target/paw/platform/executor/heartbeat/trust | execution_required | API CALDERA đọc hiện tại + snapshot ghim; bỏ có thể chạy sai runner |
| preflight: Survey age | execution_required | Khảo sát lại cho lượt mới; không dùng fresh heartbeat thay toàn bộ Survey |
| prerequisite unknown | execution_required | Chỉ điều kiện executor có typed runtime evidence được tự xác minh; điều kiện khác vẫn cần bằng chứng |
| parameters/dependency/payload/cleanup/unsupported syntax | unsupported hoặc execution_required unresolved | Cần adapter/schema/phạm vi có test; không sửa source để né gate |
| needs_information/manual review | execution_required khi chưa revalidate | Inventory được hỗ trợ có thể thỏa bằng evidence riêng; label LLM không phải quyền thực thi |
| Wazuh/telemetry/detection | telemetry_optional | Warning, không tham gia quyền dispatch nếu các điều kiện execution đủ |
| endpoint busy/POST bất định | execution_required | Dừng/đối soát trước; không retry POST mù |

Classification dùng mô tả blocker hiện hữu để trình bày, **không dùng phân loại để bỏ gate**. Schema validity được kiểm tra trước preflight; validation.ready là execution readiness, không phải telemetry hoặc detection readiness.

Execution `bc213c6e53d44dc6a1ace2b10134a5de` đã chạy lúc Survey còn mới. Kiểm tra chỉ đọc hiện tại của chính plan này bị chặn bởi Survey quá cũ, kéo theo không được revalidate readiness/manual-review. Artifact: `review/validate-report-20261124T100325/current-validation.json`. Không sao chép ready của execution cũ sang preview mới.

## Identity lịch sử và health

API agent directory hiện tại chỉ được coi là identity live cho window vừa kết thúc (tối đa 300 giây). Window lịch sử cần mapping do quản trị xác nhận riêng. Alert IP/name/id tự nó không phải nguồn xác minh mapping. Không hardcode ID009.

File tùy chọn server-local `GUI/telemetry_identity_bindings.json`, schema `schemas/historical-identity-bindings-v1.schema.json`:

```json
{"schema_version":"historical_identity_bindings_v1","bindings":[{
  "target":{"ip":"192.0.2.1","host":"lab-host"},
  "agent":{"id":"admin-supplied-id","name":"admin-supplied-name","ip":"192.0.2.1"},
  "purpose":"historical_identity","verified_by":"administrator",
  "verified_at":"2026-11-24T00:00:00Z",
  "valid_from":"2026-11-23T08:00:00Z","valid_until":"2026-11-23T10:00:00Z",
  "evidence_refs":[{"file":"review/admin-identity-attestation.json","sha256":"actual-file-sha256"}]
}]}
```

Đây là template, không phải mapping thật. Quản trị phải xác nhận bằng bằng chứng độc lập và khoảng hiệu lực bao trùm window gồm skew/grace. Không có UI/public API tự cấp binding. Resolve kiểm tra target, interval có timezone, unique mapping, evidence file/hash/path/symlink, từng hit ID/IP/name; drift/ambiguity không được nâng thành correlation. Không suy live health từ historical binding. Chưa tạo binding cho execution thật vì nguồn xác nhận độc lập chưa có.

## Expected và phép đo

Profile `windows_executor_process_launch_v1`: kỳ vọng ít nhất một event Security4688 hoặc Sysmon1 tương quan với bước Windows cmd/psh; chỉ chứng minh **process launch**, không chứng minh nội dung lệnh hay detection. `expected_count=null`; không đặt số log cố định. Unsupported executor có expectation not_defined. Không suy rule ID từ technique hoặc observed alert.

- Execution completion: bước completed + exit0 / toàn bộ bước expected (failed/skipped/not_run trong mẫu số).
- Telemetry coverage: bước thành công có expectation + evidence phù hợp / bước thành công có expectation đánh giá được. Alerts-only không chứng minh không có event; bằng chứng dương có thể xác lập presence, thiếu evidence giữ unavailable. Hiện tổng expectation/not_evaluated để không giấu mẫu số thiếu.
- Alert coverage: hiện 0/0 → N/A vì chưa có baseline/rule contract độc lập. Alert tương quan nếu có là association, không phải detection efficacy.
- Techniques là tập unique tách expected/executed/telemetry_supported/alert_associated.
- `counts_v2.candidate_alert_documents`: unique index/doc; `correlated_alert_documents=null` nếu identity chưa xác minh. Tổng alert không nhân lên khi liên hệ nhiều bước. Hiện correlator chỉ gán một step khi duy nhất, ambiguous giữ candidate.
- Source event dedup dùng source event ID hoặc agent/computer/channel/eventRecordID/source timestamp; cùng event ở archive và alert không cộng hai lần. Không có identity source thì không đoán tổng raw events. `raw_event_count=null` khi archives absent/403, truncated, error hoặc thiếu event identity. Raw count nếu có chỉ thuộc query/filter/window, không phải mọi log host.
- Count quality exact_within_query/lower_bound/unavailable; HTTP401/403, TLS/network và archive absent giữ mã riêng. Partial/truncated không kết luận missed_detection.
- AI actual chỉ lấy usage có thật từ artifacts; unknown requests và internal charge tách riêng, không coi charge là actual hoặc toàn bộ chi phí. Không gọi Gemini để tính metrics. Validation duration của record cũ không có thì null.

## Live read-only acceptance

- CALDERA GET: operation `9df4859e-6661-4d0b-84ef-675d5aaa05d4` finished; host_group đúng duy nhất datnptit, ba link có collect/finish/status0 khớp execution record. Không gửi POST/PATCH CALDERA.
- Plan SHA256 `7daf71bba1946affacc9e2bad2ad0729f79bb4b7fd25ec7b9f4a1b26c5eb367f`, target PTIT/.150. Technique expected T1057/T1007/T1082 lấy từ plan hash khớp.
- Indexer search HTTP thành công: **31 alert ứng viên**, cửa sổ record gồm lookback/skew/grace (rộng hơn cửa sổ kiểm tra tay trước có19). **Raw count=null, correlated alert count=null**, identity candidate_only. Không dùng MOCK cho phần live. TLS/pin hiện có giữ nguyên.
- Lệnh thành công 3/3 (100%); telemetry/alert coverage N/A, 3 expectation chưa đánh giá. Behavior unknown. AI Scenario actual đã biết88.204, hai requests thiếu usage, internal charge88.716; không diễn giải thành quota/TPM.
- Evidence: `review/validate-report-20261124T100325/caldera-existing-operation.json`, `live-report-summary.json`, report JSON/Markdown dưới telemetry_reports/execution ID.

## Kiểm thử và triển khai

- GUI regression qua wrapper cách ly audit/root/enqueue; mock CALDERA kiểm tra confirm/dispatch/POST timeout/restart/lock/hash/readiness.
- Telemetry/auth/expected tests riêng; identity missing/ambiguous/window/hash, source-event dedup, alerts-only/null/zero, independent expected, repeated steps/techniques, denominator0, partial, candidate-only, artifact schema keys. Schema live validate bằng jsonschema sẵn có của Scenario interpreter (GUI interpreter không cài jsonschema; không cài dependency mới).
- Node DOM tests: validate không tự confirm, expiry, reload không POST, cache export/refresh, N/A/unavailable, không chèn HTML không tin cậy.
- Scenario runtime regression token/grounding/context:54 PASS.
- Kết quả cuối cùng GUI/Node lưu trong review directory; xem mục xác nhận cuối tài liệu. Không thực thi endpoint mới để làm test xanh.

Lệnh:

```bash
cd /home/soc/DATN/GUI
.venv/bin/python -B tools/test_telemetry_regression.py
PYTHONPATH=tests:. .venv/bin/python -B -m unittest test_expected_reality test_execution_telemetry test_wazuh_auth_fix -q
node --test tests/*.test.cjs
cd /home/soc/build_scenario_agent
PYTHONPATH=tests:. .venv/bin/python -B -m unittest test_gemini_runtime test_generation_contract test_token_budget test_context_requirements -q
```

## File và rollback

Mới: engine/execution_contracts.py, engine/telemetry_identity.py, tools/replay_execution_report.py, tests/test_expected_reality.py, ba JSON schemas và handoff này.
Sửa: engine/scenario_execution.py, execution_telemetry.py, wazuh_connector.py; static/scenario.js, scenario-execution.js, index.html; tests/test_scenario_execution.py, scenario-ui.test.cjs; các handoff. Không đổi config/key/model/catalog/runtime/Wazuh server.

Backup trước sửa: `review/validate-report-20261124T100325/backup/`. Chỉ rollback code khi Survey/Scenario/Execution/collection idle: khôi phục các file sửa từ backup, bỏ các module/test/schema mới của nhiệm vụ nếu cần, restart riêng user service. Giữ executions, scenario_outputs, outputs, telemetry_reports, audit và journal; không quay lùi lịch sử hay tạo lại operation. Nếu pending recovery, đối soát trước.

## Còn thiếu có chủ đích

Credential API hoặc historical identity attestation độc lập; archives/retention/rules phía server (xem WAZUH_SERVER_PENDING.md); typed parameter/dependency/secret adapters và verifier riêng cho từng observable; alert baseline có version. Không biến các phần thiếu thành ready/detected. Giao diện nhập tham số chỉ nên thêm khi backend có schema/adapter tương ứng. Không chạy live mới trong nhiệm vụ này.

## Xác nhận cuối triển khai

- **160/160** GUI regression PASS (wrapper cách ly), **33/33** telemetry/auth/expected PASS, **34/34** Node DOM PASS, **54/54** Scenario runtime PASS. Telemetry/expected test nhóm riêng trùng một phần wrapper; không cộng thành tổng test unique.
- Live report/expected/validation artifacts đạt JSON Schema bằng interpreter Scenario có sẵn jsonschema. GUI không được cài thêm dependency.
- Một test UI cũ kỳ vọng one-click được cập nhật sang yêu cầu Validate mới. Regression revision pin phát hiện nhánh generic có thể nhận ID nguồn ghim nhưng revision khác; đã loại ID ghim khỏi nhánh generic và chạy lại đạt. Không bỏ assertion revision pin để làm xanh.
- Đã kiểm tra Survey/Scenario/Execution/collection idle, restart **riêng user GUI service**, service active. HTTP200 cho HTML, JS mới, cached report, JSON và Markdown; nội dung export đúng 3/3 và candidate31/raw null/correlated null. `deployment.json`, `idle-check.json`, `regression.log`, `node-tests.log` nằm trong review directory.
- UI đã kiểm tra bằng DOM tests và HTTP assets/export của service thật; chưa có kiểm tra thị giác bằng browser automation trong đợt này. Không bấm confirm mới. Không gọi API từ GET/poll/export.
