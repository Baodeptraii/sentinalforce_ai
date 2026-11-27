# Scenario nhận Survey v2 — triển khai và bàn giao

> Bổ sung hiện hành: [CONTEXT_REQUIREMENTS_HANDOFF.md](CONTEXT_REQUIREMENTS_HANDOFF.md), adapter 2.2. Các số liệu/artifact dưới đây mô tả lần bàn giao 2.1, được giữ để truy vết.


Đã sửa Scenario runtime `/home/soc/build_scenario_agent` và bridge/API/UI trong GUI. Survey producer không thay đổi trong task này. Không chạy model live, thực thi ability/operation, gửi traffic tới victim, rebuild catalog/index hoặc restart dịch vụ.

## Contract và mapping thực tế

Producer dùng schema_version `2.0`, đã đọc được bundle thật tại `review/survey-v2-8722.zip`: 82 observations và 29 artifact được manifest attestation. Các schema producer được copy nguyên bản vào runtime `input/schema/survey_v2/`; schema input envelope mới ở cùng thư mục. Không dùng example.json thay cho bundle.

GUI nội bộ gửi `survey_run_id`, `text`, `scope`, `max_steps`. Backend tra trong `outputs/<id>/survey_v2`; run lịch sử có thể dùng snapshot đã chuyển đổi trong thư mục review cố định, với manifest mang đúng run ID. Không nhận catalog/index/file path từ client. Nếu v2 hỏng, từ chối trước worker/model; không chuyển ngầm sang profile-only.

Loader dùng chung là `scenario_agent/survey_input.py`, chỉ cần Python standard library, chạy được trong cả interpreter Survey và Scenario. GUI nạp module này bằng đường dẫn server-configured; worker chạy bằng `.venv/bin/python` của Scenario. Không import Pydantic của interpreter khác.

| Dữ liệu Survey | Scenario |
| --- | --- |
| target_profile_v2 | `input_envelope.target_profile` |
| survey_context | `input_envelope.survey_context`, gồm values/status/time/refs, coverage, gaps, conflicts |
| scenario_handoff | Manifest attesting bytes sau redaction, copy vào `input/survey/` |
| source_manifest, evidence_index | Giữ nguyên lớp provenance nguồn cũ; không dùng hash nguồn cũ để xác minh bytes sau redaction |
| target_profile legacy | Adapter cho executor/retrieval cũ; không coi capability inferred là observed |
| Lựa chọn scope/max_steps | Policy riêng, mode=plan_only, execution_authorized=false |
| Kết quả parse mục tiêu | user_request.json và behavior_analysis.json trong workflow run; raw request/policy ban đầu giữ trong input snapshot |

Input envelope có schema_version `2.0`, adapter `scenario_survey_v2.1`. Profile-only legacy vẫn chạy với evidence_quality/limitation rõ, không có evidence registry và không được bind giá trị hay tạo verified prerequisites như v2.

Loader kiểm tra schema producer bằng bộ validator stdlib cho đúng subset schema được pin; kiểm tra version, identity giữa các tài liệu, hash, JSON Pointer và source của các predicate có thể xác minh. Chống traversal, symlink, JSON key trùng, file thiếu, self-hash/manifest member trùng. ZIP có giới hạn 512 members cộng manifest, 32 MB tổng giải nén, 8 MB/file; từ chối symlink, duplicate, encrypted/unattested entries. Không đọc URL từ evidence. Hash chứng minh toàn vẹn so với manifest, không phải chữ ký xác thực người gửi.

Dữ liệu bundle có secret/raw body/command/output chưa redaction bị từ chối; form values cũng phải đã lọc. Không chuyển cookie/token/password từ Survey thành phiên chạy Scenario.

## Luồng mới và các file thay đổi

Runtime:

- `scenario_agent/survey_input.py`: loader thư mục/ZIP, schema/pointer/hash/identity validation, immutable snapshot, policy và profile adapter.
- `scenario_agent/target_evidence.py`: chọn context, phân tích requirements từ command thật, binding có kiểu/source, đánh giá và lọc ứng viên, kiểm tra evidence semantics.
- `scenario_agent/workflow.py`: đưa context vào parse/ground/build, lưu selection/report, pin snapshot/adapter/code hash và kiểm tra khi resume, validate/finalize có evidence.
- `scenario_agent/validation.py`: giữ legacy gates; với v2 kiểm tra bindings/conditions/facts/blockers và pinned policy độc lập với response schema.
- `scenario_agent/models.py`: generation schema chỉ mở verified survey prerequisite khi có input snapshot; telemetry/readiness vẫn giữ giới hạn.
- `scenario_agent/catalog.py`: OS null giữ unknown, không lỗi `.lower()`.
- `scenario_agent/cli.py`: `--target` nhận profile hoặc thư mục/ZIP Survey v2; thêm inspect-survey offline. Retrieve diagnostic v2 cũng dùng loader/context/compatibility.
- `input/schema/survey_v2/`: schema producer nguyên bản và scenario_input_envelope mới.
- `tests/test_survey_input_v2.py`: integration/malicious model/bundle/resume/policy tests.

GUI:

- `engine/scenario_bridge.py`: nhận run ID, xác minh v2 trước worker, pin input, allowlist download và trả source/time/evidence summary.
- `engine/scenario_worker.py`: dùng runtime riêng; pin policy/request, nối input vào workflow, copy report/sidecar/result, phân biệt process completed và readiness.
- `app.py`: endpoint file hỗ trợ các artifact lồng trong input snapshot qua allowlist.
- `static/app.js`, `static/scenario.js`: transfer bằng run ID; upload/chọn profile legacy xóa run ID cũ; hiển thị nguồn/thời gian khảo sát, evidence, readiness và blockers từ API.
- `tests/test_scenario_input_v2.py`, `tests/scenario-ui.test.cjs`: validation trước worker, giới hạn legacy và UI dữ liệu API thật.
- `tools/replay_scenario_v2.py`: replay offline có nhãn mock rõ, dùng catalog fixture hoặc keyword retrieval thật; chặn khởi tạo Gemini.

## Chọn context và kiểm tra compatibility

Context budget 65.000 bytes cho facts cùng diagnostics. Ưu tiên location/session/runner/OS và facts liên quan source command; bổ sung module cần bởi candidates. Gaps/conflicts/coverage được giữ; diagnostics quá budget gây lỗi rõ ràng. Selection ghi included/omitted/reason/bytes/truncated/hash. Fact bị bỏ vì budget hoặc domain không được diễn giải là không tồn tại.

Payload LLM chứa values cùng IDs, timestamps và refs; inventory dài không được lặp trong target payload. Catalog mô tả hành vi và Survey mô tả mục tiêu là hai nguồn riêng. Instruction coi cả dữ liệu request/catalog/evidence là dữ liệu không được ghi đè policy. Guard Python kiểm tra độc lập sau generation.

Compatibility có ba trạng thái: compatible/incompatible/needs_information. Runner metadata configured, source privilege chưa biết, dependencies, session thực thi, setup và cleanup review tạo blockers riêng. Vì chưa có preflight execution provider, các ứng viên hợp mục tiêu hiện vẫn thường là needs_information.

Kiểm tra gồm platform/privilege, phạm vi surface, URL host/scheme/port/path, form method/query parameter, security level, effects mở rộng SQLi thành XSS/fuzzing, source dependencies và cleanup. Executor không tương thích bị lọc khỏi retrieval. Chain chỉ được giữ khi các ability còn phù hợp; validator vẫn kiểm tra executor cụ thể sau LLM.

Chỉ bind những tên có semantic mapping rõ (ví dụ target_ip, base_url, scheme, port); tên chưa biết giữ null và blocker. Module/path chưa quan sát không có nghĩa không tồn tại: giữ yêu cầu xác minh, không dựng endpoint mới. Không tự sửa command.

Source có environment URL override được nhận diện bằng cấu trúc assignment và việc biến đó thật sự được dùng trong URL; fallback chỉ được bỏ qua khi có quan hệ này. Binding môi trường là proposed_setup, luôn cần xác minh trên runner. Không thêm environment variable vào executor fact_placeholders một cách giả tạo. Bởi vậy source không có placeholders vẫn có parameters={} trong ScenarioPlan, còn environment binding nằm trong step_evidence và phải có blocker.

Nguồn công khai được biểu diễn bằng catalog URI với revision/hash; đường dẫn vật lý của catalog giữ phía server. Không thêm output vào catalog/index.

## Output và ý nghĩa verified

ScenarioPlan giữ schema metadata `1.0`, có sidecar versioned; không phải file operation/ability thực thi và không tuyên bố nạp thẳng CALDERA sẽ chạy đúng metadata.

Một prerequisite có `condition=survey.<predicate>:<subject>` và `evidence=<fact-id>` chỉ được verified khi fact thực sự observed và có timestamp. Ý nghĩa là **quan sát trong snapshot đã được đối chiếu**, không phải quyền hoặc session/executor đang hoạt động hiện tại. Configured/inferred/unknown không được nâng thành observed. Condition/predicate sai, fact không liên quan, fact không tồn tại hoặc bị bỏ khỏi selected context bị từ chối.

Known supported prerequisites phải được giữ theo registry; không được đổi thành assumed để che mất căn cứ. Thời gian nguồn không được đổi sang giờ hiện tại. Session survey luôn đi kèm blocker revalidation cho execution. Không có provider telemetry live: không cho expected_telemetry availability=verified. Manager ingestion phải có typed manager samples; service running và local_event không tạo detection.

Các artifact tại job:

| Artifact | Vai trò |
| --- | --- |
| `input/input_manifest.json` | Hash các input bất biến; không hash chính nó |
| `input/input_envelope.json` | Request/policy/profile/context/evidence quality |
| `input/survey/*` | Snapshot nguyên bytes bundle đã redaction, gồm evidence cần truy vết |
| `context_selection.json` | Facts được đưa vào model, lý do/budget/omissions |
| `compatibility_report.json` | Tất cả cặp candidate/executor cùng reasons/blockers/bindings/source hash |
| `validation_report.json` | Hợp lệ hoặc lỗi; bounded repair tối đa hai plan generations |
| `step_evidence.json` | Target/run identity, checks, parameter/environment bindings, nguồn, readiness, telemetry và manual-review của từng bước |
| `scenario_plan.yml` | Chỉ xuất khi schema + business/evidence validation đạt |
| `result.json` | Process status riêng với execution/detection readiness, blockers, evidence quality |

Workflow run/checkpoint nằm trong `job/runs/<readable-name>/`. Job giữ input snapshot cho download; workflow có bản sao snapshot được pin riêng trong run để rename/copy run không phải đọc kho Survey mới. Ref của evidence là tương đối với input/survey. Linked sidecar được đặt cạnh YAML ở job và run.

Resume xác minh manifest/input hash, code adapter hash/version, target/catalog/contracts/model fingerprints và context selection. Clarification đi qua parse/request guard và không thể nâng scope, max_steps hoặc execution_authorized. Checkpoint cũ không có v2 vẫn xem được và chỉ resume theo legacy khi fingerprint/adapter còn tương thích; nếu thiếu input hoặc thay adapter thì báo tạo job mới từ request cũ, không sửa lịch sử thành v2. Interrupted job vẫn hướng dẫn tạo job mới.

## So sánh ca SQLi thực tế

Đã đọc request cũ `scenario_outputs/716ce1eb90a74aac8b03d2b035bdedf3/request.json`: “Kiem tra kha nang phat hien sqli”, scope web, max_steps=4. Yêu cầu không đòi XSS/fuzzing hoặc điền đủ bốn bước.

Replay mới dùng request cùng hành vi SQL injection/SOC, catalog và keyword retrieval thật; **parse/ground/build là mock có nhãn**, không phải kết quả Gemini live.

| Trước | Sau trong replay offline |
| --- | --- |
| Profile-only mất nội dung module/form | Loader đọc 82 facts; 39 facts được chọn, 43 facts ngoài domain không đưa vào model; 32.760/65.000 bytes, không cắt vì budget |
| Module GET/id/Submit, security low bị ghi assumed/null | Prerequisites dẫn fact IDs cho location, module sqli và các lần quan sát session/security |
| target_ip null | Target identity giữ 192.168.1.150 trong envelope/step_evidence; binding target_ip từ identity khi source thực sự cần placeholder này |
| Command search.php/port80 được dùng như phù hợp app đã khảo sát | Command URL/port mismatch bị loại; endpoint chưa quan sát được ghi rõ, không tự tạo search.php |
| Bước trộn XSS/fuzzing | Extra behavior bị loại khi request chỉ yêu cầu SQLi |
| Max_steps=4 dễ thành bốn bước | Một bước source-grounded đáp ứng hành vi của fixture; max_steps vẫn chỉ là trần |
| Biến URL/cookie source chưa có căn cứ | Source DVWA có environment override: đề xuất DVWA_URL=http://192.168.1.150:8080/dvwa, explicit transform bỏ slash cuối vì command nối suffix; cookie execution riêng vẫn blocker |
| Dễ gộp plan hợp lệ với khả năng chạy/detection | completed, readiness=needs_information, execution_readiness=conditional_manual_review, detection_readiness=not_verified, execution_authorized=false |

Bước mẫu dùng ability SQLi có thật trong catalog; không viết command/payload mới. HTTP request hoặc log không chứng minh khai thác thành công. Behavior verification yêu cầu so sánh baseline/phản hồi phù hợp, vẫn manual review và chưa thực hiện. Một bước là kết quả ca mock, không phải quy tắc hardcode cho mọi SQLi request.

## Lệnh và kết quả kiểm chứng

Từ runtime:

```bash
cd /home/soc/build_scenario_agent
.venv/bin/python -m scenario_agent.cli inspect-survey /home/soc/DATN/GUI/review/survey-v2-8722.zip
.venv/bin/python -m unittest discover -s tests
```

Từ GUI:

```bash
cd /home/soc/DATN/GUI
.venv/bin/python -m unittest discover -s tests -p 'test_scenario_input_v2.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
node --test tests/flow-core.test.cjs tests/scenario-ui.test.cjs
/home/soc/build_scenario_agent/.venv/bin/python tools/replay_scenario_v2.py review/NEW_REPLAY_DIRECTORY --real-keyword-retrieval
```

CLI run v2 dùng cùng loader/policy/validator, nhưng **lệnh dưới sẽ gọi model nếu thực thi**; chưa chạy lệnh này trong task:

```bash
.venv/bin/python -m scenario_agent.cli run --target /path/to/survey-v2.zip \
  --text 'Yêu cầu kiểm thử' --scope web --max-steps 4 --mode keyword
```

Kết quả:

- Baseline runtime trước sửa: 94/94 đạt.
- Runtime sau sửa: 108/108 đạt, gồm 14 tests mới. Đi xuyên loader → selection → catalog fixture → mock generation → validators → serializer → bridge/worker/API; có replay riêng với keyword retrieval thật.
- GUI tests mới: 3/3 đạt. Bộ GUI đầy đủ: 94 tests, vẫn 1 failure + 2 subtest errors có trước trong test_web_normalization (fixture 8/6 thay vì 11/9, IP fixture ngoài allowed_networks). Không sửa test/config để che lỗi.
- Node: 21/21 đạt, bao gồm send run ID, xóa ID khi chọn legacy và hiển thị source/time/readiness/blocker từ API.
- Hash của 520 file catalog/index/Survey/historical Scenario outputs trước/sau không đổi.
- Có kiểm tra malformed ZIP/hash/pointer/version/target/traversal/symlink, cấu hình/inferred không được nâng cấp, fake/unrelated fact, binding sai, downgrade prerequisite, hidden blocker, verified telemetry giả, extra step, scope expansion và resume clarification.

Artifact mẫu cuối: `review/scenario-input-v2-verified/<job-id>/` (một job, tìm offline_replay.json). Đây là job mock trong review, không đưa vào lịch sử production và không thêm catalog. Xem scenario_plan.yml, step_evidence.json, compatibility_report.json và result.json cạnh nhau. Các draft replay nội bộ đã được dọn; outputs lịch sử không đổi.

Logs tại `review/scenario-input-v2-validation/`; kiểm tra bảo toàn tại `review/scenario-input-v2-source-verification.json`.

## Giới hạn, vận hành và rollback

Source analysis là normalizer xác định cho cấu trúc URL/placeholder/environment/form được nhận diện, không phải bộ phân tích ngôn ngữ shell tổng quát. Construct/dependency/privilege/side effect chưa thể chứng minh giữ manual_review/blocker hoặc bị loại bảo thủ; không khẳng định verified chỉ vì lời giải thích của model. Semantic matching hành vi vẫn cần independent model review và source quote; kiểm thử mock không chứng minh chất lượng model live hoặc hybrid E5 ranking. Replay keyword thật kiểm tra tích hợp, không đánh giá relevance của embedding model.

Chưa kiểm chứng LLM live, session thực thi, dependency/tool trên runner, operation CALDERA, exploit success, Wazuh ingestion hoặc SOC detection. Không có auto-survey để lấp khoảng trống. Code đã sửa nhưng dịch vụ đang chạy không bị restart; cần nạp mã trong lần khởi động bảo trì thông thường.

Rollback mã bằng bản trước sửa trong `review/scenario-input-v2-code-backup/runtime/` và `.../gui/`. Khôi phục các file đã tồn tại, gỡ import/call v2 nếu rollback từng phần; các file mới không còn được import có thể giữ để review. Không xóa output/checkpoint để rollback. Snapshot v2 của các job dùng adapter khác không nên tiếp tục dưới code đã rollback; tạo job mới từ raw request khi cần. Survey producer/historical evidence giữ nguyên.
