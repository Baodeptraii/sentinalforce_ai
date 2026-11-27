> Cập nhật 2026-11-19: đã sửa truy xuất PowerShell → cmd, grounding tiếng Việt không dấu và báo thiếu bao phủ. Runtime 140/140, GUI 96/96, Node 21/21. Báo cáo: `/home/soc/DATN/GUI/review/process-parent-fix-20261119/README.md`. Kết quả lịch sử giữ nguyên; chưa gọi AI/live execution để tạo plan mới.

# Context Survey → Scenario tổng quát — adapter 2.2

> Cập nhật 2026-11-19: ba lỗi test GUI normalization đã sửa; GUI Python **94/94**, Node **21/21** đạt. Chi tiết và log mới: `/home/soc/DATN/GUI/review/gui-normalization-fix-20261119/README.md`. Các số liệu lỗi GUI ngày 17/11 bên dưới được giữ làm lịch sử trước lần sửa này.


Bổ sung theo `BO_SUNG_CONTEXT_SURVEY_SCENARIO.md`. Thay đổi chính là requirement registry, mở rộng từ inventory đã xác thực và association theo ứng dụng/bước. SQLi tiếp tục là regression case, không phải cơ chế chọn context chính.

## Phạm vi và version

- Survey producer, schema nguồn và output lịch sử giữ nguyên. Scope task chính là Scenario: bổ sung adapter đọc các inventory refs mà producer 2.0 đã cung cấp; không sửa hai phía thành contract mới hoặc thu thập thêm.
- Survey snapshot/input envelope source schema: **2.0**. Adapter mới: **scenario_survey_v2.2**.
- `evidence_registry.json`: schema **1.0**; nguồn gốc và projection được ghi riêng.
- Selected context gửi model: schema **1.0**, context_kind `scenario_selected_context`, source_schema_version **2.0**. Các gap nội bộ như unsupported_normalizer không bị gán nhầm vào schema gap của producer.
- Requirement assessment: registry_version **1.0**, kinds/status có enum và schema riêng.
- ScenarioPlan giữ metadata schema **1.0**; thông tin bổ sung nằm trong step_evidence có liên kết rõ.
- Không thay credentials/config/OS/network/CALDERA/Wazuh, rebuild corpus/index, gọi model live, khảo sát live, thực thi ability hoặc restart dịch vụ.

## Luồng dữ liệu

```text
Manifest/hash/pointer/identity validation
  → immutable input snapshot
  → local evidence registry: original facts + typed inventory/origin projections
  → initial context by request/shared identity
  → catalog retrieval
  → source requirements + typed resolvers + application associations
  → expanded selected context / explicit known-but-unselected budget diagnostics
  → independent behavior grounding + mock/live generation boundary
  → schema + policy + fact/binding/compatibility validation
  → ScenarioPlan + per-step evidence/readiness
```

`requirement_registry.py::RULES` khai báo loại requirement và các predicates có thể hỗ trợ. `PARAMETERS` khai báo semantic của từng tên input được hỗ trợ. Source analysis lấy URL templates, method, parameter names, environment/literal assignments, process/service operations, dependencies, effects và cleanup từ executor/catalog. Không chọn theo ability ID, IP hoặc tên DVWA.

Registry snapshot có source fact count, derived fact count, target/run identity, SHA-256 manifest Survey đã redaction và evidence_root tương đối. Source_manifest/evidence_index cũ không dùng thay hash của scenario_handoff.

## Mở rộng evidence có giới hạn

- Inventory được lấy **chỉ** từ target_profile_v2.inventory_refs thuộc manifest đã xác thực. Projector đọc source bytes, kiểm tra SHA-256/JSON Pointer rồi whitelist trường process/service.
- Fact process gồm tên, PID, executable_path nếu đã có; service gồm tên/display_name/state/PID. Inventory root ghi số record **được trả về**, không khẳng định đã liệt kê mọi tài nguyên trên host.
- Thời gian lấy từ endpoint collected_at; không dùng giờ chuyển đổi. Thiếu giờ vẫn null. Metadata CALDERA giữ configured; legacy capability giữ inferred/unknown.
- Projector tối đa 512 record mỗi inventory; có gap truncated, source ref và số record gốc. Shape/field/kind chưa hỗ trợ được giữ trong evidence và gap unsupported_normalizer, không âm thầm coi tương thích.
- Namespace derived-* thuộc adapter. Raw producer extension kiểu process/service/inventory/web_origin/resource_path chưa có typed verifier được giữ opaque, không giả làm projection đã kiểm tra.
- HTTP access có thể tạo fact **web_origin**: scheme/host/port đã quan sát. Nó không tạo application base path, form, auth hoặc vulnerability fact. HTTP-only request vẫn có context hữu ích và blockers cho phần chưa khảo sát.
- Context expansion có hai giai đoạn: initial request/shared context, sau retrieval bổ sung requirements; không có vòng thu thập mạng. Giới hạn được ghi trong context_selection.expansion.

## Mapping fact → requirement → step

Mỗi assessment có requirements[]:

- id ổn định theo ability/executor/kind/subject/expected;
- kind, subject, expected, status, fact_ids;
- source ability ID/revision và command SHA-256;
- detail cho thiếu/ambiguous/unsupported/conflicting.

Status gồm observed/configured/inferred/unknown/ambiguous/conflicting/unsupported/incompatible. Status mô tả mức bằng chứng của requirement; không cấp quyền hoặc xác nhận execution hiện tại.

`context_selection.included[].requirement_links` giữ ability ID, executor, requirement ID/kind/subject. Facts dùng chung chỉ xuất hiện một lần trong selected context. `step_evidence.steps[]` nối assessment vào step_index và behavior_requirements (B1/B2...), đồng thời giữ bindings, requirements, source, prerequisites, blockers và telemetry theo subject.

Condition dạng survey.<predicate>:<subject> chỉ được verified cho **quan sát lịch sử** có status observed và thời gian nguồn thật. Known required checks không được đổi thành assumed hoặc dùng fact của predicate/subject khác. Unknown runner/session vẫn phải preflight riêng.

Nếu facts đã có nhưng không đủ budget để đưa vào model: required_but_unselected liệt kê IDs; build_plan dừng trước generation và yêu cầu thu hẹp context/tăng budget server, không yêu cầu khảo sát lại dữ liệu đã có. Fact thiếu, fact opaque/chưa có resolver và fact có nhưng chưa chọn là ba trường hợp khác nhau.

## Association và binding

- Chọn application bằng origin/base path, cấu trúc URL nguồn, environment override/literal assignment và request; không lấy location đầu tiên khi có nhiều lựa chọn.
- Endpoint form/auth/session chỉ được ghép trong cùng base URL/origin/port/path. Hai app cùng suffix `action/` vẫn có method/inputs/security/session riêng.
- Web telemetry tạo requirement riêng cho từng app. Log có URL/app A không chứng minh availability cho app B. Log chung không có attribution giữ unknown. Transport-only observation chỉ có thể gắn log đúng endpoint, không giả thành coverage cả app.
- Process/network telemetry dựa trên loại sự kiện có nguồn; event tại endpoint, manager ingestion và detection là các mức khác nhau. Sysmon event không tự tạo Wazuh ingestion hoặc detection.
- URL/IP/port/scheme/module_path có semantic riêng. `remote.host.port` lấy listener target, không lấy cổng app mặc định. Nhiều listener/resource mà chưa chọn được thì ambiguous/null.
- Path từ executable_path quan sát có thể bind khi xác định duy nhất resource; luôn giữ blocker kiểm tra filesystem existence/access. Không coi path metadata là kết quả đọc ACL hoặc Test-Path.
- Source `#{base_url}/...` và environment URL có transform bỏ slash cuối được ghi rõ để đúng phép nối trong source. Source `#{base_url}...` giữ slash của base URL. Module path lấy từ form contract phù hợp đã quan sát, không tạo endpoint mới.
- Literal URL, host/IP assignment và port trong source được kiểm tra cả khi qua biến. Biến URL/host không có mapping được nhận diện tạo blocker cụ thể; không tự coi nó đã trỏ về victim.
- Không rewrite command, tạo shell/payload hoặc tự thiết lập environment/session. Bindings là dữ liệu đề xuất, kèm nguồn và phần cần kiểm tra.
- Matching behavior vẫn dựa vào independent grounding + literal command evidence. Một số effect tags bảo vệ các compound behavior rõ ràng; chúng là guard phụ, không thay requirement registry bằng chuỗi if SQLi/XSS.

## Ma trận coverage

| Requirement | Nguồn fact | Selector / validator | Test chính | Giới hạn / phần cần thêm Survey |
| --- | --- | --- | --- | --- |
| target.os/architecture | os_name, architecture | Platform gate, architecture aliases, unknown không thành mismatch | real_process_ability; architecture_alias_and_unknown | Không suy Linux/WSL từ Windows; kiến trúc chưa có giữ unknown |
| runner.executor/privilege | executors, privilege configured; is_elevated observed | Giữ status nguồn; privilege âm tính có căn cứ / conflict riêng | real_dependency_and_privilege; conflict_and_negative | Cần runner preflight hiện tại; configured không phải executed |
| endpoint.process_inventory | inventory_refs processes | Typed root baseline + projected records/ref/hash/time | real_process_ability_expands_attested_inventory | Collector có thể chỉ trả process gắn listener, không phải full process list |
| endpoint.service_inventory | inventory_refs services | Named resource / returned inventory baseline | named_service_state; unique_resource_parameter | Service running không chứng minh logging/detection |
| endpoint.listener | listener + PID/service association | Typed listener source validation; port binding tách app port | listener_port_binding | Nhiều listener cần lựa chọn; không suy runner connectivity |
| endpoint.path | observed process executable_path | Exact semantic/resource association, ambiguous null | unique_resource_parameter; real_dependency | Không có ACL/file existence/staging/dependency installation checks |
| web.application | application_location/identity, derived web_origin | Origin/path/port association; transport-only base unknown | plain_http; multi_application_ambiguity; mutated_address | Version/base path/auth/form có thể chưa được collector xác minh |
| web.request GET/POST | module_access_and_forms, http_access | Method/params/action per call, cùng app; dynamic body unknown | method_parameters; two_apps; typed_url_and_module | Không parse shell/Python tùy ý; routing chưa chứng minh giữ blocker |
| web.authentication/CSRF | same-app survey_session; form csrf_present | Historical scope; execution-session/token reference riêng | application_associations | Chưa có execution session/token; không truyền secrets |
| catalog.dependency | requirements/payloads/source metadata | Unsupported plugin/metadata có reason, không tự satisfy | unknown_requirement; real_dependency; unsupported_network | Chưa có normalizer toàn bộ plugin CALDERA hay inventory phần mềm/tools |
| catalog.cleanup/effects | source command + cleanup catalog | Mọi bước giữ review baseline/health/cleanup, không kết luận none từ [] | real_dependency; mixed_plan | Static analysis có giới hạn; không chứng minh hiệu ứng của script tổng quát |
| telemetry.process/network/web | local_event, typed manager_ingestion | Theo loại event và subject từng app; expected ≠ detected | process_telemetry; two_apps telemetry; listener_port | Cần correlation/manager/detection preflight; shared log không có attribution giữ unknown |
| unknown/unsupported | opaque source/ref và gaps | Unsupported/manual review, không default compatible | unknown_inventory_type; unverified_producer_extension | Bổ sung checker/typed verifier trước khi mở khả năng verified |
| context budget và pin | selection links + input/registry hashes | Known-but-unselected riêng; chặn trước model; registry tamper guard | known_required_context_over_budget; registry_artifact_tamper | Tăng budget là cấu hình server / thu hẹp yêu cầu, không tự re-survey |
| mixed endpoint + web | Bundle thật + hai catalog records thật | Loader → expansion → fixture retrieval → mock grounding/build → validators → YAML | real_bundle_mixed_plan | Không chứng minh ranking E5 hoặc chất lượng Gemini live |

Tên test rút gọn trong bảng nằm ở `tests/test_context_requirements.py` (23 test mới). Coverage chi tiết có bản máy đọc tại `review/context-generalization-validation/coverage.json`. Synthetic fixtures có nhãn rõ và dùng IP tài liệu; không được báo là quan sát host thật. Matrix không đại diện cho mọi ability trong catalog.

## Job mẫu và kiểm chứng

Job cuối tại `review/context-generalization-v22/<job-id>/` dùng Survey thật `8722...`, record thật:

- WMIC Process Enumeration (`94f21386-9547-43c4-99df-938ab05d45ce`).
- Web Command Injection POST probe (`a1b2c3d4-dvwa-0003-cmdi-000000000003`).

Đây là **retrieval fixture dựa trên catalog thật và model mock**, không phải E5/Gemini live. Không có source command nào được thực thi. Bản replay cho hai hành vi sinh hai bước, dưới max_steps=4; output luôn plan_only và execution_authorized=false.

Bundle có 82 source facts; adapter mở rộng 106 service records, 16 process records, hai inventory root và ba HTTP origin observations, tổng **127 derived facts**. Lựa chọn context có fact IDs, requirements và thông tin omitted; số liệu cuối nằm trong offline_replay/context_selection của job, không hardcode vào runtime.

Xem cùng nhau:

- input/input_manifest.json và input/survey/scenario_handoff.json;
- evidence_registry.json — facts đầy đủ và giới hạn projection;
- context_selection.json — nội dung được chọn, requirement links, omitted/budget/rounds;
- compatibility_report.json — requirements và lý do phù hợp/loại/chưa đủ;
- step_evidence.json — behavior → requirement → fact/ref → step;
- scenario_plan.yml, result.json — completed riêng với readiness;
- offline_replay.json, offline_verification.json — nhãn mock và kiểm chứng độc lập.

## Lệnh đã dùng

```bash
cd /home/soc/build_scenario_agent
.venv/bin/python -m unittest discover -s tests -p test_context_requirements.py -v
.venv/bin/python -m unittest discover -s tests

cd /home/soc/DATN/GUI
.venv/bin/python -m unittest discover -s tests
node --test tests/flow-core.test.cjs tests/scenario-ui.test.cjs
/home/soc/build_scenario_agent/.venv/bin/python tools/replay_context_requirements.py review/NEW_DIRECTORY
/home/soc/build_scenario_agent/.venv/bin/python tools/verify_context_replay.py review/NEW_DIRECTORY/JOB_ID
```

Verifier kiểm tra schema bằng jsonschema tiêu chuẩn, snapshot/checkpoint, refs/hash, từng derived projection và validate lại YAML với requirement registry. Có thể copy cả job sang thư mục khác rồi dùng cùng verifier; refs tương đối với input/survey. Verifier không gọi model hay thực thi Scenario.

Kết quả/log cuối tại `review/context-generalization-validation/`; kiểm chứng giữ nguyên các file đã có ở `protected-files.json`. Bộ GUI vẫn có ba lỗi normalization đã được xác định trước task; không sửa kỳ vọng fixture hoặc allowed_networks để che lỗi.

## File thay đổi và mở rộng rule tiếp theo

Runtime: thêm requirement_registry.py; cập nhật target_evidence.py, survey_input.py, workflow.py, cli.py. Thêm schema requirement_assessment/evidence_registry/selected_context và nâng adapter trong scenario_input_envelope schema. Thêm test_context_requirements.py. GUI: cập nhật worker để copy registry và trả context_expansion; bridge allowlist evidence_registry; thêm hai tools replay/verify. UI hiện có hiển thị JSON result thật và link artifact nên không cần dựng mẫu dữ liệu UI mới.

Để thêm requirement:

1. Định nghĩa kind/predicates trong RULES và enum schema, semantic input alias trong PARAMETERS nếu có.
2. Viết normalizer từ metadata/command được nhận diện; giữ raw source hash và báo unsupported cho construct chưa xử lý.
3. Viết resolver kiểm tra subject/value/status/time. Chỉ mở inventory projection khi có ref/hash/pointer và whitelist/typed validation rõ; không tự đọc file/URL ngoài snapshot.
4. Bổ sung requirement với fact_ids hoặc unknown/unsupported reason; selector tự bổ sung facts và links theo assessment.
5. Thêm positive/negative/ambiguous/multi-subject tests, rồi kiểm tra sidecar/semantic validator và cập nhật coverage table. Không suy observed từ inferred/configured.

## Compatibility, rollback và giới hạn còn lại

Producer 2.0 và profile-only legacy tiếp tục dùng được. Snapshot/checkpoint adapter 2.1 cũ giữ nguyên để xem lịch sử; resume dưới code 2.2 bị từ chối rõ khi version/code hash không tương thích và yêu cầu tạo job mới từ request cũ. Không tự sửa checkpoint cũ thành registry mới. Bản 2.2 pin registry artifact/hash cùng input/context selection.

Bản sao mã trước thay đổi ở `review/context-generalization-backup/runtime/` và `.../gui/`. Rollback các file đã tồn tại từ đó; giữ output/checkpoint. File/schema mới có thể giữ để review khi code cũ không còn import chúng. Bản handoff 2.1 được giữ làm lịch sử; tài liệu này mô tả phiên bản hiện tại.

Chưa có normalizer toàn bộ shell/PowerShell/Python và plugin/dependency của catalog. Không có dữ liệu ACL, filesystem existence/access, software/package/tool installation hoặc execution session khi Survey chưa thu thập. Những phần đó cần Survey/checker bổ sung hoặc preflight, không được coi đã đủ context. Chưa chạy LLM live, hybrid ranking evaluation, operation/exploit, ingestion/detection validation hoặc restart dịch vụ. Chất lượng generation live và khả năng thực thi thực tế vẫn chưa được chứng minh.

## Kết quả chốt của lần bổ sung

- Runtime: **131/131 tests đạt**, gồm **23 tests matrix mới** ngoài bộ 108 trước đó.
- Node UI/flow: **21/21 đạt**. Bộ GUI Python vẫn có 94 tests với 1 failure + 2 subtest errors cũ ở test_web_normalization: expected request/observation 11/9 nhưng fixture trả 8/6; hai subcase dùng IP ngoài allowed_networks.
- **641 file đã có trước task không đổi hash**, gồm catalog/index, Survey outputs, Scenario history và các bundle/job review trước đó.
- Job mẫu cuối: `review/context-generalization-v22/650cd7a662de439a896dcc0121e12a66/`. Hai bước process + web POST, 82 source facts, 127 derived facts, 71 selected facts, 138 omitted theo domain/resource; 49.630/65.000 bytes, không truncation và không thiếu required facts trong selection.
- Verifier chuẩn đạt: 209 evidence refs, 127 projections, schemas, checkpoint/input hashes, YAML business validation và requirement-to-step links. Copy cả job sang thư mục khác và verify lại cũng đạt. Dữ liệu portable; verifier cần runtime/catalog tương thích.
- Process completed; execution readiness conditional_manual_review; detection not_verified; execution_authorized=false. Model/retrieval đều có nhãn mock/fixture rõ; không có live model call hoặc thực thi Scenario.
