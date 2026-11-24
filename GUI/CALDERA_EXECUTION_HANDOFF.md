> **Cập nhật 24/11/2026:** Đã có validation/expected contract riêng và báo cáo Expected/Reality. Thiếu API55000 không còn chặn đọc indexer; thiếu identity lịch sử vẫn chỉ trả candidates. GUI dùng Validate → xác nhận. Các kết quả test/trạng thái triển khai bên dưới là lịch sử ngoài package staging; cần chạy lại trước khi dùng. Không mở quyền chạy mọi ability và không xác nhận detection từ exit0.

# Tích hợp Scenario → CALDERA — 21/11/2026

## Kết quả và phạm vi

Đã thay nút thực thi tạm bằng luồng **preview/preflight → xác nhận đúng IP/hash → theo dõi → dừng/đối soát**. Survey và Scenario vẫn độc lập; không có LLM thực thi và sinh plan không tự chạy.

**Chưa chạy kịch bản thật lên endpoint trong đợt tích hợp này.** Controller thực thi được kiểm tra bằng fake API theo schema/source CALDERA ở môi trường triển khai; API thật chỉ được gọi GET. Kiểm tra triển khai là service/HTTP/API chỉ đọc, không gửi xác nhận execution thật.

Adapter v1 có giới hạn có chủ đích: chỉ hỗ trợ lệnh discovery và HTTP GET literal trong tập cú pháp được nhận diện, executor `psh`, `cmd`, `sh`, `bash`. HTTP origin/port phải có trong profile Survey đã ghim; target phải khớp IP/hostname. PS nhiều dòng dùng UTF-16LE EncodedCommand và giữ source đọc được trong preview; có thể phát sinh alert PowerShell Base64. GET không chứng minh ứng dụng không có tác động; người dùng phải xem source/tác động trước xác nhận.

Bước có tham số động, placeholder, payload/upload/parser/variation/dependency, executor code/build, cleanup cần điều kiện hoặc thao tác ghi/xóa/chạy nội dung chưa có adapter phạm vi sẽ **bị chặn cụ thể**. Không sinh lệnh thay thế, không nhập cookie/credential vào facts, không ghi đè ability dùng chung. Không tuyên bố mọi plan từ catalog đều chạy được.

Plan `needs_information`, prerequisite `assumed/unknown`, profile_only hoặc Survey quá cũ vẫn bị chặn. Cần tạo phiên bản mới với bundle/context đầy đủ và có readiness/điều kiện đã được kiểm tra; xác nhận chạy không biến giả định thành bằng chứng. Không sửa YAML/checkpoint lịch sử chỉ để vượt gate.

## Kiến trúc và luồng dữ liệu

1. GUI giữ `survey_run_id` cùng lựa chọn Survey, gửi thêm `input_kind=survey_v2`. Backend yêu cầu ID khi chọn loại này; không hạ xuống profile_only khi thiếu ID/bundle.
2. Scenario snapshot giữ manifest/hash, target, policy/scope, timestamp và provenance. Mở job/history không tự thay input đang chọn trong một request muộn.
3. `engine/execution_context.py` chạy bằng Python Scenario, chỉ đọc: kiểm tra ScenarioPlan schema, checkpoint/code/catalog fingerprint, snapshot Survey v2, artifact context so với checkpoint, source file SHA-256/provenance và executor của từng bước.
4. `engine/scenario_execution.py` kiểm tra agent, heartbeat, platform/executor/quyền, operation đang mở, allowlist, freshness, từng prerequisite, origin web và giới hạn adapter. Preview chỉ GET CALDERA, chưa đăng ký artifact hoặc tạo operation.
5. Người dùng xem source, tham số đã lọc, tác động/cleanup/blocker; tích xác nhận đã xem và nhập lại đúng IP. Server gắn xác nhận vào execution ID, hash, target và scope đã lưu.
6. Controller khóa endpoint, kiểm tra lại toàn bộ binding, đăng ký bản ability riêng cho từng bước và Adversary/Source riêng; source facts rỗng. Tạo operation **paused, autonomous=0**, xác minh membership/thứ tự, rồi chuyển running. Controller chỉ bật link của bước kế tiếp khi các bước trước trả thành công.

### Điều tra profile_only

Job `f987d00f4905481ea3ab7a1f794f7382` lưu `request.json` chỉ có text/scope/max_steps và provenance `profile_only`; không có snapshot. Lịch sử này không đủ để kết luận chính xác thao tác trình duyệt trước đó. Code cũ có thể nạp profile job từ một phản hồi `showScenario` muộn sau khi người dùng vừa chọn Survey; đã loại việc tự phục hồi input ngoài thao tác mở history rõ ràng và thêm version kiểm tra lựa chọn. Regression tái hiện phản hồi muộn xác nhận Survey ID không bị mất.

Có test thực việc chọn Survey v2 → tạo job/snapshot với Thread giả, kiểm tra manifest/target/survey ID, và từ chối `input_kind=survey_v2` thiếu ID. Không ghép bundle mới vào plan lịch sử theo IP. Plan cũ đọc được như trước, muốn đổi context dùng phiên bản mới.

## Binding, idempotency và recovery

- Plan, profile/policy, context/compatibility/step evidence, snapshot manifest và code adapter tham gia binding; source revision/executor đối chiếu catalog và file nguồn thực tế.
- Mọi artifact được băm lại trước dispatch. Không xóa job đang có execution mở/cần phục hồi.
- Freshness mặc định: Survey 3.600 giây, heartbeat 180 giây, preview 300 giây; cho phép lệch đồng hồ tối đa 60 giây. Thiếu detection không chặn một lệnh standalone đủ điều kiện; detection giữ `unknown`.
- Khóa `activity-<ip>.lock` chia sẻ toàn bộ Survey GUI và execution; execution còn giữ khóa `endpoint-<ip>.lock` trùng runner Survey. Khóa được giữ suốt controller chạy. Journal recovery tiếp tục chặn endpoint sau khi tiến trình mất khóa do crash.
- Group riêng có journal intent trước PATCH; kiểm tra đúng một paw. Chỉ khôi phục nếu group vẫn là group riêng hoặc đã là group ban đầu. Group do bên khác đổi không bị ghi đè.
- Execution ID là idempotency key do server cấp. Confirm cùng ID là retry, không tạo worker/operation thứ hai. Tạo preview khác là một intent khác nhưng vẫn không vượt khóa endpoint.
- Journal `operation_post_intent` được fsync trước POST và operation ID lưu ngay khi có response. POST timeout đối soát tên/group duy nhất, **không POST lại và không tự dispatch**, kể cả đã tìm được ID.
- Chạy `initialize` sau restart chỉ đánh dấu journal mở `recovery_required`, không gọi CALDERA hoặc resume. Người dùng dùng đối soát/yêu cầu dừng. Reconcile không tự gửi bước tiếp theo.
- Atomic planner thật chờ link trước, nhưng không tự chứng minh dependency. Adapter chặn dependency chưa hỗ trợ; mỗi lần dùng lại source ID có execution ability ID riêng để không bị planner gộp bước.
- Pause không hủy lệnh đã dispatch. Dừng sẽ pause operation và discard link chưa giao; giữ trạng thái cần theo dõi/phục hồi khi lệnh đã giao chưa trả kết quả. Không bịa cleanup hoặc rollback. Controller không sửa OS/firewall/AV/Wazuh/Sysmon.

Không chạy đồng thời tác vụ ngoài GUI trên cùng endpoint: một chương trình bên ngoài không dùng khóa/journal của GUI không thể bị khóa file của ứng dụng điều phối. Controller vẫn kiểm tra membership và agent trước dispatch; drift dẫn đến dừng gửi và recovery.

## State machine và kết luận

`ready / blocked → confirmed → registering → creating_operation → running → completed / failed`.

Nhánh dừng: `stop_requested → stopped` nếu không còn lệnh đã dispatch đang chạy; nếu chưa rõ kết quả: `recovery_required`. Restart hoặc POST bất định cũng đi `recovery_required`. UI có trạng thái kiểm tra trong lúc chờ preview.

Trạng thái bước: `not_run`, `pending`, `sent`, `dispatched`, `completed`, `error`, `skipped`. Exit code khác 0, command/paw/ability mismatch, bước trùng hoặc lỗi output chặn bước sau. `completed` của execution yêu cầu đủ mọi bước trả thành công, không dựa riêng vào CALDERA `finished`.

Ba kết luận tách riêng:

- `command_status`: kết quả lệnh/exit code.
- `behavior_evidence=not_evaluated`: chưa có bộ kiểm chứng độc lập hành vi.
- `detection=unknown`: chưa đánh giá Sysmon/Wazuh/SOC.

## API và contracts

Mọi POST dùng `X-Survey-Token` và kiểm tra Origin hiện có; không nhận quyền thực thi/target tùy ý từ client.

| API | Hành vi |
| --- | --- |
| `POST /api/scenarios/<job>/execute`, `{}` | Preview mới, trả execution record; chỉ GET CALDERA. Có thể trả blocked. |
| `POST /api/executions/<id>/confirm` | `{confirmed:true,target_ip,plan_sha256}`; xác thực server và tạo controller sau khi ghi xác nhận. |
| `GET /api/executions/<id>` | Record hiện tại; không tự resume. |
| `GET /api/executions` | 100 record mới nhất; khóa/recovery vẫn quét cả record cũ. |
| `POST /api/executions/<id>/stop`, `{}` | Yêu cầu dừng gửi lệnh; xử lý cả sau restart. |
| `POST /api/executions/<id>/reconcile`, `{}` | Đối soát intent/operation/group; không tự chạy tiếp. |
| `GET /api/executions/<id>/files/<name>` | Download allowlist artifact. |

Artifact dưới `GUI/executions/<execution_id>/`:

- `execution_request.json`: source job/hash, target, scope, idempotency key và thời điểm.
- `execution_preflight.json`: preview đã duyệt, policy, bước, provenance, blocker và artifact hashes.
- `execution_manifest.json`: execution/source ID mapping, revision, command transport hash, Adversary/Source IDs, Survey refs và target.
- `operation-summary.json`: summary giới hạn, trạng thái và thời gian/step.
- `execution_result.json`: state, xác nhận, operation ID, bước, stdout/stderr đã lọc và ba kết luận.

Schema version `caldera_execution_v1`; JSON Schema tại `schemas/execution_v1/`. Output mặc định tối đa 16 KiB/kết quả; vượt giới hạn chuyển recovery, không lưu raw response. Redact các key/pattern secret/cookie/credential và URL userinfo; không có cơ chế cấp secret thì source step bị chặn ngay từ preview. Không lưu response API đầy đủ không giới hạn. Giữ giới hạn 8 MB của API client và bản sửa repeated include cho operation list; controller dùng nested projection `host_group.paw` đã thử trên API thật.

## Cấu hình

Dùng nguyên `caldera_url`, key_file/env và `allowed_networks` hiện có. Không đổi `config.json`, bind address hay credentials. Có thể cấu hình tùy chọn `scenario_execution` với:

```json
{"preview_ttl_seconds":300,"survey_max_age_seconds":3600,"agent_max_age_seconds":180,"timeout_seconds":900,"max_output_bytes":16384}
```

Các giá trị có giới hạn server-side trong `policy()`; không có cờ bỏ qua integrity/readiness hoặc cho phép secret. URL CALDERA của GUI lấy từ cấu hình; nếu truy cập GUI qua tunnel, cần tunnel CALDERA tương ứng để mở liên kết loopback.

## Kiểm thử và dữ liệu thật

- GUI Python: **140/140**, gồm execution fake API, source/schema thực bằng runtime subprocess và các regression Survey/Scenario.
- JavaScript/DOM mock: **29/29**, gồm preview blocked, IP/ack/confirm, poll/reload và không tự confirm.
- Scenario runtime: **140/140**.
- 414 file config/output/history/library/static snapshot: SHA-256 giữ nguyên trong lần kiểm tra trước triển khai; `engine/runner.py` giữ byte-for-byte bản trước sửa.
- Regression ban đầu có mock Survey cũ không hiểu query include của bản sửa runner đã tồn tại trước nhiệm vụ. Đã cập nhật fake HTTP server dùng `urlsplit(...).path` theo API thật; không bỏ bản sửa response limit để làm test xanh. Hai test 501 cũ được chuyển sang contract preview mới.

Lệnh:

```bash
cd GUI
.venv/bin/python -m unittest discover -s tests
node --test tests/flow-core.test.cjs tests/scenario-ui.test.cjs
cd ../scenario_agent
.venv/bin/python -m unittest discover -s tests
```

Log, backup, preservation check và preflight thật chỉ đọc nằm ngoài package staging. GUI test dùng FakeAPI, không gọi endpoint thật. Preflight profile-only/readiness/prerequisite/session/target bị chặn đúng; không đăng ký lại ability thiếu hoặc chưa xác minh.

## File thay đổi

- Mới: `engine/scenario_execution.py`, `engine/execution_context.py`, `static/scenario-execution.js`, `schemas/execution_v1/`, `tests/test_scenario_execution.py`.
- Sửa: `app.py`, `engine/lifecycle.py`, `engine/scenario_actions.py`, `engine/scenario_bridge.py`, `static/scenario.js`, `static/index.html`, `static/style.css` và các test tương ứng.
- `engine/runner.py`, Scenario runtime/catalog/index, `config.json`, output/history giữ nguyên. Backup có cả các file đọc liên quan để đối chiếu.

## Triển khai và rollback

Chỉ restart riêng `datn-survey.service` sau kiểm tra Survey, Scenario và execution đều không hoạt động. Kiểm tra HTTP GET `/api/meta`, `/api/scenarios`, `/api/executions`, asset mới và GET CALDERA compact operations; không gọi confirm thật. Kết quả triển khai phải lưu ngoài package staging, trong deployment workspace được kiểm soát.

Rollback khi không có lượt hoạt động: stop GUI, khôi phục các file đã sửa từ `review/caldera-integration-20261121/backup/`, rồi start lại GUI. Giữ toàn bộ `outputs`, `scenario_outputs`, `scenario_library`, `executions`. Nếu đã có execution journal mở, đối soát/dừng operation trước rollback; không bỏ journal hoặc coi pause là hoàn tất.

## Kiểm thử lab sau khi người dùng duyệt

Chọn một plan mới từ đúng Survey v2 còn mới, đủ prerequisite/readiness, source command thuộc tập hỗ trợ. Bấm Thực thi để xem preview; kiểm tra IP/host/paw/scope, revision, từng lệnh và các blocker. Chỉ khi hết blocker mới nhập IP, tích xác nhận và bấm xác nhận thực thi. Theo dõi operation ID và từng bước; thử reload hoặc yêu cầu dừng ở môi trường được duyệt. Tải artifact, đối chiếu kết quả lệnh, bằng chứng hành vi và log SOC riêng. Không dùng plan SQLi thiếu phiên/cookie hoặc plan ghi/xóa hệ thống làm bài test mặc định.
