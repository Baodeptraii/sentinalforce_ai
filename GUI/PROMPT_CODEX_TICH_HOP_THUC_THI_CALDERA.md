# Prompt gửi Codex trên máy 192.168.1.164

Sao chép toàn bộ khối dưới đây vào Codex. Prompt này dành cho agent có quyền chạy lệnh thật: kiểm tra đường dẫn, phạm vi thay đổi và điều kiện dừng trước khi gửi.

```text
Bạn là Codex đang làm việc trực tiếp trên máy Ubuntu 192.168.1.164. Hãy thiết kế rồi triển khai luồng thực thi Scenario qua CALDERA vào SOC Agent GUI hiện có. Dùng công cụ để đọc mã, sửa, chạy kiểm thử và kiểm chứng triển khai; không dừng ở đề xuất kiến trúc.

MỤC TIÊU VÀ PHẠM VI

Giữ Survey Agent và Scenario Agent tách biệt. Bổ sung lớp orchestration thực thi xác định bằng code, dùng lại nút “Thực thi” sau khi sinh kịch bản. Không cần thêm LLM Agent thực thi. Sinh plan thành công không tự động chạy: người dùng chọn plan, xem kiểm tra điều kiện và bấm xác nhận chạy đúng mục tiêu trên GUI.

Được đọc, sửa, kiểm thử trong project GUI và adapter Scenario liên quan; đọc CALDERA source/API hiện có; tạo backup; restart riêng GUI sau khi xác minh không có Survey, Scenario hoặc execution đang chạy. Không thay đổi firewall, bind address, OS, antivirus, Wazuh, Sysmon, không xóa lịch sử/output hoặc ghi đè thay đổi của người dùng. Không cài dependency hệ thống nếu chưa cần và chưa được phép. Không in secrets.

Trong lần triển khai này, tự hoàn thành kiểm thử offline/mock và kiểm tra API chỉ đọc. Chưa tự bấm thực thi kịch bản thật lên endpoint. Hoàn thiện chức năng để người dùng thực thi qua GUI sau khi xem preview. Nếu cần chạy thử thật, trước hết chuẩn bị đầy đủ plan cụ thể, mục tiêu, lệnh nguồn, tác động và kết quả preflight để người dùng duyệt. Không dùng sự cho phép phát triển phần mềm làm quyền chạy mọi ability.

BỐI CẢNH ĐÃ KIỂM TRA NGÀY 21/11/2026 — PHẢI XÁC MINH LẠI

- GUI: /home/soc/DATN/GUI; Python .venv; systemd user service datn-survey.service; start.sh; HTTP 127.0.0.1:8765.
- Scenario runtime: /home/soc/build_scenario_agent. CALDERA source: /home/soc/caldera; API hiện dùng http://127.0.0.1:8888. Đọc cấu hình thật, không hardcode khóa hoặc chép credentials vào prompt/code.
- Endpoint lab: 192.168.1.150, Windows host PTIT, Sandcat paw datnptit. Lần kiểm tra trước trusted, heartbeat mới, executor psh và Elevated. Phải xác minh lại trước mỗi execution.
- app.py có POST /api/scenarios/{id}/execute gọi engine/scenario_actions.py::execute, hiện trả HTTP 501 và status not_implemented.
- engine/scenario_bridge.py đặt execution_supported=False; plan_only và execution_authorized=False. static/scenario.js đã có nút scenario-execute. Dùng lại luồng này.
- Survey mới nhất đã kiểm tra: 8afe9472dafa40549f76b054be086861, completed_with_unknowns, có outputs/<run_id>/survey_v2/scenario_handoff.json và evidence.
- Scenario f987d00f4905481ea3ab7a1f794f7382 sinh thành công nhưng dùng profile_only, readiness=needs_information. Plan SQLi có ability a1b2c3d4-dvwa-0005-sqli-000000000005 đã có trên CALDERA; a1b2c3d4-dvwa-0006-bsql-000000000006 trả 404. Đây là ví dụ phát hiện lỗi, KHÔNG phải phạm vi thiết kế chỉ dành SQLi.
- GET operations từng vượt giới hạn 8 MB. engine/runner.py đã sửa GET danh sách dùng include lặp lại cho id,name,group,state,host_group. Giữ bản sửa, không tải toàn bộ lịch sử để kiểm tra endpoint bận và không bỏ giới hạn response.

Trước sửa, đọc AGENTS.md/rules.md và tài liệu handoff hiện có trong project. Kiểm tra git status, process, job đang chạy và code thật; bảo toàn thay đổi ngoài nhiệm vụ. Ghi nhận những điểm khác bối cảnh trên, không áp dụng snapshot cũ lên code mới.

LUỒNG CẦN TRIỂN KHAI

1. Bảo toàn đầu vào Survey → Scenario → Execution
Khi chọn kết quả Survey trên GUI, truyền survey_run_id và nạp bundle v2 có manifest/hash; giữ target identity, scope, timestamps, context_selection, compatibility_report, step_evidence và provenance theo contract thực tế. Điều tra vì sao scenario mới dùng profile_only dù Survey có bundle; sửa đường truyền input này. Không tự ghép một bundle khác vào plan lịch sử chỉ vì cùng IP. Plan cũ vẫn đọc được; muốn cập nhật context phải tạo phiên bản mới hoặc có revalidation được ghi rõ. Thiếu evidence cần cho một bước thì báo blocker cụ thể, không tự đổi unknown/assumed thành verified.

2. Tạo execution preflight và preview không có side effect
Tách API kiểm tra/preview khỏi API tạo operation. Kiểm tra server-side: plan tồn tại, chưa bị xóa, hoàn tất và hợp lệ; hash/version plan; target/scope; evidence integrity và độ mới theo chính sách được giải thích; các điều kiện riêng từng bước; planner/source; Sandcat alive/trusted/platform/executor/privilege; operation chưa kết thúc có cùng paw; tham số và dependencies/payload/cleanup cần dùng.
Không dùng riêng status=completed để quyết định chạy. Phân biệt thiếu điều kiện thực thi và thiếu dữ liệu detection: thiếu telemetry không mặc nhiên chặn mọi kịch bản, nhưng phải giữ detection=unknown.
Preview hiển thị mục tiêu, thứ tự bước, ability nguồn, executor, tham số đã lọc secrets, tác động, điều kiện còn thiếu và cleanup. Context áp dụng chung cho endpoint/web và mọi nhóm hành vi, không hardcode theo SQLi.

3. Adapter ScenarioPlan → artifact CALDERA
Đọc schema và handler của phiên bản CALDERA cài tại máy trước khi chọn endpoint/payload. ScenarioPlan, Adversary, Ability và Atomic Red Team là các schema khác nhau; không POST nguyên scenario_plan.yml như một operation.
Resolve ability từ nguồn catalog/dataset đã xác minh, đối chiếu revision/hash và executor với plan. Lệnh phải xuất phát từ nguồn được kiểm chứng; không để LLM tự sinh shell để bù phần thiếu. Validate dữ liệu và tham số theo từng loại, chặn placeholder chưa resolve, tham số mở rộng target/scope và shell injection.
Đối chiếu ability hiện có trên CALDERA theo nội dung thực thi, không chỉ ID/tên. Nếu thiếu hoặc khác revision: preview báo rõ; chỉ đăng ký bản đã kiểm chứng trong pha thực thi được người dùng xác nhận. Không ghi đè ability dùng chung. Nếu cần ID riêng, lưu mapping source ID → execution ID; giữ nguyên ý nghĩa và thứ tự bước.
Tạo Adversary và Source/facts riêng theo execution khi cần, chỉ dùng tham số thuộc target/scope. Đảm bảo thứ tự thực thi/dependencies theo semantics thật của planner; không giả định atomic_ordering bảo đảm mọi tiền điều kiện. Nếu không hỗ trợ một loại bước, chặn rõ bước đó thay vì tuyên bố mọi plan đều chạy được.
Credentials/cookie phải được xử lý qua cơ chế bí mật phù hợp, không lưu giá trị vào plan, provenance, trace, facts công khai, báo cáo hoặc log command. Thiếu cơ chế cấp secret an toàn thì báo blocker thay vì nhúng tạm.

4. Tạo Operation đúng endpoint và không trùng
Sau xác nhận người dùng, xác thực lại plan hash, preview còn hiệu lực, scope, paw và điều kiện runtime. Giữ cơ chế token/origin hiện có; không tin execution_authorized hoặc target từ client. Ghi nhận xác nhận phía server gắn với plan hash, target, scope và execution ID; không sửa plan_only lịch sử thành bằng chứng đã được phép chạy.
Dùng khóa theo endpoint chia sẻ với Survey để ngăn chạy đồng thời gây đổi group hoặc xung đột. Chọn cơ chế giới hạn host_group/paw được CALDERA hỗ trợ. Nếu phải dùng group riêng, lưu group trước, đối chiếu membership đúng một paw trước dispatch và khôi phục có điều kiện; không ghi đè group đã bị bên khác đổi.
Lưu execution intent/idempotency key trước POST, rồi operation_id ngay khi nhận phản hồi. Double-click/retry/reload không được tạo operation trùng. Nếu POST timeout sau khi CALDERA có thể đã tạo operation, reconcile bằng dấu nhận dạng ổn định; không POST lại mù quáng. Nếu không thể xác định duy nhất, giữ trạng thái cần phục hồi, không tự chạy tiếp.

5. Theo dõi, dừng và phục hồi
Execution có state riêng, không ghi đè trạng thái sinh Scenario. Thiết kế state machine bao gồm kiểm tra, bị chặn, đang tạo operation, đang chạy, hoàn tất, lỗi, yêu cầu dừng và cần phục hồi; ánh xạ rõ sang CALDERA states.
Poll có timeout/backoff, response limit và giới hạn dữ liệu. Lưu trạng thái từng bước: chưa chạy, đã gửi, hoàn tất, lỗi, bị bỏ qua/chặn; đối chiếu link/ability/paw với execution đã duyệt. Lưu stderr/stdout sau lọc secrets, exit code và thời gian khi có.
Restart GUI phải có thể đọc execution record và reconcile operation_id, không tạo lại hoặc tự resume operation. Thao tác dừng phải dùng semantics API thật: pause không đồng nghĩa hủy lệnh đã giao cho Sandcat. Cleanup chỉ chạy khi có nguồn, điều kiện và phạm vi được xác minh; không tự bịa rollback.
Tách ba kết luận: trạng thái lệnh, bằng chứng hành vi thực sự xảy ra, và bằng chứng telemetry/detection. Operation finished không chứng minh mọi bước chạy hoặc SOC phát hiện.

6. GUI và artifact handoff
Dùng lại nút Thực thi: mở preview/preflight → hiển thị blocker hoặc cho xác nhận → chuyển sang theo dõi execution. Hiển thị operation_id, liên kết CALDERA theo cấu hình, tiến độ từng bước, lỗi có thể xử lý, yêu cầu dừng và kết quả. Reload vẫn theo dõi đúng execution. Tạo execution mới có chủ ý phải khác retry cùng execution.
Giữ giao diện tiếng Việt, không thêm dashboard không liên quan. Lưu artifact riêng, ví dụ execution_request.json, execution_preflight.json, execution_manifest.json, operation-summary.json và execution_result.json theo schema có version; danh sách này có thể điều chỉnh theo kiến trúc thật. Gắn scenario ID/hash, Survey run ID, evidence refs, ability revisions, target, operation ID và timestamps. Không ghi secrets hay raw response không giới hạn.

KIỂM THỬ VÀ ĐIỀU KIỆN HOÀN THÀNH

Viết test phù hợp cho: bundle v2 được giữ khi chuyển bước; sai hash/target; thiếu ability hoặc revision lệch; thiếu executor/dependency/parameter; plan completed nhưng readiness bị chặn; agent stale/untrusted/busy; double-click/concurrent requests; timeout sau tạo operation; restart/reconcile; dừng khi lệnh đã dispatch; membership sai; lọc secrets và output quá lớn. Kiểm thử nhiều nhóm hành vi bằng fixture, không chỉ SQLi.

Mock API phải phản ánh schema CALDERA đã kiểm tra từ bản cài thật. Kiểm tra UI preview/chặn/confirm/poll/reload bằng mock, không vô tình gọi endpoint execute thật. Chạy regression phù hợp cho Survey và Scenario hiện có; ghi rõ lỗi có từ trước. Có thể dùng .venv/bin/python -m unittest nếu project đang dùng unittest; chọn test runner theo mã thật, không giả định.

Chỉ restart GUI sau khi kiểm tra cả Survey, Scenario và execution đều không hoạt động; nếu đang bận thì giữ nguyên process, hoàn tất phần kiểm thử độc lập và ghi trạng thái chờ triển khai. Sau triển khai xác minh service và HTTP/API đọc, không tự chạy kịch bản thật.

Tạo CALDERA_EXECUTION_HANDOFF.md trong GUI, gồm: kiến trúc và luồng dữ liệu, API/contracts, state machine, cơ chế binding target/idempotency/recovery, file thay đổi, cấu hình, backup/rollback, lệnh test đã chạy cùng kết quả, cách dùng nút Thực thi, giới hạn thực tế và hướng dẫn kiểm thử lab sau khi người dùng duyệt. Ghi rõ phần nào mock, API đọc thật, triển khai thật và thực thi endpoint chưa kiểm chứng.

Thực hiện đến khi có bản tích hợp cụ thể có thể review và sử dụng; không chỉ trả lời thiết kế. Khi gặp thiếu thông tin chỉ chặn nhánh phụ thuộc và tiếp tục phần độc lập. Không sửa ngoài phạm vi để làm test xanh. Báo tiến độ ngắn gọn; kết thúc bằng kết quả, đường dẫn tài liệu, kiểm thử và blocker còn lại. Không tuyên bố chạy thành công trên endpoint nếu chưa có bằng chứng.
```

🎯 Target: Codex trên máy `.164`. 💡 Tập trung tích hợp nút hiện có với context đầy đủ, kiểm tra điều kiện thực thi, chống tạo operation trùng và phục hồi sau gián đoạn.
