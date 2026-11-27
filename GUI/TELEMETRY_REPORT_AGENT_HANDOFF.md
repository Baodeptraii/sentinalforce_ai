> **Cập nhật 24/11/2026:** Đã có validation/expected contract riêng và báo cáo Expected/Reality. Thiếu API55000 không còn chặn đọc indexer; thiếu identity lịch sử vẫn chỉ trả candidates. GUI dùng Validate → xác nhận. Các kết quả test/trạng thái triển khai bên dưới là lịch sử; xem [VALIDATE_EXECUTE_REPORT_HANDOFF.md](VALIDATE_EXECUTE_REPORT_HANDOFF.md) cho bản hiện hành. Không mở quyền chạy mọi ability và không xác nhận detection từ exit0.

> **Cập nhật 22/11/2026 16:29 UTC:** Đã sửa credential parser/slot indexer và xác thực HTTP 200, search được 50 alert thật trong 60 phút, archives absent → alerts_only. Connector hiện enabled cho indexer diagnostic; API credential/identity execution vẫn chưa xác minh. Các đoạn 401/disabled bên dưới là lịch sử trước sửa, không phải trạng thái hiện tại. Xem [WAZUH_CONNECTOR_AUTH_FIX_HANDOFF.md](WAZUH_CONNECTOR_AUTH_FIX_HANDOFF.md) và `review/wazuh-auth-fix/live-diagnostic.json`. Không có execution thật được tạo hoặc gắn alert lịch sử.

# Tổng hợp triển khai telemetry và báo cáo SOC Agent

Cập nhật: 22/11/2026. Phạm vi: GUI `.164`, collector trên Windows `.150`, truy vấn đọc Wazuh `.112`.

## 1. Kết quả và vấn đề còn tồn tại

**Đã sửa code, triển khai collector trên hai host, thêm báo cáo JSON/Markdown và giao diện Telemetry/Báo cáo. Chưa nghiệm thu được luồng tới indexer Wazuh.**

- Windows: GET vô hại tới DVWA đã xuất hiện trong Apache access log và JSONL chuẩn hóa. Wazuh Agent đã mở JSONL, chạy lại và connected, ACK mới, buffer 0.
- Ubuntu: audit JSONL riêng đã được thêm vào Wazuh Agent. Agent đã mở file, connected, ACK mới, buffer 0. Sau rotation, kiểm tra `/proc` xác nhận logcollector giữ inode của file hiện tại.
- GUI: service đã được restart sau khi kiểm tra không có Survey/Scenario/Execution hoạt động; backend và phần giao diện mới hoạt động.
- API Wazuh và indexer: kiểm chứng CA hệ thống ban đầu thất bại. Sau khi người dùng cho phép dùng thông tin lab, đã ghim chứng chỉ và thử **một lần xác thực cho mỗi API** bằng tài khoản có trong `host.txt`. **Cả hai trả HTTP 401**. Không thử lặp mật khẩu, không sửa tài khoản/role/server.
- Vì vậy `telemetry_report.json.enabled=false`. Collector vẫn chạy; ứng dụng báo giới hạn thay vì tự coi không có alert là không phát hiện.
- `/api/executions` hiện có **0 record** của execution controller mới. Không chạy operation thật để tạo dữ liệu. Báo cáo mẫu mang nhãn **MOCK**; chưa có báo cáo execution thật được đối chiếu Wazuh.

`host.txt` là thông tin vào host, không tự chứng minh tài khoản đó có quyền Wazuh API/indexer. Cần thông tin xác thực API phù hợp hoặc quản trị viên cấu hình quyền đọc ngoài nhiệm vụ này.

## 2. Những gì đã làm

### Luồng dữ liệu

```text
Survey / Scenario / Execution transitions (.164)
    → audit/events.jsonl [soc_audit_v1, metadata allowlist]
    → Wazuh Agent Ubuntu ─────────────────────────┐
                                                 │
Apache access/error (.150)                       │
    → scheduled metadata collector               │
    → C:\ProgramData\SOC-Agent\telemetry\web.jsonl │
    → Wazuh Agent Windows ────────────────────────┤
                                                 ▼
                                    Wazuh manager/indexer .112
                                    [không sửa phía server]
                                                 │
                        API identity + indexer bounded search, chỉ đọc
                                                 ▼
                       normalization → correlation → report JSON/Markdown
                                                 ▼
                                   GUI Telemetry / Báo cáo
```

Wazuh Agent mở file/ACK tổng không chứng minh từng dòng đã được manager phân tích hoặc lưu index. Chưa có bằng chứng marker ở indexer.

### Ubuntu `.164`

- Thêm localfile JSON cho `/home/soc/DATN/GUI/audit/events.jsonl`; giữ các nguồn hiện có.
- Audit ghi append-only, từng event có version, UUID, UTC, host/component, IDs run/scenario/execution/operation/link/ability, target/paw, phase/status và refs/hash khi có. ID không áp dụng giữ null.
- Survey ghi khi đổi stage/status; Scenario ghi phase/save/error; Execution ghi state/link transition. Không sao chép prompt, source command, stdout/stderr, header hoặc toàn bộ CALDERA response vào audit.
- CALDERA metadata lấy từ controller đang có; không tạo agent/operation mới để vận chuyển log.
- Audit file `0640`, thư mục `0750`, khóa thread + `flock`, chống symlink, flush/fsync; rename khi đạt 5 MB. Không truncate file cũ.
- Retention cấu hình 30 ngày, xóa mặc định tắt. `tools/telemetry_retention.py` mặc định dry-run, chỉ xét file audit đã rotate đúng mẫu tên; không đụng executions/outputs/scenario history hoặc log nguồn.
- Đã kiểm tra journald có event SSH; không thêm auth.log để tránh thu trùng nguồn này. Giữ nguyên journald và nguồn Linux đã có.
- Suricata `eve.json` đo được **2.022.651.223 byte**, chưa thấy `/etc/logrotate.d/suricata`. Chưa sửa rotation nguồn này hoặc restart Suricata. Cần kiểm tra cơ chế rotation khác, reopen-log, disk và retention trước khi áp dụng.
- Linux Apache access/lab_access đo được 0 byte; giữ cấu hình đã có và ghi chưa có bằng chứng request mới. Có logrotate Apache.

### Windows `.150`

- Xác minh effective Apache config bằng `httpd.exe -t -D DUMP_RUN_CFG`, Include/LogFormat/CustomLog. ErrorLog là `C:\xampp\apache\logs\error.log`; CustomLog combined là `logs/access.log`.
- GET `/dvwa/?soc_probe=<UUID>` vô hại trả 200 và marker xuất hiện tại nguồn. HTTP 200 chỉ chứng minh request này tới được ứng dụng, không chứng minh hành vi tấn công.
- Quyền SYSTEM đọc file được xác minh; WazuhSvc và Apache chạy LocalSystem.
- Không forward raw Apache combined/error mới vì request/query/referrer có thể chứa credentials. Dùng collector projection JSONL: source path, hash dòng, method/status hoặc AH error code, UUID marker kiểm thử. Không xuất query/header/body/raw error message.
- Collector chạy Scheduled Task `SOC-Web-Telemetry-v1`, SYSTEM, mỗi phút, timeout 45 giây, IgnoreNew. Script và dữ liệu dưới `C:\ProgramData\SOC-Agent\telemetry`, ACL chỉ SYSTEM/Administrators.
- Cursor lưu byte offset + source creation identity; lần đầu bắt đầu EOF, không backfill. Xử lý partial line, truncate/replacement, output rotation; mỗi lượt đọc tối đa 1 MiB/nguồn. Dòng đơn vượt giới hạn dừng có health failure, không âm thầm bỏ qua.
- Error continuation/multiline được ghi từng dòng hash; **không tuyên bố tái dựng đầy đủ stacktrace**. Full source giữ ở host.
- Event ID của JSONL được băm từ host/source/source identity/byte offset/hash. Khi crash giữa append và cursor save, có thể phát lại; ID ổn định hỗ trợ dedup, không hứa exactly-once.
- Rotate JSONL tại 5 MB. Script có `MaxBytes`, `RetentionDays`, `PruneArchives`; mặc định không prune. Không xóa lịch sử trong lượt này.
- Hợp nhất Security: bỏ query phụ 4625/4688/4776 chỉ sau khi xác minh query chính đã bao phủ ba ID, giữ nguyên union.
- Sysmon collection từ 1,3,10,11,13 thành **1,2,3,5,10,11,12,13,14,22,23,26**. **Không đổi generation config Sysmon**.
- Sysmon generation hiện là cấu hình webflood có filter Process/Network/FileCreate/Registry/DNS. Chưa chứng minh tạo log mọi thao tác trong `C:\SOC-Lab`, file delete hoặc mọi sửa file. Thêm subscription không làm Sysmon tự sinh event bị lọc.
- Giữ PowerShell 4104; chưa bật 4103/ModuleLogging hoặc audit policy rộng.
- Thêm Defender Operational subscription **1116/1117/5007**; không thử malware, không tắt AV/active response.
- TaskScheduler Operational đang disabled, chưa bật. PHP/MySQL general query log không bật; chưa có nguồn error/audit riêng được chứng minh cần thiết.
- Binary Wazuh Windows hiện tại **không hỗ trợ `-t`**, trả `Unknown option: -t`. Không coi exit 1 đó là validation đạt. Đã dùng XML parser và EventLogReader kiểm tra XPath của từng subscription, rồi kiểm tra service/collector sau restart. Hai thông báo Unknown option trong log do lần kiểm tra này, không phải lỗi cấu hình mới.

## 3. Connector, correlation và contract

### Connector chỉ đọc

`engine/wazuh_connector.py` chỉ cho phép:

- Wazuh API: GET `/security/user/authenticate?raw=true`, GET `/agents?limit=500&select=id,name,ip,status,lastKeepAlive`.
- Indexer: GET `/`, GET danh sách `wazuh-archives-*`, POST search `wazuh-alerts-*`/`wazuh-archives-*`, POST `/_search/scroll`.
- Không cho API thay cấu hình, delete/index/update documents, operation hoặc shell. Redirect và proxy môi trường bị từ chối/tắt.
- Credentials có hai slot `api` và `indexer`, file ngoài repo, owner hiện tại và mode `0600`; không giả định dashboard/SSH login dùng được cho cả hai.
- Resolve agent theo IP đã ghim, chỉ chấp nhận đúng một identity; giữ name/id/ip/status. Không hardcode 009/010. Directory bị cắt hoặc mapping mơ hồ thì dừng.
- Chỉ hỗ trợ cơ chế scroll khi indexer tự khai báo OpenSearch; phiên bản live **chưa xác minh được do 401**. Snapshot manager 4.12.0 không được dùng thay bằng chứng version indexer hiện tại.
- Scroll `_doc` snapshot TTL 1 phút, tối đa 5 pages × 200 rows, 1.000 events, 2 MB/response, timeout 6 giây, deadline collection 45 giây. Đọc response theo chunk và kiểm tra deadline/size.
- Query bắt buộc agent ID + agent IP + execution time window. Archives absent/403 được phân biệt; khi không đọc archives dùng `alerts_only`, không coi zero alerts là zero logs.
- Một lần thử cho mỗi query; không retry transport/auth vô hạn. Refresh có cooldown 30 giây và khóa tiến trình. Có một lần cuối sau ingest grace khi lượt đầu thành công và đang chờ ingest; không tự retry lỗi xác thực.

### TLS và kết quả xác thực thật

Mặc định code dùng `verified_ca`, HTTPS với kiểm chứng chain và hostname. Nếu thiếu CA hoặc creds, connector không hoạt động.

Sau trả lời cho phép lab của người dùng, cấu hình hiện tại có `tls_mode=lab_tofu_pinned`, fingerprint DER SHA-256 riêng mỗi endpoint. Kết nối kiểm tra pin **trước khi gửi HTTP Authorization**. Chứng chỉ đổi sẽ fail; không tự cập nhật pin. Đây là **TOFU trong lab, chưa kiểm chứng CA độc lập**, được ghi trong state/report; không áp dụng cho endpoint khác.

Thử đọc thực tế: API 55000 → 401, indexer 9200 → 401. File `review/telemetry-report-20261122/wazuh-readonly-probe.json` lưu kết quả đã lọc. Không lưu JWT/password trong artifact.

### Window, cursor và restart

- Start: confirmed_at hoặc created_at; lookback 30 giây + clock skew allowance 10 giây.
- End: execution updated_at + ingest grace 120 giây + skew 10 giây.
- Max window 3.600 giây; quá ngân sách thì `execution_window_over_budget`, không thu hẹp ngầm.
- Tự thu sau terminal transition mới có operation_id. Refresh trong execution chưa kết thúc trả `waiting_execution_end`, không dispatch lại.
- Khóa thread + file lock, cooldown/cursor persist theo execution. Scroll cursor phía server hết hạn sau 1 phút; sau restart đọc lại **window hữu hạn đã lưu**, dedup theo index/document ID; không quét toàn index.
- Không cố giữ scroll ID đã hết hạn. State lưu window, seen doc IDs, counts, truncated, lỗi và checkpoint_reused.
- Startup chỉ khôi phục collection journal còn collecting/waiting_ingest; không tạo/resume CALDERA operation.
- Report ghi ingest pending. Chưa có timestamp ingest indexer thực tế; window/grace không chứng minh delay thực tế hoặc pipeline đầy đủ.

### Quy tắc tương quan

- Host + time: chỉ candidate, ambiguous, không tính detection.
- Execution ID đúng và operation không xung đột; hoặc operation ID đúng khi không có execution ID xung đột: confidence high.
- Link ID khớp thêm step_index.
- Request marker phải có trong danh sách marker đã đăng ký của execution; không lấy UUID bất kỳ trong URL làm bằng chứng.
- PID từ CALDERA link chỉ dùng khi exact PID khớp, có dispatch/finish interval (±5 giây), duy nhất một bước, identity đúng và không có execution khác cùng target chồng window: confidence medium. Không suy diễn cả chuỗi tiến trình/hành vi từ PID.
- Marker kiểm thử tách riêng, không cộng vào bằng chứng detection của scenario thật.
- Giữ document/index IDs, rule ID/level/description đã lọc + hash, channel/event ID/location, timestamps, matched_fields/method/confidence/ambiguous. Không lưu commandLine/scriptBlock/raw response lớn.
- Backend kiểm tra lại agent identity trên từng hit và refs/hash artifact local trước khi đưa vào báo cáo.

### Contract và API GUI

Schema mới: `schemas/execution-telemetry-report-v1.schema.json`, version `execution_telemetry_report_v1`.

- `command_status`: dispatched/completed/failed/unknown. Adapter legacy success → completed, error → failed, incomplete → dispatched; not_run/stopped/khác → unknown. Giá trị gốc lưu `legacy_command_status`; execution_result.json không bị viết lại để đổi enum.
- `behavior_status`: observed/not_verified/unknown. Triển khai hiện giữ **unknown** vì chưa có verifier theo từng hành vi; exit 0, PID hoặc HTTP 200 không tự nâng thành observed.
- `telemetry_status`: observed/partial/unavailable/unknown; bằng chứng hiện chỉ đủ partial khi có event tương quan, không tuyên bố coverage đầy đủ.
- `detection_status`: matched_alert/unknown/not_evaluable. Không sinh missed_detection tự động.

Routes:

```text
GET  /api/executions/<id>/telemetry
POST /api/executions/<id>/telemetry/refresh
GET  /api/executions/<id>/telemetry/report.json
GET  /api/executions/<id>/telemetry/report.md
```

GET/poll/export chỉ đọc cached/local projection, không gọi Wazuh/LLM/CALDERA. POST refresh dùng CSRF/Origin checks hiện có. Download chỉ hai tên cố định, ID 32 hex, chống path traversal/symlink. Service vẫn bind loopback, không mở webhook/public listener; UI chèn log bằng textContent, Markdown escape nội dung động.

Artifacts mới tách riêng tại `telemetry_reports/<execution-id>/`: report.json, report.md, telemetry_state.json, events.json, lock. Mode file 0600, thư mục từng execution 0700. Không ghi đè checkpoint/output gốc.

GUI: mở execution → mục **Telemetry / Báo cáo** → **Thu thập / làm mới log** → xem phase/status/mode/counts/lỗi → tải JSON hoặc Markdown. Reload/poll không tự thực thi. Trong thời gian execution chưa kết thúc cần chờ; khi 401 cần sửa cấu hình/quyền API, không bổ sung thông tin kịch bản giả hoặc chạy lại operation.

## 4. Bảng nghiệm thu theo nguồn

PASS ở một chặng không nâng toàn tuyến thành PASS. Chi tiết snapshot: `telemetry_host_inventory.json`.

| Nguồn | Source event | Collector | Manager/indexer | Correlation | Report | Toàn tuyến |
|---|---|---|---|---|---|---|
| Windows Apache access | PASS: GET UUID | PASS: JSONL + Wazuh mở file | BLOCKED: API 401 | NOT_TESTED live; PASS mock marker | PASS mock | PARTIAL |
| Windows Apache error | PARTIAL: effective path/file có dữ liệu cũ | PASS fixture multiline/hash; configured live | BLOCKED | NOT_TESTED | PASS mock | PARTIAL |
| Windows Security | PASS: EventLogReader query đọc hợp lệ | PASS cấu hình union/agent; chưa chứng minh từng event forward | BLOCKED | PASS mock PID; live chưa test | PASS mock | PARTIAL |
| Windows Sysmon | PARTIAL: channel/config hiện hữu; generation có filter | PASS XPath/subscription | BLOCKED | PASS mock process; live chưa test | PASS mock | PARTIAL |
| Windows PowerShell | PARTIAL: channel có record, giữ 4104 | PASS XPath; agent chạy | BLOCKED | NOT_TESTED live | PASS mock | PARTIAL |
| Windows Defender | PARTIAL: channel có record cũ | PASS XPath subscription mới | BLOCKED | NOT_TESTED live | PASS mock | PARTIAL |
| TaskScheduler | NOT_TESTED / disabled | NOT_TESTED | BLOCKED | NOT_TESTED | unknown | NOT_TESTED |
| PHP/MySQL error/audit riêng | NOT_TESTED | NOT_TESTED | BLOCKED | NOT_TESTED | unknown | NOT_TESTED |
| Ubuntu SOC audit | PASS marker JSONL | PASS Wazuh mở file/inode sau rotate | BLOCKED | PASS mock IDs; live chưa test | PASS mock | PARTIAL |
| Ubuntu SSH/journald | PASS có event SSH | PARTIAL: cấu hình giữ nguyên | BLOCKED | NOT_TESTED live | coverage snapshot | PARTIAL |
| Ubuntu Suricata | PARTIAL: eve.json ~2 GB | PARTIAL: nguồn hiện có; rotation chưa xác minh | BLOCKED | NOT_TESTED live | coverage snapshot | PARTIAL |
| Ubuntu Apache | NOT_TESTED event mới; access 0 byte | PARTIAL: configured/logrotate có sẵn | BLOCKED | NOT_TESTED live | unknown | PARTIAL |
| Execution thật | NOT_TESTED: hiện 0 controller record | Hook đã tích hợp; PASS mock | BLOCKED | PASS offline/mock | JSON schema + MD PASS mock | NOT_TESTED end-to-end |

## 5. Kiểm thử và triển khai đã thực hiện

- **22 tests telemetry mới PASS**: audit append/rotation, metadata allowlist, permission/symlink failure; host-time không là proof; endpoint/web; exact IDs/conflict/test marker; registered marker; PID uniqueness/overlap; agent mapping; window oversized; pagination/archive 403; dedup late event/restart; 401/403/timeout/TLS/response limit; pin trước HTTP auth; resume collection không dispatch; prerequisites/unknown/provenance; HTTP export/CSRF/refresh không run operation.
- **143 regression Python GUI PASS**, gồm Survey/Scenario/Execution/token budget. Regression dùng temporary audit/report roots và mock enqueue để không tạo audit hoặc gọi API từ fixture test.
- **31 Node tests PASS**, gồm reload/export/refresh chỉ dùng telemetry endpoint và textContent cho nội dung không tin cậy.
- **53 Scenario runtime tests liên quan PASS**: gemini_runtime, generation_contract, token_budget, context_requirements. Không sửa runtime trong nhiệm vụ này, không gọi Gemini thật.
- JSON schema validate báo cáo fixture PASS. `sample-report-MOCK.json/.md` có nhãn offline fixture, không phải execution thật.
- Windows fixture chạy thật trong thư mục test riêng: parse script, redaction, marker, dedup, partial line, completion, output rotation, source replacement đều true; live collector health ok. Không tạo payload tấn công.
- Ubuntu native validation `wazuh-logcollector -t` và `wazuh-agentd -t` đều exit 0 trước restart. Windows dùng XML + XPath, không giả vờ `-t` được hỗ trợ.
- GUI restart khi idle; backend HTTP và DOM section mới kiểm tra đạt. Không có execution thật để kiểm chứng export live bằng dữ liệu thật; HTTP mock/export đã test.
- SHA đối chiếu **928 file lịch sử/config/checkpoint/output được bảo vệ: 0 file đổi**. Không đổi key/model, không rebuild RAG, không chạy CALDERA operation, không thay firewall/server Wazuh.

Một số lần chạy test ban đầu thất bại do mock wrapper che chính hàm enqueue cần test, tên module test không tồn tại, và lỗi fixture symlink/MagicMock; đã chỉnh cách chạy/fixture và code kiểm tra symlink, chạy lại các nhóm nêu trên đạt. Không quy chúng thành lỗi hệ thống cũ hoặc tuyên bố một full-suite chưa chạy.

Lệnh tái kiểm tra chính:

```bash
cd /home/soc/DATN/GUI
PYTHONPATH=tests:. .venv/bin/python -B -m unittest test_execution_telemetry -q
node --test tests/*.test.cjs
.venv/bin/python -B tools/telemetry_retention.py  # dry-run, không xóa

cd /home/soc/build_scenario_agent
PYTHONPATH=tests:. .venv/bin/python -B -m unittest test_gemini_runtime test_generation_contract test_token_budget test_context_requirements -q
```

Không chạy unittest toàn GUI trực tiếp với audit root thật nếu muốn tránh fixture ghi audit metadata. Wrapper cách ly regression lưu tại `tools/test_telemetry_regression.py`.

## 6. File thay đổi

Code mới:

- `engine/audit_stream.py`: stream metadata append-only.
- `engine/wazuh_connector.py`: read-only transport, identity, TLS, bounded search/scroll.
- `engine/execution_telemetry.py`: collection journal, correlation, report và adapter lịch sử.
- `deployment/windows-web-collector.ps1`: collector metadata Windows.
- `tools/telemetry_host_admin.py`: helper triển khai qua OpenSSH/sudo; đọc secret file ngoài repo, không chứa mật khẩu.
- `tools/telemetry_retention.py`: dry-run/explicit retention của audit đã rotate.
- `tools/test_telemetry_regression.py`: wrapper cách ly regression cũ.
- `tests/test_execution_telemetry.py`, `schemas/execution-telemetry-report-v1.schema.json`.
- `telemetry_report.json`, `telemetry_host_inventory.json`.

Code tích hợp sửa: `app.py`, `engine/scenario_execution.py`, `engine/scenario_worker.py`, `static/index.html`, `static/scenario-execution.js`, `tests/scenario-ui.test.cjs`.

Không có repository Git tại GUI; review bằng backup/file list và checksum lịch sử.

Không sửa contract `telemetry_evidence_v1` Survey cũ, config/key/model/token-budget files. `host.txt` chỉ siết quyền thành 0600, không đổi nội dung.

## 7. Backup, secrets và rollback

- Backup code trước sửa: `review/telemetry-report-20261122/backup/`.
- Ubuntu config backup: `/var/ossec/etc/ossec.conf.soc-telemetry-20261122T154920.bak`, mode 0600.
- Windows config backup: `C:\Program Files (x86)\ossec-agent\ossec.conf.soc-telemetry-20261122T154858.bak`.
- Windows collector có backup phiên bản trước cập nhật ngay trong thư mục telemetry; đường dẫn/hash cuối lưu trong `windows-collector-tests.json`.
- `.config/datn-telemetry` ngoài repo mode 0700; credential JSON mode 0600. Không đưa giá trị secrets vào tài liệu. `windows.json`/`local.json` phục vụ quản trị host; `wazuh-readonly.json` hai slot riêng hiện chứa account đã thử nhưng **không xác thực được**, cần thay bằng API credentials đúng.
- SSH Windows dùng known_hosts đã ghim. Lần đầu TOFU trong lab, chưa xác minh fingerprint độc lập; sau đó StrictHostKeyChecking=yes.

Rollback chỉ khi idle:

1. Giữ `telemetry_report.json.enabled=false`; dừng/đợi collection worker. Không xóa audit/reports/lịch sử.
2. Restore đúng những file tích hợp từ backup (backup đã bao gồm bản token optimization trước nhiệm vụ này); giữ file mới trên đĩa để review. Restart GUI khi idle.
3. Ubuntu: restore backup ossec.conf có quyền root, chạy hai lệnh native validation, restart riêng Wazuh Agent, kiểm tra ACK/buffer.
4. Windows: restore backup ossec.conf, validate XML/XPath, unregister **chỉ** task `SOC-Web-Telemetry-v1`, restart riêng WazuhSvc. Giữ JSONL/source/backup. Apache không bị sửa/restart trong nhiệm vụ này.
5. Không rollback/chỉnh bất kỳ cấu hình nào trên `.112`: chưa có thay đổi server.

## 8. Những gì còn thiếu và thứ tự làm tiếp

1. **Ưu tiên cao: cấp đúng credentials đọc cho Wazuh API và indexer.** Không dùng lại account SSH với giả định sẽ được. Xác minh từng API độc lập; không ghi password trong chat/log. Cập nhật file secret ngoài repo bằng editor bảo mật.
2. Cung cấp CA chain tin cậy cho cả hai endpoint và chuyển `tls_mode` về `verified_ca` khi có thể. Pin hiện là lựa chọn lab rõ ràng, không phải CA verification.
3. Sau khi auth được: kiểm tra version/agent identity/archives bằng API đọc; bật connector có kiểm soát; query một marker UUID trong window hẹp. Nếu archives tắt và marker không tạo alert thì ghi **không quan sát được qua indexer**, không thêm rule để làm xanh.
4. Phần server/archives/retention/rules chưa triển khai: xem `WAZUH_SERVER_PENDING.md`; cần quyền riêng và đánh giá ảnh hưởng toàn bộ agents.
5. Định nghĩa verifier typed cho từng hành vi endpoint/web trước khi cho behavior_status=observed. Kịch bản nhiều hành vi cần bằng chứng theo từng bước; không suy từ command success.
6. Kiểm thử end-to-end một execution hợp lệ có explicit approval, rồi đối chiếu process/link/request marker thật. **Nhiệm vụ hiện tại không chạy operation này.**
7. Rà generation Sysmon/audit policy theo hành vi thật: SOC-Lab file create/delete/timestamp/content modification có thể chưa sinh event với filter hiện tại. Đo volume trên test giới hạn trước khi mở rộng. TaskScheduler/PHP/MySQL chỉ bật khi cần và có tiêu chí kiểm tra.
8. Rà Suricata rotation/disk/reopen-log; kiểm tra thêm raw Linux web logging có dữ liệu nhạy cảm trước khi mở rộng. Không tự rotate/xóa nguồn cũ ngay.
9. Đo volume/throughput dài hơn, disk growth, deadline/window cho execution dài; hiện mới kiểm thử giới hạn, chưa load test dài ngày hoặc production-hardening.

**Không có kết luận “thu toàn bộ log”, “đã phát hiện kịch bản” hoặc “missed detection”.** Kết quả hiện tại là bản tích hợp host/app có thể review, đã triển khai phần trong quyền, cùng blocker xác thực Wazuh và các bước nghiệm thu còn lại được ghi rõ.
