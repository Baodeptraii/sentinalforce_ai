# Prompt sửa xác thực và nghiệm thu connector Wazuh

Gửi toàn bộ khối prompt dưới đây cho Codex trên `.164`. Agent có quyền chạy lệnh thật: đối chiếu phạm vi, đường dẫn và điều kiện dừng trước khi thực hiện. Không đính kèm secrets vào prompt.

```text
Bạn là Codex trên Ubuntu 192.168.1.164. Hãy điều tra và sửa lỗi xác thực Wazuh connector của SOC Agent, rồi nghiệm thu việc lấy alert thật đã tồn tại từ indexer về ứng dụng. Sửa trực tiếp phần cấu hình/code phía GUI trong phạm vi dưới đây, không chỉ đưa lời khuyên.

MỤC TIÊU VÀ PHẠM VI

- GUI: /home/soc/DATN/GUI. Service user: datn-survey.service, HTTP 127.0.0.1:8765.
- Được đọc/sửa connector, secret configuration phía .164, kiểm thử và tài liệu liên quan. Giữ nguyên Survey/Scenario/Execution, key/model AI, token budget và dữ liệu lịch sử ngoài phần cần sửa.
- Wazuh 192.168.100.112 chỉ được truy cập bằng API đọc/search hiện có. KHÔNG sửa user/role/password, manager, Filebeat, indexer settings, dashboard, rules/decoders, archives, retention; không SSH để thay đổi và không restart máy/dịch vụ Wazuh.
- Không chạy operation CALDERA, không gọi Gemini, không tạo traffic khai thác. Không đổi cấu hình collector .150 khi không liên quan lỗi xác thực.
- Không in password, API key, JWT, Authorization header, raw credential file hoặc response chứa secrets. Không lưu secrets vào repo/test/log/handoff. Không gửi credentials sang endpoint ngoài .112 đã cấu hình.
- Restart riêng GUI chỉ khi cần và đã xác minh không có Survey/Scenario/Execution/collection đang chạy. Thiếu quyền phía server phải báo blocker cụ thể, không tự mở rộng quyền.

BỐI CẢNH VÀ MÂU THUẪN CẦN GIẢI QUYẾT

Đọc AGENTS.md, rules.md, TELEMETRY_REPORT_AGENT_HANDOFF.md và WAZUH_SERVER_PENDING.md cùng code thật trước khi sửa. Kiểm tra các thay đổi chưa commit hoặc không có Git; backup phần sẽ sửa và bảo toàn công việc của agent khác.

Theo handoff ngày 22/11/2026:
- engine/wazuh_connector.py đã có transport chỉ đọc, identity lookup, bounded search/scroll, TLS verified_ca và chế độ lab_tofu_pinned.
- Credentials ngoài repo, thường ở ~/.config/datn-telemetry/wazuh-readonly.json với hai slot api/indexer; xác minh đường dẫn từ cấu hình thật.
- Lần thử trước trả HTTP 401 cho cả API 55000 và indexer 9200. telemetry_report.json.enabled=false.
- Collector host đã hoạt động; hiện chưa có execution record thật của controller mới. Báo cáo mẫu là MOCK.

Bằng chứng độc lập trước đó cùng ngày:
- Một truy vấn đọc từ máy quản trị tới https://192.168.100.112:9200 bằng tài khoản dashboard admin trong host.txt đã THÀNH CÔNG: GET /_cluster/health, GET /_cat/indices và search wazuh-alerts-*.
- Indexer có alert mới của agent 009/victim_win10 tại 192.168.1.150 và 010/victim_ubuntu tại 192.168.1.164.
- Chưa có bằng chứng tài khoản dashboard đó đăng nhập được Wazuh API 55000.
- Tài khoản SSH OS của .112 là một credential khác. Không dùng tài khoản SSH để suy ra API/indexer login.
- Manager đang logall_json=no, Filebeat archives.enabled=true, chưa có wazuh-archives-*; hiện chỉ có thể nghiệm thu alerts_only.

Vì vậy không được kết luận “phải tạo tài khoản mới” chỉ từ lần thử 401. Trước hết đối chiếu credential source, cách parse host.txt, endpoint, HTTP auth, biến môi trường và file secrets thực tế. Bằng chứng cũ không bảo đảm credentials hiện tại chưa thay đổi; xác minh lại có kiểm soát.

1. ĐIỀU TRA CẤU HÌNH VÀ AUTH

Tìm host.txt trong phạm vi project hoặc vị trí được chỉ định; chỉ trích đúng bản ghi Wazuh dashboard/API nếu có. Không đọc/in toàn bộ file. Nếu có nhiều bản ghi hoặc format mơ hồ, báo đường dẫn và loại credential cần chọn, không đoán mật khẩu hoặc thử danh sách tài khoản.

Kiểm tra an toàn:
- File secret đang được process GUI/collector nạp có đúng đường dẫn, owner, mode 0600 và encoding không.
- Hai slot api/indexer có bị điền cùng tài khoản SSH, đọc sai dòng, nhầm password hoặc bị env override không.
- Chỉ báo present/missing/match/mismatch, không in giá trị hoặc fingerprint mật khẩu.
- Chuỗi username/password không bị strip/escape/truncate tùy tiện; bảo toàn ký tự hợp lệ. Nếu cần parser, viết test bằng secrets giả có khoảng trắng/ký tự đặc biệt, không dùng giá trị thật trong fixture.
- Endpoint thực tế, proxy, redirect, TLS mode và Authorization scheme. Không để redirect làm lộ credentials.

Phân biệt:
- TLS failure trước HTTP: chưa có kết luận về auth.
- HTTP 401: authentication không thành công.
- HTTP 403: có thể thiếu quyền cho endpoint/index cụ thể, không mặc định sai password.
- HTTP 404 hoặc index không tồn tại: không biến thành lỗi auth.

Xác minh indexer riêng bằng tài khoản đã có bằng chứng dùng được, tối đa một lần cho cấu hình đã kiểm tra; chỉ lặp khi đã xác định và sửa một nguyên nhân cụ thể. Không brute force hoặc thử mật khẩu mặc định.

API 55000: dùng credential đúng cho Wazuh API nếu có. Không giả định admin dashboard hoặc tuyen SSH dùng được. Token chỉ giữ trong memory với cơ chế hết hạn phù hợp; không lưu JWT vào artifact.

2. SỬA SECRET CONFIG PHÍA .164

Nếu xác định indexer slot đang sai, cập nhật bằng credential dashboard/indexer đúng từ nguồn được người dùng cung cấp. Dùng thao tác file an toàn, mode 0600, ngoài repo; không nhúng secret vào source hoặc lệnh hiển thị. Không thay tài khoản phía Wazuh.

Giữ TLS verified_ca làm mặc định. Nếu lab_tofu_pinned đã được người dùng chấp thuận trước đó thì chỉ giữ đúng endpoint/pin hiện có, kiểm tra pin trước khi gửi auth. Không tự cập nhật pin khi cert đổi, không tự chuyển verify=False. Có CA chain đáng tin thì cấu hình phía client, không sao chép server private key. Ghi rõ mức xác minh TLS trong health/report.

Không tạo credential mới hoặc tuyên bố đã sửa xác thực nếu mới chỉ so sánh chuỗi. Phải có response thật chứng minh endpoint đọc hoạt động.

3. KHÔNG ĐỂ THIẾU API HEALTH CHẶN MỌI TRUY VẤN INDEXER

Đọc kiến trúc hiện tại và xử lý dependency hợp lý:
- Nếu API 55000 và indexer đều dùng được: dùng API xác minh identity/status, indexer đọc alert/archive theo quyền thực tế.
- Nếu indexer dùng được nhưng API thiếu credential/quyền: cho phép health/diagnostic và truy vấn alert hữu hạn trong chế độ degraded, không tự tuyên bố agent alive/healthy.
- Việc tạo báo cáo gắn execution vẫn phải có identity binding đáng tin. Chỉ dùng binding đã lưu được xác minh hoặc dữ liệu indexer đủ đối chiếu ID/name/IP và nguồn bằng chứng phù hợp. Historical alert không chứng minh IP vẫn thuộc cùng agent hiện tại.
- Nếu identity không thể xác định duy nhất, trả identity_unverified/ambiguous và chặn correlation chắc chắn; vẫn có thể hiển thị diagnostic rằng indexer authenticated và có dữ liệu. Không hardcode 009/010 để bỏ qua kiểm tra.
- Không bỏ global enabled=false chỉ để UI trông hoạt động. Bật connector sau khi capability/identity requirements của chế độ được xác minh; hiển thị riêng khả năng indexer search, API health và archives.

4. KIỂM CHỨNG VERSION, SEARCH VÀ GIỚI HẠN COVERAGE

Sau khi xác thực được, đọc version/distribution response thật và kiểm tra API search/scroll hiện dùng. Không từ chối chỉ vì version string tương thích Elasticsearch nếu distribution thực tế là OpenSearch; cũng không tự giả định mọi phiên bản đều hỗ trợ như nhau.

Giữ query allowlist, agent/target/time filter, pagination, response/page/event/deadline limit, dedup và redaction. GET/poll/export GUI không tự gọi Wazuh hoặc chạy operation. Manual refresh có cooldown và idempotency.

Không sửa Wazuh archives. Nếu index không có, ghi alerts_only; nếu không đủ quyền kiểm tra index existence, ghi coverage unknown/access_denied, không khẳng định archive vắng mặt. Zero result không phải chứng minh không có telemetry hoặc SOC bỏ sót.

5. NGHIỆM THU BẰNG DỮ LIỆU THẬT ĐÃ TỒN TẠI

Chạy một truy vấn đọc hữu hạn, ưu tiên 15–60 phút gần nhất của .150/.164; nếu không có thì mở rộng có ghi nhận, tối đa 24 giờ cho diagnostic. Không query toàn bộ lịch sử hoặc toàn bộ agents để làm mẫu.

Lưu bằng chứng đã lọc: timestamp kiểm tra, endpoint, HTTP result, distribution/version, agent identity được quan sát, query window, document count và một số document/index IDs + channel/eventID/rule ID/timestamps. Không lưu raw commandLine/scriptBlock/full_log hoặc credentials.

Hiện có thể không có execution record thật: KHÔNG tạo execution giả, sửa job cũ hoặc gắn alert lịch sử vào scenario chỉ vì cùng host/time. Tạo artifact “LIVE CONNECTIVITY/INGEST CHECK — NOT AN EXECUTION REPORT” riêng để chứng minh đọc được alert thật. Mẫu execution report MOCK giữ nhãn cũ.

Nếu có execution thật phù hợp thì chỉ refresh telemetry read-only, giữ điều kiện correlation, không dispatch/resume CALDERA. Không nâng behavior_status=observed chỉ vì thấy event hoặc exit 0. Typed behavior verifier là nhiệm vụ tiếp theo, không tự viết verifier chung khẳng định mọi hành vi.

6. TEST VÀ TRIỂN KHAI

Viết/chạy regression liên quan:
- Credential parsing bằng dữ liệu giả, api/indexer slots độc lập, config/env precedence và không rò secrets.
- 401/403/TLS/pin mismatch được phân biệt; pin kiểm tra trước auth; không tự retry credential.
- Indexer OK/API unavailable, identity ambiguity/drift, archives missing/forbidden, zero alerts.
- Product/version detection, bounded search/scroll, dedup và giới hạn dữ liệu.
- Diagnostic không tạo execution/report giả, không gọi Gemini hoặc API ghi Wazuh/CALDERA.
- UI hiển thị capability/degraded/alerts_only và hướng xử lý, không báo hệ thống đã full coverage.

Dùng wrapper cách ly tests hiện có để fixture không ghi audit thật. Đọc handoff trước khi chọn lệnh; dự kiến GUI có test_execution_telemetry, tests Node và tools/test_telemetry_regression.py. Chỉ báo các test thực sự đã chạy.

Backup cấu hình/code cần sửa. Nếu chỉ thay secret có thể nạp lại mà không restart thì ưu tiên cơ chế hiện có; nếu cần restart, kiểm tra idle toàn bộ jobs rồi restart riêng GUI và kiểm tra API/asset. Không restart Wazuh hoặc collector Windows vì lỗi auth connector.

ĐẦU RA VÀ ĐIỀU KIỆN HOÀN THÀNH

Tạo WAZUH_CONNECTOR_AUTH_FIX_HANDOFF.md trong GUI:
- Nguyên nhân 401 đã chứng minh; phân biệt điều chưa xác định.
- File thay đổi và rollback, không chứa secret.
- Trạng thái độc lập của API 55000, indexer 9200, TLS, identity lookup, alerts, archives.
- Bằng chứng truy vấn alert thật, đường dẫn diagnostic artifact, mức coverage.
- Tests và kết quả triển khai; nhãn MOCK/live giữ rõ ràng.
- Blocker server còn lại, gồm archives/permissions nếu có; không áp dụng thay đổi server.

Cập nhật TELEMETRY_REPORT_AGENT_HANDOFF.md và WAZUH_SERVER_PENDING.md để bỏ thông tin 401/disabled đã lỗi thời nếu đã sửa; giữ lịch sử ngắn gọn và ngày kiểm chứng mới. Không xóa giới hạn chưa được giải quyết.

Hoàn thành đến khi indexer auth và truy vấn có bằng chứng, hoặc nêu rõ credential/quyền cụ thể còn thiếu sau khi đã xử lý hết phần độc lập. Không yêu cầu người dùng gửi password vào chat; nếu thiếu, chỉ rõ secret slot/path cần cập nhật an toàn.
```

🎯 Target: Codex trên `.164`. 💡 Tập trung xử lý mâu thuẫn xác thực, kiểm chứng dữ liệu thật và giữ nguyên ranh giới không sửa Wazuh server.
