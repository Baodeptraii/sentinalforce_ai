> **Cập nhật 24/11/2026:** Đã có validation/expected contract riêng và báo cáo Expected/Reality. Thiếu API55000 không còn chặn đọc indexer; thiếu identity lịch sử vẫn chỉ trả candidates. GUI dùng Validate → xác nhận. Các kết quả test/trạng thái triển khai bên dưới là lịch sử; xem [VALIDATE_EXECUTE_REPORT_HANDOFF.md](VALIDATE_EXECUTE_REPORT_HANDOFF.md) cho bản hiện hành. Không mở quyền chạy mọi ability và không xác nhận detection từ exit0.

# Sửa Wazuh connector auth — 22/11/2026

## Kết quả thực tế

Indexer 9200 đã xác thực và search thành công HTTP 200. Diagnostic đọc được 50 alert thật trong cửa sổ 15:29:39–16:29:39 UTC ngày 22/11/2026, giới hạn IP .150/.164, tối đa 50 mẫu. Archives không có index hiện tại: alerts_only. Đây là **LIVE CONNECTIVITY/INGEST CHECK — NOT AN EXECUTION REPORT**.

Artifact: `review/wazuh-auth-fix/live-diagnostic.json`; product response đã lọc: `review/wazuh-auth-fix/product.json`. GET `/api/telemetry/diagnostic` chỉ đọc artifact này; mở GUI không gọi Wazuh. GUI sau restart trả diagnostic HTTP 200, 50 mẫu và alerts_only.

## Nguyên nhân đã chứng minh

Parser trước dùng split whitespace trên phần `user: admin/ pass: ...`, giữ `/` ở cuối username. Slot indexer/API được điền từ cùng bản ghi với username sai. Đã sửa slot indexer ngoài repo dùng bản ghi Wazuh dashboard, bỏ đúng delimiter, giữ password nguyên ký tự. Không thay password/user server.

Trong điều tra lần này có một lần chọn nhầm bản ghi dòng kế tiếp (SSH) và nhận 401. Sau kiểm tra nhãn dòng Wazuh/SSH, sửa nguyên nhân lựa chọn nguồn, một lần xác thực bằng đúng bản ghi dashboard thành công. Không thử danh sách password/default credentials.

Indexer trả version `7.10.2` nhưng tagline chính xác `The OpenSearch Project: https://opensearch.org/`. Code cũ chỉ chấp nhận version.distribution=opensearch nên sẽ từ chối sản phẩm hợp lệ sau auth. Đã nhận diện cả distribution chính thức và tagline chính xác; version string đơn lẻ không đủ.

## Trạng thái độc lập

| Khả năng | Kết quả |
|---|---|
| Indexer authentication | PASS HTTP 200 |
| Search alert hiện có | PASS 50 mẫu hữu hạn |
| Wazuh API 55000 | Credential đúng chưa có nguồn xác minh; không dùng dashboard/SSH thay thế |
| Identity execution hiện tại | Chưa xác minh; correlation execution bị chặn với identity_unverified_api_credentials_missing |
| Agent alive | unknown; alert lịch sử không chứng minh sống hiện tại |
| Archives | Absent trong kiểm tra index existence; alerts_only |
| TLS | Giữ nguyên pin lab TOFU từng endpoint; không cập nhật pin hoặc tắt kiểm tra pin. verified_ca vẫn mặc định code |
| CALDERA / Gemini | Không gọi/chạy |

`enabled=true` chỉ sau xác minh indexer search capability. API slot trống có chủ đích, không giữ credential sai. Thiếu API không chặn diagnostic đọc indexer; vẫn chặn báo cáo execution nếu thiếu identity đáng tin. Không tạo execution giả, không liên kết alert lịch sử vào scenario. Báo cáo MOCK cũ giữ nguyên.

## Thay đổi

- `engine/wazuh_connector.py`: nhận diện product OpenSearch tương thích; báo identity_unverified khi thiếu API credential.
- `engine/wazuh_diagnostic.py`: parser bản ghi dashboard có format rõ, product detector, diagnostic 60 phút/2 target/50 mẫu, field projection không commandLine/scriptBlock/full_log.
- `telemetry_report.json`: bật capability indexer, cập nhật status độc lập. Secret vẫn ngoài repo.
- `~/.config/datn-telemetry/wazuh-readonly.json`: indexer slot sửa, api slot rỗng, mode0600. Không env override; connector đọc đường dẫn config mỗi instance.
- `app.py`, `static/index.html`, `static/scenario-execution.js`: cached diagnostic endpoint và status UI, không network upstream tự động.
- Tests auth/parser/product/API dependency và fixtures GUI GET allowlist cập nhật.

Diagnostic chỉ hiện trạng một lần kiểm tra, có timestamp rõ. Chạy lại có chủ đích bằng `engine.wazuh_diagnostic.check(config)`, không tự poll/query toàn index. Identity lịch sử lưu ID/name/IP để audit, không nâng thành binding hiện tại. Cần API credentials đọc hợp lệ trong slot `api` hoặc quy trình binding xác minh riêng trước khi collect execution. Không cần tạo tài khoản mới nếu quản trị viên đã có account API phù hợp.

## Kiểm thử và triển khai

- 26 tests telemetry/auth PASS (`test_execution_telemetry`, `test_wazuh_auth_fix`).
- Wrapper cách ly regression 147 tests PASS (143 cũ + 4 auth mới).
- Node 31 tests PASS. Hai assertion allowlist ban đầu chưa có cached diagnostic GET đã cập nhật; chạy lại đạt.
- Live root/auth, bounded search và archive existence PASS; GUI cached diagnostic PASS sau restart.
- Restart riêng GUI sau kiểm tra không có active Survey/Scenario/Execution/collection. Không restart Wazuh/Windows collector. Không sửa server, archive/rules/roles/billing/token budget.
- Chưa nghiệm thu live scroll nhiều trang trong lượt này (diagnostic một trang 50 mẫu); offline pagination/dedup tests vẫn PASS. Chưa xác minh API55000 health hoặc execution end-to-end.

## Rollback

Code/config connector trước sửa ở `review/wazuh-auth-fix/backup/`. Secret backup ngoài repo tại `~/.config/datn-telemetry/wazuh-readonly.pre-auth-fix.json` mode0600; chứa credential sai trước sửa, chỉ dùng nếu cần tái hiện, không khuyến nghị phục hồi để vận hành.

Để vô hiệu hóa: đặt enabled=false, giữ artifacts/lịch sử. Restore connector/config từ backup và gỡ cached diagnostic UI/route nếu rollback toàn tính năng; restart GUI khi idle. Không cần hành động server. Không đưa secret backup vào repository hoặc báo cáo.

## Còn thiếu

1. Credential Wazuh API hợp lệ trong slot api, cập nhật qua file private; không gửi password trong chat.
2. CA chain tin cậy để chuyển từ lab pin TOFU về verified_ca nếu có.
3. Archives/retention phía manager/indexer vẫn chờ quyền và kế hoạch riêng; không sửa trong nhiệm vụ.
4. Typed behavior verification và execution thật được duyệt riêng: chưa được chứng minh bằng diagnostic ingest.

## Xác minh bổ sung 23/11/2026 03:24:59 UTC

Theo yêu cầu trực tiếp của người dùng, đã thử đúng một lần tài khoản dashboard/indexer đang hoạt động với GET API55000 `/security/user/authenticate?raw=true`, giữ nguyên certificate pin. API trả **HTTP401**: tài khoản này không xác thực được API55000 tại thời điểm kiểm tra. Không ghi tài khoản này vào API slot, không thay credentials/server và không restart. Kết quả không có secret: `review/wazuh-auth-fix/api-dashboard-verification.json`. Indexer đã được nghiệm thu trước đó là dịch vụ riêng; kết quả401 này không phủ định khả năng đọc alert qua9200.
