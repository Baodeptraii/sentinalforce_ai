# Wazuh server: việc chờ triển khai riêng

Cập nhật 24/11/2026. Nhiệm vụ GUI không thay đổi server .112, collectors, roles, rules hoặc restart dịch vụ. Tình trạng connector/credentials/identity và báo cáo ứng dụng được chuyển sang [VALIDATE_EXECUTE_REPORT_HANDOFF.md](VALIDATE_EXECUTE_REPORT_HANDOFF.md). Tài liệu này chỉ ghi việc archives, retention và rules cần xử lý sau.

## Archives

Indexer kiểm tra chỉ đọc hiện không có archive indices, report giữ alerts_only. Snapshot quản trị trước có logall_json=no, archives.json rỗng; không tái cấu hình hoặc coi alert count là tổng log. Filebeat archives.enabled từng được ghi nhận true: kiểm tra lại trước thay đổi, không ghi đè toàn bộ Filebeat config.

Nếu quản trị chọn bật archives: đo EPS/bytes/day/disk/shards và ảnh hưởng toàn bộ agents; backup cấu hình tối thiểu, native validation, cửa sổ restart riêng. Chứng minh từng chặng source → manager JSON archives → Filebeat → indexer → quyền search. Không dùng collector ACK hoặc có file cấu hình làm bằng chứng đã indexed.

## Retention

Lập chính sách manager/indexer/ISM và dung lượng được duyệt trước khi bật lưu toàn bộ log. Không tự xóa lịch sử hoặc đổi replicas để che cluster yellow; đánh giá single-node/topology riêng. Archive retention server khác retention audit/report trên GUI.

## Rules và baselines

Chỉ xây rule/decoder theo hành vi và bằng chứng cụ thể, thử fixture có ground truth, đo noise/false positives trước rollout. Không tạo rule chung để mọi marker thành alert và làm coverage giả. Không dùng rule PowerShell Base64 chứng minh toàn bộ command semantics. Mỗi expectation alert cần rule ID/family mapping có nguồn, profile/baseline version và phạm vi.

## Nghiệm thu sau thay đổi được duyệt

- Query event không tạo alert để chứng minh archives thực sự hoạt động, kiểm tra permission/pagination/dedup/late arrival.
- Kiểm tra cùng event ở alerts và archives không đếm hai raw events.
- Chỉ chạy marker mới hoặc execution mới sau phê duyệt đúng kế hoạch; không gắn marker chẩn đoán vào scenario cũ.
- Không thấy alert vẫn không đủ kết luận missed_detection; cần behavior proof và source/rule coverage đã xác minh.

Bản tài liệu trước cập nhật được giữ tại `review/validate-report-20261124T100325/backup/WAZUH_SERVER_PENDING.md`.
