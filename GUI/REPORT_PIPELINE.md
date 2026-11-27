# Luồng báo cáo Wazuh tự động — 27/11/2026

## Đã triển khai

- Máy: `192.168.1.164`, user `soc`, nguồn chuẩn `/home/soc/DATN/GUI`.
- Service: `systemctl --user status datn-survey.service`; GUI vẫn ở `127.0.0.1:8765`.
- Xử lý số liệu bằng Python, không gọi LLM, không phát sinh token cho báo cáo.
- Đã sao lưu mã thay đổi và toàn bộ báo cáo trước triển khai tại `/home/soc/DATN/backups/report-pipeline-20261127T042403Z`.
- Không sửa Wazuh, Windows, CALDERA hoặc chạy operation mới trong đợt kiểm chứng này.

## Luồng hoạt động

1. Người dùng xác nhận execution trên GUI như trước.
2. Backend tạo phiên thu thập theo execution ID ngay khi trạng thái chuyển sang `confirmed`.
3. GUI mở tab báo cáo riêng. Nếu trình duyệt chặn popup, dùng liên kết **Mở báo cáo trực tiếp** trong phần artifact thực thi.
4. Một worker Python cho mỗi execution truy vấn Wazuh API/Indexer, chuẩn hóa metadata, kiểm tra danh tính, loại bản ghi trùng và tính các chỉ số.
5. Mặc định nghỉ 5 giây giữa các lượt truy vấn; thời gian request và ingest của Wazuh cộng thêm vào độ trễ. Đây là gần thời gian thực, không cam kết tức thời.
6. GUI nhận thay đổi qua SSE; nhiều tab xem cùng báo cáo không tạo thêm collector.
7. Khi execution kết thúc, cửa sổ thời gian sự kiện được giữ cố định. Collector tiếp tục chờ log đến muộn trong khoảng grace, mặc định 120 giây.
8. Báo cáo được lưu để mở lại hoặc tải JSON/Markdown. Khi GUI restart, chỉ khôi phục thu thập đang dang dở, không chạy lại operation.

Wazuh được **truy vấn định kỳ**, chưa cài webhook đẩy từ Wazuh Manager. SSE là luồng backend đẩy cập nhật tới trình duyệt.

## Script và mã chính

| File trong GUI | Vai trò |
|---|---|
| `engine/execution_telemetry.py` | Điều phối thu thập, danh tính theo phiên, chuẩn hóa, khử trùng, thống kê và xuất báo cáo |
| `engine/wazuh_connector.py` | Đọc API/Indexer trong phạm vi và giới hạn đã cấu hình; thêm MITRE rule tags |
| `engine/scenario_execution.py` | Mở phiên báo cáo khi xác nhận execution |
| `app.py` | API báo cáo, SSE chỉ đọc cache, tên file tải theo phiên/thời gian |
| `static/report.js`, `static/report.html` | Màn hình báo cáo tự cập nhật |
| `static/scenario-execution.js` | Mở tab báo cáo sau xác nhận và liên kết mở lại |
| `tools/report_execution.py` | Đọc, làm mới, theo dõi và xuất JSON qua GUI API |

### Dùng bằng dòng lệnh trên Ubuntu

```bash
cd /home/soc/DATN/GUI
# Thay EXECUTION_ID bằng ID 32 ký tự của execution đã có.
.venv/bin/python -B tools/report_execution.py EXECUTION_ID
.venv/bin/python -B tools/report_execution.py EXECUTION_ID --watch --output /tmp/execution-report.json
.venv/bin/python -B tools/report_execution.py EXECUTION_ID --refresh --watch --output /tmp/execution-report.json
```

- `--refresh` chỉ yêu cầu thu thập Wazuh; không thực thi lại kịch bản.
- Báo cáo và trạng thái chính: `telemetry_reports/<execution_id>/report.json`, `report.md`, `events.json`, `telemetry_state.json`.
- Snapshot đầy đủ tối đa khoảng mỗi phút trong lúc chạy, thêm snapshot khi complete/degraded; không nhân bản báo cáo đầy đủ mỗi 5 giây.
- `first_observed_by_collector_at` là lúc collector thấy bản ghi, không phải thời điểm Indexer ingest.
- Có retry/backoff và giới hạn thời gian/số bản ghi; lỗi kéo dài được thể hiện là degraded. Có thể thu thập lại sau khi sửa kết nối.

## Ý nghĩa kết quả

- Lệnh hoàn tất: theo kết quả execution; exit 0 không tự chứng minh hành vi.
- Alert ứng viên: phù hợp host và thời gian truy vấn.
- Alert tương quan: có bằng chứng liên kết với execution; không đồng nghĩa phát hiện đúng kỹ thuật.
- MITRE rule tags: giữ metadata có thật từ Wazuh, đối chiếu với kỹ thuật kỳ vọng; không tự coi tag trùng là detection thành công.
- Hành vi và phát hiện kỹ thuật giữ chưa đánh giá khi thiếu verifier hoặc tiêu chí rule đã kiểm chứng.
- Raw event count giữ `null` khi chỉ có alerts, không đổi số alert thành tổng raw logs.
- Các trường/schema v1 cũ được giữ tương thích. `assessment` là phần diễn giải Python bổ sung; `detection_status=matched_alert` cũ chỉ biểu thị alert liên kết, không phải hiệu quả phát hiện.
- Danh tính quan sát được lúc execution được lưu để mở lại lịch sử. Khi Wazuh agent identity thay đổi, không tự gán bằng chứng cũ sang máy mới.

## Kiểm chứng

- 7 kiểm thử mới về vòng đời thu thập, cửa sổ thời gian, danh tính, worker duy nhất, SSE và giới hạn kết luận.
- 22 kiểm thử telemetry hiện có đạt.
- 34 kiểm thử JavaScript đạt, gồm mở tab báo cáo sau xác nhận.
- Bộ hồi quy Python 171 kiểm thử đạt trên staging có fixture sao chép; không chạy provider/victim.
- Live: truy vấn lại execution `4e4efecdcddb4dc7a31ec65d79fe9dd0` qua Wazuh thật.
  - 33 alert ứng viên, 2 alert tương quan.
  - Cả 2 là alert tạo tiến trình; chưa đủ chứng minh phát hiện T1078/T1110.001.
  - Raw count `null`, LLM requests `0`.
  - SSE nhận báo cáo đúng execution, tải JSON có tên riêng, hash execution record không đổi.
- Mã đang chạy khớp hash bản đã kiểm thử, service active.
- Chưa kiểm thử end-to-end bằng operation mới sau triển khai; chưa thực hiện kiểm tra bố cục bằng trình duyệt thật. Vòng đời đang chạy đã kiểm thử offline, đọc Wazuh và SSE đã kiểm chứng live.

## Triển khai và khôi phục

- Staging: `/home/soc/DATN/incoming/report-review-20261127/GUI`.
- Bằng chứng: thư mục cha staging chứa `regression.log`, `node-tests.log`, `live-report.json`, `live-verification.json`.
- Bản local: `E:\Study\DATN\review\report_session_20261127\source`.
- Backup có `manifest.json` liệt kê từng file và hash. Nếu cần rollback, dừng riêng GUI lúc không có tác vụ, khôi phục các file đã tồn tại theo manifest rồi khởi động GUI. Không chép đè config/secrets/output và không tự phục hồi toàn bộ báo cáo cũ vì sẽ mất cập nhật mới.
- Sau triển khai chỉ cần tải lại trang GUI để nhận JavaScript mới; service đã được restart trong đợt này.

## Việc tiếp theo

- Chạy một kịch bản đã duyệt từ GUI, kiểm tra tab báo cáo mở và số liệu thay đổi khi Wazuh ingest.
- Nếu cần đánh giá phát hiện đúng kỹ thuật, bổ sung tiêu chí rule và verifier hành vi cho từng loại kịch bản. Không thay tiêu chí này bằng việc thấy bất kỳ alert nào.
- Nếu báo cáo chạm giới hạn bản ghi hoặc thời gian, tăng giới hạn có cân nhắc tải Indexer; báo cáo hiện nêu rõ partial/degraded, không tuyên bố bao phủ đầy đủ.
