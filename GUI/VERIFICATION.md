> Cập nhật 24/11/2026: tài liệu này ghi kết quả kiểm tra lịch sử. Các log, backup và artifact triển khai ngoài package không được phát hành cùng source. Kết quả mới phải chạy lại theo lệnh bên dưới. Điểm khởi động: `GUI/start.sh`.

# Kết quả kiểm tra — 07/11/2026

Bản được kiểm tra: `GUI`, dùng hợp đồng tại `final_template`. Bản gốc `GUI` chưa thay đổi vì nằm ngoài vùng được phép ghi.

## Kết quả hiện tại

- 17 unittest Python: 15 đạt, 2 bỏ qua vì sandbox cấm tạo socket localhost. Hai test bị bỏ qua là pipeline qua HTTP CALDERA giả lập và HTTP web fixture. Trong shell thông thường, chúng vẫn chạy như cũ.
- Test không cần socket đã kiểm tra runner với API trong bộ nhớ, cả nhánh thành công và lỗi, lưu kết quả và khôi phục group; không phải lab thật.
- Test hồi quy: bỏ yêu cầu ART và kiểm tra module khỏi định nghĩa survey, dùng ID v2, profile đúng sáu trường gốc, giữ unknown, từ chối kiểu boolean sai/trường gốc thừa, từ chối bước lặp, và đọc/download profile lịch sử mà không sửa bằng chứng gốc.
- 244 tài liệu template/input đạt kiểm tra cấu trúc; chưa kiểm tra liên kết target ID hoặc resolve ability với dataset.
- Đã loại 22 bước lặp trên 19 adversary, giữ thứ tự lần xuất hiện đầu tiên, cập nhật giới hạn request tương ứng. Migration chạy lại không đổi dữ liệu.
- 5 tests Node đạt: đọc/kiểm tra profile, tìm/lọc kho, giữ YAML nguyên bản, chuyển profile khảo sát sang thiết kế, phân trang và chọn mẫu. Hai test tương tác dùng DOM fixture tối thiểu, không phải trình duyệt thực.
- `node --check` đạt cho `app.js`, `scenario-core.js`, `scenario.js`.
- 11 file Python parse được bằng Python 3.8.10; CLI app và runner trả help thành công.
- 19 file artifact lịch sử trong bản GUI đã sửa giống từng byte với bản gốc.

Log kiểm tra giao diện, báo cáo migration và artifact lịch sử không nằm trong package staging; cần cung cấp từ deployment workspace nếu cần audit.

## Giới hạn

Chưa mở server/trình duyệt để kiểm tra bố cục giao diện hiện tại trong sandbox vì socket bị cấm. Snapshot giao diện có 113 adversary và 3 profile; tạo lại snapshot không làm thay đổi nội dung. Các route mới chỉ phục vụ static asset, không có backend sinh kịch bản. Chưa chạy ability survey v2 hoặc kịch bản tấn công trên lab. Chưa xác minh ingestion Wazuh hoặc detection. Các ảnh preview là ảnh tham khảo từ phiên bản trước.

Bộ artifact khảo sát endpoint 04/11/2026 trong `outputs/` có kết quả thực thi thành công được lưu và nhất quán qua các bước parse. Đây là bằng chứng lịch sử, không phải xác minh môi trường hiện tại hoặc kiểm thử phiên bản v2.

Cài `jsonschema` qua pip gặp lỗi DNS; bộ kiểm tra mặc định dùng validator nhỏ không cần dependency. Nếu jsonschema có sẵn, cùng schema được kiểm tra bằng Draft202012Validator. PyYAML hiện có phục vụ validator YAML/migration; GUI không phụ thuộc PyYAML.

## Chạy lại

```bash
cd project-root
python3 -B -m unittest discover -s GUI/tests -v
python3 -B final_template/validate_all_templates.py --project
node --check GUI/static/app.js
node --check GUI/static/scenario.js
node GUI/tests/scenario-ui.test.cjs
GUI/start.sh
```

Mở `http://127.0.0.1:8765`. Chạy app để xem giao diện không tự tạo operation; chỉ bấm bắt đầu khảo sát khi muốn thực thi trên endpoint được phép.

## Bổ sung kiểm tra luồng — 09/11/2026

- 6 test core mô phỏng đạt: chặn tại phê duyệt, lỗi agent, thiếu telemetry, pause/step/reset, bảo toàn context và thứ tự đồ thị.
- Bộ test UI Node hiện có 6 test đạt, gồm thao tác chuyển chế độ, chọn/ghim/theo dõi node, xử lý lỗi mô phỏng, duyệt và tự dừng khi rời màn hình. Đây là DOM fixture, chưa phải browser.
- 17 test Python: 15 đạt, 2 HTTP integration bị bỏ qua do sandbox cấm socket. Các route mới chỉ phục vụ ba static asset flow; không gọi survey/backend thực thi.
- Tổng 27 test đạt, 2 test bỏ qua. Kiểm tra cú pháp các script đạt.
- Thử mở preview server cục bộ cổng 8766 bị `PermissionError` khi tạo socket. Chưa chụp ảnh/xác minh bố cục bằng trình duyệt thực.
- Log kiểm tra flow không nằm trong package staging. Không chạy lab hoặc thay đổi dữ liệu kịch bản.
