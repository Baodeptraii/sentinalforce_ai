# Thao tác kịch bản đã sinh

Thanh thao tác nằm ngay dưới trạng thái Scenario Agent.

| Nút | Hành vi |
| --- | --- |
| Thêm vào kho kịch bản | Chỉ nhận lượt `completed`, kiểm tra schema ScenarioPlan bằng runtime, lưu nguyên YAML và thông tin yêu cầu vào `GUI/scenario_library/<job_id>.json`. Lưu lại cùng nội dung không tạo bản trùng. |
| Tạo lại | Tạo job và request/plan ID mới, giữ nguyên profile, policy, snapshot Survey v2 và nguyên văn yêu cầu đã bổ sung. Không ghi đè lượt trước. |
| Hủy sinh kịch bản | Chỉ hiện khi đang sinh; gửi yêu cầu dừng process group của worker do GUI tạo. Giữ bằng chứng; trạng thái chuyển `cancelling` rồi `cancelled`. |
| Xóa khỏi lịch sử | Chỉ hiện khi đã dừng. Đánh dấu `deleted_at`, ẩn khỏi lịch sử/API xem và tải file. Dữ liệu vẫn giữ trên đĩa; bản đã lưu vào kho vẫn tồn tại. |
| Thực thi | Mở preview/preflight, xem blocker và xác nhận đúng IP/hash trước khi controller tạo operation. Xem CALDERA_EXECUTION_HANDOFF.md. |

Kho gồm dữ liệu gốc 113 kịch bản và nhóm **Kịch bản đã sinh**, tải qua API khi mở trang và cập nhật sau mỗi lần lưu. Bộ lọc, số lượng, YAML chi tiết và tải file dùng được với bản đã lưu. Chọn bản đã sinh để dùng lại sẽ nạp yêu cầu gốc/profile; dùng **Tạo lại** ở lịch sử để giữ chính xác cả phần bổ sung và snapshot. Không tự nhập ID mới vào catalog RAG hay đăng ký lên CALDERA.

## API

`GET /api/scenario-library` trả `{items, total}`. Các POST dưới đây nhận JSON `{}` và dùng cùng `X-Survey-Token`/kiểm tra Origin như API hiện tại.

| Endpoint | Kết quả |
| --- | --- |
| `POST /api/scenarios/<id>/library` | 200, `{status: saved/already_saved, item}` |
| `POST /api/scenarios/<id>/regenerate` | 202, `{id, parent_job_id}` |
| `POST /api/scenarios/<id>/cancel` | 202, `{id, status: cancelling}` |
| `POST /api/scenarios/<id>/delete` | 200, `{id, status: deleted}` |
| `POST /api/scenarios/<id>/execute` | 200, execution preview `ready/blocked`; chưa tạo operation. |

Backend thực thi đã được tích hợp qua `engine/scenario_execution.py`. Plan lịch sử vẫn `plan_only`; xác nhận được ghi riêng vào execution record. Xem `CALDERA_EXECUTION_HANDOFF.md` về phạm vi adapter và điều kiện chặn.

## Mã nguồn

- `engine/scenario_actions.py`: lưu kho, kiểm tra schema, endpoint thực thi tạm.
- `engine/scenario_bridge.py`: tạo lại, hủy, xóa và quản lý worker.
- `engine/scenario_worker.py`: nhận nguyên văn yêu cầu của lượt tạo lại; lệnh kiểm tra schema offline.
- `static/index.html`, `static/scenario.js`, `static/style.css`: nút, trạng thái và cập nhật kho.

Các API mới cần **khởi động lại riêng GUI** để tiến trình đang chạy nạp mã mới; sau đó tải lại trang. Thay đổi này không tự restart GUI, CALDERA hay dịch vụ lab.
