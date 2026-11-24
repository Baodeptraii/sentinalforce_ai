# Cấu trúc chuẩn của đồ án SOC AI Agent

Cập nhật theo yêu cầu ngày 07/11/2026. Thư mục `final_template/` là nguồn hợp đồng dữ liệu dùng chung cho GUI và validator. Kiểm tra cấu trúc đạt không chứng minh ability tồn tại, thực thi thành công hoặc SOC phát hiện được.

## Đầu vào nghiệp vụ

Chỉ có ba nhóm:

| Nhóm | Nội dung |
|---|---|
| `user_request` | Yêu cầu, phạm vi và giới hạn lập kịch bản |
| `target_profile` | Hồ sơ môi trường từ kết quả khảo sát |
| `dataset` | Kịch bản, ability CALDERA, test ART và các nguồn kiểm thử |

Ưu tiên dữ liệu đã cung cấp trong `generated_adversaries/`. Dataset ability đầy đủ sẽ bổ sung sau; không tạo một đầu vào danh mục riêng. Bằng chứng, schema và báo cáo kiểm tra được lưu riêng với input nghiệp vụ.

## File chuẩn

| File | Vai trò |
|---|---|
| `target_profile_template.json` | Ví dụ từ profile khảo sát 04/11, đã bỏ yêu cầu ART |
| `target_profile_schema.json` | Ràng buộc profile |
| `user_request_template.json` | Ví dụ yêu cầu |
| `user_request_schema.json` | Ràng buộc yêu cầu |
| `scenario_adversary_template.yaml` | Ví dụ adversary endpoint |
| `scenario_web_dvwa_template.yaml` | Ví dụ adversary web |
| `scenario_adversary_schema.json` | Ràng buộc adversary |
| `contracts.py` | Bộ kiểm tra không phụ thuộc thư viện ngoài, hỗ trợ tập keyword schema đang dùng |
| `validate_all_templates.py` | Kiểm tra cấu trúc offline |
| `normalize_project.py` | Đồng bộ profile và loại bước lặp; không chạy lab |

## Target profile

Đúng sáu trường gốc: `id`, `os`, `address`, `services`, `capabilities`, `telemetry`. Không thêm metadata mô tả schema vào JSON nghiệp vụ.

- Không có trường `art_ready` trong capabilities. Không yêu cầu cài hoặc chạy Invoke-AtomicRedTeam trên victim để khảo sát.
- Capability hiện dùng: `sandcat_online`, `powershell_ready`, `web_runner_ready`, `web_reachable`, `dvwa_session_ready`, `admin_ready`; giá trị boolean hoặc null. Có thể bổ sung thông tin lồng theo bằng chứng, ví dụ `execution_scope`.
- Thông tin chưa xác minh giữ `null`/`unknown`. Không biến lỗi đọc dữ liệu thành false.
- Quyền Sandcat là `User` hoặc `Elevated`; admin chỉ là điều kiện cho từng thao tác cần quyền đó.
- Thiếu Wazuh/Sysmon/log không chặn khảo sát hoặc lập kế hoạch.
- Bốn security level là bốn trạng thái của cùng một DVWA.
- Profile lịch sử còn trạng thái giả định phải được đọc cùng mô tả bằng chứng; không coi đó là xác minh hiện tại.
- Liên kết `request.target_id` với `profile.id` tạm hoãn chuẩn hóa. Validator hiện không bắt hai giá trị khớp nhau.

## User request

Đúng sáu trường gốc: `id`, `text`, `target_id`, `scope`, `max_steps`, `mode`.

- `scope`: endpoint, web hoặc cả hai; không có phần tử trùng.
- `max_steps`: số nguyên dương, không chấp nhận boolean.
- `mode`: `plan_only` trong bộ input hiện tại. Nội dung text yêu cầu thực thi không tự kích hoạt operation.

## Adversary CALDERA

Bốn trường bắt buộc: `id`, `name`, `description`, `atomic_ordering`. Hai trường tùy chọn: `objective`, `tags`. Không có trường gốc ngoài các trường trên.

`atomic_ordering` chứa các ability ID, không rỗng và không có bước lặp. Giữ nguyên ID nguồn, kể cả ID không có hình thức UUID; không tự thay chúng bằng UUID mới vì có thể làm đứt tham chiếu. Không suy ra ability tồn tại chỉ từ hình thức của ID. Khi dataset được bổ sung, phải đối chiếu ID, executor, tham số, payload, dependency và cleanup trước khi thực thi.

Các file adversary hiện là mẫu/ứng viên có cấu trúc. Schema ART và CALDERA được giữ riêng; không nạp trực tiếp ART YAML như CALDERA ability.

## Kiểm tra

Chạy tại thư mục dự án:

```bash
python3 final_template/validate_all_templates.py
python3 final_template/validate_all_templates.py --project
python3 -B -m unittest discover -s GUI/tests -v
```

GUI và kiểm tra profile JSON không cần pip. Đọc YAML trong validator/migration cần PyYAML (đã có ở môi trường hiện tại). `jsonschema` không bắt buộc: `contracts.py` kiểm tra tập keyword hiện dùng và từ chối keyword chưa hỗ trợ. Các schema JSON vẫn có thể dùng với thư viện JSON Schema độc lập khi môi trường có thư viện đó.

`--project` kiểm tra template, profile, request và adversary đã cung cấp, gồm tính duy nhất của bước và giới hạn `max_steps`. Không gọi API CALDERA, không kiểm tra ID mục tiêu giữa các nguồn và không tuyên bố kết quả lab.

`normalize_project.py` chỉ chạy khi muốn áp dụng lại migration. Nó ưu tiên profile cùng tên trong `generated_adversaries/target_profiles/`, giữ nguyên ID mục tiêu/ability, bỏ yêu cầu ART, loại bước lặp theo lần xuất hiện đầu tiên và đồng bộ `max_steps` của request tương ứng. Bản sao dữ liệu trước lượt chỉnh sửa này nằm trong `.backups/input-sync-before.tar.gz`.
