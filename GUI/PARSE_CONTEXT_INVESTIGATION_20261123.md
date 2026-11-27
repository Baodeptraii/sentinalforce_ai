# Điều tra context parse — offline, 23/11/2026

Checkpoint: Scenario ca33fb72b6b04620a7ade7d2c97d35da, Survey 1e9a0b45f1a04faa9349e89701ebed8e.

Tái dựng project → intern → validate_wire → estimate từ checkpoint bằng code hiện tại, không gọi Gemini, không sửa checkpoint/config/code. Kết quả khớp chính xác reservation đã chặn: 51.595.

| Thành phần | UTF-8 bytes |
|---|---:|
| User text (không bao gồm JSON quoting) | 383 |
| Contents JSON tổng | 41.332 |
| Trong contents: survey_context | 38.153 |
| Trong survey_context: observations | 30.079 |
| System instruction | 3.527 |
| Response schema | 6.224 |
| Tổng payload tính bởi estimate | 51.083 |
| Reservation: tổng byte +512 | 51.595 |

Không cộng các dòng “trong contents” thêm lần nữa. 51.595 là allowance dự phòng, **không phải token thực tế**. Actual usage null. Công thức offline còn ghi lower estimate8.514; đó cũng không phải tokenizer hoặc khoảng đảm bảo chính xác.

## Ba nguyên nhân

1. Workflow.node_parse gọi evidence_payload/select_context dùng chung trước parse. Selection lấy toàn domain endpoint cùng authentication/runner/telemetry và base predicates; text relevance chủ yếu xếp hạng, không yêu cầu mọi fact phải liên quan trực tiếp. Lượt này chọn60 observations:45 endpoint,11 runner,2 authentication,2 telemetry, kèm15 conflicts,20 gaps,6 coverage. context_projection.project(parse) bỏ compatibility_report và included selection nhưng giữ nguyên survey_context. Không có full catalog hay compatibility report trong parse payload này.
2. estimate sử dụng số UTF-8 byte +512 làm input_tokens_reserved. Vì vậy một payload ~51KB bị so với parse_input49.152. User text còn xuất hiện cả text và app_context.text, nhưng phần lặp ~383byte không phải nguyên nhân chính.
3. Official count fallback lỗi cục bộ: llm.py truyền config.system_instruction vào client.models.count_tokens. SDK google.genai đang cài có _CountTokensConfig_to_mldev chủ động raise ValueError: “system_instruction parameter is only supported in Gemini Enterprise Agent Platform mode, not in Gemini Developer API mode.” Đã tái hiện bằng converter offline với chuỗi giả, không credentials/network. Vì thế không có số đếm official; code rơi về byte allowance. Ledger ghi một attempted count_tokens không chứng minh HTTP request đã đến Google.

## Hướng sửa cần thực hiện tiếp

- Sửa countTokens theo request format thực sự được Gemini Developer API/SDK hỗ trợ, kiểm tra converter/transport mock; không coi việc chuyển system text sang user text là exact count cho request gốc nếu khác format.
- Thiết kế parse projection riêng: identity/scope/user intent và tóm tắt có cấu trúc các facts cần hiểu yêu cầu; giữ unknown/conflict/gaps có refs ổn định; chi tiết executor/prerequisite/evidence dùng tại grounding/build. Không cắt JSON/command hoặc bỏ fact bắt buộc ngầm.
- Phân biệt estimated allowance/actual/count API trên UI; phase_input_limit không thể sửa bằng chờ cửa sổ TPM.
- So sánh offline trên checkpoint này và regression endpoint/web/multiple behaviors trước API thử nghiệm.

Chưa tăng budget, đổi model/key, gọi resume hoặc thay thuật toán trong lượt điều tra này.

Số đo máy đọc được: review/gui-e2e-20261123/parse-context-measurement.json.

## Bản sửa và kiểm chứng

Projection của parse giữ ID, loại, chủ thể, trạng thái và giá trị của cả 60 observations, cùng conflicts, gaps và coverage. Chi tiết provenance từng observation nằm trong snapshot đã ghim. Checkpoint hiện tại vượt qua kiểm tra fingerprint.

| Đại lượng | Trước | Sau |
|---|---:|---:|
| Payload UTF-8, byte | 51.083 | 38.841 |
| Reservation khi dùng ước lượng dự phòng | 51.595 | 39.353 |
| Giới hạn parse | 49.152 | 49.152 |

`count_tokens` gửi contents bằng format SDK hỗ trợ. Hệ thống cộng phần ước lượng riêng cho system instruction, schema và overhead. Cache dùng khóa mới để tách kết quả đếm chỉ contents với số đếm theo format trước. GUI hướng dẫn giảm context hoặc điều chỉnh budget cho `phase_input_limit`.

54 kiểm thử Python và 31 kiểm thử Node đạt. Số đo sau sửa nằm tại `review/gui-e2e-20261123/parse-context-after-fix.json`. Kết quả xác minh offline với SDK mock, chưa có số đếm hoặc kết quả sinh từ Gemini thật.
