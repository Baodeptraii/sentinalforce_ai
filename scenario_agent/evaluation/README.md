# Kiểm chứng Scenario Agent

Đánh giá bản triển khai bằng nguồn/catalog thật, E5/FAISS thật, các phản hồi LLM được kiểm soát, kiểm tra các phản ví dụ và tùy chọn chạy Gemini thực tế. Không thực thi ability hoặc tạo operation CALDERA.

`results_20261112/SUMMARY.md` là kết luận tiếng Việt; `RESULTS.md` và `results.json` chứa chi tiết. Các plan EVAL FIXTURE chỉ dùng kiểm thử, không coi là đầu ra Gemini.

Chạy offline từ terminal, không gọi API:

```bash
/home/soc/build_scenario_agent/.venv/bin/python -B run_verification.py \
  --agent-root /home/soc/build_scenario_agent \
  --output-dir /home/soc/build_scenario_agent/outputs/verification_offline
```

Chạy riêng 5 case Gemini thật (tiêu thụ quota project):

```bash
/home/soc/build_scenario_agent/.venv/bin/python -B run_verification.py \
  --agent-root /home/soc/build_scenario_agent \
  --output-dir /home/soc/build_scenario_agent/outputs/verification_live \
  --live --live-only
```

Có thể giới hạn bằng `--max-live-cases 1` đến `5`. Dừng khi gặp 429/API error; không chuyển model hoặc lặp vô hạn. Mỗi lượt dùng retry budget của agent hiện tại; tối đa hai request hợp lệ và hai plan hợp lệ cho từng case theo workflow. Case quota offline dùng SDK 429 mô phỏng, không cố ý làm cạn quota thật.

Mã thoát: `0` khi mọi kiểm tra đã chạy đạt, `1` khi có FAIL/ERROR, `2` khi live bị chặn/chưa chạy đủ. FAIL ở phản ví dụ là một thiếu sót thật của bộ kiểm tra nghiệp vụ, không được đổi nhãn thành PASS chỉ vì đó là ca âm.

Case tự nhiên chỉ là ba phép thử nhãn technique trong catalog; không dùng tỷ lệ này để tuyên bố độ chính xác Gemini hoặc toàn bộ hệ thống. Plan mẫu thực tế đã lưu được đối chiếu thêm với command catalog; chưa có thực thi để kết luận SOC phát hiện.

`install_and_run_live.sh` sao chép bộ kiểm chứng vào `evaluation/` của thư mục triển khai và lưu bằng chứng offline dưới `outputs/verification_20261112_offline/`, rồi chạy live từ đó. Nó không sửa mã agent, schema, YAML hoặc catalog; cập nhật manifest để ghi nhận các file đánh giá mới. Không sao chép key hoặc dependency/model cache.

## Tiếp tục các case live sau lỗi API

`--append --resume-live` sử dụng lại checkpoint của các case bị BLOCKED và bỏ qua case đã PASS; không tạo lại lượt đang bị lỗi. Phải dùng đúng output-dir của lần trước.

```bash
.venv/bin/python -B evaluation/run_verification.py \
  --agent-root . --output-dir outputs/verification_retry_1 \
  --live --live-only --max-live-cases 1 --append --resume-live
```

Khi case đầu đạt, dùng lại lệnh với `--max-live-cases 5` để chạy tiếp bốn case còn lại. Tiến độ node/API được hiển thị trong live mode. Default timeout 300 giây và parse thinking low do agent cung cấp; có thể kiểm tra bằng `doctor`. Đây là thay đổi tham số để xử lý tình huống chờ lâu, không chứng minh lỗi 504 phía dịch vụ đã được khắc phục.

Các fixture kiểm thử có kiểm soát nằm trong `fixtures.py`; chúng mô phỏng cả phân tích hành vi và đối chiếu lệnh thật. Chúng không chứng minh Gemini tự phân tích đúng. Lượt live và báo cáo mới nhất xem `outputs/verification_behavior_fix_20261113/REVIEW.md`.
