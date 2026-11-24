# Scenario Agent + RAG cho SOC

Package Python lập kế hoạch từ yêu cầu người dùng và target profile. Không có chức năng chạy lệnh ability hoặc tạo operation CALDERA. Mã nguồn tích hợp Gemini, E5/FAISS và LangGraph; cần phân biệt mã đã viết với các tích hợp đã kiểm chứng trong báo cáo.

## 1. Cài môi trường

Chạy từ thư mục package `scenario_agent/`:

Có thể chạy script tự động cài thư viện, tải E5, tạo FAISS và cập nhật báo cáo từ terminal có Internet:

```bash
bash scripts/setup_scenario_agent.sh
```

Script lưu output tại `reports/implementation/setup.log`, dừng khi có lỗi và không gọi Gemini để sinh nội dung. Không cần `sudo`. Nếu cài từng bước, dùng các lệnh sau:

```bash
python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install --index-url https://download.pytorch.org/whl/cpu torch
.venv/bin/python -m pip install --upgrade pip 'setuptools>=68' wheel 'packaging>=24.2'
.venv/bin/python -m pip install --no-build-isolation -e .
.venv/bin/python -m scenario_agent doctor
```

E5 chạy CPU, lần đầu cần mạng để tải model vào `.cache/huggingface`. CPU Torch tránh tải gói GPU lớn. Các phiên bản phụ thuộc chưa được khóa vì máy hiện chưa cài được các thư viện tích hợp. Sau khi cài và kiểm thử thành công, lưu phiên bản bằng `.venv/bin/python -m pip freeze > requirements.resolved.txt`.

Package yêu cầu `Pillow>=10,<13`: Transformers có thể nạp các tiện ích ảnh ngay khi import model văn bản. Pillow 9.0.1 của hệ thống thiếu `Image.Resampling`, gây lỗi gián tiếp `Could not import module PreTrainedModel`. `doctor` kiểm tra module có được tìm thấy, không chứng minh mọi import và model hoạt động.

Nếu lần trước dừng ở lỗi thiếu `build_editable`, chạy lại script đã sửa. Script giữ bản CPU PyTorch đã cài, cập nhật pip/setuptools/wheel/packaging và dùng backend setuptools trong `.venv` qua `--no-build-isolation`; các dependency runtime vẫn được cài bình thường. `packaging>=24.2` tránh lỗi `canonicalize_version(..., strip_trailing_zero=...)` khi setuptools mới gặp packaging cũ. Log lượt trước được giữ tại `setup.previous.log`.

## 2. Cấu hình Gemini

Vào https://aistudio.google.com/app/apikey, tạo key trong project **Free tier**. Google AI Pro và billing của API là hai cấu hình khác nhau. Xem hạn mức model trong AI Studio; ứng dụng không thể suy ra billing tier chỉ từ key.

```bash
nano .env
chmod 600 .env
```

Nội dung mẫu (không gửi key vào chat, không ghi key vào báo cáo):

```dotenv
GEMINI_API_KEY=thay_bang_key_tren_may
GEMINI_MODEL=gemini-3.8-flash
GEMINI_FREE_TIER_CONFIRMED=true
```

Chỉ đặt dòng xác nhận `true` sau khi kiểm tra project đang ở Free tier. Đây là xác nhận thủ công, không phải khóa chống tính phí nếu project được đổi gói sau đó. `doctor` chỉ báo có key hay chưa, không hiển thị key, không gọi API. Lệnh `run` và `resume` có gọi Gemini; code không tự chuyển sang model trả phí hoặc retry vô hạn khi hết quota. Kiểm tra chính sách Free tier trước khi gửi dữ liệu lab.

## 3. Chuẩn bị RAG

```bash
.venv/bin/python -m scenario_agent prepare-corpus
.venv/bin/python -m scenario_agent build-index
.venv/bin/python -m scenario_agent check-index
```

`prepare-corpus`: đọc SQLite ở chế độ read-only, tạo `data/rag/passages.json` (mapping vị trí → loại/ID/provenance/text) và `corpus_manifest.json`. Không sao chép các YAML kịch bản. Chỉ mục là dữ liệu dẫn xuất, không phải nguồn YAML thứ hai.

`build-index`: E5 mã hóa với tiền tố `passage: `, chuẩn hóa vector, FAISS IndexFlatIP lưu `index.faiss`; `embeddings.npy` phục vụ tìm kiếm trên tập đã lọc target; `index_manifest.json` ghi fingerprint catalog/corpus/model và hash artifact. Thay catalog phải tạo lại corpus và index.

Revision E5 lấy từ đường dẫn snapshot qua API cache chính thức của Hugging Face, không phụ thuộc trường `_commit_hash` nội bộ của Transformers. Model đã tải đủ được nạp từ cache ở chế độ offline. `check-index` kiểm tra hash, số lượng/kích thước và độ chuẩn hóa vector mà không mã hóa lại corpus. Khi đã có chỉ mục, script báo cáo dùng lệnh kiểm tra này.

```bash
.venv/bin/python -m scenario_agent retrieve --mode keyword --text 'T1033 Windows user discovery'
.venv/bin/python -m scenario_agent retrieve --mode hybrid --text 'Khảo sát thông tin người dùng Windows'
```

`retrieve` là lệnh chẩn đoán, chưa chuẩn hóa yêu cầu. Keyword mode là kiểm tra offline, không tìm theo ý nghĩa. Hybrid dùng E5+FAISS và exact ID/keyword, hợp nhất bằng Reciprocal Rank Fusion, tách xếp hạng ability và adversary để hai nhóm không lấn nhau. Ability Linux bị loại khi target là Windows; ability Elevated bị loại nếu admin chưa sẵn sàng. Executor không rõ platform bị loại. Scope lệnh, quyền còn thiếu, dependencies và telemetry vẫn cần kiểm chứng trước khi duyệt.

## 4. Chạy workflow

```bash
.venv/bin/python -m scenario_agent run --text 'Tôi muốn khảo sát thông tin người dùng Windows trên endpoint để đánh giá SOC, tối đa 1 test.'
```

Luồng LangGraph: `parse → validate_request → retrieve → build_plan → validate_plan → finalize`. Gemini chuẩn hóa text và lập plan; Pydantic + JSON Schema kiểm tra cấu trúc; Python tra SQLite kiểm tra ID/executor/technique/provenance, thứ tự, giới hạn số test. Có tối đa 2 lượt tạo request và 2 lượt tạo plan để sửa lỗi schema/nghiệp vụ. Không đủ ứng viên thì trả `no_candidates`, không sinh ID giả.

Ứng viên adversary chỉ được dùng nguyên chuỗi khi mọi ability có executor phù hợp target và không vượt giới hạn test. Nguồn xung đột hoặc thiếu tham chiếu bị loại. Alias chỉ được resolve qua bản ghi hash-pinned trong SQLite; đầu ra dùng canonical ID. Ưu tiên reuse nếu đúng mục tiêu, adapt hoặc compose khi cần. LLM vẫn có thể chọn sai mục tiêu; validator chưa chứng minh độ bao phủ ngữ nghĩa.

Đầu ra mỗi lượt tại `outputs/runs/<run_id>/`:

- `state.json`: trạng thái từng node, fingerprint và điểm tiếp tục.
- `user_request.json`: yêu cầu đã đạt schema và được đối chiếu target.
- `retrieval.json`: các bản ghi thật đã truy hồi cùng nguồn.
- `scenario_plan.yml`: chỉ xuất khi đạt schema và các kiểm tra nghiệp vụ đã triển khai.

`completed` nghĩa là đã xuất plan, không phải plan được duyệt hay lab đã thực thi. V0.1 chưa có bộ kiểm chứng môi trường nên plan chỉ có thể là `needs_information` hoặc `blocked`; validator từ chối `ready_for_review` và các bằng chứng `verified` tự sinh. Mọi ability đã chọn tính là test; setup/cleanup mô tả riêng, chưa hỗ trợ ability có role setup/cleanup trong atomic_ordering. Fact chưa được bind giữ `null`. Không thể đáp ứng một giới hạn thì agent cần báo vấn đề, không bỏ giới hạn.

Khi thiếu dữ kiện, trạng thái `needs_information` kèm câu hỏi. Khi Gemini trả 429, lưu `waiting_quota`; ứng dụng không có lịch tự chạy lại. Người dùng tiếp tục bằng:

```bash
.venv/bin/python -m scenario_agent resume RUN_ID --clarification 'Tôi chọn phạm vi endpoint, chỉ dùng dữ liệu giả trong C:\SOC-Lab.'
.venv/bin/python -m scenario_agent resume RUN_ID
```

Thay `RUN_ID` bằng ID thật. Lệnh thứ hai dùng khi tiếp tục sau quota/lỗi môi trường. Target/catalog/schema/model thay đổi thì từ chối tiếp tục, phải tạo lượt mới. Checkpoint dùng JSON do ứng dụng quản lý, chưa dùng backend checkpoint SQLite của LangGraph. Mỗi node lưu state sau khi xong; crash giữa một API call có thể khiến call được gọi lại khi tiếp tục. Giữ nguyên `GEMINI_MODEL` khi resume.

## 5. Kiểm tra và báo cáo

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/build_implementation_report.py
```

Báo cáo `Bao_cao_trien_khai_Scenario_Agent_AI_RAG_SOC.docx` chứa lệnh, output và ảnh dựng từ output terminal thực tế. Đây không phải ảnh chụp desktop. Log cùng ảnh nằm trong `reports/implementation/`. Script báo cáo không gọi Gemini, không chạy ability, không tự cài thư viện. Bài kiểm thử LangGraph dùng LLM giả có nhãn fixture; không kiểm chứng chất lượng Gemini. Thiếu LangGraph thì bài đó được ghi skipped.

Nguồn 113 kịch bản vẫn chỉ ở `input/knowledge base/scenarios/`. Không chỉnh sửa kịch bản gốc hoặc nạp thêm bản sao YAML. `data/catalog.sqlite` và chỉ mục là dữ liệu dẫn xuất để agent đọc; YAML gốc dùng làm nguồn import/audit/provenance và giai đoạn tích hợp sau.

## Tài liệu chính thức

- Gemini API keys: https://ai.google.dev/gemini-api/docs/api-key
- Giá và Free tier: https://ai.google.dev/gemini-api/docs/pricing
- Python GenAI structured JSON: https://googleapis.github.io/python-genai/
- LangGraph graph API: https://docs.langchain.com/oss/python/langgraph/graph-api
- Multilingual E5 Small: https://huggingface.co/intfloat/multilingual-e5-small
