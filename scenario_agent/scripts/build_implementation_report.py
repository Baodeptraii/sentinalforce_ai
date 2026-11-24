#!/usr/bin/env python3
"""Run offline evidence commands and create a DOCX using stdlib OOXML + Pillow.

No API calls, dependency installation, attack execution or desktop screenshots.
"""
import hashlib
import json
import shlex
import subprocess
import sys
import textwrap
import zipfile
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / 'reports/implementation'
OUT = ROOT / 'Bao_cao_trien_khai_Scenario_Agent_AI_RAG_SOC.docx'
PYTHON = str(ROOT / '.venv/bin/python')

def hash_file(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def scenario_hashes():
    folder = ROOT / 'input/knowledge base/scenarios'
    return {str(p.relative_to(ROOT)): hash_file(p) for p in sorted(folder.rglob('*')) if p.is_file()}

def capture(name, args):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, timeout=900 if name == 'index' else 90)
    command = shlex.join(args).replace(str(ROOT) + '/', '')
    value = {'command': command, 'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
    (REPORT / (name + '.json')).write_text(json.dumps(value, ensure_ascii=False, indent=2))
    (REPORT / (name + '.log')).write_text('$ ' + command + '\n' + result.stdout + result.stderr + f'\nexit_code={result.returncode}\n')
    return value

def terminal_png(name, record):
    font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf', 18)
    header_font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 20)
    body = '$ ' + record['command'] + '\n' + record['stdout'] + record['stderr'] + f"\nexit_code={record['exit_code']}"
    lines = []
    for line in body.splitlines():
        lines.extend(textwrap.wrap(line, width=106, replace_whitespace=False, drop_whitespace=False) or [''])
    im = Image.new('RGB', (1220, 90 + len(lines) * 25), '#101b2a')
    draw = ImageDraw.Draw(im)
    draw.text((24, 16), 'OUTPUT TERMINAL THỰC TẾ — ảnh dựng từ log, không phải ảnh chụp desktop', font=header_font, fill='#9fceff')
    for i, line in enumerate(lines):
        draw.text((24, 66 + 25 * i), line, font=font, fill='#e4edf8')
    path = REPORT / (name + '.png')
    im.save(path)
    return path

W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
R = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'
REL = 'http://schemas.openxmlformats.org/package/2006/relationships'
NS = {'w': W, 'r': R, 'wp': 'http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing',
      'a': 'http://schemas.openxmlformats.org/drawingml/2006/main', 'pic': 'http://schemas.openxmlformats.org/drawingml/2006/picture'}
for prefix, uri in NS.items():
    ET.register_namespace(prefix, uri)

def e(tag, attrs=None, text=None):
    prefix, name = tag.split(':')
    return ET.Element('{' + NS[prefix] + '}' + name, attrs or {}, **{}) if text is None else text_element(tag, attrs, text)

def text_element(tag, attrs, text):
    node = e(tag, attrs)
    node.text = str(text)
    return node

def wa(**attrs):
    return {'{' + W + '}' + k: str(v) for k, v in attrs.items()}

def xml(node):
    return ET.tostring(node, encoding='utf-8', xml_declaration=True)

class Document:
    def __init__(self):
        self.doc = e('w:document'); self.body = e('w:body'); self.doc.append(self.body)
        self.images = []

    def para(self, text='', style=None):
        p = e('w:p'); self.body.append(p)
        if style:
            props = e('w:pPr'); props.append(e('w:pStyle', wa(val=style))); p.append(props)
        # Use separate paragraphs for explicit newlines to preserve readable commands.
        r = e('w:r'); t = e('w:t', text=text)
        t.set('{http://www.w3.org/XML/1998/namespace}space', 'preserve')
        r.append(t); p.append(r)

    def page(self, title):
        p = e('w:p'); r = e('w:r'); r.append(e('w:br', wa(type='page'))); p.append(r); self.body.append(p)
        self.para(title, 'Heading1')

    def command(self, text):
        for line in text.splitlines():
            self.para(line, 'Code')

    def image(self, path, caption):
        rid = 'rIdImage' + str(len(self.images) + 1)
        self.images.append((rid, path))
        width, height = Image.open(path).size
        cx = 5900000; cy = int(cx * height / width)
        if cy > 6500000:
            cx = int(cx * 6500000 / cy); cy = 6500000
        p = e('w:p'); r = e('w:r'); drawing = e('w:drawing'); inline = e('wp:inline')
        inline.append(e('wp:extent', {'cx': str(cx), 'cy': str(cy)}))
        inline.append(e('wp:docPr', {'id': str(len(self.images)), 'name': path.name}))
        graphic = e('a:graphic'); data = e('a:graphicData', {'uri': NS['pic']})
        pic = e('pic:pic'); nv = e('pic:nvPicPr')
        nv.append(e('pic:cNvPr', {'id': '0', 'name': path.name})); nv.append(e('pic:cNvPicPr')); pic.append(nv)
        fill = e('pic:blipFill'); fill.append(e('a:blip', {'{' + R + '}embed': rid}))
        stretch = e('a:stretch'); stretch.append(e('a:fillRect')); fill.append(stretch); pic.append(fill)
        sp = e('pic:spPr'); transform = e('a:xfrm')
        transform.append(e('a:off', {'x': '0', 'y': '0'})); transform.append(e('a:ext', {'cx': str(cx), 'cy': str(cy)})); sp.append(transform)
        geom = e('a:prstGeom', {'prst': 'rect'}); geom.append(e('a:avLst')); sp.append(geom); pic.append(sp)
        data.append(pic); graphic.append(data); inline.append(graphic); drawing.append(inline); r.append(drawing); p.append(r); self.body.append(p)
        self.para(caption, 'Caption')

    def save(self, path):
        sect = e('w:sectPr'); sect.append(e('w:pgSz', wa(w=11906, h=16838)))
        sect.append(e('w:pgMar', wa(top=1000, bottom=1000, left=1000, right=1000))); self.body.append(sect)
        styles = e('w:styles'); defaults = e('w:docDefaults'); rd = e('w:rPrDefault'); rp = e('w:rPr')
        rp.append(e('w:rFonts', wa(ascii='DejaVu Sans', hAnsi='DejaVu Sans'))); rp.append(e('w:sz', wa(val=22)))
        rp.append(e('w:lang', wa(val='vi-VN'))); rd.append(rp); defaults.append(rd)
        pd = e('w:pPrDefault'); pp = e('w:pPr'); pp.append(e('w:spacing', wa(after=100, line=265, lineRule='auto'))); pd.append(pp); defaults.append(pd); styles.append(defaults)
        for name, size, color in [('Normal', 22, '243447'), ('Title', 36, '173C5D'), ('Heading1', 28, '173C5D'), ('Code', 18, '243447'), ('Caption', 18, '52667D')]:
            style = e('w:style', wa(type='paragraph', styleId=name)); style.append(e('w:name', wa(val=name)))
            if name == 'Normal': style.set('{' + W + '}default', '1')
            rpr = e('w:rPr'); rpr.append(e('w:sz', wa(val=size))); rpr.append(e('w:color', wa(val=color)))
            if name in ('Title', 'Heading1'): rpr.append(e('w:b'))
            if name == 'Code': rpr.append(e('w:rFonts', wa(ascii='DejaVu Sans Mono', hAnsi='DejaVu Sans Mono')))
            style.append(rpr)
            if name in ('Title', 'Heading1'):
                pp = e('w:pPr'); pp.append(e('w:keepNext')); style.append(pp)
            styles.append(style)
        rels = ET.Element('{' + REL + '}Relationships')
        def relationship(parent, rid, kind, target):
            ET.SubElement(parent, '{' + REL + '}Relationship', {'Id': rid, 'Type': R + '/' + kind, 'Target': target})
        relationship(rels, 'rIdStyles', 'styles', 'styles.xml')
        for rid, image in self.images: relationship(rels, rid, 'image', 'media/' + image.name)
        rootrels = ET.Element('{' + REL + '}Relationships'); relationship(rootrels, 'rIdDocument', 'officeDocument', 'word/document.xml')
        cturi = 'http://schemas.openxmlformats.org/package/2006/content-types'; ct = ET.Element('{' + cturi + '}Types')
        for ext, mime in [('rels', 'application/vnd.openxmlformats-package.relationships+xml'), ('xml', 'application/xml'), ('png', 'image/png')]:
            ET.SubElement(ct, '{' + cturi + '}Default', {'Extension': ext, 'ContentType': mime})
        for part, mime in [('document', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'), ('styles', 'application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml')]:
            ET.SubElement(ct, '{' + cturi + '}Override', {'PartName': '/word/' + part + '.xml', 'ContentType': mime})
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, node in [('word/document.xml', self.doc), ('word/styles.xml', styles), ('word/_rels/document.xml.rels', rels), ('_rels/.rels', rootrels), ('[Content_Types].xml', ct)]:
                archive.writestr(name, xml(node))
            for rid, image in self.images: archive.write(image, 'word/media/' + image.name)

def main():
    REPORT.mkdir(parents=True, exist_ok=True)
    before = scenario_hashes()
    records = {}
    records['doctor'] = capture('doctor', [PYTHON, '-m', 'scenario_agent', 'doctor'])
    records['corpus'] = capture('corpus', [PYTHON, '-m', 'scenario_agent', 'prepare-corpus'])
    # Summarize the actual full-record retrieval without filling the report with commands from abilities.
    script = "import json; from scenario_agent.config import Config; from scenario_agent.rag import retrieve; c=Config(); t=json.load(open('input/target_profile.json')); r=retrieve(c, {'text':'30fe7c15-fca4-4af8-aced-4d245bc51c94 T1033','objective':None,'requested_techniques':['T1033'],'max_tests':1},t,'keyword',1); print(json.dumps({'mode':r['mode'],'eligible':r['eligible'],'top': [{'id': x['record']['canonical_id'],'name':x['record']['ability']['name'],'source':x['record']['provenance']} for x in r['abilities']]},ensure_ascii=False,indent=2))"
    records['retrieval'] = capture('retrieval', [PYTHON, '-c', script])
    # Save the complete reproducible command, shorten only its image display.
    index_command = 'check-index' if (ROOT / 'data/rag/index_manifest.json').is_file() else 'build-index'
    records['index'] = capture('index', [PYTHON, '-m', 'scenario_agent', index_command])
    if records['index']['exit_code'] == 0:
        semantic_script = "import json; from scenario_agent.config import Config; from scenario_agent.rag import retrieve; c=Config(); t=json.load(open('input/target_profile.json')); r=retrieve(c, {'text':'Khảo sát thông tin người dùng Windows','objective':None,'requested_techniques':[],'max_tests':1},t,'hybrid',3); print(json.dumps({'mode':r['mode'],'eligible':r['eligible'],'query':'Khảo sát thông tin người dùng Windows','top':[{'id':x['record']['canonical_id'],'name':x['record']['ability']['name'],'technique':x['record']['ability']['technique_id']} for x in r['abilities']]},ensure_ascii=False,indent=2))"
        records['semantic'] = capture('semantic', [PYTHON, '-c', semantic_script])
    records['tests'] = capture('tests', [PYTHON, '-m', 'unittest', 'discover', '-s', 'tests', '-v'])
    records['nodes'] = capture('nodes', [PYTHON, 'scripts/demo_offline_nodes.py'])
    after = scenario_hashes()
    unchanged = before == after
    (REPORT / 'scenario_integrity.json').write_text(json.dumps({'unchanged_during_verification': unchanged, 'files': len(after), 'before': before, 'after': after}, indent=2))
    doctor = json.loads(records['doctor']['stdout'])
    corpus = json.loads(records['corpus']['stdout'])
    missing = [name for name, available in doctor['dependencies'].items() if not available]
    images = {}
    for name, record in records.items():
        shown = dict(record)
        if name in ('retrieval', 'semantic'): shown['command'] = '.venv/bin/python -c <script lookup trong ' + name + '.json>'
        images[name] = terminal_png(name, shown)
    install_path = REPORT / 'dependency_install.json'
    if install_path.exists():
        records['install'] = json.loads(install_path.read_text()); images['install'] = terminal_png('install', records['install'])
    d = Document()
    d.para('BÁO CÁO TRIỂN KHAI SCENARIO AGENT + RAG', 'Title')
    d.para('SOC lab • Python • Gemini • E5/FAISS • LangGraph')
    d.para('Thời điểm ghi nhận: ' + datetime.now().astimezone().isoformat(timespec='seconds'))
    d.para('Phạm vi: triển khai package và kiểm tra offline trên catalog hiện có. Chỉ lập kế hoạch, không thực thi ability, không sửa 113 kịch bản nguồn.')
    d.para('Trạng thái tổng thể: đã có mã nguồn, hợp đồng và corpus; chưa xác nhận chạy trọn luồng Gemini + E5/FAISS + LangGraph. Ảnh trong báo cáo được dựng từ log lệnh thực tế, không phải ảnh chụp desktop hay ảnh minh họa kết quả giả.')
    d.para('Đã thực hiện: tạo .venv, package scenario_agent, kiểm tra schema và catalog, keyword/exact retrieval, validator, checkpoint và kiểm thử node với LLM fixture. Thư viện còn thiếu tại thời điểm báo cáo: ' + (', '.join(missing) or 'không có theo kiểm tra import') + '. Kết quả build E5/FAISS và kiểm thử LangGraph xem các output ở bước sau. Chưa gọi Gemini trong script báo cáo.')
    d.para('Có thể tiếp tục cài đặt trên terminal có Internet bằng: bash scenario_agent/scripts/setup_scenario_agent.sh. Lệnh không gọi Gemini sinh nội dung; log tại reports/implementation/setup.log.')
    d.para('Các kết quả chi tiết, lệnh đầy đủ và ảnh PNG: reports/implementation/. Tài liệu vận hành: README.md. Chạy lại script báo cáo sau khi cài thư viện sẽ cập nhật kết quả offline; không tự gọi Gemini.')
    d.page('1. Dựng môi trường và package')
    d.para('Mục đích: tách mã agent thành package có CLI, cấu hình và các module độc lập. Dùng thư viện hệ thống sẵn có để kiểm thử offline trong khi chờ cài đủ phụ thuộc.')
    d.command('cd scenario_agent\npython3 -m venv --system-site-packages .venv\n.venv/bin/python -m scenario_agent doctor')
    d.para('Kết quả doctor ghi nhận sự hiện diện thư viện và key ở dạng boolean; không in giá trị key, không gọi API.')
    d.image(images['doctor'], 'Hình 1. Kiểm tra môi trường thực tế.')
    d.para('Các module: config.py (cấu hình/hash), models.py (hợp đồng), catalog.py (lookup), rag.py (truy hồi), llm.py (Gemini), validation.py, workflow.py và cli.py. .gitignore loại .env và cache khỏi nguồn.')
    d.page('2. Cài thư viện và cấu hình API')
    if 'install' in images:
        d.para('Bằng chứng lần cài trước đây trong môi trường agent trả mã lỗi như bên dưới. Trạng thái thư viện hiện tại lấy từ doctor ở bước 1; không suy ra trạng thái hiện tại chỉ từ lỗi lịch sử này.')
        d.command(records['install']['command']); d.image(images['install'], 'Hình 2. Output cài thư viện thực tế.')
    d.para('Lệnh cần chạy lại trên terminal có truy cập kho package:')
    d.command(".venv/bin/python -m pip install --index-url https://download.pytorch.org/whl/cpu torch\n.venv/bin/python -m pip install --upgrade pip 'setuptools>=68' wheel 'packaging>=24.2'\n.venv/bin/python -m pip install --no-build-isolation -e .")
    d.para('API: tạo key tại https://aistudio.google.com/app/apikey, chọn project Free tier, mở nano .env và thêm GEMINI_API_KEY. Không chụp key hoặc gửi key vào báo cáo.')
    d.command('nano scenario_agent/.env\nchmod 600 scenario_agent/.env')
    d.para('Sau khi xác nhận project Free tier trên AI Studio: cấu hình GEMINI_FREE_TIER_CONFIRMED=true và GEMINI_MODEL=gemini-3.8-flash. Mã không kiểm tra billing tier từ key. Không có cơ chế tự chuyển model khi lỗi/quota.')
    d.para('Tại lúc tạo báo cáo: api_key_configured=' + str(doctor['api_key_configured']) + '; chưa gọi API Gemini trong các lệnh bằng chứng.')
    d.page('3. Hợp đồng và dữ liệu đầu vào')
    d.para('Pydantic tạo model từ schema đang có để tránh hai bộ cấu trúc lệch nhau; JSON Schema Draft 2020-12 kiểm tra pattern, trường bắt buộc và điều kiện readiness. Schema gửi Gemini chỉ là tập thuộc tính được API hỗ trợ; đầu ra luôn được kiểm tra lại bằng schema đầy đủ.')
    d.para('Đầu vào: văn bản người dùng + input/target_profile.json. Không tạo schema target mới. Target mẫu là Windows/DVWA, quyền User và nhiều trạng thái telemetry/dependencies còn assumed; không nâng chúng thành verified.')
    d.command('.venv/bin/python -m scenario_agent check-schema request input/schema/user_request.ransomware.example.json')
    d.para('Lệnh này chỉ kiểm tra hợp đồng. Kiểm tra target, ID, executor, source, thứ tự và giới hạn test do validator nghiệp vụ thực hiện. Một plan đạt schema chưa chứng minh an toàn hoặc sẵn sàng thực thi.')
    d.para('V0.1 chưa tích hợp bộ kiểm chứng môi trường: mọi plan vẫn cần xác minh quyền, fact, dependencies, scope lệnh và telemetry. Validator từ chối ready_for_review và các bằng chứng verified tự sinh; đây là giới hạn triển khai có chủ đích, chưa đạt mức tự xác nhận sẵn sàng chạy.')
    d.page('4. Tạo corpus và chỉ mục RAG')
    d.command('.venv/bin/python -m scenario_agent prepare-corpus\n.venv/bin/python -m scenario_agent build-index')
    d.para(f"Corpus thực tế: {corpus['passages']} passage = {corpus['abilities']} ability + {corpus['adversaries']} adversary. {corpus['excluded']} ability bị loại khi không đạt điều kiện catalog. 71 adversary đủ tham chiếu chưa có nghĩa là phù hợp mọi target.")
    d.image(images['corpus'], 'Hình 3. Corpus được tạo từ SQLite thực tế.')
    d.para('Passage chứa tên, mô tả, tactic/technique và provenance. Adversary có mô tả chuỗi; dữ liệu đầy đủ vẫn đọc từ SQLite bằng ID. Không sao chép YAML của 113 kịch bản. Dùng lại chuỗi phải kiểm tra toàn bộ ability, không tự cắt bỏ bước không phù hợp.')
    d.image(images['index'], 'Hình 4. Trạng thái lệnh tạo index; chưa có FAISS nếu thư viện còn thiếu.')
    d.para('Tích hợp đã viết: E5 CPU, passage/query prefixes, normalize, FAISS inner product, mapping và fingerprint SHA-256. Manifest pin revision model E5. Đổi catalog hoặc model thì phải build lại. Chưa đo chất lượng semantic retrieval; văn bản dài chịu giới hạn tokenizer E5.')
    d.page('5. Kiểm tra truy hồi và lookup bản ghi thật')
    d.command(".venv/bin/python -m scenario_agent retrieve --mode keyword --text 'T1033 Windows user discovery'")
    d.para('Ảnh sau là kiểm tra exact ID trên catalog thật; đoạn Python đầy đủ nằm trong retrieval.json. ID đứng đầu được đối chiếu với tên, technique và nguồn SQLite. Không gọi Gemini hoặc E5 trong kiểm tra này.')
    d.image(images['retrieval'], 'Hình 5. Lookup ability thật với ID xác định.')
    d.para('Hybrid sau khi cài thư viện: lọc executor/platform/quyền theo target trước, E5 mã hóa query, FAISS tìm ngữ nghĩa trên tập hợp lệ, RRF kết hợp exact/keyword/dense. SQLite trả toàn bộ bản ghi gốc cho Gemini chọn. Nguồn adversary xung đột, thiếu tham chiếu hoặc có bước không tương thích target không được reuse.')
    d.para('Giới hạn: lọc kỹ thuật hiện kiểm tra platform và quyền được khai báo; chưa chứng minh scope/đích bên trong mọi lệnh. Chất lượng xếp hạng tiếng Việt và độ bao phủ mục tiêu phải đánh giá bằng tập câu hỏi/expected candidates sau khi tạo index.')
    if 'semantic' in images:
        d.para('Kiểm tra hybrid thực tế với câu tiếng Việt không chứa ID: E5 mã hóa query, FAISS tìm ứng viên phù hợp target rồi kết hợp keyword bằng RRF. Đây là một kiểm tra hoạt động, chưa phải đánh giá chất lượng trên tập dữ liệu đầy đủ.')
        d.image(images['semantic'], 'Hình 5b. Kết quả hybrid E5/FAISS thực tế từ chỉ mục đã tạo.')
    d.page('6. Nối workflow và vì sao có thể tự động')
    d.para('LangGraph nhận trạng thái và chạy node theo cạnh. Python gọi Gemini ở parse/build_plan; các node còn lại đọc catalog và kiểm tra bằng mã. Sau mỗi node, ứng dụng lưu state.json và tự chuyển node tiếp theo theo trường next. Người dùng không phải gọi từng bước thủ công.')
    d.para('Luồng: parse → validate_request → retrieve → build_plan → validate_plan → finalize. Request/plan sai được sửa tối đa 2 lượt tạo; không đủ thông tin thì trả câu hỏi; không ứng viên thì kết thúc; HTTP 429 lưu waiting_quota để người dùng tiếp tục sau.')
    d.para('Checkpoint là JSON do ứng dụng quản lý, không phải backend SQLite checkpoint của LangGraph. Resume kiểm tra fingerprint target/catalog/schema/model; thay đầu vào thì phải chạy lượt mới. Crash giữa API call có thể phát sinh gọi lại khi resume.')
    d.command('.venv/bin/python scripts/demo_offline_nodes.py')
    d.image(images['nodes'], 'Hình 6. Kiểm thử sáu hàm node với LLM fixture; không chạy LangGraph/Gemini.')
    d.para('Plan mẫu fixture có nhãn OFFLINE FIXTURE, không phải kết quả sinh bởi AI. completed chỉ nghĩa là xuất plan; readiness vẫn needs_information. Bài test LangGraph thực tế được ghi skipped nếu chưa có thư viện.')
    d.page('7. Kiểm thử và kiểm tra kịch bản nguồn')
    d.command('.venv/bin/python -m unittest discover -s tests -v')
    d.image(images['tests'], 'Hình 7. Kết quả kiểm thử thực tế, bao gồm dòng skipped nếu có.')
    d.para('Bao phủ: request schema strict; câu hỏi khi thiếu scope; executor Windows và quyền Elevated; adversary xung đột; exact ID; fingerprint corpus; plan fixture hợp lệ; ID/technique/source/fact bịa; bằng chứng verified giả; giới hạn test/reuse; quota lưu checkpoint. Bài LangGraph dùng fixture LLM và không chứng minh Gemini hoạt động.')
    d.para(f'Đối chiếu hash trước và sau các lệnh xác minh: {len(after)} file nguồn, unchanged={unchanged}. Bằng chứng tại scenario_integrity.json. Script không chỉnh sửa YAML gốc hoặc DB catalog.')
    d.page('8. Việc còn lại và cách chạy tiếp')
    d.para('1) Cài đủ dependency bằng lệnh ở bước 2; chạy doctor để kiểm tra. 2) Cấu hình key của project Free tier trên máy. 3) Build index E5/FAISS. 4) Chạy lại tests để xác nhận bài LangGraph. 5) Gọi workflow thật và đánh giá request/plan theo yêu cầu tiếng Việt. 6) Bổ sung bộ kiểm chứng scope, dependencies, quyền/facts trước khi mở readiness ready_for_review.')
    d.command(".venv/bin/python -m scenario_agent run --text 'Khảo sát thông tin người dùng Windows trên endpoint để đánh giá SOC, tối đa 1 test.'")
    d.para('Khi hỏi lại: dùng resume RUN_ID --clarification với câu trả lời. Khi quota: đợi hạn mức phục hồi rồi resume RUN_ID. Đầu ra thật nằm trong outputs/runs/<run_id>/. Không chụp .env, key hoặc thông tin xác thực khi bổ sung ảnh báo cáo.')
    d.para('Sau khi cài và kiểm thử thành công, lưu dependency versions bằng pip freeze. Kiểm chứng tương thích SDK và chất lượng AI vẫn là việc cần làm; báo cáo này không khẳng định ba tích hợp chưa chạy đã thành công.')
    d.para('Tài liệu tham chiếu chính thức (đã tra cứu trong phiên triển khai):')
    for link in ['https://ai.google.dev/gemini-api/docs/api-key', 'https://ai.google.dev/gemini-api/docs/pricing', 'https://googleapis.github.io/python-genai/', 'https://docs.langchain.com/oss/python/langgraph/graph-api', 'https://huggingface.co/intfloat/multilingual-e5-small']:
        d.para(link, 'Caption')
    d.save(OUT)
    with zipfile.ZipFile(OUT) as archive:
        assert archive.testzip() is None
        for name in archive.namelist():
            if name.endswith('.xml') or name.endswith('.rels'): ET.fromstring(archive.read(name))
    summary = {'report': str(OUT), 'bytes': OUT.stat().st_size, 'images': len(d.images),
               'scenario_files': len(after), 'scenarios_unchanged': unchanged,
               'commands': {k: v['exit_code'] for k, v in records.items()},
               'xml_and_zip_valid': True, 'live_gemini_tested': False}
    (REPORT / 'report_validation.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if unchanged and all(records[k]['exit_code'] == 0 for k in ('doctor', 'corpus', 'retrieval', 'tests', 'nodes')) else 1

if __name__ == '__main__':
    raise SystemExit(main())
