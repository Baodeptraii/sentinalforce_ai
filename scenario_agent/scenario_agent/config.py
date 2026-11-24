import hashlib
import json
import os
from pathlib import Path
from dataclasses import dataclass
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]

def sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    temp.replace(path)

@dataclass
class Config:
    root: Path = ROOT

    def __post_init__(self):
        self.root = Path(self.root).resolve()
        load_dotenv(self.root / '.env', override=False)
        self.catalog = self.root / 'data/catalog.sqlite'
        self.index = self.root / 'data/rag'

        self.runs = self.root / 'outputs/runs'
        self.model = os.getenv('GEMINI_MODEL', 'gemini-3.8-flash')
        self.embedding_model = os.getenv('E5_MODEL', 'intfloat/multilingual-e5-small')
        self.embedding_revision = os.getenv('E5_REVISION') or None
        self.cache = self.root / '.cache/huggingface'
        self.free_confirmed = os.getenv('GEMINI_FREE_TIER_CONFIRMED', '').lower() == 'true'

    def contract_hash(self):
        return digest({p.name: sha256(p) for p in (self.root / 'input/schema').glob('*schema*')})
