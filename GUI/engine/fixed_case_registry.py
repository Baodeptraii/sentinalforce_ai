"""Deterministic request-to-fixed-case mapping for the five demo scenarios.

Enforces by code (not prompt) that a request matching one of the five demo
groups resolves to the exact fixed scenario. The classifier never invents
content: it only selects a case_id; the plan content comes from the runtime's
fixed-case sources. Ambiguous or out-of-scope requests return None and fall
through to the normal LLM planning flow, which stays fully intact.
"""
import re
import unicodedata

SPEC_VERSION = 1


def _fold(text):
    return ''.join(c for c in unicodedata.normalize('NFKD', str(text).lower().replace('đ', 'd'))
                   if not unicodedata.combining(c))


# Each pattern must be a distinctive intent signal for exactly one case.
PATTERNS = {
    'EP-01': [
        r'ra quet.*thong tin may', r'liet ke (tien trinh|dich vu)', r'thong tin he dieu hanh',
        r'\bdiscovery\b', r'\bkiem ke\b', r'tien trinh.*dich vu',
    ],
    'EP-02': [
        r'\bransom\b', r'ma hoa gia', r'gia lap.*ransom', r'ransom note',
        r'(tao|them|sua|doi ten|xoa).*file.*(ma hoa|ransom)', r'ghi (vao )?file.*ransom',
        r'mo phong.*(thay doi|ransom).*file',
    ],
    'EP-03': [
        r'\bbeacon', r'heartbeat', r'\bexfil', r'trang (di|du) lieu', r'truyen (mot )?file',
        r'gui file.*receiver|receiver noi bo|gui.*receiver', r'lan truyen du lieu gia lap',
    ],
    'WEB-01': [
        r'sql injection', r'\bsqli\b', r'\bxss\b', r'cross.?site', r'\binjection\b.*dvwa|dvwa.*\binjection\b',
        r'probe union',
    ],
    'WEB-02': [
        r'brute.?force', r'dang nhap thu', r'thu (toi da )?\d* ?(lan|mat khau)', r'doan mat khau',
    ],
}

# Cases that must not both match; a request touching both goes to None (ambiguous).
MUTUALLY_EXCLUSIVE = (('WEB-01', 'WEB-02'),)


def classify_case(text):
    """Return {'case_id', 'matched_by': 'keyword'} or None. Never raises."""
    folded = _fold(text)
    scores = {}
    for case_id, patterns in PATTERNS.items():
        score = sum(1 for pattern in patterns if re.search(pattern, folded))
        if score:
            scores[case_id] = score
    if not scores:
        return None
    for left, right in MUTUALLY_EXCLUSIVE:
        if left in scores and right in scores:
            return None
    best = max(scores.values())
    winners = sorted(case for case, score in scores.items() if score == best)
    if len(winners) != 1:
        return None
    return {'case_id': winners[0], 'matched_by': 'keyword', 'spec_version': SPEC_VERSION}


def resolve_case(case_id):
    """Explicit UI selection. Returns the same mapping shape or raises ValueError."""
    from .runtime_fixed_cases import CASE_TITLES
    if case_id not in CASE_TITLES:
        raise ValueError('Mã case cố định không hợp lệ: ' + str(case_id))
    return {'case_id': case_id, 'matched_by': 'explicit', 'spec_version': SPEC_VERSION}


def case_titles():
    try:
        from .runtime_fixed_cases import CASE_TITLES
    except (ImportError, ValueError):
        return {}
    return dict(CASE_TITLES)
