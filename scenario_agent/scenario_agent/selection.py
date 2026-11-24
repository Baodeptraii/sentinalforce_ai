"""Conservative source-chain editing rules; never rewrites source YAML."""
import re
import unicodedata


def plain(text):
    return ''.join(c for c in unicodedata.normalize('NFKD', str(text).lower().replace('đ', 'd'))
                   if not unicodedata.combining(c))


def check_adaptation(chains, ordering, request):
    if len(chains) != 1:
        raise ValueError('Adaptation must cite exactly one source adversary')
    chain = chains[0]
    original = chain['ordering']
    # v0.1 adaptation supports deleting steps while preserving source order.
    # New/replaced/reordered steps must use compose and explain the changes.
    remaining = iter(original)
    if not ordering or not all(any(ref == current for current in remaining) for ref in ordering):
        raise ValueError('Adapt must retain an ordered subsequence of its cited source; use compose for a new chain')
    text = plain(request['text'] + ' ' + ' '.join(request.get('constraints', {}).get('additional_constraints', [])))
    keep_rest = any(phrase in text for phrase in ('giu nguyen cac buoc con lai', 'khong them hoac thay the', 'keep remaining'))
    if not keep_rest:
        return
    # Resolve removal references conservatively by canonical ID, step number,
    # or a distinctive token shared with exactly one source ability name.
    removed = set()
    clauses = re.findall(r'(?:loai bo|bo|remove|drop)\s+([^.;,\n]+)', text)
    for clause in clauses:
        clause = re.split(r'\b(?:giu|keep|khong)\b', clause)[0]
        numbered = re.search(r'(?:buoc|step)\s+(\d+)\b', clause)
        if numbered and 1 <= int(numbered[1]) <= len(original):
            removed.add(original[int(numbered[1]) - 1])
            continue
        exact = [ref for ref in original if ref in clause]
        if exact:
            removed.update(exact)
            continue
        tokens = set(re.findall(r'[a-z0-9]+', clause)) - {'dung', 'buoc', 'cua', 'dau', 'tien', 'the', 'first', 'step', 'only'}
        matches = [a['canonical_id'] for a in chain['abilities']
                   if tokens & set(re.findall(r'[a-z0-9]+', plain(a['ability']['name'])))]
        if len(matches) == 1:
            removed.add(matches[0])
    if not removed:
        raise ValueError('Cannot resolve the requested removal while preserving remaining steps; clarify step ID or number')
    if ordering != [ref for ref in original if ref not in removed]:
        raise ValueError('Adapt violates requested removal/preserve-remaining constraint')
