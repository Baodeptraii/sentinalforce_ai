"""E5 passage/query encoding, FAISS cosine search and catalog-backed RRF.

Keyword mode is explicit and can run offline; it is not semantic retrieval.
"""
import json
import re
from pathlib import Path
from collections import Counter
import numpy as np
from .catalog import ability, adversary, compatible_executors, connect, corpus, technique_abilities
from .config import digest, sha256, write_json
from .behaviors import significant_tokens
from .intent_evidence import INTENT_VERSION, process_requirement, process_evidence
import math

def prepare(config):
    before = sha256(config.catalog)
    passages, excluded = corpus(config.catalog)
    if sha256(config.catalog) != before:
        raise ValueError('Catalog changed during corpus build; retry')
    config.index.mkdir(parents=True, exist_ok=True)
    write_json(config.index / 'passages.json', passages)
    write_json(config.index / 'corpus_manifest.json', {
        'format_version': 1, 'catalog_sha256': before, 'passages_sha256': digest(passages),
        'passages': len(passages), 'excluded': excluded})
    return {'passages': len(passages), 'abilities': sum(p['kind'] == 'ability' for p in passages),
            'adversaries': sum(p['kind'] == 'adversary' for p in passages), 'excluded': len(excluded),
            'embeddings_created': False}

def load_corpus(config):
    manifest = json.loads((config.index / 'corpus_manifest.json').read_text())
    passages = json.loads((config.index / 'passages.json').read_text())
    if manifest['catalog_sha256'] != sha256(config.catalog) or manifest['passages_sha256'] != digest(passages):
        raise ValueError('Stale/corrupt corpus. Run prepare-corpus and build-index again')
    return passages, manifest

def model_snapshot_revision(config, revision=None):
    """Resolve the public Hub cache path, independent of Transformers internals.

    Keep the snapshot path lexical: resolving its symlink would point into blobs
    and lose the repository commit. Resolve a branch once, then pin all loads.
    """
    from huggingface_hub import hf_hub_download, try_to_load_from_cache
    requested = revision or config.embedding_revision or 'main'
    cached = try_to_load_from_cache(config.embedding_model, 'modules.json',
                                    cache_dir=str(config.cache), revision=requested)
    if not isinstance(cached, str):
        cached = hf_hub_download(config.embedding_model, 'modules.json',
                                 cache_dir=str(config.cache), revision=requested)
    path = Path(cached)
    commit = path.parent.name
    if path.parent.parent.name != 'snapshots' or re.fullmatch(r'[0-9a-f]{40}', commit) is None:
        raise ValueError('Cannot identify a pinned Hugging Face snapshot from modules.json')
    return commit

def encoder(config, revision=None):
    from sentence_transformers import SentenceTransformer
    pinned = revision or model_snapshot_revision(config)
    options = {'revision': pinned, 'cache_folder': str(config.cache),
               'device': 'cpu', 'trust_remote_code': False}
    try:
        return SentenceTransformer(config.embedding_model, local_files_only=True, **options)
    except OSError:
        # A partial snapshot may still need weights/tokenizer files, using the
        # same pinned commit rather than silently resolving a newer branch.
        return SentenceTransformer(config.embedding_model, local_files_only=False, **options)

def build_index(config):
    import faiss
    passages, corpus_manifest = load_corpus(config)
    resolved_revision = model_snapshot_revision(config)
    model = encoder(config, resolved_revision)
    vectors = model.encode(['passage: ' + p['text'] for p in passages],
                           batch_size=16, normalize_embeddings=True, show_progress_bar=True)
    vectors = np.asarray(vectors, dtype=np.float32)
    index = faiss.IndexFlatIP(vectors.shape[1])
    index.add(vectors)
    faiss.write_index(index, str(config.index / 'index.faiss'))
    np.save(config.index / 'embeddings.npy', vectors, allow_pickle=False)
    write_json(config.index / 'index_manifest.json', {
        'format_version': 1, 'catalog_sha256': corpus_manifest['catalog_sha256'],
        'passages_sha256': corpus_manifest['passages_sha256'], 'model': config.embedding_model,
        'model_revision': resolved_revision,
        'dimension': int(vectors.shape[1]), 'count': len(passages), 'normalized': True,
        'prefixes': ['passage: ', 'query: '],
        'files': {name: sha256(config.index / name) for name in ('index.faiss', 'embeddings.npy')}})
    return {'vectors': len(passages), 'dimension': int(vectors.shape[1]), 'model': config.embedding_model}

def tokens(text):
    return set(re.findall(r'[\w.:-]+', text.lower()))

def load_index(config):
    import faiss
    passages, cm = load_corpus(config)
    manifest = json.loads((config.index / 'index_manifest.json').read_text())
    if any(manifest[k] != cm[k] for k in ('catalog_sha256', 'passages_sha256')) or manifest['model'] != config.embedding_model:
        raise ValueError('Stale index or different E5 model; rebuild index')
    if re.fullmatch(r'[0-9a-f]{40}', manifest['model_revision']) is None:
        raise ValueError('Invalid pinned E5 revision')
    if config.embedding_revision and config.embedding_revision != manifest['model_revision']:
        raise ValueError('E5 revision differs from index; rebuild index')
    for name in ('index.faiss', 'embeddings.npy'):
        if sha256(config.index / name) != manifest['files'][name]:
            raise ValueError('Index fingerprint mismatch: ' + name)
    index = faiss.read_index(str(config.index / 'index.faiss'))
    vectors = np.load(config.index / 'embeddings.npy', allow_pickle=False)
    if (vectors.ndim != 2 or index.ntotal != len(passages) or len(vectors) != len(passages)
            or index.d != vectors.shape[1] or manifest['dimension'] != index.d
            or manifest['count'] != index.ntotal):
        raise ValueError('Index/mapping size mismatch')
    if not np.isfinite(vectors).all() or not np.allclose(np.linalg.norm(vectors, axis=1), 1, atol=1e-4):
        raise ValueError('Invalid or unnormalized E5 embeddings')
    return manifest, index, vectors

def check_index(config):
    manifest, index, vectors = load_index(config)
    return {'index_valid': True, 'vectors': index.ntotal, 'dimension': index.d,
            'model': manifest['model'], 'model_revision': manifest['model_revision'],
            'fingerprints_valid': True, 'vectors_normalized': True}

def eligible(config, passages, target, request):
    result = {}
    with connect(config.catalog) as db:
        for i, passage in enumerate(passages):
            try:
                if passage['kind'] == 'ability':
                    record = ability(db, passage['id'])
                    if compatible_executors(record, target):
                        result[i] = record
                else:
                    record = adversary(db, passage['id'])
                    compatible = [a['canonical_id'] for a in record['abilities'] if compatible_executors(a, target)]
                    if compatible:
                        limit = request.get('max_tests')
                        record['compatible_ordering'] = compatible
                        record['reuse_eligible'] = (len(compatible) == len(record['ordering'])
                                                   and (limit is None or len(record['ordering']) <= limit))
                        record['adaptation_required'] = not record['reuse_eligible']
                        result[i] = record
            except LookupError:
                continue
    return result

def retrieve(config, request, target, mode='hybrid', limit=8):
    if mode not in ('keyword', 'hybrid'):
        raise ValueError('Retrieval mode must be keyword or hybrid')
    passages, cm = load_corpus(config)
    candidates = eligible(config, passages, target, request)
    query = request['text'] + ' ' + str(request.get('objective') or '') + ' ' + ' '.join(request.get('requested_techniques', []))
    query_tokens = tokens(query)
    kw = {i: len(query_tokens & tokens(passages[i]['text'])) for i in candidates}
    exact_ids = set(re.findall(r'[a-fA-F0-9]{8}-[a-fA-F0-9-]{27,}', query))
    # Resolve original Atomic GUIDs to canonical catalog IDs before exact boost.
    with connect(config.catalog) as db:
        exact_techniques = technique_abilities(db, request.get('requested_techniques', []), target)
        for ref in list(exact_ids):
            try:
                exact_ids.add(ability(db, ref)['canonical_id'])
            except LookupError:
                pass
    ability_indices = {passages[i]['id']: i for i in candidates if passages[i]['kind'] == 'ability'}
    technique_indices = {}
    for technique, records in exact_techniques.items():
        if any(identifier not in ability_indices for identifier in records):
            raise ValueError('Technique lookup missing from eligible corpus; rebuild corpus/index')
        technique_indices[technique] = [ability_indices[identifier] for identifier in records]
    dense = {}
    behavior_dense = {}
    behaviors = request.get('_behavior_queries', [])
    if mode == 'hybrid':
        import faiss
        manifest, full_index, vectors = load_index(config)
        if candidates:
            ids = np.array(list(candidates), dtype=np.int64)
            # Apply SQL-backed eligibility before FAISS nearest-neighbour search.
            subset = faiss.IndexIDMap(faiss.IndexFlatIP(vectors.shape[1]))
            subset.add_with_ids(np.ascontiguousarray(vectors[ids]), ids)
            queries = [query] + [b['query_en'] for b in behaviors]
            q = encoder(config, manifest['model_revision']).encode(['query: ' + value for value in queries], normalize_embeddings=True)
            scores, found = subset.search(np.asarray(q, dtype=np.float32), len(ids))
            dense = {int(i): float(s) for s, i in zip(scores[0], found[0]) if i >= 0}
            behavior_dense = {b['id']: {int(i): float(s) for s, i in zip(scores[n], found[n]) if i >= 0}
                              for n, b in enumerate(behaviors, 1)}
    output = {'mode': mode, 'catalog_sha256': cm['catalog_sha256'], 'eligible': len(candidates),
              'abilities': [], 'adversaries': [], 'execution_authorized': False}
    output['technique_lookup'] = {
        'requested': list(exact_techniques),
        'eligible_ids': {technique: list(records) for technique, records in exact_techniques.items()},
        'missing_compatible': [technique for technique, records in exact_techniques.items() if not records]}
    for kind, out_key in (('ability', 'abilities'), ('adversary', 'adversaries')):
        members = [i for i in candidates if passages[i]['kind'] == kind]
        ranks = Counter()
        for scores in (kw, dense):
            ranked = sorted((i for i in members if i in scores and (scores is not kw or scores[i] > 0)), key=lambda i: (-scores[i], i))
            for rank, i in enumerate(ranked, 1):
                ranks[i] += 1 / (60 + rank)
        for i in members:
            if passages[i]['id'] in exact_ids:
                ranks[i] += 100
        pinned = set()
        if kind == 'ability':
            for indices in technique_indices.values():
                for i in indices:
                    ranks[i] += 50
                if indices:
                    pinned.add(min(indices, key=lambda i: (-ranks[i], i)))
            pinned.update(i for i in members if passages[i]['id'] in exact_ids)
        # Reserve at least one candidate per available requested technique and
        # every explicit ability ID. The normal limit is a soft retrieval budget,
        # independent of the maximum tests permitted in the final plan.
        ordered = sorted(ranks, key=lambda i: (-ranks[i], i))
        selected = sorted(pinned, key=lambda i: (-ranks[i], i))
        selected += [i for i in ordered if i not in pinned][:max(0, limit - len(selected))]
        for i in selected:
            output[out_key].append({'score': ranks[i], 'record': candidates[i]})
    if behaviors:
        members = [i for i in candidates if passages[i]['kind'] == 'ability']
        # English query rewriting plus command-aware BM25. Source YAML/vector
        # files stay unchanged; generic Vietnamese wrapper words cannot dominate
        # each individual behavior's lexical ranking.
        docs = {i: Counter(significant_tokens(
            str(candidates[i]['ability'].get('name') or '') + ' ' +
            str(candidates[i]['ability'].get('description') or '') + ' ' +
            ' '.join(str(ex.get('command') or ex.get('code') or '')
                     for ex in compatible_executors(candidates[i], target)))) for i in members}
        df = Counter(token for doc in docs.values() for token in doc)
        avg = sum(sum(doc.values()) for doc in docs.values()) / max(1, len(docs)) or 1
        output['behavior_candidates'] = {}
        output['behavior_retrieval_version'] = INTENT_VERSION
        output['intent_candidates'] = {}
        existing = {x['record']['canonical_id'] for x in output['abilities']}
        explicit = {i for i in members if passages[i]['id'] in exact_ids}
        for item in output['adversaries']:
            if item['record']['id'] in exact_ids:
                explicit.update(ability_indices[a['canonical_id']] for a in item['record']['abilities'] if a['canonical_id'] in ability_indices)
        for behavior in behaviors:
            terms = significant_tokens(behavior['query_en'] + ' ' + ' '.join(behavior['keywords']))
            lexical = {}
            for i, doc in docs.items():
                length = sum(doc.values())
                score = sum(math.log(1 + (len(docs) - df[t] + .5) / (df[t] + .5)) *
                            doc[t] * 2.2 / (doc[t] + 1.2 * (.25 + .75 * length / avg))
                            for t in terms if doc[t])
                if score: lexical[i] = score
            ranks = Counter()
            for scores in (lexical, behavior_dense.get(behavior['id'], {})):
                for rank, i in enumerate(sorted((i for i in scores if i in docs), key=lambda i: (-scores[i], i)), 1):
                    ranks[i] += 1 / (60 + rank)
            # Reserve bounded slots for literal parent/child launches in eligible
            # source commands. Actor names alone are not evidence of a launch.
            relation = process_requirement(behavior)
            direct = {}
            if relation:
                for i in members:
                    for ex in compatible_executors(candidates[i], target):
                        command = str(ex.get('command') or ex.get('code') or '')
                        proof = process_evidence(command, ex['name'], relation)
                        if proof and len(command) <= 16000:
                            dependencies = len(ex.get('payloads') or []) + len(re.findall(r'(?i)PathToAtomicsFolder|Invoke-AtomicTest', command))
                            direct[i] = (command.count('#{') + dependencies, len(command), proof)
                            break
            reserved = sorted(direct, key=lambda i: (direct[i][0], direct[i][1], i))[:3]
            selected = reserved + [i for i in sorted(ranks, key=lambda i: (-ranks[i], i)) if i not in reserved][:6-len(reserved)]
            output['intent_candidates'][behavior['id']] = [
                {'ability_id': candidates[i]['canonical_id'], 'evidence': direct[i][2]} for i in reserved]
            selected += sorted(explicit - set(selected))
            output['behavior_candidates'][behavior['id']] = [candidates[i]['canonical_id'] for i in selected]
            for i in selected:
                record = candidates[i]
                if record['canonical_id'] not in existing:
                    output['abilities'].append({'score': ranks[i], 'record': record})
                    existing.add(record['canonical_id'])
    return output
