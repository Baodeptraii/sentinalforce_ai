"""E5 passage/query encoding, FAISS cosine search and catalog-backed RRF.

Keyword mode is explicit and can run offline; it is not semantic retrieval.
"""
import json
import re
from pathlib import Path
from collections import Counter
import numpy as np
from .catalog import ability, adversary, compatible_executors, connect, corpus
from .config import digest, sha256, write_json

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
                    # A complete chain must fit the target; don't silently drop steps.
                    if all(compatible_executors(a, target) for a in record['abilities']):
                        limit = request.get('max_tests')
                        if limit is None or len(record['ordering']) <= limit:
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
        for ref in list(exact_ids):
            try:
                exact_ids.add(ability(db, ref)['canonical_id'])
            except LookupError:
                pass
    dense = {}
    if mode == 'hybrid':
        import faiss
        manifest, full_index, vectors = load_index(config)
        if candidates:
            ids = np.array(list(candidates), dtype=np.int64)
            # Apply SQL-backed eligibility before FAISS nearest-neighbour search.
            subset = faiss.IndexIDMap(faiss.IndexFlatIP(vectors.shape[1]))
            subset.add_with_ids(np.ascontiguousarray(vectors[ids]), ids)
            q = encoder(config, manifest['model_revision']).encode(['query: ' + query], normalize_embeddings=True)
            scores, found = subset.search(np.asarray(q, dtype=np.float32), len(ids))
            dense = {int(i): float(s) for s, i in zip(scores[0], found[0]) if i >= 0}
    output = {'mode': mode, 'catalog_sha256': cm['catalog_sha256'], 'eligible': len(candidates),
              'abilities': [], 'adversaries': [], 'execution_authorized': False}
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
        for i, score in sorted(ranks.items(), key=lambda item: (-item[1], item[0]))[:limit]:
            output[out_key].append({'score': score, 'record': candidates[i]})
    return output
