"""Readable run directories, stable UUID identity and legacy checkpoint lookup."""
import copy
import json
from datetime import datetime
from pathlib import Path
import re
import unicodedata
import uuid
from zoneinfo import ZoneInfo
from .config import write_json

LOCAL_TIMEZONE = ZoneInfo('Asia/Ho_Chi_Minh')
SAFE_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,159}')


def now_iso():
    return datetime.now(LOCAL_TIMEZONE).isoformat(timespec='seconds')


def goal_slug(text):
    value = str(text).lower().replace('đ', 'd')
    value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode()
    value = re.sub(r'[^a-z0-9]+', ' ', value).strip()
    value = re.sub(r'^(?:toi muon|toi can|hay|giup toi)\s+', '', value)
    # Remove narrative SOC wrappers before truncation, preserving the action.
    if re.match(r'^(?:danh gia|kiem tra).*\bsoc\b', value):
        parts = re.split(r'\b(?:hanh vi|khi|viec)\b', value, maxsplit=1)
        if len(parts) == 2:
            value = parts[1].strip()
    value = re.sub(r'^(?:(?:mot )?chuong trinh|hanh vi)\s+', '', value)
    value = re.sub(r'^(?:thu khai thac loi|khai thac loi|thu khai thac|thu)\s+', '', value)
    value = re.split(r'\b(?:de danh gia|nham danh gia|toi da|tren endpoint|trong lab)\b', value, maxsplit=1)[0]
    value = re.sub(r'\b(?:thong tin|noi dung|da cai dat|cac|nhung|roi|sau do)\b', '', value)
    words = value.split()[:12]
    return '-'.join(words)[:64].rstrip('-') or 'scenario'


def scenario_label(state):
    """Name the requested behaviors, never infer intent from an unvalidated plan."""
    descriptions = [b.get('description', '') for b in
                    (state.get('behavior_analysis') or {}).get('behaviors', [])]
    labels = descriptions or [(state.get('request') or {}).get('objective') or state.get('text') or 'scenario']
    text = state.get('text', '').casefold()
    contexts = [s['name'] for s in state.get('target', {}).get('services', [])
                if s.get('url') and s.get('name') and s['name'].casefold() in text]
    parts = []
    for label in labels:
        for context in contexts:
            label = re.sub(r'(?i)\b' + re.escape(context) + r'\b', '', label)
        label = re.sub(r'(?i)\s+trên\s+(?:endpoint|máy|ứng dụng)\b[^,.;]*', '', label)
        label = re.sub(r'(?i)\s+trong\s+(?:lab|môi trường)\b[^,.;]*', '', label)
        parts.append(goal_slug(label))
    return goal_slug(' '.join(contexts + parts))



def folder_name(text, run_id, created_at):
    identifier = str(uuid.UUID(run_id))
    moment = datetime.fromisoformat(created_at)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=LOCAL_TIMEZONE)
    stamp = moment.astimezone(LOCAL_TIMEZONE).strftime('%Y%m%d_%H%M%S')
    return f'{stamp}_{goal_slug(text)}_{identifier[:8]}'


def child_directory(runs, name):
    if not isinstance(name, str) or not SAFE_NAME.fullmatch(name):
        raise ValueError('Run folder must be a single safe directory name')
    base = Path(runs).resolve()
    directory = base / name
    if directory.resolve().parent != base:
        raise ValueError('Run directory escapes outputs/runs')
    return directory


def state_directory(runs, state):
    identifier = str(uuid.UUID(state['run_id']))
    return child_directory(runs, state.get('run_folder', identifier))


def ensure_directory(runs, state):
    """Reserve a folder before writes; never overwrite another UUID's files."""
    identifier = str(uuid.UUID(state['run_id']))
    first = state.get('run_folder', identifier)
    candidates = [first]
    if first != identifier and first.endswith('_' + identifier[:8]):
        candidates.append(first.rsplit('_', 1)[0] + '_' + identifier)
    Path(runs).mkdir(parents=True, exist_ok=True)
    for name in candidates:
        directory = child_directory(runs, name)
        try:
            directory.mkdir()
        except FileExistsError:
            checkpoint = directory / 'state.json'
            if checkpoint.is_file():
                existing = json.loads(checkpoint.read_text(encoding='utf-8'))
                if existing.get('run_id') == identifier:
                    state['run_folder'] = name
                    return directory
            continue
        state['run_folder'] = name
        write_json(directory / 'state.json', state)
        return directory
    raise FileExistsError('Run folder already belongs to another or incomplete run')


def save_state(runs, state):
    directory = ensure_directory(runs, state)
    write_json(directory / 'state.json', state)
    return directory


def load_run(runs, identifier):
    child_directory(runs, identifier)  # Reject traversal before any lookup.
    try:
        canonical = str(uuid.UUID(identifier))
    except ValueError:
        canonical = None
    base = Path(runs).resolve()
    candidates = [base / identifier]
    if canonical:
        candidates += [base / canonical]
        candidates += list(base.glob('*_' + canonical[:8]))
        candidates += list(base.glob('*_' + canonical))
    elif not (base / identifier / 'state.json').is_file():
        # Readable names may have been refined after intent extraction.
        for checkpoint in base.glob('*/state.json'):
            child_directory(base, checkpoint.parent.name)
            saved = json.loads(checkpoint.read_text(encoding='utf-8'))
            if identifier in saved.get('run_folder_aliases', []):
                candidates.append(checkpoint.parent)
    found = {}
    for directory in candidates:
        directory = child_directory(base, directory.name)
        checkpoint = directory / 'state.json'
        if not checkpoint.is_file():
            continue
        state = json.loads(checkpoint.read_text(encoding='utf-8'))
        actual_id = str(uuid.UUID(state['run_id']))
        if canonical and actual_id != canonical:
            continue
        state['run_folder'] = directory.name
        found[directory] = state
    if not found:
        raise LookupError('No checkpoint found for UUID or folder name')
    if len(found) != 1:
        raise ValueError('Multiple folders share this UUID; specify the folder name')
    directory, state = next(iter(found.items()))
    return state, directory


def _relocate_run(runs, state, source, name):
    updated = copy.deepcopy(state)
    destination = child_directory(runs, name)
    if destination != source and destination.exists():
        fallback = name.rsplit('_', 1)[0] + '_' + str(uuid.UUID(state['run_id']))
        destination = child_directory(runs, fallback)
        name = fallback
        if destination.exists():
            raise FileExistsError('Destination already exists; no folder was overwritten')
    updated['run_folder'] = name
    if updated.get('output'):
        updated['output'] = str(destination / Path(updated['output']).name)
    moved = destination != source
    if moved:
        aliases = updated.setdefault('run_folder_aliases', [])
        if source.name not in aliases:
            aliases.append(source.name)
        source.rename(destination)
    try:
        write_json(destination / 'state.json', updated)
    except Exception:
        if moved:
            destination.rename(source)
        raise
    return updated, destination, moved


def name_from_behaviors(runs, state):
    """Called by the owning workflow after its first meaningful analysis."""
    if state.get('run_naming_version') == 2:
        return
    source = ensure_directory(runs, state)
    label = scenario_label(state)
    proposed = dict(state, goal_label=label, run_naming_version=2)
    name = folder_name(label, state['run_id'], state['created_at'])
    updated, _, _ = _relocate_run(runs, proposed, source, name)
    state.update(updated)


def rename_run(runs, identifier, refresh_goal=False):
    state, source = load_run(runs, identifier)
    if state.get('status') == 'running':
        raise ValueError('Wait for the active run to stop before renaming it')
    updated = copy.deepcopy(state)
    if not updated.get('created_at'):
        # Older checkpoints have no creation timestamp. Use the oldest saved
        # artifact rather than the time a later repair rewrote state.json.
        times = [(source / name).stat().st_mtime for name in
                 ('state.json', 'user_request.json', 'retrieval.json', 'scenario_plan.yml')
                 if (source / name).is_file()]
        updated['created_at'] = datetime.fromtimestamp(min(times), LOCAL_TIMEZONE).isoformat(timespec='seconds')
    label = scenario_label(updated) if refresh_goal else (updated.get('request') or {}).get('objective') or updated.get('text') or 'scenario'
    # Keep an already readable name stable, including its timestamp/goal.
    current_is_readable = re.match(r'^\d{8}_\d{6}_.+_', source.name)
    name = source.name if current_is_readable and not refresh_goal else folder_name(label, updated['run_id'], updated['created_at'])
    if refresh_goal:
        updated.update(goal_label=label, run_naming_version=2)
    updated, destination, moved = _relocate_run(runs, updated, source, name)
    name = updated['run_folder']
    return {'run_id': updated['run_id'], 'run_folder': name,
            'previous_folder': str(source), 'folder': str(destination),
            'renamed': moved, 'output': updated.get('output')}
