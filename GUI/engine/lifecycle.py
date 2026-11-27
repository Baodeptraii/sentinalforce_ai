"""Local lifecycle primitives; these functions never contact the lab."""
import os
import json
from pathlib import Path


class Cancelled(RuntimeError):
    pass


def check_cancel(directory):
    if (Path(directory) / 'cancel.requested').exists():
        raise Cancelled('Survey cancelled; inspect operation summary for cleanup status.')


def pending_recovery(outputs):
    """Read local journals only; never automatically resume/restore an operation."""
    pending = []
    for path in Path(outputs).glob('*/caldera/summary.json'):
        try:
            value = json.loads(path.read_text(encoding='utf-8'))
            unresolved = value.get('cleanup_required', not value.get('group_restored', False))
            if unresolved:
                pending.append({'run_id': path.parent.parent.name, 'target_ip': value.get('expected_ip'),
                                'paw': value.get('paw'), 'operation_id': value.get('operation_id'),
                                'journal': str(path), 'reason': 'Cleanup not confirmed; reconcile before another survey.'})
        except (ValueError, OSError):
            pending.append({'run_id': path.parent.parent.name, 'target_ip': None, 'journal': str(path), 'reason': 'Unreadable cleanup journal'})
    for path in Path(outputs).glob('*/recovery_required.json'):
        try:
            if json.loads(path.read_text(encoding='utf-8')).get('resolved_at'): continue
        except (OSError, ValueError): pass
        if not any(row['run_id'] == path.parent.name for row in pending):
            pending.append({'run_id': path.parent.name, 'target_ip': None, 'journal': str(path), 'reason': 'Watchdog interrupted runner; manual reconciliation required'})
    return pending


class InstanceLock:
    """Advisory process lock on Ubuntu, released by the OS after a crash."""
    def __init__(self, path):
        self.path = Path(path)
        self.file = None

    def __enter__(self):
        import fcntl
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = self.path.open('a+')
        try:
            fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            raise RuntimeError('Another Survey Console/runner owns this lock: ' + str(self.path)) from None
        self.file.seek(0); self.file.truncate(); self.file.write(str(os.getpid())); self.file.flush()
        return self

    def __exit__(self, *args):
        self.file.close()


def endpoint_runner_path(address):
    import ipaddress
    return Path.home()/'.cache/datn-survey'/('endpoint-'+str(ipaddress.ip_address(address))+'.lock')


def endpoint_activity_path(address):
    import ipaddress
    return Path.home()/'.cache/datn-survey'/('activity-'+str(ipaddress.ip_address(address))+'.lock')
