"""Read a bounded tail on the manager. Emits metadata only, never event payloads."""
import json
import re
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path


def scan(spec):
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=spec['window_hours'])
    result = {'format': 'wazuh_observation_v1', 'checked_at': now.isoformat(),
              'agent_id': spec['agent_id'], 'hostname': spec['hostname'],
              'window_start': start.isoformat(), 'sources': [], 'samples': [],
              'counts': dict.fromkeys(['process_events', 'network_events', 'web_access_logs', 'wazuh_ingestion'], 0)}
    for filename in ['alerts/alerts.json', 'archives/archives.json']:
        path = Path('/var/ossec/logs') / filename
        entry = {'file': filename, 'status': 'unavailable', 'tail_only': True}
        result['sources'].append(entry)
        try:
            with path.open('rb') as stream:
                size = stream.seek(0, 2)
                offset = max(0, size - 8 * 1024 * 1024)
                stream.seek(offset)
                if offset: stream.readline()
                raw = stream.read(8 * 1024 * 1024)
            entry.update(status='read', bytes_read=len(raw), truncated=offset > 0)
        except OSError:
            continue
        for line in raw.splitlines():
            try:
                row = json.loads(line)
                agent = row.get('agent', {})
                if agent.get('id') != spec['agent_id'] or str(agent.get('name', '')).casefold() != spec['hostname'].casefold(): continue
                stamp = datetime.fromisoformat(re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', row['timestamp'].replace('Z', '+00:00')))
                if stamp.tzinfo is None or not start <= stamp <= now + timedelta(seconds=120): continue
                system = row.get('data', {}).get('win', {}).get('system', {})
                channel = system.get('channel', '')
                event = str(system.get('eventID', ''))
                location = row.get('location', '')
                fields = []
                if channel.casefold() == 'microsoft-windows-sysmon/operational':
                    if event == '1': fields.append('process_events')
                    if event == '3': fields.append('network_events')
                if location.replace('\\', '/').casefold() in [p.replace('\\', '/').casefold() for p in spec['web_log_paths']]:
                    fields.append('web_access_logs')
                # Agent status/vulnerability inventory alone is not proof of log ingestion.
                if fields or channel: fields.append('wazuh_ingestion')
                for field in fields:
                    result['counts'][field] += 1
                    existing = [s for s in result['samples'] if s['field'] == field]
                    sample = {'field': field, 'timestamp': stamp.isoformat(), 'agent_id': agent['id'],
                              'agent_name': agent['name'], 'channel': channel[:120], 'event_id': event[:16],
                              'location': location[:260], 'source': filename}
                    if not existing: result['samples'].append(sample)
                    elif sample['timestamp'] > existing[0]['timestamp']:
                        result['samples'].remove(existing[0]); result['samples'].append(sample)
            except (ValueError, TypeError, KeyError, AttributeError):
                continue
    return result


if __name__ == '__main__':
    print(json.dumps(scan(json.loads(sys.argv[1]))))
