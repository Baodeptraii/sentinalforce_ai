"""Small bounded Chat Completions tool-calling adapter; compatible gateways/Ollama.

No model default: the operator explicitly configures a tool-capable model.
"""
import json
import copy
import os
import re
import time
import hashlib
import uuid
from .llm_budget import module as budget_module
from .network_io import read_limited
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class LLMError(RuntimeError):
    def __init__(self, message, http_status=None, provider_status=None, retry_at=None, budget_reason=None, details=None):
        super().__init__(message)
        self.retry_at=retry_at
        self.budget_reason=budget_reason
        self.details=details or {}
        self.http_status = http_status
        self.provider_status = provider_status


def redact(text, secrets=(), limit=1500):
    """Bound diagnostic text, never return keys, signatures or reasoning fields."""
    text = str(text)
    for secret in sorted((x for x in secrets if isinstance(x, str) and x), key=len, reverse=True):
        text = text.replace(secret, '[REDACTED]')
    text = re.sub(r'(?i)Bearer\s+[^\s\"\x27,}]+', 'Bearer [REDACTED]', text)
    text = re.sub(r'AIza[\w-]+|sk-[\w-]{8,}', '[REDACTED]', text)
    text = re.sub(r'(?i)([?&](?:key|api_key|token)=)[^\s&\"\x27]+', r'\1[REDACTED]', text)
    text = re.sub(r'(?i)((?:api[_-]?key|authorization|password|thought_signature|reasoning_content)\s*[\"\x27]?\s*[:=]\s*)[\"\x27]?[^\n,}\"\x27]+', r'\1[REDACTED]', text)
    return ''.join(c for c in text if c in '\n\t' or ord(c) >= 32)[:limit]


def protocol_secrets(value):
    values = []
    if isinstance(value, dict):
        for key, item in value.items():
            if ('signature' in key.lower() or key in ('reasoning', 'reasoning_content', 'thinking')) and isinstance(item, str):
                values.append(item)
            else:
                values.extend(protocol_secrets(item))
    elif isinstance(value, list):
        for item in value:
            values.extend(protocol_secrets(item))
    return values


def assistant_message(call, client=None):
    """Replay wire metadata only in model history, never in profile or audit."""
    original = getattr(client, 'last_assistant_message', None)
    if original and original.get('tool_calls', [{}])[0].get('id') == call['id']:
        return copy.deepcopy(original)
    return {'role': 'assistant', 'content': None, 'tool_calls': [copy.deepcopy(call)]}


def public_call(call):
    """Only validated tool parameters enter the audit trail."""
    from .contracts import TOOL_ARGUMENTS
    name = call['function']['name']
    try:
        arguments = TOOL_ARGUMENTS[name].model_validate_json(call['function']['arguments']).model_dump()
    except (KeyError, ValueError, TypeError):
        arguments = {'error': 'invalid_or_unknown_arguments'}
    return {'id': call['id'], 'type': 'function', 'function': {'name': name, 'arguments': json.dumps(arguments)}}


def protocol_shape(messages):
    return [{'role': m['role'], 'tool_call_id': m.get('tool_call_id'),
             'calls': [{'id': c['id'], 'name': c['function']['name'],
                        'argument_bytes': len(c['function']['arguments']),
                        'signature_present': bool(protocol_secrets(c))} for c in m.get('tool_calls', [])]}
            for m in messages]


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise LLMError('LLM endpoint redirect bị chặn; kiểm tra base_url.')


def settings(config):
    data = dict(config.get('llm', {}))
    data['base_url'] = os.environ.get('SURVEY_LLM_BASE_URL', data.get('base_url', '')).rstrip('/')
    data['model'] = os.environ.get('SURVEY_LLM_MODEL', data.get('model', ''))
    data.setdefault('max_steps', 8)
    data.setdefault('max_seconds', 600)
    data.setdefault('timeout_seconds', 45)
    data.setdefault('max_output_tokens', 1000)
    parsed = urlsplit(data['base_url'])
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.query or parsed.fragment:
        raise ValueError('Cần cấu hình llm.base_url hợp lệ, không chứa key hoặc query.')
    if parsed.scheme == 'http' and parsed.hostname not in ('localhost', '127.0.0.1', '::1'):
        raise ValueError('LLM từ xa cần HTTPS; Ollama local có thể dùng http://127.0.0.1:11434/v1.')
    if not isinstance(data['model'], str) or not data['model'].strip():
        raise ValueError('Chưa cấu hình llm.model / SURVEY_LLM_MODEL hỗ trợ tool calling.')
    for field, low, high in [('max_steps', 1, 16), ('max_seconds', 30, 1800), ('timeout_seconds', 5, 120), ('max_output_tokens', 128, 4096)]:
        if type(data[field]) is not int or not low <= data[field] <= high:
            raise ValueError('Cấu hình LLM không hợp lệ: ' + field)
    key = os.environ.get('SURVEY_LLM_API_KEY', '')
    if not key and data.get('key_file'):
        try:
            key = Path(data['key_file']).expanduser().read_text(encoding='utf-8').strip()
        except OSError:
            raise ValueError('Không đọc được llm.key_file.') from None
    if not key and parsed.hostname not in ('localhost', '127.0.0.1', '::1'):
        raise ValueError('Chưa có SURVEY_LLM_API_KEY hoặc llm.key_file.')
    data['_key'] = key
    return data


class ChatClient:
    def __init__(self, config):
        self.options = settings(config)
        self.budget_api=budget_module(config)
        self.budget_run='survey:standalone:'+uuid.uuid4().hex
        self.metrics_path=None
        self.opener = build_opener(ProxyHandler({}), NoRedirect())
        self.last_assistant_message = None
        self._protocol_secrets = []
        self.last_usage = None

    def bind_budget(self,run_id,metrics_path):
        self.budget_run='survey:'+run_id
        self.metrics_path=Path(metrics_path)

    def budget_metrics(self,ledger,wait=None):
        value=ledger.metrics(self.budget_run)
        if wait:value['last_wait']={'reason':wait.reason,'retry_at_epoch':wait.retry_at}
        if self.metrics_path:
            from .runner import save
            save(self.metrics_path,value)
        return value

    def choose(self, messages, tools, timeout=None, tool_choice='auto'):
        options = self.options
        result_status='invalid_response';error_info=None;retry_delay=None
        self.last_usage = None
        body = {'model': options['model'], 'messages': messages, 'tools': tools,
                'tool_choice': tool_choice, 'parallel_tool_calls': False,
                'max_completion_tokens': min(options['max_output_tokens'],self.budget_api.settings()['survey_output']), 'stream': False}
        headers = {'Content-Type': 'application/json'}
        if options['_key']:
            headers['Authorization'] = 'Bearer ' + options['_key']
        encoded_body=json.dumps(body,ensure_ascii=False,separators=(',',':')).encode('utf-8')
        request = Request(options['base_url'] + '/chat/completions',
                          data=encoded_body, headers=headers, method='POST')
        request_deadline = time.monotonic() + (timeout or options['timeout_seconds'])
        ledger=self.budget_api.Ledger();started=time.monotonic();request_id=None;token_usage=self.budget_api.usage_fields(None)
        measured=self.budget_api.estimate({'body':encoded_body.decode('utf-8')})
        fingerprint=hashlib.sha256(json.dumps(body,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
        try:
            try:
                request_id=ledger.reserve(options['model'],self.budget_run,'survey',fingerprint,measured['input_tokens_reserved'],body['max_completion_tokens'],measured)
                self.budget_metrics(ledger)
            except self.budget_api.BudgetWait as wait:
                self.budget_metrics(ledger,wait)
                raise LLMError('Đang chờ ngân sách LLM nội bộ: '+wait.reason,retry_at=wait.retry_at,budget_reason=wait.reason) from None
            effective_timeout=min(timeout or options['timeout_seconds'],ledger.remaining_seconds(self.budget_run))
            request_deadline=time.monotonic()+effective_timeout
            with self.opener.open(request, timeout=effective_timeout) as response:
                raw = read_limited(response, 2_000_000, request_deadline)
            if len(raw) > 2_000_000:
                raise LLMError('LLM response quá lớn.')
            data = json.loads(raw)
            usage = data.get('usage')
            token_usage=self.budget_api.usage_fields(usage,'openai')
            if isinstance(usage, dict):
                self.last_usage = {k: usage[k] for k in ('prompt_tokens', 'completion_tokens', 'total_tokens') if type(usage.get(k)) is int and usage[k] >= 0} or None
            choice = data['choices'][0]
            message = choice['message']
            if not isinstance(message, dict) or message.get('role') != 'assistant':
                raise ValueError('Invalid message')
            calls = message.get('tool_calls') or []
            if not isinstance(calls, list) or len(calls) > 1:
                raise LLMError('LLM phải chọn tối đa một tool mỗi bước.')
            if not calls:
                if choice.get('finish_reason') == 'length':
                    raise LLMError('LLM hết giới hạn output trước khi chọn tool.')
                result_status='success'
                return None
            call = calls[0]
            if call.get('type') != 'function' or not isinstance(call.get('id'), str) or not call['id'] or len(call['id']) > 128:
                raise ValueError('Invalid tool call')
            function = call['function']
            if not isinstance(function.get('name'), str) or not isinstance(function.get('arguments'), str) or len(function['arguments']) > 2048:
                raise ValueError('Invalid function')
            # Keep the provider's tool-call object intact (including extra_content).
            # Private reasoning text is not needed to replay function-call metadata.
            self.last_assistant_message = copy.deepcopy({k: v for k, v in message.items()
                if k not in ('reasoning', 'reasoning_content', 'thinking', 'thoughts')})
            self._protocol_secrets.extend(protocol_secrets(message))
            result_status='success'
            return copy.deepcopy(call)
        except HTTPError as exc:
            try:
                payload = json.loads(exc.read(8192))
                error = payload.get('error', {})
                if not isinstance(error, dict): error = {}
                status = redact(error.get('status', ''), [options['_key']] + self._protocol_secrets, 100)
                detail = self.budget_api.safe_provider_summary(error.get('message'))
            except (ValueError, OSError, TypeError):
                status, detail = '', 'Provider không trả lỗi JSON có thể đọc được.'
            result_status='provider_error'
            error_info=self.budget_api.provider_details(payload if 'payload' in locals() else {},exc.headers)
            error_info['http_status']=exc.code
            error_info['provider_status']=status
            for violation in error_info['quota_violations']:
                for k in violation:violation[k]=redact(violation[k],[options['_key']] + self._protocol_secrets,160)
            retry_delay=error_info.get('retry_after_seconds')
            if retry_delay is None and exc.code in (429,500,502,503,504):retry_delay=60
            raise LLMError('LLM HTTP %s%s: %s' % (exc.code, ' (' + status + ')' if status else '', detail),exc.code,status,
                           retry_at=time.time()+retry_delay if retry_delay else None,details=error_info) from None
        except OSError as exc:
            result_status='transport_unknown';error_info={'type':type(exc).__name__};retry_delay=60
            raise LLMError('Không kết nối được LLM (%s): %s' % (type(exc).__name__,
                redact(str(exc), [options['_key']] + self._protocol_secrets))) from None
        except (ValueError, KeyError, IndexError, TypeError):
            raise LLMError('Không nhận được phản hồi tool-calling hợp lệ từ LLM.') from None

        finally:
            if request_id:
                ledger.finish(request_id,result_status,usage=token_usage,error=error_info,duration=time.monotonic()-started,retry_after=retry_delay)
                self.budget_metrics(ledger)
