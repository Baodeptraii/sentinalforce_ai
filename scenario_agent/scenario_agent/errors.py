"""Bounded, key-redacted diagnostics without logging HTTP headers or prompts."""
import os
import re


def redact_error(value, limit=2000):
    message = str(value)
    for name in ('GEMINI_API_KEY', 'GOOGLE_API_KEY'):
        key = os.getenv(name)
        if key:
            message = message.replace(key, '[REDACTED]')
    message=re.sub(r'(?i)(Bearer\s+|(?:password|cookie|api[_-]?key|secret|access[_-]?token)\s*[=:]\s*)[^\s,;]+',r'\1[REDACTED]',message)
    return message[:limit]


class GeminiAPIError(RuntimeError):
    def __init__(self, code, status, message, retry_after=None, details=None):
        self.retry_after = retry_after
        self.details = details or {}
        self.code = code
        self.status = redact_error(status or 'UNKNOWN', 100)
        super().__init__(redact_error(f'Gemini HTTP {code} {self.status}: {message or "No API error message"}'))


class ServiceUnavailable(GeminiAPIError):
    """Transient provider failure after the bounded retry budget."""
    pass

def error_message(error):
    cause = error
    seen = set()
    while id(cause) not in seen:
        seen.add(id(cause))
        nested = cause.__cause__ or (None if cause.__suppress_context__ else cause.__context__)
        if nested is None:
            break
        cause = nested
    if isinstance(cause, ModuleNotFoundError) and cause.name:
        return f'Missing dependency: {cause.name}. Install project dependencies; see README.md.'
    if isinstance(cause, FileNotFoundError):
        return 'Required local input/index is missing. Run doctor and prepare-corpus/build-index.'
    return redact_error(f'{type(cause).__name__}: {cause}')
