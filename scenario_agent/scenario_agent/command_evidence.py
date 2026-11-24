"""Conservative command-fragment matching; never executes or rewrites a source."""


def _powershell_continuations(text):
    """Canonicalize token-separated continuations outside strings/comments.

    Retain ordinary newlines and all quoted/escaped data. Decline constructs
    requiring a full PowerShell parser. Spans map evidence back to original text.
    """
    output, spans, continuations = [], [], []
    mode = 'code'
    i = 0

    def emit(value, start, end):
        output.extend(value)
        spans.extend([(start, end)] * len(value))

    while i < len(text):
        char = text[i]
        pair = text[i:i + 2]
        if mode == 'comment':
            emit(char, i, i + 1)
            if char == '\n':
                mode = 'code'
            i += 1
            continue
        if mode in ('single', 'double'):
            if mode == 'double' and pair == '$(':
                return None
            if mode == 'double' and char == '`' and i + 1 < len(text):
                emit(pair, i, i + 2)
                i += 2
                continue
            if mode == 'single' and pair == "''":
                emit(pair, i, i + 2)
                i += 2
                continue
            if char == ("'" if mode == 'single' else '"'):
                mode = 'code'
            emit(char, i, i + 1)
            i += 1
            continue
        if pair in ("@'", '@"', '<#', '$(') or text[i:i + 3] == '--%':
            return None
        if char == '#':
            mode = 'comment'
        elif char in ("'", '"'):
            mode = 'single' if char == "'" else 'double'
        elif char in ' \t':
            end = i + 1
            while end < len(text) and text[end] in ' \t':
                end += 1
            emit(' ', i, end)
            i = end
            continue
        elif char == '`' and i + 1 < len(text):
            end = i + 1
            if text[end:end + 2] == '\r\n':
                end += 2
            elif text[end] == '\n':
                end += 1
            else:
                # Preserve an escape pair, including an escaped backtick.
                emit(pair, i, i + 2)
                i += 2
                continue
            if i > 0 and text[i - 1] in ' \t':
                while end < len(text) and text[end] in ' \t':
                    end += 1
                continuations.append((i, end))
                i = end
                continue
        emit(char, i, i + 1)
        i += 1
    if mode in ('single', 'double'):
        return None
    return ''.join(output), spans, continuations


def command_fragment_evidence(command, quote, executor):
    """Return literal source evidence or None; only PowerShell gets a fallback."""
    if len(quote) < 3:
        return None
    if quote in command:
        return {'method': 'literal', 'source_fragment': quote}
    if executor not in ('psh', 'pwsh', 'powershell'):
        return None
    source = _powershell_continuations(command)
    fragment = _powershell_continuations(quote)
    if source is None or fragment is None or not fragment[0]:
        return None
    start = source[0].find(fragment[0])
    if start < 0:
        return None
    end = start + len(fragment[0])
    original_start, original_end = source[1][start][0], source[1][end - 1][1]
    if not fragment[2] and not any(original_start <= a < original_end for a, b in source[2]):
        return None
    return {'method': 'powershell_explicit_continuation',
            'source_fragment': command[original_start:original_end]}
