"""Two provider requests, mocked tools only. Never invokes CALDERA or victim tools."""
import argparse
import json
import secrets

from pydantic import StrictStr
from .contracts import NoArguments, StrictModel
from .llm import ChatClient, LLMError, assistant_message, protocol_secrets
from .survey import load_config


class Receipt(StrictModel):
    nonce: StrictStr


def check(client):
    tools = []
    for name, model in [('confirm_connection', NoArguments), ('confirm_receipt', Receipt)]:
        tools.append({'type': 'function', 'function': {'name': name,
            'description': 'Protocol smoke test only; no external action.',
            'parameters': model.model_json_schema(), 'strict': True}})
    messages = [{'role': 'user', 'content': 'Call confirm_connection. After the tool result, call confirm_receipt with the exact nonce from that result. No external actions.'}]
    first = client.choose(messages, [tools[0]], tool_choice={'type': 'function', 'function': {'name': 'confirm_connection'}})
    if not first or first['function']['name'] != 'confirm_connection':
        raise LLMError('Lượt đầu không trả confirm_connection; đã dừng, không retry.')
    NoArguments.model_validate_json(first['function']['arguments'])
    nonce = secrets.token_hex(12)
    messages.extend([assistant_message(first, client), {'role': 'tool', 'name': 'confirm_connection',
        'tool_call_id': first['id'], 'content': json.dumps({'status': 'ok', 'nonce': nonce, 'mock': True})}])
    second = client.choose(messages, tools, tool_choice={'type': 'function', 'function': {'name': 'confirm_receipt'}})
    if not second or second['function']['name'] != 'confirm_receipt':
        raise LLMError('Lượt sau tool result không trả confirm_receipt; không retry.')
    receipt = Receipt.model_validate_json(second['function']['arguments'])
    if receipt.nonce != nonce:
        raise LLMError('Model không xác nhận đúng tool result ở lượt hai.')
    return {'status': 'multi_turn_verified', 'model': client.options['model'], 'api_requests': 2,
            'first_call_signature_present': bool(protocol_secrets(first)), 'lab_actions': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', help='Write sanitized verification result to JSON')
    args = parser.parse_args()
    try:
        result = check(ChatClient(load_config()))
        code = 0
    except (LLMError, ValueError, OSError) as exc:
        result = {'status': 'not_verified', 'error': str(exc), 'lab_actions': 0}
        code = 1
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        from pathlib import Path
        Path(args.output).write_text(text + '\n', encoding='utf-8')
    print(text)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
