"""Bind a structured execution, without reading files or granting authority."""
import hashlib
import ntpath
import re
import struct


def bind_execution(image: str, execution: dict) -> tuple[str, dict]:
    def path(value):
        return (type(value) is str and 3 <= len(value) <= 1024
                and len(ntpath.splitdrive(value)[0]) == 2 and value[1] == ':'
                and ntpath.isabs(value) and not any(ord(c) < 32 or c in '*?' for c in value)
                and ':' not in value[2:])

    def digest(value):
        return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)

    keys = {'argv', 'working_directory', 'executable_sha256', 'payloads', 'purpose'}
    if (type(execution) is not dict or set(execution) not in (keys, keys | {'continuation'}, keys | {'new_run'})
            or not path(image)):
        raise ValueError('program_launch_execution_binding_invalid')
    argv, payloads = execution['argv'], execution['payloads']
    purpose = execution['purpose']
    if (not path(execution['working_directory']) or not digest(execution['executable_sha256'])
            or type(argv) is not list or len(argv) > 128
            or any(type(v) is not str or len(v) > 8192 or '\0' in v for v in argv)
            or sum(map(len, argv)) > 24000 or type(payloads) is not list or len(payloads) > 32
            or any(type(v) is not dict or set(v) != {'path', 'sha256'}
                   or not path(v['path']) or not digest(v['sha256']) for v in payloads)
            or type(purpose) is not str or not purpose.strip() or len(purpose) > 1024
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in purpose)):
        raise ValueError('program_launch_execution_binding_invalid')
    wire = {'Argv': argv, 'WorkingDirectory': execution['working_directory'],
            'ExecutableSha256': execution['executable_sha256'],
            'Payloads': [{'Path': v['path'], 'Sha256': v['sha256']} for v in payloads], 'Purpose': purpose}
    continuation = execution.get('continuation')
    if 'continuation' in execution:
        if (type(continuation) is not dict or set(continuation) != {'previous_request_id', 'outcome', 'evidence'}
                or type(continuation['previous_request_id']) is not str
                or re.fullmatch(r'[a-zA-Z0-9_-]{1,128}', continuation['previous_request_id']) is None
                or continuation['outcome'] not in ('completed', 'failed', 'partial')
                or type(continuation['evidence']) is not str or not continuation['evidence'].strip()
                or len(continuation['evidence']) > 2048
                or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in continuation['evidence'])):
            raise ValueError('program_launch_continuation_invalid')
        wire['Continuation'] = {'PreviousRequestId': continuation['previous_request_id'],
                                'Outcome': continuation['outcome'], 'Evidence': continuation['evidence']}
    new_run = execution.get('new_run')
    if 'new_run' in execution:
        if (type(new_run) is not dict or set(new_run) != {'exit_reference', 'evidence'}
                or not digest(new_run['exit_reference']) or type(new_run['evidence']) is not str
                or not new_run['evidence'].strip() or len(new_run['evidence']) > 2048
                or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in new_run['evidence'])):
            raise ValueError('program_launch_new_run_invalid')
        wire['NewRun'] = {'ExitReference': new_run['exit_reference'], 'Evidence': new_run['evidence']}
    body = bytearray()

    def put(value):
        data = value.encode('utf-8')
        body.extend(struct.pack('<i', len(data)))
        body.extend(data)

    for value in ('flower-semantic-launch-v2', image, wire['WorkingDirectory'], wire['ExecutableSha256']):
        put(value)
    body.extend(struct.pack('<i', len(argv)))
    for value in argv:
        put(value)
    body.extend(struct.pack('<i', len(payloads)))
    for value in payloads:
        put(value['path'])
        put(value['sha256'])
    if continuation is not None:
        put('flower-semantic-next-run-v1')
        for value in (continuation['previous_request_id'], continuation['outcome'], continuation['evidence']):
            put(value)
    if new_run is not None:
        put('flower-independent-new-run-v1')
        put(new_run['exit_reference'])
        put(new_run['evidence'])
    return hashlib.sha256(body).hexdigest(), wire
