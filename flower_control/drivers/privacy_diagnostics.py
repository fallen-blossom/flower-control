"""Fixed, content-free metadata about a failed password-property scan."""

STAGES = frozenset({
    'request_or_identity', 'root', 'password_descendants', 'root_password',
    'password_recheck', 'password_offscreen', 'password_rectangle',
    'focus_element', 'focus_identity', 'focus_process', 'focus_root',
    'focus_password', 'focus_ancestor', 'focus_rectangle', 'focus_recheck',
})
EXCEPTIONS = frozenset({
    'COMException', 'TimeoutException', 'PropertyNotSupportedException', 'ArgumentException',
    'InvalidOperationException', 'ElementNotAvailableException', 'UnauthorizedAccessException',
    'NotSupportedByFrameworkException', 'PropertyNotCachedException', 'InvalidCastException',
    'JsonException', 'unknown_native_exception',
})


def scan_diagnostics(value):
    if (type(value) is not dict or set(value) != {'stage', 'exception_type', 'hresult'}
            or type(value['stage']) is not str or value['stage'] not in STAGES
            or type(value['hresult']) is not int or not -(2**31) <= value['hresult'] < 2**31):
        return None
    kind = value['exception_type']
    return {'stage': value['stage'], 'hresult': value['hresult'],
            'exception_type': kind if type(kind) is str and kind in EXCEPTIONS else 'unknown_native_exception'}
