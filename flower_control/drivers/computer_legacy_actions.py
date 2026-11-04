"""Legacy action dictionaries adapted to the current bounded batch contract.

No old runtime/session code is imported. Coordinates keep the current explicit
coordinate space; this adapter does not restore the old frame/session protocol.
"""
from decimal import Decimal


_FIELDS = {
    'click': {'x', 'y', 'button', 'count', 'coordinate_space'},
    'double_click': {'x', 'y', 'button', 'coordinate_space'},
    'right_click': {'x', 'y', 'coordinate_space'},
    'middle_click': {'x', 'y', 'coordinate_space'},
    'move': {'x', 'y', 'coordinate_space'},
    'scroll': {'x', 'y', 'dx', 'dy', 'clicks', 'coordinate_space'},
    'drag': {'path', 'button', 'keys', 'duration', 'coordinate_space'},
    'key': {'keys', 'key'},
    'text': {'text'},
    'type': {'text'},
    'hold': {'keys', 'button', 'x', 'y', 'duration', 'coordinate_space'},
}


def canonical_batch(arguments):
    """Return steps unchanged, or translate 1..16 old type/action dictionaries.

    Existing event, coordinate and total hold budgets still run in _plan_input.
    No delays, repeats, nested batches or unknown fields are accepted here.
    """
    if type(arguments) is not dict or 'actions' not in arguments:
        return arguments
    actions = arguments['actions']
    if (set(arguments) != {'actions'} or type(actions) is not list
            or not 1 <= len(actions) <= 16):
        raise ValueError('invalid_legacy_action_batch')
    steps = []
    for raw in actions:
        if type(raw) is not dict or len({'type','action'} & set(raw)) != 1:
            raise ValueError('invalid_legacy_action')
        discriminator = 'type' if 'type' in raw else 'action'
        kind = raw[discriminator]
        if (type(kind) is not str or kind not in _FIELDS
                or set(raw) - _FIELDS[kind] - {discriminator}):
            raise ValueError('invalid_legacy_action')
        values = {key: value for key, value in raw.items() if key != discriminator}
        if kind in {'double_click','right_click','middle_click'}:
            if kind == 'double_click': values['count'] = 2
            else: values['button'] = 'right' if kind == 'right_click' else 'middle'
            kind = 'click'
        if kind == 'type': kind = 'text'
        if kind == 'key' and 'key' in values:
            chord = values.pop('key')
            if ('keys' in values or type(chord) is not str or not 1 <= len(chord) <= 100
                    or any(not item for item in chord.split('+'))):
                raise ValueError('invalid_legacy_key_chord')
            values['keys'] = chord.split('+')
        if kind in {'hold', 'drag'}:
            duration = values.pop('duration', 0.5)
            if type(duration) not in (int, float):
                raise ValueError('invalid_legacy_duration')
            duration = Decimal(str(duration))
            if not duration.is_finite() or not Decimal('0.01') <= duration <= 3:
                raise ValueError('invalid_legacy_duration')
            milliseconds = duration * 1000
            if milliseconds != milliseconds.to_integral_value():
                raise ValueError('invalid_legacy_duration')
            values['duration_ms'] = int(milliseconds)
        if kind == 'hold':
            if ('keys' in values) == ('button' in values):
                raise ValueError('invalid_legacy_hold')
            if 'keys' in values:
                if {'x', 'y', 'coordinate_space'} & set(values):
                    raise ValueError('invalid_legacy_hold')
                kind = 'key'
            else:
                kind = 'mouse_hold'
        if kind == 'scroll':
            if discriminator == 'action' and not {'clicks','dx','dy'} & set(values):
                values['clicks'] = 1
            if 'clicks' in values:
                clicks = values.pop('clicks')
                if ({'dx','dy'} & set(values) or type(clicks) is not int or not 1 <= abs(clicks) <= 10):
                    raise ValueError('invalid_legacy_scroll_clicks')
                values['dy'] = clicks * 120
            values.setdefault('dx', 0)
            values.setdefault('dy', 0)
        steps.append({'command': kind, 'arguments': values})
    return {'steps': steps}
