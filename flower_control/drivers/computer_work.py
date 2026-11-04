"""Deterministic input-work admission; weights are budgets, not latency claims."""


def operation_budget(operation):
    if operation['Kind'] == 'computer_input_plan':
        return input_wire_budget(operation['Plan'])
    if operation['Kind'] == 'app_request' and operation['Plan']['command'] == 'guarded_input':
        from . import computer_native as native
        args = operation['Plan']['arguments']
        batches = native.plan_unicode_batches(args['text'])
        if args.get('replace', False):
            ctrl, key = native.virtual_key, native.virtual_key
            batches = (native.plan_batch((ctrl(0x11, down=True), key(0x41, down=True),
                                          key(0x41, down=False), ctrl(0x11, down=False))), *batches)
        # Preserve App's existing capacity, including its replace chord.
        if len(batches) > 131:
            raise ValueError('input_plan_rejected')
        return native.input_execution_budget(batches)
    return 5000


def input_wire_budget(value):
    try:
        return _input_wire_budget(value)
    except (KeyError, TypeError, IndexError, AttributeError):
        raise ValueError('input_plan_rejected') from None


def _input_wire_budget(value):
    plans = value.get('plans') if type(value) is dict else None
    if type(plans) is not list or not 1 <= len(plans) <= 8192:
        raise ValueError('input_plan_rejected')
    budget = 2000
    physical_allowance = 0
    for plan in plans:
        duration, segments = plan['duration_ms'], plan['segments']
        if type(duration) is not int or not 0 <= duration <= 3000 or not segments:
            raise ValueError('input_plan_rejected')
        budget += duration
        first = segments[0]['events'][0]
        if first['kind'] == 'mouse_absolute':
            budget += 120
        held = set()
        for segment in segments:
            events = segment['events']
            if not events:
                raise ValueError('input_plan_rejected')
            def token(event):
                kind = event['kind']
                return ((kind, event['code']) if kind == 'virtual_key' else
                        (kind, event['unit']) if kind == 'unicode_key' else
                        (kind, event['button']) if kind == 'mouse_button' else None)
            owned_ups = all(token(e) is not None and e.get('down') is False and token(e) in held for e in events)
            if not owned_ups:
                motion_sample = type(plan.get('pointer')) is dict and all(e['kind'] == 'mouse_absolute' for e in events)
                physical_key = any(e['kind'] == 'virtual_key' and e['code'] != 9 for e in events)
                weight = 500 if not motion_sample and any(e['kind'].startswith('mouse_') for e in events) else 50
                budget += weight
                if physical_key and weight == 50:
                    physical_allowance += 450
            if any(e.get('down') is True and (e['kind'] == 'mouse_button' or
                    e['kind'] == 'virtual_key' and e['code'] == 9) for e in events):
                budget += 150
            for event in events:
                identity = token(event)
                if identity is not None:
                    if event.get('down') is True:
                        if identity in held:
                            raise ValueError('input_plan_rejected')
                        held.add(identity)
                    elif event.get('down') is False and identity in held:
                        held.remove(identity)
                    else:
                        raise ValueError('input_plan_rejected')
        if held:
            raise ValueError('input_plan_rejected')
    if budget > 30000:
        raise ValueError('input_plan_budget_exceeded')
    return min(30000, max(5000, budget + physical_allowance))
