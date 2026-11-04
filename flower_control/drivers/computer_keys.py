"""Pure physical-key chord planner; no layout lookup, IME or input dispatch.

Punctuation names/literals identify US keyboard positions. They are shortcuts,
not a guarantee of the character produced by a different active Windows layout.
Literal document text belongs to the separate Unicode text planner.
"""
from .computer_native import plan_batch,virtual_key


_NAMED_KEYS = {
    "CTRL":0x11,"SHIFT":0x10,"ALT":0x12,
    "CTRL_L":0xA2,"CTRL_R":0xA3,"SHIFT_L":0xA0,"SHIFT_R":0xA1,
    "ALT_L":0xA4,"ALT_R":0xA5,
    "ENTER":0x0D,"ESC":0x1B,"TAB":0x09,"BACKSPACE":0x08,
    "DELETE":0x2E,"INSERT":0x2D,"HOME":0x24,"END":0x23,
    "PAGEUP":0x21,"PAGEDOWN":0x22,"LEFT":0x25,"UP":0x26,"RIGHT":0x27,"DOWN":0x28,
    "SPACE":0x20,"WIN":0x5B,"LWIN":0x5B,"RWIN":0x5C,"MENU":0x5D,
    "CAPSLOCK":0x14,"NUMLOCK":0x90,"SCROLLLOCK":0x91,"PRINTSCREEN":0x2C,"PAUSE":0x13,
    "ADD":0x6B,"SUBTRACT":0x6D,"MULTIPLY":0x6A,"DIVIDE":0x6F,"DECIMAL":0x6E,
    **{f"NUM{number}":0x60+number for number in range(10)},
    **{f"F{number}":0x6F+number for number in range(1,25)},
    "OEM_1":0xBA,"OEM_PLUS":0xBB,"OEM_COMMA":0xBC,"OEM_MINUS":0xBD,
    "OEM_PERIOD":0xBE,"OEM_2":0xBF,"OEM_3":0xC0,"OEM_4":0xDB,
    "OEM_5":0xDC,"OEM_6":0xDD,"OEM_7":0xDE,"OEM_102":0xE2,
}
_ALIASES = {
    "CONTROL":"CTRL","RETURN":"ENTER","ESCAPE":"ESC","SUPER":"WIN","CMD":"WIN",
    "PAGE_UP":"PAGEUP","PAGE_DOWN":"PAGEDOWN","DEL":"DELETE","BACK_SPACE":"BACKSPACE",
    "PRIOR":"PAGEUP","NEXT":"PAGEDOWN","PRINT_SCREEN":"PRINTSCREEN","PRINT":"PRINTSCREEN",
    "CAPS_LOCK":"CAPSLOCK","NUM_LOCK":"NUMLOCK","SCROLL_LOCK":"SCROLLLOCK",
    "CONTROL_L":"CTRL_L","CONTROL_R":"CTRL_R","SUPER_L":"LWIN","SUPER_R":"RWIN",
    "WIN_L":"LWIN","WIN_R":"RWIN",
    **{f"{prefix}{number}":f"NUM{number}" for prefix in ("KP_","NUMPAD_") for number in range(10)},
    **{f"{prefix}{name}":name for prefix in ("KP_","NUMPAD_")
       for name in ("ADD","SUBTRACT","MULTIPLY","DIVIDE","DECIMAL")},
}
# (physical virtual key, requires Shift on a US layout).
_PUNCTUATION = {
    ";":(0xBA,False),":":(0xBA,True),"=":(0xBB,False),"+":(0xBB,True),
    ",":(0xBC,False),"<":(0xBC,True),"-":(0xBD,False),"_":(0xBD,True),
    ".":(0xBE,False),">":(0xBE,True),"/":(0xBF,False),"?":(0xBF,True),
    "`":(0xC0,False),"~":(0xC0,True),"[":(0xDB,False),"{":(0xDB,True),
    "\\":(0xDC,False),"|":(0xDC,True),"]":(0xDD,False),"}":(0xDD,True),
    "'":(0xDE,False),'"':(0xDE,True),
    **{symbol:(ord(number),True) for symbol,number in zip("!@#$%^&*()","1234567890")},
}
_SYMBOL_NAMES = {
    "SEMICOLON":";","COLON":":","EQUAL":"=","PLUS":"+","COMMA":",","LESS":"<",
    "MINUS":"-","UNDERSCORE":"_","PERIOD":".","GREATER":">","SLASH":"/","QUESTION":"?",
    "GRAVE":"`","ASCIITILDE":"~","BRACKETLEFT":"[","BRACELEFT":"{","BACKSLASH":"\\",
    "BAR":"|","BRACKETRIGHT":"]","BRACERIGHT":"}","APOSTROPHE":"'","QUOTERIGHT":"'",
    "QUOTEDBL":'"',"EXCLAM":"!","AT":"@","NUMBERSIGN":"#","DOLLAR":"$","PERCENT":"%",
    "ASCIICIRCUM":"^","AMPERSAND":"&","ASTERISK":"*","PARENLEFT":"(","PARENRIGHT":")",
}
_MODIFIER_FAMILIES = ((0x11,0xA2,0xA3),(0x10,0xA0,0xA1),(0x12,0xA4,0xA5))
_SHIFT_CODES = {0x10,0xA0,0xA1}


def key_batch(keys:object):
    """1..5 explicit key names, distinct physical keys, exact reverse releases.

    Generic and side-specific variants of one modifier cannot be mixed. An
    implied Shift reuses an explicit Shift; it never causes duplicate presses.
    KP_Enter stays unsupported until the wire can distinguish extended Return.
    """
    if (type(keys) is not list or not 1<=len(keys)<=5 or any(type(key) is not str for key in keys)):
        raise ValueError("invalid_key_list")
    codes=[];shifted=[]
    for raw in keys:
        key=_ALIASES.get(raw.upper(),raw.upper())
        symbol=_SYMBOL_NAMES.get(key,key)
        if symbol in _PUNCTUATION:code,shift=_PUNCTUATION[symbol]
        else:
            code=_NAMED_KEYS.get(key)
            if code is None and len(key)==1 and key in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":code=ord(key)
            shift=False
        if code is None or code in codes:raise ValueError("invalid_key_list")
        codes.append(code)
        if shift:shifted.append(code)
    for generic,left,right in _MODIFIER_FAMILIES:
        if generic in codes and (left in codes or right in codes):raise ValueError("invalid_key_list")
    if shifted:
        first=min(codes.index(code) for code in shifted)
        shifts=[code for code in codes if code in _SHIFT_CODES]
        if not shifts:codes.insert(first,0x10)
        else:
            # Even when listed after punctuation, Shift must be down first.
            late=[code for code in shifts if codes.index(code)>first]
            for code in late:codes.remove(code)
            codes[first:first]=late
    return plan_batch(tuple(virtual_key(code,down=True) for code in codes)
        +tuple(virtual_key(code,down=False) for code in reversed(codes)))
