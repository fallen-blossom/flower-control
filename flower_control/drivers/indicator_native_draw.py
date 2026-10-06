"""Original layered-image upload, copied locally without the old controller.

Images are rendered by Pillow. Screen-compatible memory DCs, top-down DIBs,
explicit destination coordinates and premultiplied BGRA match the old uploader.
"""
import ctypes as C
from ctypes import wintypes as W

u = C.WinDLL('user32', use_last_error=True)
g = C.WinDLL('gdi32', use_last_error=True)
dwm = C.WinDLL('dwmapi', use_last_error=True)


def bind(lib, name, args, result):
    function = getattr(lib, name)
    function.argtypes, function.restype = args, result
    return function


class Header(C.Structure):
    _fields_ = [('size', W.DWORD), ('width', W.LONG), ('height', W.LONG),
                ('planes', W.WORD), ('bits', W.WORD), ('compression', W.DWORD),
                ('image_size', W.DWORD), ('xppm', W.LONG), ('yppm', W.LONG),
                ('used', W.DWORD), ('important', W.DWORD)]


class Info(C.Structure):
    _fields_ = [('header', Header), ('colors', W.DWORD * 3)]


class Blend(C.Structure):
    _fields_ = [('operation', W.BYTE), ('flags', W.BYTE), ('alpha', W.BYTE), ('format', W.BYTE)]


create_dc = bind(g, 'CreateCompatibleDC', [W.HDC], W.HDC)
delete_dc = bind(g, 'DeleteDC', [W.HDC], W.BOOL)
select = bind(g, 'SelectObject', [W.HDC, W.HGDIOBJ], W.HGDIOBJ)
delete_object = bind(g, 'DeleteObject', [W.HGDIOBJ], W.BOOL)
dib = bind(g, 'CreateDIBSection', [W.HDC, C.POINTER(Info), W.UINT,
                                C.POINTER(C.c_void_p), W.HANDLE, W.DWORD], W.HBITMAP)
flush = bind(g, 'GdiFlush', [], W.BOOL)
update = bind(u, 'UpdateLayeredWindow', [W.HWND, W.HDC, C.POINTER(W.POINT),
    C.POINTER(W.SIZE), W.HDC, C.POINTER(W.POINT), W.COLORREF, C.POINTER(Blend), W.DWORD], W.BOOL)
get_dc = bind(u, 'GetDC', [W.HWND], W.HDC)
release_dc = bind(u, 'ReleaseDC', [W.HWND, W.HDC], C.c_int)
window_rect = bind(u, 'GetWindowRect', [W.HWND, C.POINTER(W.RECT)], W.BOOL)
affinity = bind(u, 'SetWindowDisplayAffinity', [W.HWND, W.DWORD], W.BOOL)
get_dpi = bind(u, 'GetDpiForWindow', [W.HWND], W.UINT)
frame_bounds = bind(dwm, 'DwmGetWindowAttribute', [W.HWND, W.DWORD, C.c_void_p, W.DWORD], C.c_long)


class Surface:
    """One screen-compatible top-down DIB, released after each layered upload."""
    def __init__(self, width, height, screen=None):
        if not 0 < width <= 32768 or not 0 < height <= 32768 or width * height > 8_000_000:
            raise ValueError('indicator_surface_limit')
        self.width, self.height = width, height
        self.dc = create_dc(screen)
        self.bitmap = self.previous = None
        if not self.dc:
            raise C.WinError(C.get_last_error())
        info = Info(Header(C.sizeof(Header), width, -height, 1, 32, 0, 0, 0, 0, 0, 0))
        self.bits = C.c_void_p()
        self.bitmap = dib(screen or self.dc, C.byref(info), 0, C.byref(self.bits), None, 0)
        if not self.bitmap or not self.bits:
            error = C.get_last_error()
            self.close()
            raise C.WinError(error)
        self.previous = select(self.dc, self.bitmap)
        if not self.previous or self.previous == C.c_void_p(-1).value:
            self.previous = None
            self.close()
            # SelectObject does not promise a meaningful GetLastError value.
            raise OSError('SelectObject failed')
        C.memset(self.bits, 0, width * height * 4)

    def close(self):
        if self.previous:
            select(self.dc, self.previous)
        if self.bitmap:
            delete_object(self.bitmap)
        if self.dc:
            delete_dc(self.dc)
        self.dc = self.bitmap = self.previous = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def paint(hwnd, width, height, pixels):
    """Original screen-DC/explicit-destination layered upload of BGRa bytes."""
    if len(pixels) != width * height * 4:
        raise ValueError('invalid_indicator_pixels')
    rect = W.RECT()
    if not window_rect(hwnd, C.byref(rect)):
        raise C.WinError(C.get_last_error())
    screen = get_dc(None)
    if not screen:
        raise C.WinError(C.get_last_error())
    try:
        with Surface(width, height, screen) as surface:
            C.memmove(surface.bits, pixels, len(pixels))
            destination = W.POINT(rect.left, rect.top)
            size, origin, blend = W.SIZE(width, height), W.POINT(0, 0), Blend(0, 0, 255, 1)
            if not update(hwnd, screen, C.byref(destination), C.byref(size), surface.dc,
                          C.byref(origin), 0, C.byref(blend), 2):
                raise C.WinError(C.get_last_error())
    finally:
        release_dc(None, screen)


def paint_image(hwnd, image):
    # Keep the original Pillow conversion. Straight RGBA is not a layered DIB.
    data = image.convert('RGBa').tobytes('raw', 'BGRa')
    paint(hwnd, *image.size, data)


def visible_bounds(hwnd, fallback):
    rect = W.RECT()
    if frame_bounds(hwnd, 9, C.byref(rect), C.sizeof(rect)) == 0:
        if rect.left < rect.right and rect.top < rect.bottom:
            return rect.left, rect.top, rect.right, rect.bottom
    return fallback


def exclude_capture(hwnd):
    if not affinity(hwnd, 0x11):
        raise C.WinError(C.get_last_error())
