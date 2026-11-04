"""Private one-shot capture supervision; no MCP route or authority issuer.

The producer is trusted application code, never a request field/import string.
It must itself implement live native/scene/privacy/authority checks. This layer
only owns cancellation, process lifetime and a bounded sanitized-frame reply.
The fixed interpreter worker is assigned to a parent-owned Job while suspended.
"""
from dataclasses import asdict, dataclass
import hashlib
import io
import json
import math
import multiprocessing
import os
import pickle
import queue
import struct
import threading
import time
import uuid

from PIL import Image
import win32event

from flower_control.control.native import process_identity
from .desktop_capture import DesktopCaptureError, DesktopCaptureFrame, DesktopCaptureState
from .desktop_geometry import DesktopImageSpace, DesktopMonitor, DesktopRect, DesktopTopology
from .desktop_owned_process import DesktopOwnedProcess


_MAX_HEADER = 524288
_MAX_PNG = 32_000_000
_MAX_REPLY = 4 + _MAX_HEADER + _MAX_PNG


@dataclass
class _OwnedResources:
    stop_event: object
    process: object = None
    parent: object = None
    child: object = None
    reader: object = None

    def close(self):
        # Keep every uncertain handle for an exact cleanup retry. A failed
        # termination/close must not become a successful frame or lost ownership.
        if self.process is not None:
            if self.process.pid is not None:
                if self.process.is_alive():
                    win32event.SetEvent(self.stop_event)
                    self.process.join(.3)
                    if self.process.is_alive():
                        self.process.kill()
                        self.process.join(1)
                    if self.process.is_alive():
                        raise RuntimeError('owned_worker_still_live')
            self.process.close()
            self.process = None
        if self.child is not None:
            self.child.close()
            self.child = None
        if self.reader is not None:
            self.reader.join(1)
            if self.reader.is_alive(): raise RuntimeError('owned_reader_still_live')
            self.reader = None
        if self.parent is not None:
            self.parent.close()
            self.parent = None
        if self.stop_event is not None:
            self.stop_event.Close()
            self.stop_event = None


class DesktopCaptureCleanupError(DesktopCaptureError):
    def __init__(self, resources):
        super().__init__('desktop_capture_cleanup_unconfirmed')
        self._resources = resources

    def retry_cleanup(self):
        """Retry only retained owned resources; never rerun the capture."""
        self._resources.close()


def _encode(frame):
    if type(frame) is not DesktopCaptureFrame:
        raise DesktopCaptureError('invalid_desktop_worker_frame')
    # Decode our own envelope before sending, too. Raw BGRA is never a reply.
    try:
        header = json.dumps(dict(state=asdict(frame.state), source=asdict(frame.image_space.source),
            image_size=frame.image_space.image_size, captured_at=frame.captured_at, digest=frame.digest,
            surfaces=frame.surfaces),
            ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
    except Exception as error:
        raise DesktopCaptureError('invalid_desktop_worker_frame') from error
    if type(frame.png) is not bytes or not 1 <= len(frame.png) <= _MAX_PNG or len(header) > _MAX_HEADER:
        raise DesktopCaptureError('invalid_desktop_worker_frame')
    data = struct.pack('<I',len(header)) + header + frame.png
    _decode(data)
    if frame.image_space.topology != frame.state.topology:
        raise DesktopCaptureError('invalid_desktop_worker_frame')
    return data


def _decode(data):
    try:
        if type(data) is not bytes or not 4 < len(data) <= _MAX_REPLY:
            raise ValueError()
        size = struct.unpack_from('<I',data)[0]
        if not 1 <= size <= _MAX_HEADER or not 1 <= len(data)-4-size <= _MAX_PNG:
            raise ValueError()
        def unique(items):
            result = {}
            for key,value in items:
                if key in result: raise ValueError()
                result[key] = value
            return result
        h = json.loads(data[4:4+size],object_pairs_hook=unique)
        if type(h) is not dict or set(h) != {'state','source','image_size','captured_at','digest','surfaces'}:
            raise ValueError()
        raw = h['state']
        if type(raw) is not dict or set(raw) != {'desktop_binding','topology','scene_revision',
                'privacy_revision','protected_rects','interactive','secure_desktop','focus_binding'}:
            raise ValueError()
        if type(raw['topology']) is not dict or set(raw['topology']) != {'monitors'}:
            raise ValueError()
        monitors = raw['topology']['monitors']
        masks = raw['protected_rects']
        if (type(monitors) is not list or not 1 <= len(monitors) <= 32
                or type(masks) is not list or len(masks)>4096
                or type(h['image_size']) is not list or len(h['image_size']) != 2):
            raise ValueError()
        topology = DesktopTopology(tuple(DesktopMonitor(m['identifier'],DesktopRect(**m['bounds']),m['dpi'])
            for m in monitors if type(m) is dict and set(m)=={'identifier','bounds','dpi'}))
        if len(topology.monitors) != len(monitors): raise ValueError()
        state = DesktopCaptureState(raw['desktop_binding'],topology,raw['scene_revision'],
            raw['privacy_revision'],tuple(DesktopRect(**r) for r in masks),raw['interactive'],raw['secure_desktop'],
            None if raw['focus_binding'] is None else tuple(raw['focus_binding']))
        if not state.interactive or state.secure_desktop: raise ValueError()
        space = DesktopImageSpace(topology,DesktopRect(**h['source']),tuple(h['image_size']))
        if (space.source.width>32768 or space.source.height>32768
                or space.source.width*space.source.height>32_000_000): raise ValueError()
        captured = h['captured_at']
        png = data[4+size:]
        if (type(captured) not in (int,float) or not math.isfinite(captured)
                or type(h['digest']) is not str or h['digest'] != hashlib.sha256(png).hexdigest()
                or not png.endswith(b'\x00\x00\x00\x00IEND\xaeB`\x82')):
            raise ValueError()
        with Image.open(io.BytesIO(png)) as image:
            if image.format != 'PNG' or image.size != space.image_size or image.mode != 'RGB':
                raise ValueError()
            image.load()
        if type(h['surfaces']) is not list:raise ValueError()
        return DesktopCaptureFrame(png,space,state,float(captured),h['digest'],tuple(tuple(row) for row in h['surfaces']))
    except Exception as error:
        raise DesktopCaptureError('invalid_desktop_worker_frame') from error


def _worker(connection, owner, stop_name):
    # Lifetime is established before ready/go and before calling any producer.
    lifetime = None
    status = 3
    try:
        from .worker_bootstrap import initialize_dlls
        initialize_dlls()
        from .worker_lifetime import WorkerLifetime
        lifetime = WorkerLifetime(owner,stop_name)
        connection.send_bytes(b'ready')
        if connection.recv_bytes(4) != b'go':
            return
        # Only internal trusted Python code is serialized. Deserialize it after
        # Job/owner monitoring, never as an initial multiprocessing spawn arg.
        producer = pickle.loads(connection.recv_bytes(65536))
        if not callable(producer): return
        connection.send_bytes(_encode(producer()))
        status = 0
    except BaseException:
        # No exception text, window content or raw pixel buffer on either pipe.
        pass
    finally:
        connection.close()
        if lifetime is not None: lifetime.exit(status)
        os._exit(status)


def capture_in_owned_job(*, producer, authorize, validate_frame, stopped, timeout=3.0):
    """Run trusted capture code once, publish only after fresh parent checks.

    Blocking adapter intended for a cancellable host thread. Its stopped callback
    must include host cancellation/EOF/Stop; authorize must read live task state.
    No fallback, input, scope issuance or producer selection from model strings.
    Parent callbacks/serialization must themselves be bounded: this supervisor
    cannot preempt a blocking parent callback. The fixed interpreter bootstrap
    is owned by a parent Job before its first instruction, including imports.
    """
    if (not all(callable(f) for f in (producer,authorize,validate_frame,stopped))
            or type(timeout) not in (int,float) or not math.isfinite(timeout)
            or not .1 <= timeout <= 10):
        raise DesktopCaptureError('invalid_desktop_worker_request')
    deadline = time.monotonic() + timeout
    def require():
        stop = stopped()
        if type(stop) is not bool:
            raise DesktopCaptureError('desktop_capture_stop_unavailable')
        if stop: raise DesktopCaptureError('desktop_capture_cancelled')
        if time.monotonic() >= deadline: raise DesktopCaptureError('desktop_capture_timeout')
        if authorize() is not True: raise DesktopCaptureError('desktop_capture_not_authorized')
    require()
    try: serialized = pickle.dumps(producer,protocol=5)
    except Exception as error:
        raise DesktopCaptureError('invalid_desktop_worker_producer') from error
    if len(serialized)>65536: raise DesktopCaptureError('invalid_desktop_worker_producer')
    require()
    stop_name = 'Local\\FlowerControl.DesktopCapture.' + uuid.uuid4().hex
    stop_event = win32event.CreateEvent(None,True,False,stop_name)
    parent = child = process = reader = None
    owned = _OwnedResources(stop_event)
    replies = queue.Queue(maxsize=2)
    try:
        context = multiprocessing.get_context('spawn')
        parent,child = context.Pipe(duplex=True)
        owned.parent,owned.child = parent,child
        process = DesktopOwnedProcess(child,process_identity(),stop_name)
        owned.process = process
        process.start()
        child.close()
        owned.child = None
        child = None
        def read():
            try:
                for _ in range(2):
                    replies.put((True,parent.recv_bytes(_MAX_REPLY)))
            except Exception:
                replies.put((False,None))
        reader = threading.Thread(target=read,name='flower-desktop-frame-reader',daemon=True)
        reader.start()
        owned.reader = reader
        def next_reply():
            while True:
                require()
                try: ok,data = replies.get(timeout=min(.05,max(.001,deadline-time.monotonic())))
                except queue.Empty: continue
                if not ok: raise DesktopCaptureError('desktop_capture_worker_failed')
                require()
                return data
        if next_reply() != b'ready': raise DesktopCaptureError('desktop_capture_worker_protocol')
        require()
        parent.send_bytes(b'go')
        parent.send_bytes(serialized)
        data = next_reply()
        while process.is_alive():
            require()
            process.join(.01)
        if process.exitcode != 0: raise DesktopCaptureError('desktop_capture_worker_failed')
        frame = _decode(data)
        require()
        now = time.monotonic()
        if not 0 <= now-frame.captured_at < timeout:
            raise DesktopCaptureError('desktop_capture_frame_expired')
        if validate_frame(frame) is not True:
            raise DesktopCaptureError('desktop_capture_changed')
        require()
        return frame
    finally:
        try: owned.close()
        except Exception as error:
            raise DesktopCaptureCleanupError(owned) from error
