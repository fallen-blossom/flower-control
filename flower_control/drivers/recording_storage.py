"""Checkpoint measurements of this recording's owned files, without scanning."""
from __future__ import annotations

from contextlib import contextmanager
import errno
import tempfile
from pathlib import Path

from flower_control.control.state import ControlError


@contextmanager
def recording_write_errors():
    """Translate capacity failures only; never hide permission/identity errors."""
    try:
        yield
    except OSError as error:
        if is_capacity_error(error):
            raise ControlError('recording_disk_full') from None
        raise


def is_capacity_error(error):
    return error.errno in {errno.ENOSPC, getattr(errno, 'EDQUOT', errno.ENOSPC)} or getattr(error, 'winerror', None) in {39, 112}


@contextmanager
def recording_workspace(*, prefix):
    with recording_write_errors():
        directory = tempfile.TemporaryDirectory(prefix=prefix)
    try:
        yield directory.name
    finally:
        directory.cleanup()


class RecordingStorageUsage:
    def __init__(self, source):
        self.source = Path(source)
        self.source_bytes = None
        self.extracted_bytes = 0
        self.workspace_peak = 0
        self.owned_peak = 0
        self.published_bytes = None
        self.samples = 0
        self.incomplete = False

    def sample(self, workspace=None, *, published_bytes=0):
        # Diagnostics must not turn an already published result into a failure.
        # All names are our fixed encoder outputs; unrelated files are unread.
        if type(published_bytes) is not int or published_bytes < 0:
            self.incomplete = True
            return
        self.published_bytes = max(self.published_bytes or 0, published_bytes)
        try:
            source_bytes = self.source.stat().st_size
            workspace_bytes = self.extracted_bytes
            if workspace is not None:
                for name in ('frames.ffconcat', 'encode.progress', 'recording.mp4'):
                    path = Path(workspace) / name
                    try:
                        workspace_bytes += path.stat().st_size
                    except FileNotFoundError:
                        pass
        except (OSError, ValueError):
            self.incomplete = True
            return
        self.source_bytes = source_bytes
        self.workspace_peak = max(self.workspace_peak, workspace_bytes)
        self.owned_peak = max(self.owned_peak, source_bytes + workspace_bytes + published_bytes)
        self.samples += 1

    def result(self):
        return dict(source_archive_bytes=self.source_bytes, extracted_frame_bytes=self.extracted_bytes,
                    peak_workspace_observed_bytes=self.workspace_peak if self.samples else None,
                    published_copy_bytes=self.published_bytes,
                    peak_owned_files_observed_bytes=self.owned_peak if self.samples else None,
                    measurement='logical_file_bytes_at_checkpoints', samples=self.samples,
                    measurement_incomplete=self.incomplete, continuous_peak_verified=False,
                    excludes='filesystem allocation, metadata registration, RAM, system cache and unrelated files')


def zip_storage_usage(source, artifact):
    usage = RecordingStorageUsage(source)
    usage.sample(published_bytes=artifact.get('bytes'))
    return usage.result()


def include_capture_storage(result, captured):
    current, capture = result.get('storage_usage'), captured.get('storage_usage')
    if isinstance(current, dict) and isinstance(capture, dict):
        peak, capture_peak = current.get('peak_owned_files_observed_bytes'), capture.get('peak_owned_files_observed_bytes')
        if type(peak) is int and type(capture_peak) is int:
            current['capture_zip_peak_observed_bytes'] = capture_peak
            current['peak_owned_files_observed_bytes'] = max(peak, capture_peak)
        else:
            current['measurement_incomplete'] = True
        current['measurement_incomplete'] = bool(current.get('measurement_incomplete') or capture.get('measurement_incomplete'))
    return result
