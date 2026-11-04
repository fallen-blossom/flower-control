"""Negative input checks use only owned temporary files."""
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

try:
    from . import prepare
except ImportError:
    import prepare


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='encoder-input-checks-',dir=os.environ.get('FLOWER_ENCODER_TEST_TEMP'))
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)

    def test_copy_pins_source_and_never_overwrites_changed_target(self):
        source=self.root/'source';source.write_bytes(b'exact official fixture')
        target=self.root/'target';target.write_bytes(b'user change')
        with self.assertRaisesRegex(ValueError,'existing_input_changed'):
            prepare.verified_copy(source,target,prepare.digest(source))
        self.assertEqual(target.read_bytes(),b'user change')
        with self.assertRaisesRegex(ValueError,'input_digest_mismatch'):
            prepare.verified_copy(source,self.root/'new','0'*64)
        self.assertFalse((self.root/'new').exists())

    def test_archive_traversal_and_symbolic_links_are_rejected(self):
        for number,name in enumerate(('../escape','/absolute','safe/link')):
            archive=self.root/(str(number)+'.tar')
            with tarfile.open(archive,'w') as stream:
                entry=tarfile.TarInfo(name)
                if name.endswith('link'):
                    entry.type=tarfile.SYMTYPE;entry.linkname='../../outside'
                    stream.addfile(entry)
                else:
                    entry.size=7;stream.addfile(entry,io.BytesIO(b'fixture'))
            with patch.object(prepare,'capacity'),self.assertRaises(ValueError):
                prepare.extract(archive,self.root/('extract-'+str(number)))
        self.assertFalse((self.root/'escape').exists())

    def test_valid_relative_archive_extracts_without_reusing_existing_root(self):
        archive=self.root/'valid.tar'
        with tarfile.open(archive,'w') as stream:
            entry=tarfile.TarInfo('source/configure');entry.size=7
            stream.addfile(entry,io.BytesIO(b'fixture'))
        target=self.root/'extract'
        with patch.object(prepare,'capacity'):prepare.extract(archive,target)
        self.assertEqual((target/'source/configure').read_bytes(),b'fixture')
        with self.assertRaises(FileExistsError):prepare.extract(archive,target)


if __name__=='__main__':unittest.main()
