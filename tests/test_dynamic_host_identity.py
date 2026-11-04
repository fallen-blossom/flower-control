"""Real candidate WinTrust/ASAR predicates; no live control or source registration."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DynamicHostIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='flower-dynamic-host-tests-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.folder = Path(cls.temp.name)
        cls.dotnet = Path(os.environ['ProgramFiles']) / 'dotnet/dotnet.exe'
        cls.library = cls.folder / 'native/Flower.HighHelper.dll'
        env = {**os.environ, 'DOTNET_CLI_TELEMETRY_OPTOUT': '1'}
        commands = [[str(cls.dotnet), 'build', str(ROOT / 'flower_control/drivers/high_helper/Flower.HighHelper.csproj'),
                     '--no-restore', '-c', 'Release', '-o', str(cls.library.parent), '--nologo', '-v:q',
                     '/p:UseSharedCompilation=false']]
        (cls.folder / 'Probe.csproj').write_text('''<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>
<OutputType>Exe</OutputType><TargetFramework>net10.0-windows</TargetFramework>
<ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable><TreatWarningsAsErrors>true</TreatWarningsAsErrors>
<NuGetAudit>false</NuGetAudit></PropertyGroup></Project>''')
        (cls.folder / 'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>')
        shutil.copyfile(ROOT / 'tests/fixtures/dynamic_host_identity/Program.cs', cls.folder / 'Program.cs')
        commands.append([str(cls.dotnet), 'build', str(cls.folder / 'Probe.csproj'), '--nologo', '-c', 'Release',
                         '--configfile', str(cls.folder / 'NuGet.Config'), '-o', str(cls.folder / 'probe'), '-v:q'])
        # Exclude the candidate build tree from this separate console project.
        project = cls.folder / 'Probe.csproj'
        project.write_text(project.read_text().replace('</Project>',
            '<ItemGroup><Compile Remove="native/**/*.cs" /></ItemGroup></Project>'))
        for command in commands:
            result = subprocess.run(command, capture_output=True, text=True, timeout=90, env=env)
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)
        cls.probe = cls.folder / 'probe/Probe.exe'

    def run_probe(self, *args):
        result = subprocess.run([str(self.probe), str(self.library), *map(str, args)],
                                capture_output=True, text=True, timeout=40, check=True)
        return json.loads(result.stdout)

    def archive(self, nodes=None, payload=b'hello', **changes):
        file = dict(size=len(payload), offset='0', integrity=dict(algorithm='SHA256', hash=hashlib.sha256(payload).hexdigest()))
        file.update(changes)
        header = json.dumps(dict(files=nodes if nodes is not None else {'test.txt': file}), separators=(',', ':')).encode()
        padding = b'\0' * ((-len(header)) % 4)
        size = 8 + len(header) + len(padding)
        path = self.folder / ('archive-' + os.urandom(5).hex() + '.asar')
        path.write_bytes(struct.pack('<IIII', 4, size, size - 4, len(header)) + header + padding + payload)
        return path, hashlib.sha256(header).hexdigest()

    def test_valid_packed_archive_and_payload_corruption(self):
        path, header = self.archive()
        self.assertTrue(self.run_probe('archive', path, header, path.with_suffix('.unpacked'))['accepted'])
        data = path.read_bytes(); path.write_bytes(data[:-1] + b'X')
        self.assertEqual(self.run_probe('archive', path, header, path.with_suffix('.unpacked'))['reason'], 'dsh_signed_archive_changed')

    def test_untrusted_header_cannot_supply_its_own_digest(self):
        path, header = self.archive()
        self.assertEqual(self.run_probe('archive', path, '0' * 64, path.with_suffix('.unpacked'))['reason'], 'dsh_signed_archive_changed')

    def test_offsets_links_and_unsafe_names_are_rejected(self):
        for changes in ({'offset': '-1'}, {'offset': str(2**63-1)}, {'link': '../outside'}, {'size': -1}):
            path, header = self.archive(**changes)
            self.assertFalse(self.run_probe('archive', path, header, path.with_suffix('.unpacked'))['accepted'])
        path, header = self.archive(nodes={'..': {'files': {}}})
        self.assertFalse(self.run_probe('archive', path, header, path.with_suffix('.unpacked'))['accepted'])

    def test_unpacked_file_is_verified_and_cannot_be_changed(self):
        path, header = self.archive(unpacked=True)
        unpacked = path.with_suffix('.unpacked'); unpacked.mkdir()
        (unpacked / 'test.txt').write_bytes(b'hello')
        self.assertEqual(self.run_probe('archive', path, header, unpacked), dict(accepted=True, unpacked=1))
        (unpacked / 'test.txt').write_bytes(b'other')
        self.assertEqual(self.run_probe('archive', path, header, unpacked)['reason'], 'dsh_signed_archive_changed')

    def test_dead_owner_releases_archive_pin(self):
        path, _ = self.archive()
        self.assertEqual(self.run_probe('lease', path), dict(blocked=True, released=True))

    def test_active_owners_keep_pin_until_last_exit_then_timer_releases(self):
        path, _ = self.archive()
        self.assertEqual(self.run_probe('lease-live', path), dict(live=True, oneLive=True, released=True))

    def test_unpacked_directory_is_locked_and_junction_is_rejected(self):
        path, header = self.archive(unpacked=True)
        unpacked = path.with_suffix('.unpacked'); unpacked.mkdir()
        (unpacked / 'test.txt').write_bytes(b'hello')
        self.assertEqual(self.run_probe('archive-held', path, header, unpacked), dict(accepted=True, directoryLocked=True))
        moved = unpacked.with_name(unpacked.name + '-moved'); unpacked.rename(moved)
        linked = subprocess.run([os.environ['ComSpec'], '/d', '/c', 'mklink', '/j', str(unpacked), str(moved)],
                                capture_output=True, text=True, check=True)
        self.assertEqual(self.run_probe('archive', path, header, unpacked)['reason'], 'dsh_signed_archive_path_changed')

    def test_unsigned_same_name_does_not_become_codex(self):
        path = self.folder / 'codex.exe'; path.write_bytes(b'not signed')
        self.assertFalse(self.run_probe('signer', path, 'codex.exe', 'OpenAI OpCo, LLC', 0, 'null')['accepted'])

    def test_actual_codex_ancestor_uses_current_publisher_and_exact_process(self):
        value = self.run_probe('chain')
        if not value.get('found'): self.skipTest('not running under local Codex; no host fabricated')
        self.assertEqual(value, dict(found=True, accepted=True, wrongCreated=False))

    def test_current_dsh_signer_and_signed_header_match_installed_archive(self):
        configured = os.environ.get('FLOWER_TEST_DSH_IMAGE')
        if not configured: self.skipTest('set FLOWER_TEST_DSH_IMAGE for recipient-local installed DSH; no download')
        exe = Path(configured)
        if not exe.is_file(): self.fail('configured DSH image missing')
        self.assertTrue(self.run_probe('signer', exe, exe.name, 'Hangzhou DeepSeek Artificial Intelligence Co., Ltd.', 0, 'null')['accepted'])
        self.assertFalse(self.run_probe('signer', exe, exe.name, 'OpenAI OpCo, LLC', 0, 'null')['accepted'])
        header = self.run_probe('resource', exe)['header']
        archive = exe.parent / 'resources/app.asar'
        started = time.perf_counter()
        self.assertTrue(self.run_probe('archive', archive, header, str(archive) + '.unpacked')['accepted'])
        print('dsh_installed_archive_validation_ms=' + str(round((time.perf_counter() - started) * 1000)), flush=True)
