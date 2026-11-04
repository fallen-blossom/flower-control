"""Installation identity and local path counterexamples; never write HKLM."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import win32security

from flower_control import install_location as location

SID = "S-1-5-21-1-2-3-1001"


class InstallationLocationTests(unittest.TestCase):
    def test_d_drive_layout_and_untrusted_environment(self):
        value = location.prepare_location("D:/FlowerControl", SID)
        self.assertEqual(value.program_root, Path("D:/FlowerControl/Program"))
        self.assertEqual(value.data_root, Path("D:/FlowerControl/Data"))
        self.assertEqual(value.cache_root, Path("D:/FlowerControl/Cache"))
        self.assertEqual(value.packages_root, Path("D:/FlowerControl/Packages"))
        with patch.dict(os.environ, ProgramFiles="D:/forged", FLOWER_INSTALL_ROOT="D:/forged"), \
                patch.object(location, "_read_registration", return_value=None), \
                patch.object(location, "known_folder", side_effect=lambda name: Path("C:/KnownProgramFiles" if name == "ProgramFiles" else "C:/KnownLocal")):
            old = location.discover_installation(SID)
        self.assertTrue(old.legacy)
        self.assertEqual(old.program_root, Path("C:/KnownProgramFiles/FlowerControl/HighHelper"))

    def test_permissions_reader_tracks_registered_root_without_environment_or_cached_path(self):
        from flower_control import permissions
        old = location.prepare_location("D:/FlowerControl", SID)
        moved = location.prepare_location("E:/FlowerControl", SID)
        with patch.object(location, "discover_installation", side_effect=[old, moved]), \
                patch.object(permissions, "user_sid", return_value=SID):
            self.assertEqual(permissions.production_path(), old.program_root / "permissions" / (SID + ".json"))
            self.assertEqual(permissions.production_path(), moved.program_root / "permissions" / (SID + ".json"))

    def test_paths_cannot_select_unc_devices_streams_parent_or_volume(self):
        for path in ("relative", "D:/", "D:/root/../code", "D:/root./code", "D:/root /code",
                     "D:/root:stream", r"\\server\share\code", r"\\?\D:\code", "D:/r?ot"):
            with self.subTest(path=path), self.assertRaises(location.InstallLocationError):
                location.prepare_location(path, SID)

    def registered_fixture(self, temporary):
        value = location.prepare_location(Path(temporary) / "root", SID)
        value.program_root.mkdir(parents=True)
        manifest = dict(schema=1, installation_id="a" * 32, user_sid=SID,
                        host_bindings=[{"Kind": "codex", "Path": "protected host identity"}])
        manifest.update({key: str(getattr(value, key)) for key in
                         ("root", "program_root", "data_root", "cache_root", "packages_root")})
        path = value.program_root / location.MANIFEST_NAME
        path.write_text(json.dumps(manifest), encoding="utf-8")
        record = dict(schema=1, installation_id="a" * 32, user_sid=SID, root=str(value.root),
                      manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        return value, path, record, manifest

    def test_registered_layout_manifest_drift_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory(prefix="flower-location-") as temporary:
            expected, path, record, manifest = self.registered_fixture(temporary)
            # Only ACLs are synthesized. Real handles, final paths, bytes,
            # parser and registry-to-manifest digest binding stay in the path.
            with patch.object(location, "_read_registration", return_value=record), \
                    patch.object(location, "_require_acl"):
                actual = location.discover_installation(SID)
                self.assertEqual(actual.program_root, expected.program_root)
                self.assertFalse(actual.legacy)
                path.write_text(json.dumps({**manifest, "data_root": "D:/elsewhere"}))
                with self.assertRaisesRegex(location.InstallLocationError, "manifest_changed"):
                    location.discover_installation(SID)
                record["manifest_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                with self.assertRaisesRegex(location.InstallLocationError, "layout_mismatch"):
                    location.discover_installation(SID)
                raw = json.dumps(manifest)[:-1] + ',"schema":1}'
                path.write_text(raw)
                record["manifest_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                with self.assertRaisesRegex(location.InstallLocationError, "schema_rejected"):
                    location.discover_installation(SID)

    def test_registration_failure_never_becomes_legacy(self):
        for failure in (location.InstallLocationError("installation_unprotected"), PermissionError("denied")):
            with patch.object(location, "_read_registration", side_effect=failure), \
                    patch.object(location, "known_folder") as known:
                with self.assertRaises(location.InstallLocationError):
                    location.discover_installation(SID)
                known.assert_not_called()
        with patch.object(location, "_read_registration", return_value={"schema": 1}):
            with self.assertRaisesRegex(location.InstallLocationError, "registration_rejected"):
                location.discover_installation(SID)

    def test_writable_hklm_registration_rejected_before_record_read(self):
        descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            "O:BAD:(A;;KA;;;BA)(A;;KW;;;BU)", 1)
        key = MagicMock()
        key.__enter__.return_value = key
        with patch.object(location, "_open_registry_key", return_value=key), \
                patch("win32security.GetSecurityInfo", return_value=descriptor), \
                patch("winreg.QueryValueEx") as query:
            with self.assertRaisesRegex(location.InstallLocationError, "unprotected"):
                location._read_registration(SID)
            query.assert_not_called()

    def test_registry_link_itself_is_rejected_before_absent_target_can_fall_back(self):
        descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor("O:BAD:(A;;KA;;;BA)", 1)
        key = MagicMock()
        key.__enter__.return_value = key
        with patch.object(location, "_open_registry_key", return_value=key), \
                patch("win32security.GetSecurityInfo", return_value=descriptor), \
                patch("winreg.QueryValueEx", return_value=(r"\Registry\User\absent", 6)), \
                self.assertRaisesRegex(location.InstallLocationError, "registry_link_rejected"):
            location._read_registration(SID)

    def test_acl_blocks_mutable_owner_null_acl_file_and_delete_child(self):
        for sddl, mask in (("O:S-1-5-21-1-2-3-1001D:(A;;FA;;;SY)", location._MUTATION),
                           ("O:BAD:NO_ACCESS_CONTROL", location._MUTATION),
                           ("O:BAD:(A;;FA;;;BA)(A;;FW;;;BU)", location._MUTATION),
                           ("O:BAD:(A;;FA;;;BA)(A;;0x40;;;BU)", location._MUTATION),
                           ("O:BAD:(A;;FA;;;BA)(A;;0x40;;;BU)", location._PARENT_MUTATION)):
            descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1)
            with self.subTest(sddl=sddl), self.assertRaisesRegex(location.InstallLocationError, "unprotected"):
                location._require_acl(descriptor, mask)
        # Normal NTFS volume defaults permit creating independent children and
        # DELETE on the undeletable volume root, without DELETE_CHILD rights.
        descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            "O:SYD:(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1301bf;;;AU)(A;OICIIO;GA;;;AU)", 1)
        location._require_acl(descriptor, location._PARENT_MUTATION)
        with self.assertRaises(location.InstallLocationError):
            location._require_acl(descriptor, location._MUTATION)
        # Default HKLM SOFTWARE carries CREATOR_OWNER as a placeholder. It
        # grants no token principal; each object's actual owner is still pinned.
        descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            "O:SYD:(A;CI;KR;;;BU)(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KA;;;CO)", 1)
        location._require_acl(descriptor, 0x500D0026)

    def test_real_writable_directory_and_junction_rejected(self):
        import _winapi
        with tempfile.TemporaryDirectory(prefix="flower-location-links-") as temporary:
            parent = Path(temporary)
            (parent / "target").mkdir()
            with self.assertRaisesRegex(location.InstallLocationError, "unprotected"):
                location.require_protected_path(parent / "target")
            _winapi.CreateJunction(str(parent / "target"), str(parent / "alias"))
            # Keep actual path resolution and link inspection; fake only ACLs
            # of the necessarily user-owned temporary test parent.
            with patch.object(location, "_require_acl"), \
                    self.assertRaisesRegex(location.InstallLocationError, "link_rejected"):
                location.require_protected_path(parent / "alias")


if __name__ == "__main__":
    unittest.main()
