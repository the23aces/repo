import copy
import importlib.util
import plistlib
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

spec = importlib.util.spec_from_file_location('source', Path(__file__).resolve().parents[1] / 'scripts/update_source.py')
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)


def executable(entitlements):
    xml = plistlib.dumps(entitlements)
    child = struct.pack('>II', 0xFADE7171, len(xml) + 8) + xml
    signature = struct.pack('>III', 0xFADE0CC0, 20 + len(child), 1) + struct.pack('>II', 5, 20) + child
    header = struct.pack('<IIIIIIII', 0xFEEDFACF, 0x100000C, 0, 2, 1, 16, 0, 0)
    return header + struct.pack('<IIII', 0x1D, 16, 48, len(signature)) + signature


class SourceTests(unittest.TestCase):
    def test_reads_main_and_extension_metadata_without_extracting_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fixture.ipa'
            main = {'CFBundleIdentifier': 'org.example.App', 'CFBundleDisplayName': 'Example',
                    'CFBundleShortVersionString': '2.4', 'CFBundleVersion': '17', 'CFBundleExecutable': 'Main',
                    'MinimumOSVersion': '15.0', 'NSCameraUsageDescription': 'Scan a code.'}
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr('Payload/Test.app/Info.plist', plistlib.dumps(main, fmt=plistlib.FMT_BINARY))
                z.writestr('Payload/Test.app/Main', executable({'application-identifier': 'TEAM.org.example.App', 'get-task-allow': False}))
                z.writestr('Payload/Test.app/PlugIns/Widget.appex/Info.plist', plistlib.dumps({'CFBundleExecutable': 'Widget', 'NSMicrophoneUsageDescription': 'Record a note.'}))
                z.writestr('Payload/Test.app/PlugIns/Widget.appex/Widget', executable({'com.apple.security.application-groups': ['group.example']}))
                z.writestr('../../never-extracted', b'not executable')
            result = source.inspect_ipa(path)
            self.assertEqual(result['bundleIdentifier'], 'org.example.App')
            self.assertEqual((result['version'], result['buildVersion']), ('2.4', '17'))
            self.assertEqual(result['minOSVersion'], '15.0')
            self.assertIn('com.apple.security.application-groups', result['appPermissions']['entitlements'])
            self.assertIn('NSMicrophoneUsageDescription', result['appPermissions']['privacy'])
            self.assertFalse((Path(tmp).parent / 'never-extracted').exists())

    def test_reads_universal_executable(self):
        binary = executable({'com.apple.developer.siri': True})
        fat = struct.pack('>II', 0xCAFEBABE, 1) + struct.pack('>IIIII', 0x100000C, 0, 28, len(binary), 0) + binary
        self.assertEqual(source.macho_entitlements(fat), {'com.apple.developer.siri'})

    def test_rejects_bad_signature_offsets(self):
        broken = bytearray(executable({}))
        struct.pack_into('<I', broken, 40, len(broken) + 100)
        with self.assertRaisesRegex(ValueError, 'out of bounds'):
            source.macho_entitlements(bytes(broken))

    def test_refuses_der_only_permissions_instead_of_silently_omitting_them(self):
        child = struct.pack('>II', 0xFADE7172, 8)
        blob = struct.pack('>III', 0xFADE0CC0, 28, 1) + struct.pack('>II', 7, 20) + child
        with self.assertRaisesRegex(ValueError, 'DER-only'):
            source.signature_entitlements(blob)

    def test_release_sorting_filters_drafts_prereleases_and_non_ipas(self):
        def release(day, tag, **kwargs):
            return {'published_at': f'2026-10-{day}T12:00:00Z', 'tag_name': tag,
                    'assets': [{'state': 'uploaded', 'name': 'App.IPA', 'id': int(day), 'updated_at': f'2026-10-{day}T13:00:00Z'},
                               {'state': 'uploaded', 'name': 'notes.txt'}], **kwargs}
        releases = [release('01', 'v99'), release('04', 'v100', draft=True), release('02', 'v1'), release('03', 'v2', prerelease=True)]
        self.assertEqual([r['tag_name'] for r, _ in source.select_assets(releases, False)], ['v1', 'v99'])
        self.assertEqual([r['tag_name'] for r, _ in source.select_assets(releases, True)], ['v2', 'v1', 'v99'])

    def test_same_version_and_build_keeps_newest_download_without_fake_ids(self):
        meta = {'name': 'Example', 'bundleIdentifier': 'org.example.App', 'version': '1.0', 'buildVersion': '5',
                'appPermissions': {'entitlements': [], 'privacy': {}}}
        first = {'metadata': meta, 'assetName': 'new.ipa', 'date': '2026-10-12T00:00:00Z',
                 'downloadURL': 'https://example.org/new.ipa', 'size': 99, 'description': 'new'}
        duplicate = copy.deepcopy(first)
        duplicate['downloadURL'] = 'https://example.org/old.ipa'
        earlier_build = copy.deepcopy(duplicate)
        earlier_build['metadata']['buildVersion'] = '4'
        config = {'releasesRepository': 'test/ipas', 'iconURL': 'https://example.org/icon.png'}
        app = source.make_app([first, duplicate, earlier_build], config)
        self.assertEqual(app['bundleIdentifier'], 'org.example.App')
        self.assertEqual(len(app['versions']), 2)
        self.assertEqual(app['versions'][0]['downloadURL'], first['downloadURL'])
        self.assertEqual(app['downloadURL'], first['downloadURL'])
        self.assertEqual(app['versions'][1]['buildVersion'], '4')

    def test_checksum_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'app.ipa'
            path.write_bytes(b'data')
            with self.assertRaisesRegex(ValueError, 'Checksum mismatch'):
                source.verify_asset(path, {'name': 'app.ipa', 'size': 4, 'digest': 'sha256:' + '0' * 64})

    def test_generated_source_has_unique_app_identifiers(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate app bundle ID'):
            source.validate_source({'name': 'Test', 'identifier': 'org.test', 'apps': [
                {'bundleIdentifier': 'org.app', 'versions': [{'version': '1', 'buildVersion': '1', 'size': 1,
                    'downloadURL': 'https://example.org/a.ipa', 'date': '2026-10-12'}]},
                {'bundleIdentifier': 'org.app', 'versions': []}]})


if __name__ == '__main__':
    unittest.main()
