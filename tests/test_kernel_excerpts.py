"""Kernel excerpt manifests rebuild source trees without a local kernel checkout."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from capture_linux_aarch64 import reviewed_adapter

prepare = reviewed_adapter()


class KernelExcerpts(unittest.TestCase):
    def test_every_manifest_has_verified_store_assets(self):
        manifests = sorted((ROOT / 'integrations/linux_aarch64').glob('**/excerpts.json'))
        manifests += sorted((ROOT / 'tests/fixtures').glob('linux-aarch64-*/excerpts.json'))
        self.assertEqual(len(manifests), 70)
        for path in manifests:
            with self.subTest(manifest=str(path.relative_to(ROOT))):
                manifest = prepare.excerpt_manifest(path.parent)
                for name, digest in manifest['files'].items():
                    data = (prepare.EXCERPT_STORE / digest).read_bytes()
                    self.assertEqual(hashlib.sha256(data).hexdigest(), digest, name)

    def test_ingest_materialize_and_changed_manifest(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source, destination = root / 'source', root / 'destination'
            (source / 'upstream/kernel').mkdir(parents=True)
            destination.mkdir()
            (source / 'upstream/kernel/sys.c').write_bytes(b'original source\n')
            with patch.object(prepare, 'EXCERPT_STORE', root / 'store'):
                prepare.ingest(source)
                prepare.copy_excerpts(source, destination)
                tree = prepare.upstream(destination)
                self.assertEqual((tree / 'kernel/sys.c').read_bytes(), b'original source\n')
                (source / 'upstream/kernel/sys.c').write_bytes(b'updated source\n')
                prepare.ingest(source)
                prepare.copy_excerpts(source, destination)
                self.assertEqual((prepare.upstream(destination) / 'kernel/sys.c').read_bytes(),
                                 b'updated source\n')

    def test_matching_stamp_does_not_hide_files_removed_by_checkout(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'upstream/kernel').mkdir(parents=True)
            (root / 'upstream/kernel/sys.c').write_bytes(b'original source\n')
            with patch.object(prepare, 'EXCERPT_STORE', root / 'store'):
                prepare.ingest(root)
                (root / 'upstream/kernel/sys.c').unlink()
                self.assertTrue((root / 'upstream' / prepare.EXCERPT_STAMP).is_file())
                self.assertEqual((prepare.upstream(root) / 'kernel/sys.c').read_bytes(),
                                 b'original source\n')

    def test_corrupt_store_fails_before_materialization(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'upstream').mkdir()
            (root / 'upstream/source.c').write_bytes(b'original')
            destination = root / 'destination'
            destination.mkdir()
            with patch.object(prepare, 'EXCERPT_STORE', root / 'store'):
                manifest = prepare.ingest(root)
                prepare.copy_excerpts(root, destination)
                digest = manifest['files']['source.c']
                (root / 'store' / digest).write_bytes(b'corrupt')
                with self.assertRaisesRegex(ValueError, 'corrupt'):
                    prepare.upstream(destination)
                self.assertFalse((destination / 'upstream').exists())

    def test_invalid_manifest_paths_and_digests_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for path, digest in [('../escape.c', '0' * 64), ('/absolute.c', '0' * 64),
                                 ('source.c', 'invalid')]:
                (root / 'excerpts.json').write_text(json.dumps({
                    'format': 'osrec-kernel-excerpts-v1', 'files': {path: digest}}))
                with self.subTest(path=path, digest=digest), self.assertRaises(ValueError):
                    prepare.excerpt_manifest(root)


if __name__ == '__main__':
    unittest.main()
