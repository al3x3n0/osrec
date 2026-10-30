"""Preflight validates construction inputs without claiming native behavior."""
import contextlib
import gzip
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import capture_linux_aarch64 as capture
import preflight_linux_aarch64 as check


def configuration(*extra):
    return ('# Linux/arm64 6.10 Kernel Configuration\n' + ''.join(
        'CONFIG_' + s + '=y\n' for s in capture.BASE_CONFIG + extra)).encode()


def image(path, config):
    raw = bytearray(64)
    raw[56:60] = b'ARM\x64'
    raw.extend(b'Linux version 6.10-test\0IKCFG_ST')
    raw.extend(gzip.compress(config, mtime=0))
    raw.extend(b'IKCFG_ED')
    path.write_bytes(raw)
    return path


class LinuxPreflightTests(unittest.TestCase):
    def test_all_profiles_sources_recipes_abi_and_witnesses(self):
        result = check.preflight()
        self.assertEqual(result['status'], 'inputs_validated')
        self.assertEqual(result['coverage']['validated_profiles'], 35)
        self.assertEqual(len(result['coverage']['distinct_routes']), 39)
        self.assertEqual(result['coverage']['profiles_covering_union'], ['file-setrlimit'])
        self.assertEqual({p['profile'] for p in result['profiles']}, set(capture.PROFILES))
        self.assertFalse(result['native_behavior_verified'])
        self.assertFalse(result['native_source_build_attested'])
        self.assertIsNone(result['kernel'])
        self.assertIsNone(result['tools'])
        combined = next(p for p in result['profiles'] if p['profile'] == 'file-credentials')
        self.assertEqual((combined['logical_calls'], combined['route_count'],
                          combined['original_definition_count']), (821, 37, 108))
        self.assertTrue(combined['generated_witness_verified'])
        limits = next(p for p in result['profiles'] if p['profile'] == 'file-rlimit')
        self.assertEqual((limits['logical_calls'], limits['route_count'],
                          limits['original_definition_count']), (851, 38, 109))
        all_limits = next(p for p in result['profiles'] if p['profile'] == 'file-limits')
        self.assertEqual((all_limits['logical_calls'], all_limits['route_count'],
                          all_limits['original_definition_count']), (924, 38, 109))
        setters = next(p for p in result['profiles'] if p['profile'] == 'file-setrlimit')
        self.assertEqual((setters['logical_calls'], setters['route_count'],
                          setters['original_definition_count']), (973, 39, 111))
        self.assertEqual([r['function'] for r in combined['routes']
                          if r['implementation'] == 'reviewed_model'], ['linux_fcntl'])
        on_disk = {'minimal' if p == capture.INTEGRATION else p.name
                   for p in [capture.INTEGRATION, *capture.INTEGRATION.iterdir()]
                   if p.is_dir() and (p / 'port-template.json').exists()}
        self.assertEqual(on_disk, set(capture.PROFILES))
        with mock.patch.object(check, 'discover_profiles', return_value=on_disk | {'unregistered'}):
            rejected = check.preflight()
            self.assertEqual(rejected['status'], 'rejected')
            self.assertIn('unregistered', rejected['errors'][0])

    def test_requirements_preserve_all_existing_constructor_contracts(self):
        group = set(capture.PROFILES[4:14])
        files = set(capture.PROFILES[15:])
        for profile in capture.PROFILES:
            expected = set(capture.BASE_CONFIG)
            if profile in group | files:
                expected.add('ARM64_4K_PAGES')
            if profile in files:
                expected.update(('MEMFD_CREATE', 'SHMEM'))
            self.assertEqual(set(capture.required_config(profile)), expected, profile)
        for bad in (b'# CONFIG_SHMEM=y\n', b'CONFIG_SHMEM=m\n',
                    b'CONFIG_SHMEM=yy\n', b'CONFIG_SHMEM=y\nCONFIG_SHMEM=n\n',
                    b'CONFIG_SHMEM=y\n# CONFIG_SHMEM is not set\n',
                    b'CONFIG_SHMEM=y\nCONFIG_SHMEM=y\n'):
            with self.subTest(config=bad):
                self.assertEqual(capture.missing_config(bad, ['SHMEM']), ['SHMEM'])
        self.assertEqual(capture.missing_config(b'CONFIG_SHMEM=y\r\n', ['SHMEM']), [])

    def test_image_and_config_failures_are_reported_without_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'Image'
            image(path, configuration())
            result = check.preflight('file-credentials', path)
            self.assertEqual(result['status'], 'rejected')
            self.assertEqual(result['profiles'][0]['missing_builtin_config'],
                             ['CONFIG_ARM64_4K_PAGES', 'CONFIG_MEMFD_CREATE', 'CONFIG_SHMEM'])
            self.assertEqual(check.preflight('minimal', path)['status'], 'prerequisites_validated')
            for raw in (b'compressed or wrong architecture',
                        path.read_bytes() + b'Linux version 6.11-other\0',
                        path.read_bytes().replace(b'IKCFG_ST', b'BADCFG_ST'),
                        path.read_bytes().replace(b'\x1f\x8b\x08', b'\x00\x00\x00')):
                with self.subTest(raw=raw[:12]):
                    path.write_bytes(raw)
                    result = check.preflight('minimal', path)
                    self.assertEqual(result['status'], 'rejected')
                    self.assertTrue(result['errors'])
                    self.assertFalse(result['native_behavior_verified'])
            image(path, configuration())
            supplied = Path(directory) / 'config'
            supplied.write_bytes(configuration().replace(b'6.10 Kernel', b'6.11 Kernel'))
            self.assertEqual(check.preflight('minimal', path, supplied)['status'], 'rejected')

    def test_capture_rejects_missing_or_forged_config_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            args = SimpleNamespace(out=stage / 'capture', kernel_image=stage / 'Image',
                                   profile='file-credentials')
            for config in (configuration(),
                           configuration('ARM64_4K_PAGES', 'SHMEM') + b'# CONFIG_MEMFD_CREATE=y\n',
                           configuration('ARM64_4K_PAGES', 'SHMEM', 'MEMFD_CREATE') + b'CONFIG_MEMFD_CREATE=n\n'):
                image(args.kernel_image, config)
                with mock.patch.object(capture.subprocess, 'run') as run:
                    with self.assertRaisesRegex(ValueError, 'unique builtin'):
                        capture.capture(args)
                    run.assert_not_called()
                self.assertFalse(args.out.exists())

    def test_changed_source_routes_arguments_and_generated_witness_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            minimal = stage / 'minimal'
            shutil.copytree(capture.INTEGRATION, minimal,
                            ignore=lambda path, names: [n for n in names if
                                (Path(path) == capture.INTEGRATION and (Path(path) / n).is_dir() and n != 'upstream')])
            port = minimal / 'port-template.json'
            original_port = port.read_bytes()
            source = minimal / 'upstream/kernel/sys.c'
            original_source = source.read_bytes()
            with mock.patch.object(check, 'profile_integration', return_value=minimal):
                source.write_bytes(original_source.replace(b'return task_tgid_vnr(current);', b'return 1;', 1))
                with self.assertRaises(ValueError):
                    check.inspect_profile('minimal')
                source.write_bytes(original_source)
                for mutation in ('number', 'function', 'arity', 'abi', 'duplicate'):
                    value = json.loads(original_port)
                    if mutation == 'number':
                        value['roots'][0]['number'] = 9999
                    elif mutation == 'function':
                        value['roots'][0]['function'] = 'linux_unreviewed'
                    elif mutation == 'arity':
                        value['roots'][0]['arguments'].append('unsigned')
                    elif mutation == 'abi':
                        value['application_abi']['number_register'] = 9
                    else:
                        value['roots'].append(value['roots'][0])
                    port.write_text(json.dumps(value))
                    with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                        check.inspect_profile('minimal')
                port.write_bytes(original_port)
            combined = stage / 'combined'
            shutil.copytree(capture.profile_integration('file-credentials'), combined)
            application = combined / 'application.c'
            application.write_text(application.read_text() + '\n/* unreviewed edit */\n')
            with mock.patch.object(check, 'profile_integration', return_value=combined):
                with self.assertRaisesRegex(ValueError, 'generated application'):
                    check.inspect_profile('file-credentials')

    def test_tool_target_accelerator_and_timeout_failures(self):
        def probe(argv):
            if '--print-targets' in argv:
                return '  aarch64 - AArch64 (little endian)\n'
            if '-accel' in argv:
                return 'Accelerators supported in QEMU binary:\ntcg\n'
            if str(argv[0]).endswith('qemu'):
                return 'QEMU emulator version 9.2.3\n'
            return 'LLVM version 16\n'
        with mock.patch.object(check.shutil, 'which', return_value='/tool/qemu'), \
                mock.patch.object(check, 'probe', side_effect=probe):
            self.assertEqual(check.inspect_tools('/llvm', 'qemu')['qemu']['accelerator'], 'tcg')
            with self.assertRaisesRegex(ValueError, 'accelerator unavailable'):
                check.inspect_tools('/llvm', 'qemu', 'hvf')
        with mock.patch.object(check.subprocess, 'run', side_effect=subprocess.TimeoutExpired('tool', 10)):
            with self.assertRaisesRegex(ValueError, 'tool probe failed'):
                check.probe(['tool', '--version'])
        with mock.patch.object(check, 'probe', return_value='LLVM without AArch64\n'):
            with self.assertRaisesRegex(ValueError, 'no AArch64 target'):
                check.inspect_tools('/llvm', 'qemu')

    def test_cli_status_rejected_report_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            stage = Path(directory)
            out = stage / 'report.json'
            self.assertEqual(check.main(['--profile', 'minimal', '--out', str(out)]), 0)
            original = out.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                check.main(['--profile', 'minimal', '--out', str(out)])
            self.assertEqual(out.read_bytes(), original)
            bad = stage / 'bad-image'
            bad.write_bytes(b'not an Image')
            rejected = stage / 'rejected.json'
            self.assertEqual(check.main(['--profile', 'minimal', '--kernel-image', str(bad),
                                         '--out', str(rejected)]), 1)
            self.assertEqual(json.loads(rejected.read_text())['status'], 'rejected')
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                check.main(['--config', str(bad)])
            with self.assertRaises(ValueError):
                check.preflight('unknown-profile')


if __name__ == '__main__':
    unittest.main(verbosity=2)
