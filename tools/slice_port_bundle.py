"""Pinned external construction inputs for a reviewed kernel slice port.

Adapters are trusted build-time Python code, run from a checked private copy.
The resulting guest archive contains compiled code and data only.
"""
import hashlib
import re
import shutil
import sys
import types
from pathlib import Path, PurePosixPath

FORMAT = 'osrec-kernel-slice-bundle-v1'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def relative_name(name):
    if not isinstance(name, str) or not name or '\\' in name:
        raise ValueError('invalid port bundle path')
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or str(path) != name or name == '.':
        raise ValueError('invalid port bundle path: '+name)
    return name


def validate_bundle(bundle):
    if not isinstance(bundle, dict) or bundle.get('format') != FORMAT:
        raise ValueError('unsupported port bundle')
    inputs = bundle.get('inputs')
    if not isinstance(inputs, dict) or not 1 <= len(inputs) <= 4096:
        raise ValueError('port bundle requires pinned inputs')
    for name, expected in inputs.items():
        relative_name(name)
        if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected):
            raise ValueError('invalid port bundle input digest')
    adapter = relative_name(bundle.get('adapter'))
    if adapter not in inputs or not adapter.endswith('.py'):
        raise ValueError('port bundle adapter must be pinned Python source')
    proofs = bundle.get('proofs')
    if not isinstance(proofs, dict) or 'session' not in proofs or proofs.keys()-{'session', 'frame', 'cpu'}:
        raise ValueError('port bundle requires a session proof')
    for mode, proof in proofs.items():
        if not isinstance(proof, dict):
            raise ValueError('invalid port bundle proof')
        source = relative_name(proof.get('source'))
        if source not in inputs or not source.endswith('.c'):
            raise ValueError('port bundle proof source must be pinned')
        abi = proof.get('result_abi')
        if type(abi) is not int or abi not in {'session': (18, 26), 'frame': (19,), 'cpu': (20,)}[mode]:
            raise ValueError('unsupported port bundle proof result ABI')
        if mode == 'cpu':
            application = relative_name(proof.get('application'))
            if application not in inputs or not application.endswith('.S'):
                raise ValueError('port bundle CPU proof application must be pinned')


def verify_inputs(directory, inputs, exact=False):
    directory = Path(directory).resolve()
    if exact:
        actual = {str(p.relative_to(directory)) for p in directory.rglob('*') if p.is_file()}
        if actual != inputs.keys():
            raise ValueError('port bundle artifact set mismatch')
    for name, expected in inputs.items():
        path = directory/relative_name(name)
        if not path.resolve().is_relative_to(directory) or not path.is_file() or digest(path.read_bytes()) != expected:
            raise ValueError('port bundle input identity mismatch: '+name)


def snapshot(descriptor, port, destination, mode):
    """Validate before executing Python, then freeze all declared construction bytes."""
    bundle = port['bundle'];validate_bundle(bundle)
    if mode not in bundle['proofs']:
        raise ValueError('port bundle lacks selected '+mode+' proof')
    origin = Path(descriptor).resolve().parent
    verify_inputs(origin, bundle['inputs'])
    destination.mkdir()
    for name, expected in bundle['inputs'].items():
        raw = (origin/name).read_bytes()
        if digest(raw) != expected:
            raise ValueError('port bundle changed during snapshot: '+name)
        path = destination/name;path.parent.mkdir(parents=True, exist_ok=True);path.write_bytes(raw)
    verify_inputs(destination, bundle['inputs'], exact=True)
    adapter = destination/bundle['adapter']
    module = types.ModuleType('osrec_external_port_'+digest(str(adapter).encode()+adapter.read_bytes()))
    module.__file__ = str(adapter)
    code = compile(adapter.read_bytes(), str(adapter), 'exec')
    def prepare(args, sources):
        # Register during construction for standard Python features such as dataclasses.
        # Loading frozen source directly avoids undeclared __pycache__ artifacts.
        sys.modules[module.__name__] = module
        try:
            exec(code, module.__dict__)
            if not callable(getattr(module, 'prepare', None)):
                raise ValueError('port bundle adapter has no prepare(args, sources)')
            return module.prepare(args, sources)
        finally:
            sys.modules.pop(module.__name__, None)
    return types.SimpleNamespace(prepare=prepare), bundle['proofs'][mode]


def publish_inputs(source, destination, bundle):
    verify_inputs(source, bundle['inputs'], exact=True)
    shutil.copytree(source, destination)


def verify_published(directory, manifest):
    """Legacy ports have no bundle; new ports retain their complete pinned inputs."""
    port = manifest.get('port', {})
    if 'bundle' not in port:
        return
    validate_bundle(port['bundle'])
    verify_inputs(Path(directory), port['bundle']['inputs'], exact=True)
