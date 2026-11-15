"""Controller-only artifact staging tests; never execute artifact binaries."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('microlab_artifacts', ROOT / 'scripts/microlab_artifacts.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def elf(arch):
    data = bytearray(64)
    data[:6] = b'\x7fELF\x02\x01'
    data[18:20] = struct.pack('<H', a.ARCHES[arch])
    return bytes(data)


def archive(member, data, unsafe=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as tar:
        info = tarfile.TarInfo(member)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        if unsafe:
            info = tarfile.TarInfo(unsafe)
            tar.addfile(info, io.BytesIO())
    return stream.getvalue()


class ArtifactSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inventory = self.root / 'inventory/hosts.yml'
        self.inventory.parent.mkdir()
        self.inventory.write_text(yaml.safe_dump({'all': {'children': {
            'microlab_management': {'hosts': {'infra': {'ansible_host': '10.72.78.73'}}},
            'microlab_challenge': {'hosts': {'rctf': {'ansible_host': '10.72.78.72', 'micolab_expected_architecture': 'amd64'}}},
        }}}))
        self.group = self.inventory.parent / 'group_vars/microlab_management'
        self.group.mkdir(parents=True)
        self.main = self.group / 'main.yml'
        self.vars = {'micolab_expected_architecture': 'arm64', 'micolab_admin_cidrs': ['REPLACE_WITH_ADMIN_CIDR'], 'micolab_client_cidrs': ['10.72.78.0/24']}
        self.write_vars()
        self.vault = self.group / 'vault.yml'
        self.vault.write_text('$ANSIBLE_VAULT;1.1;AES256\nnot-a-real-vault\n')
        self.directory = self.root / 'artifacts'
        self.lock = self.root / 'lock.json'
        self.manifest = json.loads(a.LOCK.read_text())
        self.payloads = {}
        for name, arches in self.manifest['artifacts'].items():
            for arch, entry in arches.items():
                data = elf(arch) if name == 'forgejo' else archive(entry['member'], b'managed-DLL' if name == 'technitium' else elf(arch))
                entry['sha256'] = hashlib.sha256(data).hexdigest()
                entry['publisher_hash'] = {'sha512': hashlib.sha512(data).hexdigest()}
                self.payloads[entry['url']] = data
        self.save_lock()

    def write_vars(self):
        self.main.write_text(yaml.safe_dump(self.vars))

    def save_lock(self):
        self.lock.write_text(json.dumps(self.manifest))

    def fetch(self, url, destination):
        destination.write_bytes(self.payloads[url])

    def stage(self, **kwargs):
        return a.stage(self.inventory, self.directory, lock_path=self.lock, **kwargs)

    def populate(self):
        with patch.object(a, 'download', side_effect=self.fetch) as download:
            result = self.stage()
            self.assertEqual(download.call_count, 6)
        return result

    def test_multiarch_publisher_manifest_complete(self):
        lock = json.loads(a.LOCK.read_text())
        self.assertEqual(set(lock['artifacts']), set(a.VARS))
        for name, entries in lock['artifacts'].items():
            self.assertEqual(set(entries), {'amd64', 'arm64'})
            for entry in entries.values():
                self.assertRegex(entry['sha256'], r'^[a-f0-9]{64}$')
                self.assertTrue(entry['url'].startswith('https://'))
                self.assertNotIn('/latest/', entry['url'])
                self.assertTrue(entry['publisher_hash'])
                self.assertTrue(entry['metadata_url'].startswith('https://'))

    def test_download_publish_and_existing_inventory_preserved(self):
        before = {p: p.read_bytes() for p in (self.main, self.vault, self.inventory)}
        result = self.populate()
        self.assertEqual(result['architecture'], 'arm64')
        self.assertEqual(result['acceptance'], 'not_run')
        self.assertEqual(result['installation_readiness'], 'artifacts_only')
        for p, value in before.items():
            self.assertEqual(p.read_bytes(), value)
        variables = yaml.safe_load(Path(result['group_vars']).read_text())
        self.assertEqual(len(variables['micolab_staged_artifacts']), 6)
        for name in ['ca', 'cli']:
            path = Path(variables[f'microlab_step_{name}_artifact_src'])
            self.assertTrue(path.is_absolute())
            self.assertTrue(path.is_relative_to(self.directory))
        self.assertFalse(list(self.directory.glob('.microlab-*')))

    def test_cached_offline_and_readonly_check(self):
        self.populate()
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.rglob('*') if p.is_file()}
        with patch.object(a, 'download', side_effect=AssertionError('network forbidden')):
            self.assertEqual(self.stage(offline=True)['status'], 'ready')
            # Check must not change any files, including generated vars.
            before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.rglob('*') if p.is_file()}
            self.assertEqual(self.stage(check=True)['status'], 'checked')
        self.assertEqual(before, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.rglob('*') if p.is_file()})

    def test_network_failure_cleans_partial_and_does_not_publish_vars(self):
        def failure(url, path):
            path.write_bytes(b'partial')
            raise a.ArtifactError('network failed')
        with patch.object(a, 'download', side_effect=failure), self.assertRaisesRegex(a.ArtifactError, 'network failed'):
            self.stage()
        self.assertEqual(list(self.directory.iterdir()), [])
        self.assertFalse((self.group / a.GENERATED).exists())

    def test_actionable_url_error(self):
        with patch.object(a.urllib.request, 'urlopen', side_effect=urllib.error.URLError('offline')):
            with self.assertRaisesRegex(a.ArtifactError, 'stage the pinned file and use --offline'):
                a.download('https://example.org/releases/v1/archive.tar.gz', self.root / 'tmp')

    def test_bad_download_hash_never_published(self):
        with patch.object(a, 'download', side_effect=lambda url, p: p.write_bytes(b'bad')), self.assertRaisesRegex(a.ArtifactError, 'SHA256 mismatch'):
            self.stage()
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_existing_wrong_hash_preserved(self):
        self.populate()
        target = next(self.directory.iterdir())
        target.write_bytes(b'user file')
        with patch.object(a, 'download') as download, self.assertRaisesRegex(a.ArtifactError, 'SHA256 mismatch'):
            self.stage()
        download.assert_not_called()
        self.assertEqual(target.read_bytes(), b'user file')

    def test_wrong_arch_even_with_matching_hash(self):
        entry = copy.deepcopy(self.manifest['artifacts']['forgejo']['arm64'])
        path = self.root / 'wrong'
        path.write_bytes(elf('amd64'))
        entry['sha256'] = a.digest(path)
        entry['publisher_hash'] = {}
        with self.assertRaisesRegex(a.ArtifactError, 'wrong architecture'):
            a.validate(path, entry, 'arm64', 'forgejo')

    def test_unsafe_archive_and_wrong_layout(self):
        entry = copy.deepcopy(self.manifest['artifacts']['caddy']['arm64'])
        entry['publisher_hash'] = {}
        for data, message in [(archive('other', elf('arm64')), 'must contain caddy'), (archive('caddy', elf('arm64'), '../outside'), 'unsafe archive')]:
            path = self.root / 'bad.tar.gz'
            path.write_bytes(data)
            entry['sha256'] = a.digest(path)
            with self.assertRaisesRegex(a.ArtifactError, message):
                a.validate(path, entry, 'arm64', 'caddy')

    def test_path_escape_and_symlink(self):
        self.directory.mkdir()
        outside = self.root / 'outside'
        outside.write_text('keep')
        with self.assertRaises(a.ArtifactError):
            a.confined(self.directory, '../outside')
        (self.directory / 'link').symlink_to(outside)
        with self.assertRaises(a.ArtifactError):
            a.confined(self.directory, 'link')
        self.assertEqual(outside.read_text(), 'keep')
        other = self.root / 'symlink-dir'
        other.symlink_to(self.directory)
        with self.assertRaisesRegex(a.ArtifactError, 'symlink'):
            a.stage(self.inventory, other, lock_path=self.lock)

    def test_generated_vars_symlink_or_user_content_not_overwritten(self):
        generated = self.group / a.GENERATED
        generated.write_text('# User settings\n')
        with self.assertRaisesRegex(a.ArtifactError, 'refusing to overwrite'):
            self.stage()
        generated.unlink()
        outside = self.root / 'outside'
        outside.write_text('keep')
        generated.symlink_to(outside)
        with self.assertRaisesRegex(a.ArtifactError, 'symlink'):
            self.stage()
        self.assertEqual(outside.read_text(), 'keep')

    def test_explicit_conflict_fails_before_download(self):
        self.vars['micolab_caddy_checksums'] = {'arm64': 'f' * 64}
        self.write_vars()
        with patch.object(a, 'download') as download, self.assertRaisesRegex(a.ArtifactError, 'conflicts with publisher lock'):
            self.stage()
        download.assert_not_called()
        self.assertFalse(self.directory.exists())

    def test_manual_offline_inputs_and_extra_entries(self):
        staged = []
        for name in a.VARS:
            entry = self.manifest['artifacts'][name]['arm64']
            path = self.root / ('manual-' + name)
            path.write_bytes(self.payloads[entry['url']])
            staged.append(dict(name=name, path=str(path), version=entry['version'], sha256=entry['sha256']))
        extra = dict(name='user-extra', version='1', path='/some/file', sha256='f'*64)
        self.vars['micolab_staged_artifacts'] = staged + [extra]
        self.write_vars()
        before = self.main.read_bytes()
        with patch.object(a, 'download', side_effect=AssertionError('offline')):
            result = self.stage(offline=True)
        self.assertEqual(self.main.read_bytes(), before)
        variables = yaml.safe_load(Path(result['group_vars']).read_text())
        self.assertIn(extra, variables['micolab_staged_artifacts'])
        self.assertTrue(all(i['action'] == 'copied' for i in result['artifacts']))

    def test_custom_version_requires_explicit_pins_and_local_bytes(self):
        self.vars['microlab_step_cli_version'] = '0.30.0'
        self.write_vars()
        with self.assertRaisesRegex(a.ArtifactError, 'custom version requires'):
            self.stage()
        self.populate_custom_cli()

    def populate_custom_cli(self):
        path = self.root / 'custom-cli.tar.gz'
        path.write_bytes(archive('step_0.30.0/bin/step', elf('arm64')))
        self.vars.update(microlab_step_cli_artifact_src=str(path), microlab_step_cli_checksums={'arm64': a.digest(path)})
        self.write_vars()
        with patch.object(a, 'download', side_effect=self.fetch):
            result = self.stage()
        item = next(i for i in result['artifacts'] if i['name'] == 'step-cli')
        self.assertEqual(item['version'], '0.30.0')
        self.assertEqual(item['metadata_url'], 'inventory explicit pin')

    def test_no_controller_arch_fallback_and_offline_missing_no_writes(self):
        with self.assertRaisesRegex(a.ArtifactError, 'missing staged file'):
            self.stage(offline=True)
        self.assertFalse(self.directory.exists())
        self.vars.pop('micolab_expected_architecture')
        self.write_vars()
        with self.assertRaisesRegex(a.ArtifactError, 'controller CPU is never used'):
            self.stage()

    def test_atomic_publication_never_overwrites_existing_file(self):
        temp, target = self.root / 'temp', self.root / 'target'
        temp.write_bytes(b'new')
        target.write_bytes(b'keep')
        with self.assertRaises(FileExistsError):
            a.publish(temp, target)
        self.assertEqual(target.read_bytes(), b'keep')
        self.assertEqual(temp.read_bytes(), b'new')
        target.unlink()
        a.publish(temp, target)
        self.assertEqual(target.read_bytes(), b'new')
        self.assertFalse(temp.exists())

    def test_manifest_filename_escape_rejected_before_network(self):
        self.manifest['artifacts']['caddy']['arm64']['filename'] = '../outside'
        self.save_lock()
        with patch.object(a, 'download') as download, self.assertRaisesRegex(a.ArtifactError, 'escapes'):
            self.stage()
        download.assert_not_called()
        self.assertFalse(self.directory.exists())

    def test_other_architecture_explicit_checksums_preserved(self):
        self.vars['micolab_caddy_checksums'] = {'amd64': 'd' * 64}
        self.write_vars()
        result = self.populate()
        variables = yaml.safe_load(Path(result['group_vars']).read_text())
        self.assertEqual(variables['micolab_caddy_checksums']['amd64'], 'd' * 64)
        self.assertEqual(variables['micolab_caddy_checksums']['arm64'], self.manifest['artifacts']['caddy']['arm64']['sha256'])

    def test_amd64_selection(self):
        self.vars['micolab_expected_architecture'] = 'amd64'
        self.write_vars()
        self.assertEqual(self.populate()['architecture'], 'amd64')

    def test_cli_error_json_no_secret_output(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            result = a.main(['--inventory', str(self.inventory), '--directory', str(self.directory), '--offline'])
        self.assertEqual(result, 1)
        output = json.loads(stream.getvalue())
        self.assertEqual(output['status'], 'error')
        self.assertNotIn('not-a-real-vault', stream.getvalue())


if __name__ == '__main__':
    unittest.main()
