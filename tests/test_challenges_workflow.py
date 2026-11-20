"""Host-free challenge deployment contract tests.

These exercise scripts/microlab_challenges.py against fixture images and
fixture lock files in disposable directories, plus the structural contract of
playbooks/challenges.yml and the rctf_challenges role. No network, no
inventory target, and no real publisher archive is contacted.
"""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


challenges_module = load_module(ROOT / 'scripts/microlab_challenges.py', 'microlab_challenges')


def flatten_tasks(tasks):
    """Yield tasks, descending into block/rescue/always structures."""
    for task in tasks or []:
        if not isinstance(task, dict):
            continue
        if 'block' in task or 'rescue' in task or 'always' in task:
            for section in ('block', 'rescue', 'always'):
                yield from flatten_tasks(task.get(section))
            continue
        yield task


def assert_message(task):
    """The fail/success message strings of an assert task (empty when absent)."""
    params = task.get('ansible.builtin.assert', {})
    return str(params.get('fail_msg', '')) + str(params.get('success_msg', ''))


def module_params(task):
    key = next((k for k in task if k.startswith('ansible.builtin.')), None)
    return task.get(key, {}) if key else {}


class Loader(yaml.SafeLoader):
    pass


Loader.add_constructor('!vault', lambda loader, node: None)


def parse_yaml(text):
    return yaml.load(text, Loader=Loader)


def fake_elf(machine=62):
    data = bytearray(b'\x7fELF\x02\x01' + b'\x00' * 12)
    data[18:20] = struct.pack('<H', machine)
    return bytes(data) + b'traefik-fixture-padding'


def write_image(directory, image, files):
    root = Path(directory) / image
    root.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (root / name).write_bytes(content)
    return root


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def definition_payload(image='test-img', flags_in_data=False, container_name='app',
                       integration=None, data_image=None):
    data = {
        'name': 'fixture', 'author': 'microlab', 'category': 'web',
        'description': 'fixture', 'points': {'min': 100, 'max': 400},
        'tags': ['fixture'], 'tiebreakEligible': True, 'sortWeight': 10,
        'hidden': True, 'releaseTime': None,
        'instancerConfig': {
            'instancer': 'firecracker',
            'challengeIntegrationId': integration or 'fc-fixture',
            'timeoutMilliseconds': 1800000, 'extendable': True,
            'config': {
                'image': data_image or image, 'vcpus': 1, 'memMiB': 256,
                'diskMiB': 512, 'egress': False, 'bootTimeoutSeconds': 60,
                'readiness': {'kind': 'http', 'port': 8080, 'path': '/', 'expectStatus': 200},
                'env': {'CHALLENGE': 'fc-fixture'},
            },
            'expose': [{
                'kind': 'http', 'hostPrefix': 'fixture', 'containerName': container_name,
                'containerPort': 8080, 'shouldDisplay': True, 'title': 'fixture',
            }],
        },
    }
    if flags_in_data:
        data['flags'] = [{'provider': 'flags/static', 'config': {'flag': 'leaked'}}]
    return {'id': 'fc-fixture', 'data': data}


def write_definition(definitions, payload, image, pins=None, sizes=None):
    child = Path(definitions) / payload['id'].replace('fc-', 'fixture-')
    child.mkdir(parents=True, exist_ok=True)
    (child / 'challenge.yaml').write_text(yaml.safe_dump(payload, sort_keys=False))
    manifest = {
        'image': image,
        'files': [
            {'name': 'vmlinux',
             'sha256': (pins or {}).get('vmlinux', 'REPLACE_WITH_SHA256'),
             'size': (sizes or {}).get('vmlinux', 'REPLACE_WITH_SIZE_BYTES')},
            {'name': 'rootfs.ext4',
             'sha256': (pins or {}).get('rootfs.ext4', 'REPLACE_WITH_SHA256'),
             'size': (sizes or {}).get('rootfs.ext4', 'REPLACE_WITH_SIZE_BYTES')},
        ],
    }
    (child / 'manifest.yml').write_text('# fixture header\n' + yaml.safe_dump(manifest, sort_keys=False))
    return child


class ModuleCheckTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix='microlab-challenges-tests-'))
        self.definitions = self.work / 'challenges'
        self.images = self.work / 'images'
        self.images.mkdir(parents=True)
        self.inventory = self._inventory()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.work, ignore_errors=True)

    def _inventory(self):
        inventory = {
            'all': {'children': {
                'microlab_management': {'hosts': {'infra': {'ansible_host': '192.0.2.10'}}},
                'microlab_challenge': {'hosts': {'nuc': {'ansible_host': '192.0.2.20'}}},
            }},
        }
        path = self.work / 'hosts.yml'
        path.write_text(yaml.safe_dump(inventory))
        return path

    def check(self):
        return challenges_module.run_check(self.definitions, [self.images])

    def test_unfilled_markers_fail_closed(self):
        write_definition(self.definitions, definition_payload(), 'test-img')
        with self.assertRaisesRegex(challenges_module.ChallengeError, 'unfilled'):
            self.check()

    def test_fill_then_check_ready(self):
        write_image(self.images, 'test-img', {
            'vmlinux': b'kernel', 'rootfs.ext4': b'rootfs-bytes'})
        payload = definition_payload()
        write_definition(self.definitions, payload, 'test-img')
        result = challenges_module.run_manifest(self.definitions, [self.images], allow_update=False)
        self.assertEqual(result['status'], 'filled')
        again = challenges_module.run_manifest(self.definitions, [self.images], allow_update=False)
        self.assertEqual(again['status'], 'unchanged')
        checked = self.check()
        self.assertEqual(checked['status'], 'ready')
        definition = checked['definitions'][0]
        self.assertEqual(definition['id'], 'fc-fixture')
        self.assertTrue(definition['needs_edge'])
        self.assertEqual(len(checked['image_files']), 2)
        self.assertEqual(definition['data']['instancerConfig']['config']['image'], 'test-img')
        self.assertNotIn('flags', definition['data'])

    def test_rebuilt_image_requires_reviewed_repin(self):
        write_image(self.images, 'test-img', {'vmlinux': b'kernel', 'rootfs.ext4': b'rootfs'})
        write_definition(self.definitions, definition_payload(), 'test-img')
        challenges_module.run_manifest(self.definitions, [self.images], allow_update=False)
        write_image(self.images, 'test-img', {'vmlinux': b'kernel-rebuilt', 'rootfs.ext4': b'rootfs'})
        with self.assertRaisesRegex(challenges_module.ChallengeError, '--allow-update'):
            challenges_module.run_manifest(self.definitions, [self.images], allow_update=False)
        result = challenges_module.run_manifest(self.definitions, [self.images], allow_update=True)
        self.assertEqual(result['status'], 'filled')
        self.assertEqual(self.check()['status'], 'ready')

    def test_digest_drift_fails_closed(self):
        write_image(self.images, 'test-img', {'vmlinux': b'kernel', 'rootfs.ext4': b'rootfs'})
        payload = definition_payload()
        write_definition(self.definitions, payload, 'test-img')
        challenges_module.run_manifest(self.definitions, [self.images], allow_update=False)
        write_image(self.images, 'test-img', {'vmlinux': b'kernel-v2', 'rootfs.ext4': b'rootfs'})
        with self.assertRaisesRegex(challenges_module.ChallengeError, 'sha256 mismatch'):
            self.check()

    def test_rootfs_larger_than_reserved_disk_fails(self):
        # 64 MiB is the smallest legal diskMiB; a rootfs one byte larger
        # must fail closed at validation.
        write_image(self.images, 'test-img', {'vmlinux': b'kernel',
                                             'rootfs.ext4': b'x' * (64 * 1048576 + 1)})
        payload = definition_payload()
        payload['data']['instancerConfig']['config']['diskMiB'] = 64
        write_definition(self.definitions, payload, 'test-img')
        challenges_module.run_manifest(self.definitions, [self.images], allow_update=False)
        with self.assertRaisesRegex(challenges_module.ChallengeError, 'writable disk'):
            self.check()

    def test_committed_flags_are_refused(self):
        write_image(self.images, 'test-img', {'vmlinux': b'kernel', 'rootfs.ext4': b'rootfs'})
        write_definition(self.definitions, definition_payload(flags_in_data=True), 'test-img')
        challenges_module.run_manifest(self.definitions, [self.images], allow_update=False)
        with self.assertRaisesRegex(challenges_module.ChallengeError, 'flags must not be stored'):
            self.check()

    def test_non_app_container_name_refused(self):
        write_image(self.images, 'test-img', {'vmlinux': b'kernel', 'rootfs.ext4': b'rootfs'})
        write_definition(self.definitions, definition_payload(container_name='web'), 'test-img')
        challenges_module.run_manifest(self.definitions, [self.images], allow_update=False)
        with self.assertRaisesRegex(challenges_module.ChallengeError, 'containerName'):
            self.check()

    def test_integration_id_must_equal_id(self):
        write_image(self.images, 'test-img', {'vmlinux': b'kernel', 'rootfs.ext4': b'rootfs'})
        write_definition(self.definitions, definition_payload(integration='fc-other'), 'test-img')
        challenges_module.run_manifest(self.definitions, [self.images], allow_update=False)
        with self.assertRaisesRegex(challenges_module.ChallengeError, 'challengeIntegrationId'):
            self.check()

    def test_manifest_image_must_match_challenge_image(self):
        write_image(self.images, 'test-img', {'vmlinux': b'kernel', 'rootfs.ext4': b'rootfs'})
        write_image(self.images, 'other-img', {'vmlinux': b'kernel', 'rootfs.ext4': b'rootfs'})
        write_definition(self.definitions, definition_payload(), 'other-img')
        challenges_module.run_manifest(self.definitions, [self.images], allow_update=False)
        with self.assertRaisesRegex(challenges_module.ChallengeError, 'challenge image'):
            self.check()


class ModuleArtifactsTests(unittest.TestCase):
    def setUp(self):
        import shutil
        self.work = Path(tempfile.mkdtemp(prefix='microlab-challenges-artifacts-'))
        self.artifacts = self.work / 'artifacts'
        self.inventory = self.work / 'hosts.yml'
        self.inventory.write_text(yaml.safe_dump({
            'all': {'children': {
                'microlab_management': {'hosts': {'infra': {'ansible_host': '192.0.2.10'}}},
                'microlab_challenge': {'hosts': {'nuc': {'ansible_host': '192.0.2.20'}}},
            }},
        }))
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)

    def fixture_lock(self, archive_path, member_sha):
        entry = {
            'version': '3.7.15', 'filename': 'traefik-3.7.15-amd64.tar.gz',
            'url': 'https://example.invalid/traefik.tar.gz',
            'publisher_url': 'https://example.invalid/checksums.txt',
            'publisher_member': 'traefik_v3.7.15_linux_amd64.tar.gz',
            'sha256': sha(archive_path), 'member': 'traefik', 'member_sha256': member_sha,
            'metadata_url': 'https://example.invalid/metadata',
        }
        lock = self.work / 'challenges.lock.json'
        lock.write_text(json.dumps({'artifacts': {'traefik': {'amd64': entry}}}))
        return lock

    @staticmethod
    def fixture_archive(path):
        binary = fake_elf()
        with tarfile.open(path, 'w:gz') as archive:
            info = tarfile.TarInfo('traefik')
            info.size = len(binary)
            archive.addfile(info, io.BytesIO(binary))
        return hashlib.sha256(binary).hexdigest()

    def test_offline_staging_verifies_and_publishes_vars(self):
        archive = self.work / 'traefik-3.7.15-amd64.tar.gz'
        member_sha = self.fixture_archive(archive)
        lock = self.fixture_lock(archive, member_sha)
        # Offline semantics: the pinned archive is already staged by the
        # operator; the run re-verifies it and publishes the generated vars.
        self.artifacts.mkdir(parents=True)
        staged = self.artifacts / 'traefik-3.7.15-amd64.tar.gz'
        staged.write_bytes(archive.read_bytes())
        result = challenges_module.run_artifacts(
            self.inventory, ROOT / 'challenges', self.artifacts,
            offline=True, check=False, lock_path=lock)
        self.assertEqual(result['status'], 'ready')
        self.assertTrue(staged.is_file())
        generated = self.work / 'group_vars' / 'microlab_challenge' / \
            'zz_microlab_challenges_artifacts.yml'
        text = generated.read_text()
        self.assertTrue(text.startswith(challenges_module.MARKER))
        values = parse_yaml(text)
        self.assertEqual(values['micolab_rctf_traefik_version'], '3.7.15')
        self.assertEqual(values['micolab_rctf_traefik_artifact_src'], str(staged))
        self.assertEqual(values['micolab_rctf_traefik_checksums']['amd64'], sha(staged))
        self.assertEqual(values['micolab_rctf_traefik_binary_sha256']['amd64'], member_sha)
        checked = challenges_module.run_artifacts(
            self.inventory, ROOT / 'challenges', self.artifacts,
            offline=True, check=True, lock_path=lock)
        self.assertEqual(checked['status'], 'checked')

    def test_tampered_archive_is_refused(self):
        archive = self.work / 'traefik-3.7.15-amd64.tar.gz'
        member_sha = self.fixture_archive(archive)
        lock = self.fixture_lock(archive, member_sha)
        self.artifacts.mkdir(parents=True)
        staged = self.artifacts / 'traefik-3.7.15-amd64.tar.gz'
        staged.write_bytes(archive.read_bytes() + b'tamper')
        with self.assertRaisesRegex(challenges_module.ChallengeError, 'SHA256 mismatch'):
            challenges_module.run_artifacts(
                self.inventory, ROOT / 'challenges', self.artifacts,
                offline=True, check=True, lock_path=lock)

    def test_missing_archive_fails_closed_offline(self):
        lock = self.work / 'challenges.lock.json'
        lock.write_text(json.dumps({'artifacts': {'traefik': {'amd64': {
            'version': '3.7.15', 'filename': 'traefik-3.7.15-amd64.tar.gz',
            'url': 'https://example.invalid/traefik.tar.gz',
            'publisher_url': 'https://example.invalid/checksums.txt',
            'publisher_member': 'traefik_v3.7.15_linux_amd64.tar.gz',
            'sha256': 'a' * 64, 'member': 'traefik', 'member_sha256': 'b' * 64,
            'metadata_url': 'https://example.invalid/metadata',
        }}}}))
        with self.assertRaisesRegex(challenges_module.ChallengeError, 'missing staged archive'):
            challenges_module.run_artifacts(
                self.inventory, ROOT / 'challenges', self.artifacts,
                offline=True, check=True, lock_path=lock)

    def test_generated_vars_file_is_never_overwritten_when_unrecognized(self):
        archive = self.work / 'traefik-3.7.15-amd64.tar.gz'
        member_sha = self.fixture_archive(archive)
        lock = self.fixture_lock(archive, member_sha)
        self.artifacts.mkdir(parents=True)
        staged = self.artifacts / 'traefik-3.7.15-amd64.tar.gz'
        staged.write_bytes(archive.read_bytes())
        challenges_module.run_artifacts(
            self.inventory, ROOT / 'challenges', self.artifacts,
            offline=True, check=False, lock_path=lock)
        generated = self.work / 'group_vars' / 'microlab_challenge' / \
            'zz_microlab_challenges_artifacts.yml'
        generated.write_text('# operator content\n')
        with self.assertRaisesRegex(challenges_module.ChallengeError, 'refusing to overwrite'):
            challenges_module.run_artifacts(
                self.inventory, ROOT / 'challenges', self.artifacts,
                offline=True, check=False, lock_path=lock)


class PlaybookContractTests(unittest.TestCase):
    def setUp(self):
        text = (ROOT / 'playbooks/challenges.yml').read_text()
        self.plays = parse_yaml(text)

    def test_three_plays_with_expected_hosts(self):
        self.assertEqual([play['hosts'] for play in self.plays],
                         ['localhost', 'microlab_management', 'microlab_challenge'])
        self.assertFalse(self.plays[0]['become'])
        self.assertTrue(self.plays[2]['become'])
        self.assertTrue(self.plays[2]['any_errors_fatal'])

    def test_localhost_play_validates_through_the_module_and_shares_results(self):
        tasks = self.plays[0]['tasks']
        argv_task = next(t for t in tasks if t.get('ansible.builtin.set_fact') and
                         'micolab_rctf_challenges_check_argv' in t['ansible.builtin.set_fact'])
        self.assertIn('microlab_challenges.py', str(argv_task))
        load = next(t for t in tasks if t.get('ansible.builtin.set_fact') and
                    'micolab_challenges_definitions' in t['ansible.builtin.set_fact'])
        self.assertIn('from_json', str(load['ansible.builtin.set_fact']))
        command = next(t for t in tasks if 'ansible.builtin.command' in t and
                       t['ansible.builtin.command'].get('argv'))
        self.assertEqual(command['register'], 'micolab_challenges_check')
        self.assertFalse(command.get('changed_when', True))

    def test_dns_play_verifies_the_workload_namespace(self):
        tasks = self.plays[1]['tasks']
        dig = next(t for t in tasks if 'ansible.builtin.command' in t and
                   t['ansible.builtin.command']['argv'][0] == 'dig')
        self.assertIn('*.{{ micolab_rctf_challenges_http_domain }}',
                      ' '.join(dig['ansible.builtin.command']['argv']))
        verify = next(t for t in tasks if t.get('ansible.builtin.assert') and
                      'micolab_rctf_dns_wildcard' in str(t['ansible.builtin.assert']))
        self.assertIn('micolab_rctf_challenges_dns_accept_unverified', verify['when'])

    def test_challenge_play_stages_gated_roles(self):
        tasks = self.plays[2]['tasks']
        phases = [t for t in tasks if 'ansible.builtin.include_role' in t]
        by_name = {t['ansible.builtin.include_role']['name']: t for t in phases}
        self.assertEqual(set(by_name), {'rctf_challenges'})
        gated = [t for t in phases if 'tasks_from' in t['ansible.builtin.include_role']]
        self.assertEqual([t['ansible.builtin.include_role']['tasks_from'] for t in gated],
                         ['images', 'edge', 'register'])
        for task in gated:
            self.assertIn('micolab_rctf_challenges_stage_', task['when'])

    def test_register_stage_never_prints_flags_or_bodies(self):
        tasks = list(flatten_tasks(parse_yaml(
            (ROOT / 'roles/rctf_challenges/tasks/register.yml').read_text())))
        sensitive = [t for t in tasks if 'ansible.builtin.uri' in t or 'ansible.builtin.slurp' in t]
        self.assertGreater(len(sensitive), 0)
        for task in sensitive:
            self.assertTrue(task.get('no_log'), task.get('name'))
        reported = [t for t in tasks if t.get('ansible.builtin.assert') and not t.get('no_log')]
        self.assertGreater(len(reported), 0)
        for task in reported:
            message = assert_message(task).lower()
            self.assertNotIn('flag', message, task.get('name'))
            self.assertNotIn('teamtoken', message, task.get('name'))
            self.assertNotIn('authtoken', message, task.get('name'))

    def test_edge_stage_verifies_digests_before_installing(self):
        tasks = list(flatten_tasks(parse_yaml(
            (ROOT / 'roles/rctf_challenges/tasks/edge.yml').read_text())))
        archive_hashes = next(i for i, t in enumerate(tasks) if t.get('ansible.builtin.command') and
                              'sha256sum' in str(t['ansible.builtin.command'].get('argv', [])) and
                              '.tar.gz' in str(t['ansible.builtin.command'].get('argv', [])))
        binary_hashes = next(i for i, t in enumerate(tasks) if t.get('ansible.builtin.command') and
                             'sha256sum' in str(t['ansible.builtin.command'].get('argv', [])) and
                             '/traefik' in str(t['ansible.builtin.command'].get('argv', [])))
        assert_archive = next(i for i, t in enumerate(tasks) if t.get('ansible.builtin.assert') and
                              'staged Traefik archive' in assert_message(t))
        assert_binary = next(i for i, t in enumerate(tasks) if t.get('ansible.builtin.assert') and
                             'extracted Traefik binary' in assert_message(t))
        install = next(i for i, t in enumerate(tasks) if t.get('ansible.builtin.command') and
                       'install' in str(t['ansible.builtin.command'].get('argv', [])))
        self.assertLess(archive_hashes, assert_archive)
        self.assertLess(assert_archive, binary_hashes)
        self.assertLess(binary_hashes, assert_binary)
        self.assertLess(assert_binary, install)

    def test_images_stage_reverifies_digests_on_the_host(self):
        tasks = list(flatten_tasks(parse_yaml(
            (ROOT / 'roles/rctf_challenges/tasks/images.yml').read_text())))
        digest_command = next(i for i, t in enumerate(tasks) if t.get('ansible.builtin.command') and
                              'sha256sum' in str(t['ansible.builtin.command'].get('argv', [])))
        verify = next(i for i, t in enumerate(tasks) if t.get('ansible.builtin.assert') and
                      'pinned build digest' in assert_message(t))
        self.assertLess(digest_command, verify)

    def test_role_defaults_keep_the_documented_prefix(self):
        values = parse_yaml((ROOT / 'roles/rctf_challenges/defaults/main.yml').read_text())
        for key in values:
            self.assertTrue(key.startswith('micolab_rctf_') or key.startswith('micolab_rctf_traefik_'),
                            key)

    def test_group_vars_publish_the_workload_namespace(self):
        values = parse_yaml((ROOT / 'group_vars/all.yml').read_text())
        self.assertEqual(values['micolab_rctf_challenges_http_domain'], 'fc.rctf.microlab.hnh')
        self.assertFalse(values['micolab_rctf_challenges_dns_accept_unverified'])


class LauncherContractTests(unittest.TestCase):
    def test_challenges_subcommand_is_listed(self):
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/microlab.py'), '--help'],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ROOT)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b'challenges', result.stdout)

    def test_manifest_without_images_dir_checkpoints(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / 'scripts/microlab.py'),
             '--inventory', str(ROOT / 'inventories/example/hosts.yml'),
             'challenges', 'manifest'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ROOT)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'images-dir', result.stdout)

    def test_deploy_without_images_dir_checkpoints_before_any_host(self):
        if not (shutil.which('ansible-playbook')):
            self.skipTest('ansible-playbook is required for the deploy checkpoint')
        result = subprocess.run(
            [sys.executable, str(ROOT / 'scripts/microlab.py'),
             '--inventory', str(ROOT / 'inventories/example/hosts.yml'),
             'challenges', 'deploy'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ROOT)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'images-dir', result.stdout)
        self.assertNotIn(b'ansible-playbook --inventory', result.stdout)


class FlagsCommandTests(unittest.TestCase):
    def setUp(self):
        import shutil
        self.work = Path(tempfile.mkdtemp(prefix='microlab-flags-tests-'))
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)
        self.inventory = self.work / 'hosts.yml'
        self.inventory.write_text(yaml.safe_dump({
            'all': {'children': {'microlab_challenge': {
                'hosts': {'nuc': {'ansible_host': '192.0.2.20'}}}}},
        }))

    def _run(self, extra_env=None):
        env = {key: value for key, value in os.environ.items()
               if key != 'ANSIBLE_VAULT_PASSWORD_FILE'}
        env.update(extra_env or {})
        return subprocess.run(
            [sys.executable, str(ROOT / 'scripts/microlab.py'),
             '--inventory', str(self.inventory), 'challenges', 'flags'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ROOT, env=env)

    def test_flags_checkpoint_without_a_terminal_or_password_file(self):
        result = self._run()
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'Vault needs a terminal', result.stdout)

    def test_generated_flags_fill_every_definition_once(self):
        if not shutil.which('ansible-vault'):
            self.skipTest('ansible-vault is required for the flags workflow')
        expected = len([child for child in (ROOT / 'challenges').iterdir()
                        if (child / 'challenge.yaml').is_file()])
        self.assertGreaterEqual(expected, 3)
        password_file = self.work / 'vault.pass'
        password_file.write_text('fixture-vault-password\n')
        result = self._run({'ANSIBLE_VAULT_PASSWORD_FILE': str(password_file)})
        self.assertEqual(result.returncode, 0, result.stdout)
        lines = result.stdout.decode()
        self.assertEqual(lines.count('rctf{'), expected)
        for definition in (child.name for child in (ROOT / 'challenges').iterdir()
                           if (child / 'challenge.yaml').is_file()):
            mapping = parse_yaml((ROOT / 'challenges' / definition / 'challenge.yaml').read_text())
            self.assertIn(mapping['id'], lines)
        vault_file = self.work / 'group_vars' / 'microlab_challenge' / 'challenges-vault.yml'
        self.assertTrue(vault_file.is_file())
        self.assertTrue(vault_file.read_text().startswith('$ANSIBLE_VAULT;'))
        again = self._run({'ANSIBLE_VAULT_PASSWORD_FILE': str(password_file)})
        self.assertEqual(again.returncode, 0, again.stdout)
        self.assertIn(b'nothing was generated or changed', again.stdout)
        self.assertNotIn(b'rctf{', again.stdout.split(b'Record these once')[0] if b'Record these once' in again.stdout else again.stdout)

    def test_flag_generation_preserves_existing_values(self):
        module = load_module(ROOT / 'scripts/microlab.py', 'microlab_flags_probe')
        existing = {'fc-xweb': 'rctf{keep-me}'}
        new = module.generate_missing_flags(['fc-xweb', 'fc-m364-credit'], existing)
        self.assertEqual(set(new), {'fc-m364-credit'})
        self.assertEqual(existing['fc-xweb'], 'rctf{keep-me}')
        generated = new['fc-m364-credit']
        self.assertTrue(generated.startswith('rctf{'))
        self.assertGreater(len(generated), len('rctf{') + 16)


class DnsResolverBehaviorTests(unittest.TestCase):
    """Execute scripts/dns_a.py against an in-process fake DNS responder.

    The parser was once silently corrupted by the authoring transport (an
    underscore placeholder group made it read nscount as ancount), so source
    inspection cannot be trusted here: the file must be EXECUTED.
    """

    def test_resolves_a_wildcard_answer_with_compressed_names(self):
        import secrets
        import socket
        import struct
        import subprocess
        import threading

        def encode_name(labels):
            return b''.join(bytes([len(part)]) + part.encode() for part in labels) + bytes([0])

        question = encode_name([chr(42), 'fc', 'rctf', 'microlab', 'hnh'])
        answer = struct.pack('>HHIH', 1, 1, 300, 4) + bytes([10, 72, 78, 72])

        def responder(server_socket):
            data, peer = server_socket.recvfrom(4096)
            ident = struct.unpack('>H', data[:2])[0]
            response = struct.pack('>HHHHHH', ident, 0x8580, 1, 1, 0, 0) + data[12:] + b'\xc0\x0c' + answer
            server_socket.sendto(response, peer)

        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(('127.0.0.1', 0))
        port = server.getsockname()[1]
        thread = threading.Thread(target=responder, args=(server,), daemon=True)
        thread.start()
        try:
            result = subprocess.run(
                [sys.executable, str(ROOT / 'scripts/dns_a.py'), '127.0.0.1',
                 chr(42) + '.fc.rctf.microlab.hnh', str(port)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        finally:
            server.close()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.decode().strip(), '10.72.78.72')

    def test_orchestrator_delegates_to_the_executable_resolver(self):
        source = (ROOT / 'scripts/deploy_challenges.sh').read_text()
        self.assertIn('python3 "$HERE/scripts/dns_a.py" "$1" "$2"', source)
        # The old inline heredoc parser must be gone entirely.
        self.assertNotIn(', _, _, answers, _ =', source)
        self.assertNotIn('for _ in range(answers):', source)


class ReviewFindingsContractTests(unittest.TestCase):
    """Regressions for the pre-deployment review findings (2026-11-19)."""

    def test_dns_assert_runs_only_when_edge_is_deployed(self):
        # A duplicated `when` key silently leaves only the last condition,
        # which made images/register-only reruns fail on a skipped dig.
        tasks = list(flatten_tasks(parse_yaml(
            (ROOT / 'playbooks/challenges.yml').read_text())[1]['tasks']))
        when_keys = [len([key for key in task if key == 'when'])
                     for task in tasks if task.get('ansible.builtin.assert')]
        self.assertEqual(max(when_keys, default=0), 1, 'a task carries duplicated when keys')
        verify = next(task for task in tasks if task.get('ansible.builtin.assert') and
                      'micolab_rctf_dns_wildcard' in str(task['ansible.builtin.assert']))
        self.assertIn('micolab_rctf_challenges_edge_wanted', verify['when'])
        self.assertIn('micolab_rctf_challenges_dns_accept_unverified', verify['when'])
        dig = next(task for task in tasks if 'ansible.builtin.command' in task and
                   task['ansible.builtin.command']['argv'][0] == 'dig')
        self.assertIn('micolab_rctf_challenges_edge_wanted', dig['when'])

    def test_launcher_passes_typed_extra_vars_as_one_json_object(self):
        source = (ROOT / 'scripts/microlab.py').read_text()
        self.assertIn('"-e", json.dumps({', source)
        self.assertIn('"micolab_rctf_challenges_images_dirs": [', source)
        self.assertIn('"micolab_rctf_challenges_http_domain": "fc.rctf.microlab.hnh"', source)
        self.assertNotIn("micolab_rctf_challenges_images_dirs=\" + json.dumps", source)

    def test_agent_config_is_read_with_nested_images_dir(self):
        tasks = list(flatten_tasks(parse_yaml(
            (ROOT / 'roles/rctf_challenges/tasks/main.yml').read_text())))
        facts = next(task for task in tasks if task.get('ansible.builtin.set_fact') and
                     'micolab_rctf_images_dir' in task['ansible.builtin.set_fact'])
        expression = str(facts['ansible.builtin.set_fact']['micolab_rctf_images_dir'])
        self.assertIn('vm', expression)
        self.assertIn('/var/lib/rctf-firecracker/images', expression)

    def test_healthz_check_reads_returned_content(self):
        tasks = list(flatten_tasks(parse_yaml(
            (ROOT / 'roles/rctf_challenges/tasks/main.yml').read_text())))
        probe = next(task for task in tasks if task.get('ansible.builtin.uri') and
                     '/healthz' in task['ansible.builtin.uri']['url'])
        self.assertTrue(probe['ansible.builtin.uri'].get('return_content'))
        check = next(task for task in tasks if task.get('ansible.builtin.assert') and
                     'did not answer' in assert_message(task))
        self.assertIn('content | trim', str(check['ansible.builtin.assert']))
        self.assertNotIn('.body', str(check['ansible.builtin.assert']))

    def test_agent_config_slurp_is_protected(self):
        tasks = list(flatten_tasks(parse_yaml(
            (ROOT / 'roles/rctf_challenges/tasks/main.yml').read_text())))
        slurp = next(task for task in tasks if task.get('ansible.builtin.slurp') and
                     'challenges_agent_config' in str(task['ansible.builtin.slurp'].get('src', '')))
        self.assertTrue(slurp.get('no_log'), 'the agent config read must be protected')

    def test_register_preserves_event_visibility_and_classifies_safely(self):
        tasks = list(flatten_tasks(parse_yaml(
            (ROOT / 'roles/rctf_challenges/tasks/register.yml').read_text())))
        preread = next(task for task in tasks if task.get('ansible.builtin.uri') and
                       task['ansible.builtin.uri']['url'].endswith('/v2/admin/challs'))
        self.assertEqual(preread['ansible.builtin.uri']['method'], 'GET')
        upsert = next(task for task in tasks if task.get('ansible.builtin.uri') and
                      task['ansible.builtin.uri']['method'] == 'PUT')
        body = str(upsert['ansible.builtin.uri']['body'])
        self.assertIn('rejectattr', body)
        self.assertIn("'hidden', 'releaseTime'", body)
        self.assertIn('micolab_rctf_existing_ids', body)
        classify = next(task for task in tasks if task.get('ansible.builtin.assert') and
                        'refused the record' in assert_message(task))
        self.assertEqual(classify['loop'], '{{ microlab_challenges_definitions }}')
        self.assertIn('index_var', classify['loop_control'])

    def test_edge_checks_import_first_and_proves_traefik_answered(self):
        document = parse_yaml((ROOT / 'roles/rctf_challenges/tasks/edge.yml').read_text())
        block = next(task for task in document if 'block' in task)['block']
        first = block[0]['name']
        self.assertIn('Caddyfile', first)
        import_assert = next(task for task in block if task.get('ansible.builtin.assert') and
                              'actively import' in assert_message(task))
        self.assertIn('(?m)^', str(import_assert['ansible.builtin.assert']['that'][0]))
        defaults = parse_yaml((ROOT / 'roles/rctf_challenges/defaults/main.yml').read_text())
        self.assertEqual(defaults['micolab_rctf_challenges_traefik_bind_port'], 8180)
        probes = [str(task.get('ansible.builtin.uri', {}).get('url', '')) for task in block
                  if task.get('ansible.builtin.uri')]
        self.assertTrue(any('traefik_bind' in url for url in probes))
        body_checks = [task for task in block if task.get('ansible.builtin.assert') and
                       '404 page not found' in str(task['ansible.builtin.assert'])]
        self.assertGreaterEqual(len(body_checks), 2, 'both probes must require the Traefik body')
        restart = next(task for task in block if task.get('ansible.builtin.systemd') and
                       task['ansible.builtin.systemd'].get('state') == 'restarted')
        self.assertIn('binary', str(restart['when']).lower())

    def test_m364_records_keep_the_lab_boot_budget(self):
        for name in ('m364-credit', 'm364-recon'):
            definition = parse_yaml((ROOT / 'challenges' / name / 'challenge.yaml').read_text())
            config = definition['data']['instancerConfig']['config']
            self.assertEqual(config['bootTimeoutSeconds'], 180, name)

    def test_flags_use_one_canonical_store(self):
        source = (ROOT / 'scripts/microlab.py').read_text()
        self.assertIn('canonical = directory / (FLAGS_VAULT_STEM + ".yml")', source)
        self.assertNotIn('vars_sidecar(directory, FLAGS_VAULT_STEM)', source)
        self.assertIn('os.replace(temporary, canonical)', source)

    def test_orchestrator_caddy_stage_validates_before_installing(self):
        source = (ROOT / 'scripts/deploy_challenges.sh').read_text()
        self.assertIn('CANDIDATE', source)
        self.assertIn('pre-challenges', source)
        # The include is rendered before validation, so the candidate never
        # references a missing import target.
        include = source.index("printf 'http://*.fc.rctf.microlab.hnh")
        candidate = source.index('cp "$CADDYFILE" "$CANDIDATE"')
        self.assertLess(include, candidate)
        # The validated candidate is installed only after validate succeeds.
        validate = source.index('validate --config "$CANDIDATE"')
        install = source.index('mv "$CANDIDATE" "$CADDYFILE"')
        self.assertLess(validate, install)
        # A reload failure restores the backup Caddyfile.
        rollback = source.index('mv "$BACKUP" "$CADDYFILE"')
        self.assertLess(install, rollback)
        self.assertIn('ExecStart --value | sed -n', source)

    def test_orchestrator_sends_json_login_and_probes_from_the_controller(self):
        source = (ROOT / 'scripts/deploy_challenges.sh').read_text()
        self.assertIn('data={"teamToken": team_token}', source)
        self.assertNotIn('?teamToken=', source)
        self.assertIn('"goodLogin"', source)
        self.assertIn('/dev/tcp/$host/$port', source)
        self.assertIn('SSH-', source)
        self.assertIn('challenge_marker', source)
        self.assertIn('PRE-EXISTING', source)
        self.assertIn('launches="$(nuc_root', source)
        self.assertIn('if ! cleanup="$(nuc_root', source)

    def test_orchestrator_sudo_is_interactive_and_per_host(self):
        # No passwordless sudo requirement: each privileged phase prompts
        # once in a terminal, and non-interactive runs take TWO per-host
        # protected password files (the hosts have different users and
        # different passwords; users always come from the inventory).
        source = (ROOT / 'scripts/deploy_challenges.sh').read_text()
        self.assertIn('MICROLAB_NUC_PASS_FILE', source)
        self.assertIn('MICROLAB_PI_PASS_FILE', source)
        self.assertNotIn('MICROLAB_SUDO_PASS_FILE', source)
        self.assertIn('ssh $(ssh_args) -tt', source)
        self.assertIn('sudo -S -k', source)
        self.assertIn('check_pass_file', source)
        # Remote privileged logic runs from staged script files, never from
        # stdin, so the sudo prompt owns the terminal.
        self.assertIn('nuc_put', source)
        self.assertIn('bash /tmp/microlab-challenges-caddy-stage.sh', source)
        self.assertIn('python3 /tmp/microlab-challenges-accept-launch.py', source)
        self.assertIn('python3 /tmp/microlab-challenges-accept-cleanup.py', source)
        # The DNS convergence passes the infra host's own password file
        # through the site launcher, never a shared one.
        self.assertIn('export ANSIBLE_BECOME_PASSWORD_FILE="$PI_PASS_FILE"', source)
        # Flag order: --no-become-prompt belongs to the deploy subcommand,
        # and the interactive path must not pass it at all.
        self.assertIn('BECOME_ARGS=(--no-become-prompt)', source)
        self.assertIn('BECOME_ARGS=()', source)
        self.assertIn('./microlab deploy "${BECOME_ARGS[@]}" --stage services', source)
        self.assertNotIn('--no-become-prompt deploy --stage services', source)
        # Users are inventory-driven, with documented fallbacks only.
        self.assertIn("values.get('ansible_user') or 'caden64'", source)
        self.assertIn("values.get('ansible_user') or 'hopkeeper'", source)

    def test_site_launcher_accepts_a_become_password_file(self):
        site = Path('/home/caden64/projects/microlab/microlab-ansible/scripts/microlab.py')
        if not site.is_file():
            self.skipTest('the deployed site checkout is not present')
        source = site.read_text()
        self.assertIn('ANSIBLE_BECOME_PASSWORD_FILE', source)
        self.assertIn('--become-password-file', source)

    def test_orchestrator_publishes_artifacts_and_gates_dns_on_nxdomain(self):
        source = (ROOT / 'scripts/deploy_challenges.sh').read_text()
        self.assertIn('stage_artifacts()', source)
        self.assertIn('challenges artifacts', source)
        self.assertIn('zz_microlab_challenges_artifacts.yml', source)
        self.assertIn('[ "$answer" = "NXDOMAIN" ]', source)
        self.assertIn('SERVFAIL', source)


if __name__ == '__main__':
    unittest.main()
