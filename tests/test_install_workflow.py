"""Host-free install contract tests, including real Ansible routing with stub roles."""
import hashlib
import getpass
import grp
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('doh_firewall', ROOT / 'roles/verify/files/check_doh_firewall.py')
firewall = importlib.util.module_from_spec(spec)
spec.loader.exec_module(firewall)


class FirewallTests(unittest.TestCase):
    def document(self, before=None, family='inet', port=8053, interface='lo'):
        def rule(expr):
            return {'rule': {'family': family, 'table': 'micolab_filter', 'chain': 'input', 'expr': expr}}
        entries = [{'chain': {'family': family, 'table': 'micolab_filter', 'name': 'input', 'hook': 'input', 'policy': 'drop'}}]
        entries += [rule(e) for e in (before or [])]
        entries += [rule([
            {'match': {'op': '!=', 'left': {'meta': {'key': 'iifname'}}, 'right': interface}},
            {'match': {'op': '==', 'left': {'payload': {'protocol': 'tcp', 'field': 'dport'}}, 'right': port}},
            {'drop': None},
        ])]
        return {'nftables': entries}

    def test_inet_drop_covers_both_families(self):
        self.assertTrue(firewall.contained(self.document(), 'micolab_filter'))
        self.assertFalse(firewall.contained(self.document(family='ip'), 'micolab_filter'))

    def test_accept_jump_wrong_port_or_interface_fails_closed(self):
        for before in [[{'accept': None}], [{'jump': {'target': 'other'}}]]:
            self.assertFalse(firewall.contained(self.document(before=[before]), 'micolab_filter'))
        self.assertFalse(firewall.contained(self.document(port=5380), 'micolab_filter'))
        self.assertFalse(firewall.contained(self.document(interface='eth0'), 'micolab_filter'))

    def test_only_known_loopback_accept_may_precede_drop(self):
        lo = [{'match': {'op': '==', 'left': {'meta': {'key': 'iifname'}}, 'right': 'lo'}}, {'accept': None}]
        self.assertTrue(firewall.contained(self.document(before=[lo]), 'micolab_filter'))


@unittest.skipUnless(shutil.which('ansible-playbook'), 'Ansible is required')
class RoutingTests(unittest.TestCase):
    def run_workflow(self, name, overlap=False, extra=None, duplicate_address=False):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            # Copy actual playbooks to keep their includes and precedence real.
            shutil.copytree(ROOT / 'playbooks', d / 'playbooks')
            shutil.copytree(ROOT / 'group_vars', d / 'group_vars')
            for role in ['baseline', 'technitium_install', 'technitium_dns', 'step_ca', 'caddy', 'technitium_tls', 'forgejo', 'verify']:
                tasks = d / 'roles' / role / 'tasks'
                tasks.mkdir(parents=True)
                content = [{'name': 'Observe routed role ' + role, 'ansible.builtin.assert': {'that': [
                    "inventory_hostname == 'infra'",
                    "micolab_admin_cidrs == ['10.72.78.99/32']",
                    "micolab_client_cidrs == ['10.72.78.0/24']",
                    "micolab_dns_addresses.ca == '10.72.78.73'",
                    "micolab_dns_fixture_name == 'probe.fixture.test'",
                    "not (microlab_step_ca_initial_deploy | default(false) | bool)",
                ], 'fail_msg': 'admin={{ micolab_admin_cidrs }}, group={{ group_names }}'}}]
                if role == 'technitium_dns':
                    content += [{'ansible.builtin.set_fact': {'micolab_dns_external_acl_verified': False}}]
                if role == 'caddy':
                    content += [{'ansible.builtin.debug': {'msg': 'git_enabled={{ micolab_caddy_enable_git | bool | string }}'}}]
                if role == 'verify':
                    content += [{'ansible.builtin.set_fact': {'micolab_verify_acceptance_file': str(d / 'acceptance.json')}}]
                for file in ['main.yml', 'health_doh.yml', 'remote_probes.yml']:
                    (tasks / file).write_text(yaml.safe_dump(content))
            # Redirect status writes only. All service roles are stubs; no CA,
            # target connections, firewall changes, or host service actions run.
            for p in (d / 'playbooks').glob('*.yml'):
                p.write_text(p.read_text().replace('/var/lib/microlab/install-status.json', str(d / 'status.json')).replace('owner: root', 'owner: ' + getpass.getuser()).replace('group: root', 'group: ' + grp.getgrgid(os.getgid()).gr_name))
            inventory = {'all': {'children': {
                'microlab_management': {'hosts': {'infra': {'ansible_connection': 'local', 'ansible_host': '10.72.78.73'}}},
                'microlab_challenge': {'hosts': {('infra' if overlap else 'rctf'): {'ansible_connection': 'deliberately-invalid', 'ansible_host': '10.72.78.73' if duplicate_address else '10.72.78.72'}}},
            }, 'vars': {
                'micolab_admin_cidrs': ['10.72.78.99/32'],  # Synthetic test operator only.
                'micolab_client_cidrs': ['10.72.78.0/24'],
                'micolab_dns_addresses': {key: '10.72.78.73' for key in ['ca', 'dns', 'git', 'ns1']},
            }}}
            management_vars = d / 'group_vars' / 'microlab_management'
            management_vars.mkdir()
            (management_vars / 'main.yml').write_text(yaml.safe_dump(inventory['all'].pop('vars')))
            inventory_dir = d
            (inventory_dir / 'hosts.yml').write_text(yaml.safe_dump(inventory))
            (d / 'ansible.cfg').write_text('[defaults]\nroles_path = ' + str(d / 'roles') + '\n[privilege_escalation]\nbecome = false\n')
            env = dict(os.environ, ANSIBLE_CONFIG=str(d / 'ansible.cfg'), ANSIBLE_NOCOLOR='1')
            args = ['ansible-playbook', '-i', str(inventory_dir / 'hosts.yml'), str(d / 'playbooks' / (name + '.yml')), '-e', 'ansible_become=false']
            if extra:
                args += ['-e', json.dumps(extra)]
            result = subprocess.run(args, env=env, cwd=d, text=True, capture_output=True, timeout=60)
            status = json.loads((d / 'status.json').read_text()) if (d / 'status.json').exists() else None
            return result, status

    def test_bootstrap_successful_checkpoint_and_inventory_reuse(self):
        result, status = self.run_workflow('bootstrap')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(status['overall'], 'credential-checkpoint')
        self.assertFalse(status['local_ready'])
        self.assertNotIn('Observe routed role technitium_tls', result.stdout)
        self.assertNotIn('Observe routed role forgejo', result.stdout)

    def test_deploy_records_local_ready_and_pending_acceptance(self):
        result, status = self.run_workflow('deploy')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(status['local_ready'])
        self.assertEqual(status['external_acceptance'], 'pending')
        self.assertIn('Observe routed role technitium_tls', result.stdout)
        self.assertIn('Observe routed role forgejo', result.stdout)
        self.assertIn('git_enabled=True', result.stdout)
        self.assertNotIn('rctf :', result.stdout)

    def test_challenge_overlap_refused_before_service_roles(self):
        result, _ = self.run_workflow('deploy', overlap=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Observe routed role', result.stdout)

    def test_challenge_alias_cannot_point_at_infra(self):
        result, _ = self.run_workflow('deploy', duplicate_address=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Observe routed role', result.stdout)

    def test_verify_refuses_acceptance_override(self):
        result, _ = self.run_workflow('verify', extra={'micolab_verify_accept_unverified_external_acl': True})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Refuse incomplete acceptance overrides', result.stdout)


@unittest.skipUnless(shutil.which('ansible-playbook'), 'Ansible is required')
class StepArchiveStagingTests(unittest.TestCase):
    def test_actual_copy_and_sha256_gate_for_both_controller_archives(self):
        all_tasks = yaml.safe_load((ROOT / 'roles/step_ca/tasks/install.yml').read_text())
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            controller = d / 'controller.tar.gz'
            controller.write_bytes(b'synthetic archive for copy/checksum tests')
            for kind in ['ca', 'cli']:
                for valid in [True, False]:
                    with self.subTest(kind=kind, valid=valid):
                        prefix = 'microlab_step_' + kind
                        copy_task = next(t for t in all_tasks if t.get('ansible.builtin.copy', {}).get('src') == '{{ ' + prefix + '_artifact_src }}')
                        hash_task = next(t for t in all_tasks if t.get('register') == prefix + '_archive_stat')
                        assert_task = next(t for t in all_tasks if t.get('name') == ('Reject an unpinned step-ca archive' if kind == 'ca' else 'Reject an unpinned step CLI archive'))
                        tasks = [copy_task, hash_task, assert_task]
                        copy_task['ansible.builtin.copy']['owner'] = getpass.getuser()
                        copy_task['ansible.builtin.copy']['group'] = grp.getgrgid(os.getgid()).gr_name
                        values = {'microlab_step_ca_arch': 'amd64', prefix + '_artifact_src': str(controller),
                                  prefix + '_archive_path': str(d / (kind + '-target.tar.gz')),
                                  prefix + '_checksums': {'amd64': hashlib.sha256(controller.read_bytes()).hexdigest() if valid else '0' * 64}}
                        play = [{'hosts': 'localhost', 'gather_facts': False, 'become': False,
                                 'vars': values, 'tasks': tasks}]
                        (d / 'play.yml').write_text(yaml.safe_dump(play))
                        result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(d / 'play.yml')],
                                                cwd=d, text=True, capture_output=True, timeout=30)
                        self.assertEqual(result.returncode == 0, valid, result.stdout + result.stderr)
                        self.assertEqual((d / (kind + '-target.tar.gz')).read_bytes(), controller.read_bytes())


class BaselineInstallationTests(unittest.TestCase):
    def validate(self, **overrides):
        data = {'installation_mode': True,
                'admin_cidrs': ['10.72.78.99/32'],
                'client_cidrs': ['10.72.78.0/24']}
        data.update(overrides)
        result = subprocess.run([sys.executable, str(ROOT / 'roles/baseline/files/microlab_validate.py'), '-'],
                                input=json.dumps(data), text=True, capture_output=True, timeout=10)
        # Deliberately sparse input: other local correctness gates must still fail.
        self.assertNotEqual(result.returncode, 0)
        return result.stderr

    def test_install_needs_no_future_repo_and_allows_admin_within_client_subnet(self):
        errors = self.validate()
        self.assertNotIn('micolab_verify_git_repo', errors)
        self.assertNotIn('overlap', errors)
        self.assertIn('micolab_trust_targets', errors)

    def test_full_acceptance_still_requires_repo(self):
        self.assertIn('micolab_verify_git_repo', self.validate(installation_mode=False))
        self.assertIn('micolab_verify_git_repo', self.validate(installation_mode='false'))

    def test_client_subnet_never_substitutes_for_missing_admin(self):
        self.assertIn('micolab_admin_cidrs', self.validate(admin_cidrs=[]))


class WorkflowContractTests(unittest.TestCase):
    def test_installation_skips_only_external_and_git_in_verify(self):
        tasks = yaml.safe_load((ROOT / 'roles/verify/tasks/main.yml').read_text())
        for filename in ['git_acceptance.yml', 'external_acl.yml']:
            task = next(t for t in tasks if t.get('ansible.builtin.include_tasks') == filename)
            self.assertIn('not (microlab_installation_mode', task['when'])
        for filename in ['dns_records.yml', 'encrypted_dns.yml', 'doh_exposure.yml']:
            task = next(t for t in tasks if t.get('ansible.builtin.include_tasks') == filename)
            self.assertNotIn('when', task)

    def test_controller_step_archive_hashes_precede_extraction(self):
        tasks = yaml.safe_load((ROOT / 'roles/step_ca/tasks/install.yml').read_text())
        for kind in ['ca', 'cli']:
            copy = next(i for i,t in enumerate(tasks) if t.get('ansible.builtin.copy', {}).get('src') == '{{ microlab_step_' + kind + '_artifact_src }}')
            hashed = next(i for i,t in enumerate(tasks) if t.get('register') == 'microlab_step_' + kind + '_archive_stat')
            extracted = next(i for i,t in enumerate(tasks) if t.get('ansible.builtin.unarchive', {}).get('src') == '{{ microlab_step_' + kind + '_archive_path }}')
            self.assertLess(copy, hashed)
            self.assertLess(hashed, extracted)


if __name__ == '__main__':
    unittest.main()
