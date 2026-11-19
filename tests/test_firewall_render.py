"""Render the baseline nftables template and check it with the real `nft -c`.

`nft -c` needs CAP_NET_ADMIN, so it runs in an unprivileged user + network
namespace (`unshare -rn`); nothing touches this machine's firewall.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]


def namespace_nft_available():
    if not (shutil.which("nft") and shutil.which("unshare") and shutil.which("ansible-playbook")):
        return False
    return subprocess.run(["unshare", "-rn", "nft", "list", "ruleset"], capture_output=True).returncode == 0


@unittest.skipUnless(namespace_nft_available(), "requires nft, unshare -rn and Ansible")
class FirewallRender(unittest.TestCase):
    def render(self, **overrides):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "firewall.nft"
            playbook = Path(temp) / "render.yml"
            playbook.write_text(textwrap.dedent(f"""\
                - hosts: localhost
                  connection: local
                  gather_facts: false
                  become: false
                  tasks:
                    - ansible.builtin.include_vars: {ROOT / "group_vars/all.yml"}
                    - ansible.builtin.template:
                        src: {ROOT / "roles/baseline/templates/microlab-firewall.nft.j2"}
                        dest: {output}
            """))
            result = subprocess.run(["ansible-playbook", "-i", "localhost,", "-e", json.dumps(overrides), str(playbook)],
                                    cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            text = output.read_text()
            check = subprocess.run(["unshare", "-rn", "nft", "-c", "-f", str(output)], capture_output=True, text=True)
            loaded = subprocess.run(["unshare", "-rn", "sh", "-c", 'nft -f "$1" && nft list ruleset', "sh", str(output)],
                                    capture_output=True, text=True)
            return text, check, loaded

    def test_admin_host_inside_client_subnet_is_valid_and_merged(self):
        # The supported two-host layout: the admin workstation is on the player LAN.
        text, check, loaded = self.render(micolab_admin_cidrs=["10.72.78.241/32"], micolab_client_cidrs=["10.72.78.0/24"])
        self.assertEqual(check.returncode, 0, check.stderr + text)
        self.assertEqual(loaded.returncode, 0, loaded.stderr)
        sets = loaded.stdout
        # SSH stays admin-only; DNS and web hold the merged /24.
        self.assertIn("set mgmt4", sets)
        mgmt = sets.split("set mgmt4", 1)[1].split("}", 2)[0]
        self.assertIn("10.72.78.241", mgmt)
        self.assertNotIn("10.72.78.0/24", mgmt)
        for name in ("dns_clients4", "web_clients4"):
            block = sets.split("set " + name, 1)[1].split("}", 2)[0]
            self.assertIn("10.72.78.0/24", block)

    def test_disjoint_admin_and_client_networks_still_valid(self):
        _, check, _ = self.render(micolab_admin_cidrs=["192.168.50.10/32"], micolab_client_cidrs=["10.72.78.0/24"])
        self.assertEqual(check.returncode, 0, check.stderr)


if __name__ == "__main__":
    unittest.main()
