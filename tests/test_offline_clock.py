"""Offline clock trust: roles/baseline/tasks/clock.yml in a bubblewrap sandbox.

The target uses the test-only ``stepca_isolated`` connection, so /usr/bin/date
and /usr/bin/timedatectl can be replaced by fakes without touching this
machine's real clock. A fake ``date`` on the controller's PATH plays a
controller clock that runs ahead of the host until the host clock is "set".
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
BWRAP = os.environ.get("STEPCA_SANDBOX_BWRAP", shutil.which("bwrap") or "/usr/bin/bwrap")


@unittest.skipUnless(shutil.which("ansible-playbook") and os.path.exists(BWRAP), "requires Ansible and bubblewrap")
class OfflineClock(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.state = self.base / "state"
        self.state.mkdir()
        (self.base / "sandbox-home/.tmp").mkdir(parents=True)
        fakes = self.base / "fakes"
        controller = self.base / "controller-bin"
        fakes.mkdir()
        controller.mkdir()
        self.write_exec(fakes / "date", f"""\
            #!/bin/sh
            for arg in "$@"; do [ "$arg" = "-s" ] && printf '%s\\n' "$*" > {self.state}/set; done
            exit 0
        """)
        self.write_exec(fakes / "timedatectl", f"#!/bin/sh\ncat {self.state}/ntp\n")
        self.write_exec(controller / "date", f"""\
            #!/bin/sh
            [ "$1" = "-u" ] && shift
            offset=$(cat {self.state}/offset)
            [ -f {self.state}/set ] && offset=0
            exec /usr/bin/date -u -d "@$(( $(/usr/bin/date +%s) + offset ))" "$1"
        """)
        self.binds = [[str(fakes / "date"), "/usr/bin/date"], [str(fakes / "timedatectl"), "/usr/bin/timedatectl"],
                      [str(self.state), str(self.state)], [str(self.base / "sandbox-home"), "/srv/microlab-home"]]
        self.controller_path = str(controller)
        self.playbook = self.base / "clock.yml"
        self.playbook.write_text(textwrap.dedent("""\
            - hosts: target
              gather_facts: false
              become: false
              tasks:
                - ansible.builtin.include_role:
                    name: baseline
                    tasks_from: clock
        """))

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def write_exec(path, text):
        path.write_text(textwrap.dedent(text))
        path.chmod(0o755)

    def run_clock(self, ntp="no", offset=100, **variables):
        (self.state / "ntp").write_text(ntp + "\n")
        (self.state / "offset").write_text(str(offset))
        extra = {"micolab_time_mode": "auto", **variables}
        env = dict(os.environ,
                   PATH=self.controller_path + os.pathsep + os.environ["PATH"],
                   ANSIBLE_CONNECTION_PLUGINS=str(ROOT / "tests/plugins/connection"),
                   ANSIBLE_ROLES_PATH=str(ROOT / "roles"),
                   ANSIBLE_HOST_KEY_CHECKING="False",
                   STEPCA_SANDBOX_BWRAP=BWRAP,
                   STEPCA_SANDBOX_BINDS=json.dumps(self.binds),
                   STEPCA_SANDBOX_TMPFS=json.dumps(["/var/lib/systemd", "/srv"]),
                   STEPCA_SANDBOX_DIRS=json.dumps(["/var/lib/systemd/timesync", "/srv/microlab-home"]),
                   STEPCA_SANDBOX_TMPDIR="/srv/microlab-home/.tmp")
        return subprocess.run(
            ["ansible-playbook", "-i", "target,", "-e", "ansible_connection=stepca_isolated",
             "-e", "ansible_python_interpreter=/usr/bin/python3",
             "-e", "ansible_remote_tmp=/srv/microlab-home/.ansible-tmp", "-e", json.dumps(extra), str(self.playbook)],
            cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def test_offline_host_is_set_from_the_controller_clock(self):
        result = self.run_clock()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("-u -s @", (self.state / "set").read_text())
        self.assertIn("was corrected", result.stdout)

    def test_offline_host_within_tolerance_is_left_alone(self):
        result = self.run_clock(offset=0)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.state / "set").exists())
        self.assertIn("is within tolerance", result.stdout)

    def test_ntp_synchronized_host_never_consults_the_controller(self):
        result = self.run_clock(ntp="yes")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.state / "set").exists())
        self.assertNotIn("using the controller clock", result.stdout)

    def test_strict_ntp_mode_still_refuses_an_unsynchronized_host(self):
        result = self.run_clock(micolab_time_mode="ntp")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not NTP-synchronized", result.stdout)
        self.assertFalse((self.state / "set").exists())

    def test_drift_without_permission_to_set_fails(self):
        result = self.run_clock(micolab_time_set_from_controller=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("off the", result.stdout)
        self.assertFalse((self.state / "set").exists())

    def test_implausible_controller_clock_is_refused(self):
        result = self.run_clock(offset=-10 ** 9)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("earlier than allowed", result.stdout)
        self.assertFalse((self.state / "set").exists())


if __name__ == "__main__":
    unittest.main()
