# Install Debian on the rCTF host

This guide installs the operating system on the **Intel NUC / x86-64 workload
host**. It ends with working SSH and KVM checks. Installing the rCTF application,
Firecracker binaries, guest images and workload routing is the next stage;
those services are not installed by this guide or this repository's infra playbooks.

## 1. Know which machine you are working on

| Machine | Address | Purpose |
| --- | --- | --- |
| Infrastructure Raspberry Pi | `10.72.78.73` | Technitium DNS, step-ca, Caddy and Forgejo |
| rCTF host being installed here | `10.72.78.72` | rCTF and Firecracker microVMs |
| Your everyday computer | Its existing address | Download/write the installer and later connect with SSH |
| Player-accessible network | `10.72.78.0/24` | Client access; **not** an administrator allowlist |

These addresses are this site's chosen layout. The router's gateway address,
the rCTF host's Ethernet MAC and your administrator source address still come
from your actual network. Do not assume the gateway is `10.72.78.1`.

The rCTF host must stay outside the `microlab_management` inventory group.
That group deploys infrastructure services and an infra firewall; its forwarding
policy is unsuitable for the workload host's microVM networking.

Have the rCTF host, its SSD, an Ethernet cable, monitor, keyboard and a spare
USB stick ready. Back up anything you need from the SSD and USB before starting.

## 2. Download Debian on your everyday computer

Use **Debian 13 (Trixie), amd64, netinst** from the
[official Debian download page](https://www.debian.org/distrib/netinst).
Select the **amd64** download. It is for 64-bit Intel processors as well as AMD;
the Pi's ARM64 image is not the image for this NUC.

The downloaded file ends in `amd64-netinst.iso`. Use the current Debian 13
point release rather than depending on an old point-release filename in a guide.
Netinst downloads packages during installation, so use a working internet
connection for this step.

For download verification, Debian publishes signed checksum files alongside
the ISO; follow its [image verification instructions](https://www.debian.org/CD/verify).

## 3. Write the installer USB

Run this step on your everyday computer. **Writing the image erases the USB.**
An ISO copied into a mounted USB folder is not a written installer image.

If using GNOME Disks on Linux:

1. Insert the USB and open **Disks**.
2. Select the USB in the left-hand device list. Check its model and capacity;
   do not select your computer's system disk.
3. Open the drive menu and choose **Restore Disk Image…**.
4. Select the downloaded Debian ISO, then start restoring and confirm the
   selected USB device.
5. Wait for completion, then safely eject the USB.

If using a different imaging application, use its image-writing function to
write the ISO to the whole USB device. Debian also documents a Linux command-line
method and links to instructions for other operating systems in its
[USB preparation guide](https://www.debian.org/releases/trixie/amd64/ch04s03.en.html).

## 4. Set firmware and reserve the host address

On the rCTF host, connect Ethernet, monitor, keyboard and the installer USB.
Enter its BIOS/UEFI setup using the key shown during startup or specified in
the machine's manual. Enable **Intel Virtualization Technology / VT-x** and use
UEFI boot. Then select the USB in the boot menu.

In your router's **Address Reservation** screen, create this separate entry:

| Router field | Enter |
| --- | --- |
| MAC address | The rCTF host's **wired Ethernet** MAC |
| Reserved IP address | `10.72.78.72` |
| Description | `rctf` |
| Enabled | Yes |

Use the router's connected-client list to find the host after it requests DHCP.
If it has not appeared yet, proceed into the installer's automatic network
configuration, then return to the router. Identify the actual wired adapter;
do not copy the Pi's MAC or use the Wi-Fi adapter's MAC.

Check that `.72` is not assigned to another device. Keep the Pi's `.73`
reservation. A DHCP reservation provides the stable address needed here:
**leave Debian on DHCP**, rather than also setting a second manual address.
If you add the reservation after a lease was issued, reboot after installation
and check that the new lease uses `.72`.

During OS installation, use the network's existing working DNS supplied by DHCP.
Do not switch to the Pi's `10.72.78.73` DNS until Technitium actually works there.

## 5. Make these installer choices

Choose **Graphical install** or **Install** at the USB boot menu.

| Installer prompt | Choice |
| --- | --- |
| Language, country and keyboard | Your preferred settings |
| Primary network interface | The connected wired Ethernet adapter |
| Network configuration | Automatic / DHCP |
| Hostname | `rctf` |
| Domain name, if asked | `microlab.hnh` |
| Root password | Leave blank and continue |
| Full name | Your name |
| Username | `caden`, or your chosen login name |
| User password | A strong password you retain privately |
| Time zone | Your local time zone |
| Scan additional installation media | No |
| Debian archive mirror | `deb.debian.org` |
| HTTP proxy | Blank unless your network requires a proxy |
| Package usage survey | Your preference; not required by rCTF |

Leaving the root password blank gives the first user administrative access
through `sudo`. Commands below use `caden`; replace it with your actual username
if you choose another. Setting the domain here does not create any DNS records.

For a dedicated SSD whose existing contents can be erased:

1. Select **Guided — use entire disk**.
2. Select the rCTF SSD by model and capacity. Disconnect unrelated external
   drives first if that helps distinguish them.
3. Select **All files in one partition**. This keeps the root filesystem's free
   space available to application data and microVM images.
4. Review the partition layout, select **Finish partitioning and write changes
   to disk**, and confirm only after checking the selected SSD.

**This erases the selected SSD.** The simple guided layout above is unencrypted.
If you instead select encrypted LVM, plan how its boot-time unlock will work
before relying on unattended recovery after power loss.

At **Software selection**, use Space to select only:

```text
[ ] Debian desktop environment
[ ] GNOME / KDE / other desktops
[ ] web server
[x] SSH server
[x] standard system utilities
```

If asked where to install GRUB, select the installed system's SSD, not the USB.
Complete the installation, remove the installer USB when prompted and reboot.
These choices follow the [Debian installer guide](https://www.debian.org/releases/trixie/amd64/ch06s03.en.html).

## 6. Update and install base tools on the rCTF host

At the rCTF host's console, log in with the account you created. Run these
commands **on that host**, not on the Pi or your everyday computer:

```bash
sudo apt update
sudo apt full-upgrade
sudo apt install \
  ca-certificates curl git jq unzip \
  openssh-server python3 \
  iproute2 nftables conntrack
sudo systemctl enable --now ssh
sudo reboot
```

Enter your user's password when `sudo` asks. Review package-manager confirmation
prompts. Rebooting returns you to the login screen.

These are base tools, not a complete rCTF runtime installation. The fork's
[host setup script](https://github.com/Caden64/rctf/blob/9bc7c10c63d873b76eea32b7de815c8dc547d709/deploy/firecracker/host/host-setup.sh)
checks for `ip`, `nft`, `conntrack`, KVM and separately installed Firecracker/jailer
binaries. Do not run that script yet: those binaries and the application
configuration are a later deployment step.

## 7. Verify the installed host

After reboot, run **on the rCTF host**:

```bash
hostname
ip -4 -brief address
ip route show default
uname -m
ls -l /dev/kvm
systemctl is-active ssh
timedatectl status
df -h /
```

| Check | Expected result |
| --- | --- |
| Hostname | `rctf` |
| Ethernet IPv4 | `10.72.78.72/24` on the wired interface |
| Default route | A route through your actual router |
| Architecture | `x86_64` |
| KVM | `/dev/kvm` exists as a character device |
| SSH | `active` |
| Clock | Correct time; synchronization working before certificate-dependent deployment |
| Storage | Root filesystem on the intended SSD with room for images and workloads |

Interface names differ between machines; do not assume `eth0`.
If the address is wrong, correct the router reservation and reboot from the
local console. If `/dev/kvm` is missing on this Intel host, try:

```bash
sudo modprobe kvm_intel
ls -l /dev/kvm
```

If loading the module fails or the device is still missing, recheck firmware
VT-x support/settings before proceeding. Do not bypass this check by changing
device permissions. These checks establish OS readiness, not a successful
Firecracker VM launch or a tested capacity limit.

## 8. Verify SSH from your everyday computer

First, at the **rCTF host's local console**, display its SSH host fingerprint:

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Then run **on your everyday computer**:

```bash
ssh -o HostKeyAlgorithms=ssh-ed25519 caden@10.72.78.72
```

Replace `caden` only if you used another username. Compare the displayed
fingerprint with the console output before accepting the first connection.
Log in with the password created during installation, then verify:

```bash
hostname
sudo -v
```

The hostname should be `rctf`; `sudo -v` should accept your password. Run `exit`
to return to your everyday computer. If SSH fails, use the host's local console
to check its address and `systemctl status ssh` rather than changing firewall
rules blindly. A changed-host-key warning after reinstalling requires checking
the new console fingerprint before replacing the saved entry.

The player subnet is not an admin allowlist. Before opening the completed
workload platform to players, configure administrator SSH access and the
workload firewall for your actual admin source. Keep the privileged Firecracker
agent API local when its controller is on this same machine; the fork's sample
agent API must not be exposed to players.

## 9. Continue with the two-host setup

Return to [fresh-clone onboarding](fresh-clone.md) for the infra installation
and its [rCTF handoff](fresh-clone.md#handoff-to-the-rctf--microvm-host).
Preserve any inventory, downloads and secrets already prepared; installing this
second host is not a reason to recreate the infra configuration.

The rCTF deployment still needs application dependencies, pinned
Firecracker/jailer binaries, guest images, data services, agent/controller
configuration, workload DNS/TLS and a compatible firewall. Follow the fork's
[host networking documentation](https://github.com/Caden64/rctf/blob/9bc7c10c63d873b76eea32b7de815c8dc547d709/deploy/firecracker/host/README.md)
alongside that handoff. Its firewall tables and forwarding requirements belong
on `.72`; the infra roles remain on `.73`.

Writing this guide does not install Debian or contact either host. No live
Debian/rCTF deployment is claimed by these instructions.
