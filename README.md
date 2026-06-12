# 🛡️ OpSec Hardening Guide

> A complete, paranoid-grade guide to hardening a Linux computer or server. Extensive examples, real commands, defense-in-depth.

![Platform](https://img.shields.io/badge/platform-Linux-blue?logo=linux&logoColor=white)
![Shell](https://img.shields.io/badge/shell-Bash-121011?logo=gnubash&logoColor=white)
![Security](https://img.shields.io/badge/focus-OpSec%20%26%20Hardening-red?logo=hackthebox&logoColor=white)
![Threat Model](https://img.shields.io/badge/threat%20model-Paranoid-black)
![Maintenance](https://img.shields.io/badge/maintained-yes-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?logo=github)

---

> ⚠️ **Disclaimer**: This guide is for hardening systems you **own** or are **authorized** to administer. Apply changes in a test environment first — several steps can lock you out of a remote machine. Read each command before running it.

---

## 📑 Table of Contents

1. [Threat Modeling](#1--threat-modeling)
2. [Pre-Install & Disk Encryption](#2--pre-install--disk-encryption)
3. [User Accounts & Authentication](#3--user-accounts--authentication)
4. [SSH Hardening](#4--ssh-hardening)
5. [Firewall & Network](#5--firewall--network)
6. [Kernel & Sysctl Hardening](#6--kernel--sysctl-hardening)
7. [Mandatory Access Control (AppArmor/SELinux)](#7--mandatory-access-control)
8. [Auditing, Logging & Integrity](#8--auditing-logging--integrity)
9. [Intrusion Detection & Prevention](#9--intrusion-detection--prevention)
10. [Service & Package Minimization](#10--service--package-minimization)
11. [Automatic Updates](#11--automatic-updates)
12. [Physical & Boot Security](#12--physical--boot-security)
13. [Privacy & Anti-Forensics](#13--privacy--anti-forensics)
14. [Verification & Hardening Checklist](#14--verification--hardening-checklist)

---

<!-- SECTIONS-START -->

## 1. 🎯 Threat Modeling

Hardening without a threat model is theater. Before touching a config, answer four questions:

| Question | Example answers |
|----------|-----------------|
| **What am I protecting?** | SSH keys, customer data, crypto wallets, source code, your identity |
| **Who is the adversary?** | Script kiddies, ransomware crews, a cloud provider, a nation-state, a thief who steals the laptop |
| **What are their capabilities?** | Mass scanning, phishing, physical access, supply-chain, 0-days |
| **What happens if I lose?** | Data leak, financial loss, legal exposure, loss of life |

### Tiers of paranoia

- **Tier 1 — Hygiene:** updates, firewall, no password SSH. Stops 95% of automated attacks.
- **Tier 2 — Hardened:** MAC, auditd, IDS, minimized attack surface. Stops targeted opportunists.
- **Tier 3 — Paranoid:** full-disk encryption, secure boot, anti-forensics, air-gaps, hardware tokens. Raises cost against advanced adversaries.

This guide covers all three; pick what matches your model. **Document your decisions** — write down what you accept as residual risk:

```bash
# Keep a living threat model + change log next to your configs
mkdir -p ~/opsec && cat > ~/opsec/THREAT_MODEL.md <<'EOF'
# Threat Model — <hostname>
- Assets:
- Adversaries:
- Accepted residual risk:
- Last hardening review: 2026-06-12
EOF
```

> 🔑 **Rule of thumb:** every control should map to a threat. If you can't name the threat, you're adding complexity (= attack surface), not security.

## 2. 💽 Pre-Install & Disk Encryption

Encryption at rest is the foundation of physical security. Do it at install time — retrofitting is painful.

### Full-disk encryption with LUKS2

```bash
# Inspect target disk (DOUBLE-CHECK the device — this destroys data)
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT

# Optional: wipe with random data so used/free space is indistinguishable
sudo cryptsetup open --type plain -d /dev/urandom /dev/sdX wipe
sudo dd if=/dev/zero of=/dev/mapper/wipe bs=1M status=progress
sudo cryptsetup close wipe

# Create the LUKS2 container (Argon2id KDF, strong cipher)
sudo cryptsetup luksFormat --type luks2 \
  --cipher aes-xts-plain64 \
  --key-size 512 \
  --hash sha512 \
  --pbkdf argon2id \
  --iter-time 5000 \
  /dev/sdX

# Open it and create a filesystem
sudo cryptsetup open /dev/sdX cryptroot
sudo mkfs.ext4 /dev/mapper/cryptroot
```

### Manage LUKS key slots

```bash
# LUKS supports 8 key slots — add a backup passphrase, store it offline
sudo cryptsetup luksAddKey /dev/sdX

# Add a keyfile (e.g. on a USB token) instead of typing a passphrase
dd if=/dev/urandom of=/root/keyfile bs=512 count=8
sudo cryptsetup luksAddKey /dev/sdX /root/keyfile

# Inspect header / slots
sudo cryptsetup luksDump /dev/sdX

# 🔥 ALWAYS back up the LUKS header — corruption = permanent data loss
sudo cryptsetup luksHeaderBackup /dev/sdX --header-backup-file luks-header.img
# Store luks-header.img somewhere safe & OFFLINE. Anyone with it + passphrase
# can decrypt, so encrypt the backup itself.
```

### Encrypted swap & /tmp

```bash
# Random-key encrypted swap (re-keyed each boot, no hibernation)
echo 'swap /dev/sdY /dev/urandom swap,cipher=aes-xts-plain64,size=512' \
  | sudo tee -a /etc/crypttab

# Mount /tmp as tmpfs (RAM-backed, gone on reboot) with safe flags
echo 'tmpfs /tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777 0 0' \
  | sudo tee -a /etc/fstab
```

### Mount-option hardening (`/etc/fstab`)

Restrict what each filesystem can do. Apply `nosuid,nodev,noexec` wherever possible:

```fstab
# device        mount     fs    options                              dump pass
/dev/mapper/var /var      ext4  defaults,nosuid,nodev                0 2
tmpfs           /dev/shm  tmpfs defaults,nosuid,nodev,noexec         0 0
proc            /proc     proc  defaults,hidepid=2                   0 0
```

> 🧠 **Paranoid extra:** consider a **detached LUKS header** (`--header` on a USB key) so the disk looks like random noise with no LUKS signature at all. Boot requires the USB key present.



## 3. 👤 User Accounts & Authentication

### Principle of least privilege

```bash
# Create an admin user; never operate as root directly
sudo adduser admin
sudo usermod -aG sudo admin     # Debian/Ubuntu
# sudo usermod -aG wheel admin  # RHEL/Fedora/Arch

# Lock the root account's password (sudo still works)
sudo passwd -l root

# Audit who has a login shell / UID 0
awk -F: '($3==0){print $1" has UID 0"}' /etc/passwd
getent passwd | awk -F: '($7 !~ /(nologin|false)$/){print $1": "$7}'

# Find world-writable files and SUID/SGID binaries (attack surface)
sudo find / -xdev -perm -4000 -type f 2>/dev/null   # SUID
sudo find / -xdev -perm -2000 -type f 2>/dev/null   # SGID
sudo find / -xdev -perm -0002 -type f 2>/dev/null   # world-writable
```

### Strong password & lockout policy (PAM)

```bash
# Install password-quality module
sudo apt install libpam-pwquality   # Debian/Ubuntu

# /etc/security/pwquality.conf
sudo tee /etc/security/pwquality.conf <<'EOF'
minlen = 16
minclass = 4
maxrepeat = 3
gecoscheck = 1
dictcheck = 1
enforcing = 1
EOF
```

```ini
# /etc/login.defs — password aging
PASS_MAX_DAYS   180
PASS_MIN_DAYS   1
PASS_WARN_AGE   14
ENCRYPT_METHOD  YESCRYPT
```

```bash
# Lock account after 5 failed logins (faillock, modern PAM)
sudo tee /etc/security/faillock.conf <<'EOF'
deny = 5
unlock_time = 900
fail_interval = 900
audit
even_deny_root
EOF
# View / reset
faillock --user admin
sudo faillock --user admin --reset
```

### Two-factor authentication (TOTP) for local & SSH login

```bash
sudo apt install libpam-google-authenticator
google-authenticator -t -d -f -r 3 -R 30 -w 3   # run as the user, save backup codes!

# /etc/pam.d/sshd — add near the top
# auth required pam_google_authenticator.so
# Then in /etc/ssh/sshd_config:
#   KbdInteractiveAuthentication yes
#   AuthenticationMethods publickey,keyboard-interactive
```

### Sudo hardening

```bash
# Use a drop-in, validate with visudo -c
sudo tee /etc/sudoers.d/hardening <<'EOF'
Defaults        use_pty
Defaults        logfile="/var/log/sudo.log"
Defaults        passwd_tries=3
Defaults        timestamp_timeout=5
Defaults        !visiblepw
Defaults        requiretty
EOF
sudo visudo -c
```

> 🧠 **Paranoid extra:** require a **hardware security key** (YubiKey via `pam_u2f`) as a second factor for sudo and login — phishing-resistant, unlike TOTP.

## 4. 🔐 SSH Hardening

SSH is the #1 remote attack surface. Harden it hard.

### Key-based auth only (Ed25519)

```bash
# On your CLIENT: generate a modern key
ssh-keygen -t ed25519 -a 100 -C "admin@$(hostname)-2026"
# Or hardware-backed (key never leaves the device):
ssh-keygen -t ed25519-sk -O resident -O verify-required

# Copy the public key to the server
ssh-copy-id -i ~/.ssh/id_ed25519.pub admin@server
```

### `/etc/ssh/sshd_config` — paranoid baseline

```ini
# --- Authentication ---
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 20

# --- Access control ---
AllowUsers admin
Protocol 2
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no

# --- Strong crypto only ---
KexAlgorithms curve25519-sha256@libssh.org,sntrup761x25519-sha512@openssh.com
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com

# --- Hygiene ---
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
Banner /etc/issue.net
UseDNS no
```

```bash
# Validate config BEFORE restarting (so you don't lock yourself out)
sudo sshd -t

# Keep your current session open, restart, then test in a NEW terminal
sudo systemctl restart ssh
ssh -v admin@server
```

### Change the port & rate-limit (defense in depth)

```bash
# Move off 22 to cut scanner noise (NOT security by itself)
sudo sed -i 's/^#\?Port .*/Port 2222/' /etc/ssh/sshd_config

# Regenerate host keys, drop weak ones
sudo rm /etc/ssh/ssh_host_*key*
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

# Audit your config with an external tool
# pip install ssh-audit ; ssh-audit server -p 2222
```

> 🧠 **Paranoid extra:** put SSH behind **WireGuard** or a **Tor hidden service** so port 22 isn't reachable from the public internet at all. Combine with `Match Address` blocks to allow keys only from your VPN subnet.

## 5. 🧱 Firewall & Network

Default-deny inbound, restrict outbound, log drops.

### UFW (simple, Debian/Ubuntu)

```bash
sudo apt install ufw
sudo ufw default deny incoming
sudo ufw default deny outgoing       # paranoid: deny outbound too
sudo ufw allow out 53,80,443/tcp     # DNS + HTTP(S) for updates
sudo ufw allow out 123/udp           # NTP
sudo ufw limit in 2222/tcp comment 'SSH rate-limited'
sudo ufw logging on
sudo ufw enable
sudo ufw status verbose numbered
```

### nftables (modern, granular)

```nft
#!/usr/sbin/nft -f
# /etc/nftables.conf
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        ct state invalid drop
        iif "lo" accept
        ip protocol icmp icmp type echo-request limit rate 5/second accept
        ip6 nexthdr icmpv6 accept
        tcp dport 2222 ct state new limit rate 4/minute accept
        log prefix "nft-drop-in: " flags all counter drop
    }
    chain forward { type filter hook forward priority 0; policy drop; }
    chain output  { type filter hook output  priority 0; policy accept; }
}
```

```bash
sudo nft -c -f /etc/nftables.conf      # check syntax
sudo systemctl enable --now nftables
sudo nft list ruleset
```

### Egress filtering & DNS privacy

```bash
# Lock DNS to a trusted resolver over TLS (systemd-resolved)
sudo tee /etc/systemd/resolved.conf.d/dot.conf <<'EOF'
[Resolve]
DNS=9.9.9.9#dns.quad9.net 1.1.1.1#cloudflare-dns.com
DNSOverTLS=yes
DNSSEC=yes
Domains=~.
EOF
sudo systemctl restart systemd-resolved
resolvectl status
```

> 🧠 **Paranoid extra:** outbound default-deny + per-application egress rules catch malware phoning home. Pair with **MAC randomization** (`macchanger`) and disabling IPv6 if unused.

## 6. ⚙️ Kernel & Sysctl Hardening

Tighten the kernel's network and memory behavior.

```bash
# /etc/sysctl.d/99-hardening.conf
sudo tee /etc/sysctl.d/99-hardening.conf <<'EOF'
# --- Network: spoofing & redirects ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0

# --- Kernel: info leaks & exploit mitigation ---
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.printk = 3 3 3 3
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 2
kernel.kexec_load_disabled = 1
kernel.sysrq = 0
kernel.perf_event_paranoid = 3
kernel.randomize_va_space = 2

# --- Filesystem ---
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
EOF
sudo sysctl --system     # apply now
```

### Blacklist unused/dangerous kernel modules

```bash
# /etc/modprobe.d/blacklist-hardening.conf
sudo tee /etc/modprobe.d/blacklist-hardening.conf <<'EOF'
# Rare network protocols (CVE magnets)
install dccp /bin/false
install sctp /bin/false
install rds  /bin/false
install tipc /bin/false
# Uncommon filesystems
install cramfs   /bin/false
install freevxfs /bin/false
install jffs2    /bin/false
install hfs      /bin/false
install hfsplus  /bin/false
install udf      /bin/false
# Disable USB storage if not needed (DMA/exfil risk)
# install usb-storage /bin/false
# Disable Firewire & Thunderbolt DMA
install firewire-core /bin/false
EOF
sudo update-initramfs -u
```

### Kernel boot parameters (GRUB)

```bash
# /etc/default/grub — GRUB_CMDLINE_LINUX_DEFAULT
# slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 \
# pti=on vsyscall=none debugfs=off lockdown=confidentiality \
# module.sig_enforce=1 mce=0 spectre_v2=on spec_store_bypass_disable=on
sudo update-grub
```

> 🧠 **Paranoid extra:** run a hardened kernel (e.g. **linux-hardened** on Arch, or grsecurity-style configs) and enable **lockdown=confidentiality** to block even root from reading kernel memory.

## 7. 🔒 Mandatory Access Control

Discretionary permissions aren't enough — confine processes so a compromised service can't roam.

### AppArmor (Debian/Ubuntu/SUSE)

```bash
sudo apt install apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
sudo aa-status                       # what's loaded & enforcing

# Put a profile into enforce mode
sudo aa-enforce /etc/apparmor.d/usr.sbin.nginx

# Generate a profile for a custom binary, then learn from real usage
sudo aa-genprof /usr/local/bin/myapp
sudo aa-logprof                      # refine from audit logs

# Confirm everything is enforcing, nothing in complain mode
sudo aa-status | grep -E 'enforce|complain'
```

### SELinux (RHEL/Fedora/CentOS)

```bash
sestatus                             # should read: enforcing, targeted
sudo setenforce 1
sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

# Diagnose denials instead of disabling SELinux (the lazy, wrong fix)
sudo ausearch -m AVC,USER_AVC -ts recent | audit2why
sudo grep AVC /var/log/audit/audit.log | audit2allow -M mypolicy
sudo semodule -i mypolicy.pp

# Manage booleans (toggle policy switches) and file contexts
getsebool -a | grep httpd
sudo setsebool -P httpd_can_network_connect on
sudo restorecon -Rv /var/www
```

> 🧠 **Paranoid extra:** combine MAC with **systemd sandboxing** per service:
> `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`,
> `NoNewPrivileges=true`, `SystemCallFilter=@system-service`,
> `CapabilityBoundingSet=`, `MemoryDenyWriteExecute=true`.

## 8. 📋 Auditing, Logging & Integrity

You can't respond to what you can't see. Log everything important, make logs tamper-evident.

### auditd — kernel-level audit trail

```bash
sudo apt install auditd audispd-plugins

# /etc/audit/rules.d/hardening.rules
sudo tee /etc/audit/rules.d/hardening.rules <<'EOF'
-D
-b 8192
-f 1
# Watch sensitive files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /etc/ssh/sshd_config -p wa -k sshd
# Watch privilege escalation & module loads
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=-1 -k rootcmd
-a always,exit -F arch=b64 -S init_module,delete_module -k modules
# Time changes & user/group changes
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time
-w /etc/group -p wa -k identity
# Make the config immutable until reboot
-e 2
EOF
sudo augenrules --load
sudo systemctl restart auditd

# Query it
sudo ausearch -k rootcmd -ts today
sudo aureport --auth --summary
```

### File integrity monitoring (AIDE)

```bash
sudo apt install aide
sudo aideinit                                  # build baseline DB
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
sudo aide --check                              # detect changes
# Schedule daily checks
echo '0 5 * * * root /usr/bin/aide --check | mail -s "AIDE $(hostname)" root' \
  | sudo tee /etc/cron.d/aide
# 🔥 Store the baseline DB OFFLINE/read-only — attackers update it to hide.
```

### Centralized & tamper-resistant logging

```bash
# Make journald persistent and forward to a remote/append-only collector
sudo mkdir -p /var/log/journal
sudo tee /etc/systemd/journald.conf.d/persist.conf <<'EOF'
[Journal]
Storage=persistent
Seal=yes
ForwardToSyslog=yes
SystemMaxUse=2G
EOF
sudo systemctl restart systemd-journald

# Ship logs off-box ASAP so an attacker can't scrub them locally
# (rsyslog over TLS to a hardened log host, or vendor SIEM)
```

> 🧠 **Paranoid extra:** forward logs in **real time** to a separate, locked-down host (or write-once media). Local logs are the first thing an intruder edits. Sign log batches and monitor for gaps in sequence numbers.

## 9. 🚨 Intrusion Detection & Prevention

### fail2ban — block brute-force at the firewall

```bash
sudo apt install fail2ban
sudo tee /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 4
backend  = systemd
banaction = nftables-multiport
destemail = root@localhost
ignoreip = 127.0.0.1/8 10.0.0.0/8

[sshd]
enabled = true
port    = 2222
mode    = aggressive

[recidive]
enabled  = true
bantime  = 1w
findtime = 1d
maxretry = 5
EOF
sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd
```

### Rootkit & malware scanning

```bash
sudo apt install rkhunter chkrootkit
sudo rkhunter --update && sudo rkhunter --propupd
sudo rkhunter --check --skip-keypress
sudo chkrootkit

# On-demand AV (catches known malware, useful on file servers)
sudo apt install clamav clamav-daemon
sudo freshclam
sudo clamscan -ri --bell /home
```

### Host IDS (Wazuh / OSSEC) & network IDS (Suricata)

```bash
# Suricata in IDS mode on the WAN interface
sudo apt install suricata
sudo suricata-update                      # pull ET Open ruleset
sudo sed -i 's/^  - interface: .*/  - interface: eth0/' /etc/suricata/suricata.yaml
sudo systemctl enable --now suricata
sudo tail -f /var/log/suricata/fast.log
```

> 🧠 **Paranoid extra:** deploy **Wazuh** for centralized HIDS (FIM + log analysis + active response) and consider a **canary/honeypot** (e.g. `opencanary`) — an unused service that should *never* see traffic; any hit means someone's inside.

## 10. ✂️ Service & Package Minimization

The smallest attack surface is the code you never installed.

```bash
# What's listening, and which process owns it?
sudo ss -tulpn
sudo systemctl list-units --type=service --state=running

# Disable & mask anything you don't need
sudo systemctl disable --now avahi-daemon cups bluetooth modemmanager
sudo systemctl mask avahi-daemon          # mask = can't be started at all

# Remove unused packages and orphaned deps
sudo apt purge telnet rsh-client xinetd nis
sudo apt autoremove --purge
sudo apt list --installed | wc -l         # track your footprint

# Audit cron / timers / startup for surprises
sudo systemctl list-timers --all
ls -la /etc/cron.* /etc/systemd/system/*.timer 2>/dev/null
```

### Process accounting & resource limits

```bash
# Cap resources to blunt fork-bombs & runaway processes
sudo tee /etc/security/limits.d/hardening.conf <<'EOF'
*    hard nproc 1024
*    hard nofile 4096
*    hard core 0
root hard nproc 2048
EOF
```

> 🧠 **Paranoid extra:** start from a **minimal/netinst** image, run services in **containers or VMs** (gVisor/Kata for stronger isolation), and treat servers as **immutable** — rebuild from code rather than patching live.

## 11. 🔄 Automatic Updates

Unpatched software is the most common breach vector. Automate it.

```bash
# Debian/Ubuntu — unattended security upgrades
sudo apt install unattended-upgrades apt-listchanges
sudo dpkg-reconfigure -plow unattended-upgrades
sudo tee /etc/apt/apt.conf.d/51hardening <<'EOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF
sudo unattended-upgrade --dry-run -d      # verify it works

# RHEL/Fedora
sudo dnf install dnf-automatic
sudo sed -i 's/^apply_updates =.*/apply_updates = yes/' /etc/dnf/automatic.conf
sudo systemctl enable --now dnf-automatic.timer
```

```bash
# Verify package signatures / repo integrity periodically
sudo apt-key list 2>/dev/null; apt-config dump | grep -i allow-unauth
# Subscribe to security advisories for your distro & key software.
```

> 🧠 **Paranoid extra:** stage updates in a test environment, pin critical packages, and monitor CVE feeds (e.g. via `debsecan` or `osquery`) so you patch *before* automation catches it.

## 12. 🔌 Physical & Boot Security

If an attacker can touch the machine, all bets are off — unless you prepared.

### BIOS/UEFI & Secure Boot

```bash
# Confirm Secure Boot state
mokutil --sb-state
bootctl status

# Sign your own kernels/modules so only YOUR code boots (sbctl)
sudo sbctl create-keys
sudo sbctl enroll-keys -m
sudo sbctl sign -s /boot/vmlinuz-linux
sudo sbctl verify
```

- Set a **BIOS/UEFI admin password** and disable boot from USB/PXE/network.
- Enable **TPM-measured boot**; seal the LUKS key to the TPM so it only releases on a known-good boot chain.

### GRUB password (block single-user / kernel-arg tampering)

```bash
grub-mkpasswd-pbkdf2          # copy the grub.pbkdf2.sha512... hash
# /etc/grub.d/40_custom
cat <<'EOF' | sudo tee -a /etc/grub.d/40_custom
set superusers="admin"
password_pbkdf2 admin grub.pbkdf2.sha512.10000.XXXX...
EOF
sudo update-grub
```

### Lock physical ports & detect tampering

```bash
# USBGuard — allow only known USB devices, reject the rest
sudo apt install usbguard
sudo usbguard generate-policy | sudo tee /etc/usbguard/rules.conf
sudo systemctl enable --now usbguard
sudo usbguard list-devices

# Lock the screen automatically; require password on resume.
# Disable Thunderbolt/Firewire DMA (see module blacklist in §6).
```

> 🧠 **Paranoid extra:** epoxy/tamper-evident seals on ports & screws, **BusKill** (USB dead-man's-switch that locks/wipes on cable pull), and a detached LUKS header on a key you carry. For laptops, enable a power-on password + TPM PIN.

## 13. 🕵️ Privacy & Anti-Forensics

Reduce what the machine reveals about you, and what it leaves behind.

### Metadata, history & traces

```bash
# Don't log shell history for sensitive sessions
export HISTFILE=/dev/null HISTSIZE=0

# Securely wipe files & free space (on HDDs; see note for SSDs)
shred -vfz -n 3 sensitive.key
sudo fstrim -av                      # SSD: TRIM to discard freed blocks

# Scrub document/image metadata before sharing
sudo apt install mat2 && mat2 report.pdf photo.jpg

# Wipe an entire SSD properly via the controller (ATA secure erase)
sudo hdparm --user-master u --security-set-pass p /dev/sdX
sudo hdparm --user-master u --security-erase p /dev/sdX
```

> ⚠️ On **SSDs**, `shred` is unreliable (wear-leveling). Rely on **full-disk encryption** (§2) + crypto-erase (destroy the key) or ATA secure erase.

### Network anonymity & MAC randomization

```bash
# Randomize MAC on every connection (NetworkManager)
sudo tee /etc/NetworkManager/conf.d/00-rand-mac.conf <<'EOF'
[device]
wifi.scan-rand-mac-address=yes
[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random
EOF
sudo systemctl restart NetworkManager

# Route traffic through Tor for whole-system anonymity
sudo apt install tor torsocks
torsocks curl https://check.torproject.org/api/ip
```

> 🧠 **Paranoid extra:** use **Tails** (amnesic live OS) or **Qubes OS** (compartmentalized VMs) for high-risk work; keep a separate, hardened machine for sensitive identities; disable telemetry, camera, and microphone at the hardware/firmware level.

## 14. ✅ Verification & Hardening Checklist

Don't trust — verify. Re-run these after every change and on a schedule.

### Automated benchmarking

```bash
# Lynis — comprehensive system audit with a hardening index score
sudo apt install lynis
sudo lynis audit system
# Review /var/log/lynis.log and the suggestions list; aim to raise the index.

# CIS-CAT / OpenSCAP against an official benchmark
sudo apt install libopenscap8 ssg-debderived   # or scap-security-guide
sudo oscap xccdf eval --profile cis \
  --results scan-results.xml --report scan-report.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml

# ssh-audit (from a client) to grade your SSH crypto
ssh-audit -p 2222 your.server
```

### Manual spot-checks

```bash
sudo ss -tulpn                       # only expected ports listening?
sudo aa-status / sestatus            # MAC enforcing?
sudo ufw status verbose              # firewall up, default-deny?
sudo auditctl -l                     # audit rules loaded & immutable?
sudo fail2ban-client status          # IPS active?
last -20 ; sudo lastb -20            # recent logins / failures
sudo rkhunter --check                # rootkit scan clean?
```

### ✔️ Final checklist

- [ ] Threat model documented & reviewed
- [ ] Full-disk encryption (LUKS2) + header backed up offline
- [ ] Root login disabled; least-privilege users; sudo logged
- [ ] Strong password policy + faillock + 2FA/hardware key
- [ ] SSH: keys only, modern crypto, restricted users, validated config
- [ ] Firewall default-deny in (and out, if paranoid); DNS over TLS
- [ ] Sysctl + module blacklist + GRUB hardening params applied
- [ ] MAC (AppArmor/SELinux) **enforcing** on all services
- [ ] auditd rules loaded + immutable; AIDE baseline stored offline
- [ ] Logs shipped off-box in real time
- [ ] fail2ban + rootkit scans + IDS running
- [ ] Unused services/packages removed; resource limits set
- [ ] Automatic security updates verified working
- [ ] Secure Boot + signed kernel + GRUB password + USBGuard
- [ ] Anti-forensics: metadata scrubbing, MAC randomization
- [ ] Lynis index reviewed; OpenSCAP/CIS benchmark passed
- [ ] Backups encrypted, tested, and **offline** (3-2-1 rule)

---

> 🧠 **Remember:** hardening is a *process*, not a one-time task. Re-audit after every change, every new service, and on a recurring schedule. The goal isn't a perfect score — it's making yourself a more expensive target than the attacker is willing to pay for.

<!-- SECTIONS-END -->

## 📜 License

MIT — see [LICENSE](LICENSE).
