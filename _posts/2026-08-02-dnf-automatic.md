---
title: Automatically Installing Security Updates with dnf-automatic on RHEL 9
date: 2026-08-02 15:30:00 -0600
categories: [Linux, RHEL]
tags: [rhel, rocky, alma, dnf, security, automation, systemd]
---

## Overview

Keeping Linux systems updated is one of the simplest ways to reduce security risk. `dnf-automatic` allows systems running RHEL, Rocky Linux, AlmaLinux, and other DNF-based distributions to periodically check for updates, automatically install security fixes, and reboot only when necessary.

This guide configures `dnf-automatic` to:

- Install **security updates only**
- Apply updates automatically
- Reboot automatically only when required (for example, after a kernel update)
- Check for updates every three days at **03:00 AM**

---

## Environment

| Component | Value |
|-----------|-------|
| Operating System | RHEL 9 |
| Package Manager | DNF |
| Service | dnf-automatic |
| Scheduler | systemd timer |

---

## Installing dnf-automatic

Install the package:

```bash
sudo dnf install dnf-automatic
```

Enable the installation timer:

```bash
sudo systemctl enable --now dnf-automatic-install.timer
```

Verify that the timer is enabled:

```bash
systemctl status dnf-automatic-install.timer
```

---

## Configuring Automatic Security Updates

Edit the configuration file:

```bash
sudo vi /etc/dnf/automatic.conf
```

Update the **[commands]** section:

```ini
[commands]
upgrade_type = security
random_sleep = 0
network_online_timeout = 60

download_updates = yes
apply_updates = yes

reboot = when-needed
reboot_command = "shutdown -r +5 'Rebooting after applying package updates'"
```

### Configuration Explanation

| Parameter | Description |
|-----------|-------------|
| `upgrade_type=security` | Only installs packages associated with security advisories. |
| `download_updates=yes` | Downloads available updates automatically. |
| `apply_updates=yes` | Installs updates without user interaction. |
| `reboot=when-needed` | Reboots only when an installed package requires it, such as a new kernel. |
| `reboot_command` | Schedules a reboot five minutes after updates complete. |
| `random_sleep=0` | Disables the default randomized delay before checking for updates. |

---

## Scheduling Automatic Updates

By default, `dnf-automatic-install.timer` executes daily.

To change the schedule, create a systemd override:

```bash
sudo systemctl edit dnf-automatic-install.timer
```

Add the following:

```ini
[Timer]
OnCalendar=
OnCalendar=*-*-1/3 03:00:00
RandomizedDelaySec=0
Persistent=true
```

### Explanation

The empty `OnCalendar=` line clears the default schedule defined by the packaged timer.

The new schedule:

```text
*-*-1/3 03:00:00
```

means:

- Every **3 days**
- Starting on the **1st day of the month**
- At **03:00 AM**

Setting:

```ini
RandomizedDelaySec=0
```

ensures the timer executes exactly at the configured time.

Reload systemd:

```bash
sudo systemctl daemon-reload
sudo systemctl restart dnf-automatic-install.timer
```

---

## Verifying the Configuration

Display the effective timer configuration:

```bash
systemctl cat dnf-automatic-install.timer
```

Expected output:

```ini
# /etc/systemd/system/dnf-automatic-install.timer.d/override.conf

[Timer]
OnCalendar=
OnCalendar=*-*-1/3 03:00:00
RandomizedDelaySec=0
Persistent=true
```

Verify the next scheduled execution:

```bash
systemctl list-timers dnf-automatic-install.timer
```

Example:

```text
NEXT                        LEFT
Tue 2026-08-04 03:00:00 CST 1 day 12h left
```

---

## Testing the Configuration

Trigger an update manually:

```bash
sudo systemctl start dnf-automatic-install.service
```

Monitor its progress:

```bash
systemctl status dnf-automatic-install.service
```

A successful execution should end with:

```text
Updates completed
```

---

## Verifying Kernel Updates

List installed kernels:

```bash
rpm -q kernel
```

Example:

```text
kernel-5.14.0-687.17.1.el9_8.x86_64
kernel-5.14.0-687.30.1.el9_8.x86_64
kernel-5.14.0-687.33.1.el9_8.x86_64
```

Display the currently running kernel:

```bash
uname -r
```

Example:

```text
5.14.0-687.30.1.el9_8.x86_64
```

If a newer kernel has been installed, the configured reboot will boot into the latest version.

---

## Confirming the Scheduled Reboot

When a reboot is required, users receive a broadcast message similar to:

```text
Broadcast message from root@hostname

Rebooting after applying package updates

The system will reboot at Sun Aug 2 14:35:51 CST.
```

After the reboot completes, verify the running kernel:

```bash
uname -r
```

It should match the newest installed kernel.

---

## Troubleshooting

### Timer Override Not Being Used

Verify the override file is loaded:

```bash
systemctl cat dnf-automatic-install.timer
```

The output should include:

```text
/etc/systemd/system/dnf-automatic-install.timer.d/override.conf
```

If it does not, recreate the override and reload systemd.

---

### Updates Are Installed but the System Does Not Reboot

Verify the following configuration:

```ini
reboot = when-needed
```

A reboot only occurs when one of the installed packages requires it, such as a kernel update.

---

### Viewing Previous Executions

Display service logs:

```bash
journalctl -u dnf-automatic-install.service
```

If persistent journaling is not enabled, only logs from the current boot are available.

---

## Final Configuration

### `/etc/dnf/automatic.conf`

```ini
[commands]
upgrade_type = security
random_sleep = 0
network_online_timeout = 60

download_updates = yes
apply_updates = yes

reboot = when-needed
reboot_command = "shutdown -r +5 'Rebooting after applying package updates'"
```

### `/etc/systemd/system/dnf-automatic-install.timer.d/override.conf`

```ini
[Timer]
OnCalendar=
OnCalendar=*-*-1/3 03:00:00
RandomizedDelaySec=0
Persistent=true
```

---

## Why Use `dnf-automatic-install.timer`?

DNF provides several timers, each designed for a different purpose:

| Timer | Behavior |
|-------|----------|
| `dnf-automatic.timer` | Uses the behavior configured in `automatic.conf`. |
| `dnf-automatic-download.timer` | Downloads updates only. |
| `dnf-automatic-install.timer` | Downloads and installs updates. |
| `dnf-automatic-notifyonly.timer` | Checks for updates and sends notifications without downloading or installing. |

Since this configuration is intended to install security updates automatically, `dnf-automatic-install.timer` is the most appropriate choice.

---

## References

- Red Hat Enterprise Linux Documentation
- `man dnf-automatic`
- `man systemd.timer`
