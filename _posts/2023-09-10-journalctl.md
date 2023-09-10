---
title: Journal in Linux
permalink: prefabs/
date: 2023-09-10 -500
lastmod: 2023-09-10 -500
---
---

The `journalctl` command is used to query and view logs from the systemd journal, which is a centralized logging system used by most modern Linux distributions. It provides a structured and comprehensive way to access system logs, including kernel messages, service logs, and other system events.

#### Basic Usage:

You can use `journalctl` with various options to filter and display logs in different ways. Here are some common use cases:

### View All Logs
To view all available logs, simply run:
```sh
$ journalctl
```

### Filter by Unit (Service)
To view logs related to a specific service, use the `-u` or `--unit` option followed by the service name. For example:
```sh
$ journalctl -u sshd
$ journalctl -u apache
```

### Filter by Time
You can specify a time range to view logs from a specific time interval. For example, to view logs from the last hour:
```sh
$ journalctl --since "1 hour ago"
$ journalctl -S "yesterday"
$ journalctl -S "2 hours ago" -U "now"
```

### Real-Time Logging
To continuously monitor and display logs in real-time, use the `-f` or `--follow` option:
```sh
$ journalctl -f
```

### View logs with a specific priority level
Use the `-p` option to filter logs by priority level. For example, to view only error and critical messages:
```sh
journalctl -p err -p crit
```

### View logs for a specific user
You can filter logs for a specific user using the `_UID` field. Replace username with the username you want to filter for.
```sh
$ journalctl _UID=$(id -u username)
```

### View logs for a specific process ID (PID)
To view logs for a specific process ID, use the `_PID` field. Replace pid with the process ID you're interested in.
```sh
$ journalctl _PID=pid
```

### View logs with specific fields and in a custom format
You can use the `--output` option to specify the desired output format. For example, to display logs in JSON format:
```sh
$ journalctl --output=json
$ journalctl --output=json-pretty
$ journalctl --output=verbose
```






```sh
$ 
```