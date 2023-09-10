---
title: Analyzing perfomance in Linux
permalink: performance/
date: 2023-09-10 -500
lastmod: 2023-09-10 -500
---
---

## TOP
`top` is a command-line utility in Linux that provides a dynamic view of system processes. It displays real-time information about the system's CPU usage, memory usage, and a list of running processes. It's a powerful tool for monitoring system performance and identifying resource-intensive processes. 

### Understanding the top interface:

When you run top, you'll see a dynamic screen with various columns and information. Here are some important columns:
- `PID`: Process ID
- `USER`: Owner of the process
- `%CPU`: CPU usage percentage
- `%MEM`: Memory usage percentage
- `VSZ`: Virtual memory size in kilobytes
- `RSS`: Resident Set Size (physical memory) in kilobytes
- `TTY`: Terminal associated with the process
- `STAT`: Process status (e.g., R for running, S for sleeping)
- `TIME`: Total CPU time used by the process
- `COMMAND`: The command or program being executed

### Interacting with top
- Use the arrow keys to navigate up and down the process list.
- Press 'q' to quit top.
- Press 'k' to send a signal to a process (e.g., to kill a process, enter the process ID when prompted).
- Press 'r' to renice a process (change its priority).
- Press 'u' to filter processes by a specific user.
- Press 'M' to sort processes by memory usage.
- Press 'P' to sort processes by CPU usage.

### Filtering and Sorting
You can change the sorting order of processes by pressing the corresponding keys. For example, 'M' sorts by memory usage, and 'P' sorts by CPU usage. To filter processes by a user, press 'u' and enter the username.

### Changing Refresh Rate
By default, top updates every 3 seconds. You can change the refresh rate by pressing 'd' and entering a new time interval in seconds.

### Viewing Specific Processes
If you want to monitor a specific process or processes, you can pass their process IDs as arguments to top. For example:

```sh
$ top -p PID1,PID2
```

### Run top in Batch Mode
The "batch mode" refers to a mode of operation where top runs non-interactively and produces a single snapshot of system and process information that is suitable for saving to a file or for processing by other programs.

```sh
$ top -b
```

## PS
The `ps` (process status) command in Linux is used to display information about running processes. It provides a snapshot of the current processes running on your system. `ps` is a versatile command with various options and can be used for both basic and advanced process information retrieval. 

### Basic Usage
```sh
$ ps
```

### Display All Processes
To display information about all processes on the system (not just your own), use the `-e` option
```sh
$ ps -e
```

### Full Listing:
The `-f` option provides a full listing with more details, including parent process ID (PPID) and terminal associated with each process
```sh
$ ps -ef
```

### Display Processes in a Tree Structure
You can use the `--forest` option to display processes in a hierarchical tree structure
```sh
$ ps --forest
```

### Sort and Display Processes
You can sort processes based on various criteria using the --sort option. For example, to sort by CPU usage
```sh
$ ps --sort=-%cpu
$ ps --sort=-%mem
```
NOTE: The `-` before `%cpu` OR `%mem` sorts in descending order.

### Custom Output Format
You can customize the output format using the o option followed by a list of fields you want to display. For example, to show the process ID and command
```sh
$ ps -eo pid,cmd
```

### Display Threads
To display threads in addition to processes, you can use the `-L` option
```sh
$ ps -eL
```

### Display Processes by User
To list processes owned by a specific user, use the `-u` option followed by the username
```sh
$ ps -u username
```

### Display Real-Time Updates
Similar to top, you can use the `-e` option with ps to display real-time updates. Press 'q' to exit.
```sh
$ watch -n 1 "ps -e"
```

# vmstat
`vmstat` is a powerful command-line utility in Linux that provides detailed information about system performance, particularly in terms of virtual memory statistics. It is a valuable tool for monitoring various aspects of system resource utilization, including CPU, memory, paging, block I/O, and more. Here's how to use vmstat and interpret its output

### Basic Usage
```sh
$ vmstat [options] [delay [count]]
```

Where:
-`options`: You can specify various options to control the output of vmstat.
-`delay`: This option specifies the time interval in seconds between each set of statistics. If you omit this value, vmstat displays one set of statistics and exits.
-`count`: This option limits the number of iterations vmstat will run. If you omit this value, vmstat runs indefinitely at the specified interval.

### Basic vmstat Output
This command will display system statistics every 3 seconds for a total of 5 iterations. The output will include columns for processes, memory, swap, I/O, system, and CPU statistics
```sh
$ vmstat 3 5
```

### View Memory Usage
This command displays detailed memory statistics, including the number of pages used for different purposes, such as file cache, buffer cache, and swap space.
```sh
$ vmstat -s
```

### Monitor Disk I/O 
This command shows disk I/O statistics, including the number of blocks read from and written to disk every 2 seconds for 5 iterations. It can help you identify disk bottlenecks.
```sh
$ vmstat -d 2 5
```

### Monitor Swap Activity
This command shows swap statistics in megabytes, displaying the amount of data swapped in and out of swap space every 3 seconds for 5 iterations.
```sh
$ vmstat -S M 3 5
```
