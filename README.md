# Linux Process Monitor

An educational Python project for learning Linux process monitoring and basic defensive security investigation.

## Features in v1.0

- Detects processes that appear after the monitor starts.
- Records process name, PID, parent PID, username, executable path, and command line when permitted.
- Flags CPU usage above a configurable threshold.
- Flags executable paths under `/tmp/`, `/var/tmp/`, and `/dev/shm/` for review.
- Writes events to the terminal and `process_monitor.log`.

> **Important:** This is a learning tool, not a complete endpoint detection system. Alerts are indicators for investigation, not proof of malware. High CPU usage and executable locations can be legitimate. The monitor does not yet analyze network connections, privilege changes, or persistence mechanisms.

## Requirements

- Linux (tested conceptually for Kali Linux and other distributions)
- Python 3
- `psutil`

## Install

On Kali Linux / Debian:

```bash
sudo apt update
sudo apt install python3-psutil
```

Alternatively, install with pip in a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Run

```bash
python3 process_monitor.py
```

Press `Ctrl+C` to stop.

The monitor creates `process_monitor.log` in the current directory. **Do not publish logs** if they contain personal or system-specific information.

## Investigating an alert

For a PID reported by the monitor, inspect it with:

```bash
ps -fp PID
pstree -aps PID
readlink -f /proc/PID/exe
```

Replace `PID` with the actual process ID. A process can exit before it is inspected, and Linux permissions may restrict access to details.

## Roadmap

1. Process identity and parent-child relationships.
2. Command-line and executable analysis with false-positive considerations.
3. Process-associated network connections.
4. Persistence checks (cron and systemd).
5. Security report with event severity and context.

## Scope and safety

Use this tool only on systems you own or are authorized to monitor. It is read-only: it does not kill processes, change system settings, or attempt to remediate alerts.
