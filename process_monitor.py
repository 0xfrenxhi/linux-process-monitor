#!/usr/bin/env python3
"""Educational Linux process monitor for defensive learning."""

import logging
import time
from datetime import datetime
from pathlib import Path

import psutil

INTERVAL_SECONDS = 3
CPU_ALERT_THRESHOLD = 80.0
STATUS_INTERVAL_SECONDS = 10
LOG_PATH = Path("process_monitor.log")

# Directories worth reviewing when an executable is launched from them.
UNUSUAL_EXECUTABLE_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")


def configure_logging():
    """Write events to a log file and display them in the terminal."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(LOG_PATH, encoding="utf-8"),
        ],
    )


def process_identity(proc):
    """Return PID plus creation time to reduce confusion from reused PIDs."""
    try:
        return (proc.pid, proc.create_time())
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def describe_process(proc):
    """Return useful process details, where permissions allow."""
    details = {}
    try:
        details["pid"] = proc.pid
        details["name"] = proc.name()
        details["ppid"] = proc.ppid()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

    for key, getter in (
        ("user", proc.username),
        ("executable", proc.exe),
        ("command", proc.cmdline),
    ):
        try:
            value = getter()
            details[key] = " ".join(value) if key == "command" else value
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            details[key] = "unavailable"

    return details


def inspect_new_process(proc):
    details = describe_process(proc)
    if not details:
        return

    logging.info(
        "NEW PROCESS | PID=%s | Name=%s | User=%s | PPID=%s",
        details["pid"], details["name"], details["user"], details["ppid"],
    )
    logging.info("PROCESS DETAILS | PID=%s | Executable=%s",
                 details["pid"], details["executable"])
    logging.info("PROCESS COMMAND | PID=%s | Command=%s",
                 details["pid"], details["command"])

    executable = details["executable"]
    if executable != "unavailable" and executable.startswith(UNUSUAL_EXECUTABLE_DIRS):
        logging.warning(
            "REVIEW EXECUTABLE LOCATION | PID=%s | Path=%s",
            details["pid"], executable,
        )


def monitor():
    logging.info("Process monitor started.")
    logging.info("Press Ctrl+C to stop. Checking every %s seconds.",
                 INTERVAL_SECONDS)
    logging.info("Log file: %s", LOG_PATH.resolve())

    # Take a baseline so processes that were already running are not reported
    # as new at startup.
    known = {}
    cpu_processes = {}

    for proc in psutil.process_iter():
        identity = process_identity(proc)
        if identity is not None:
            known[identity] = proc
            try:
                proc.cpu_percent(interval=None)  # Prime CPU measurement.
                cpu_processes[identity] = proc
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    last_status = 0.0

    while True:
        current = {}

        for proc in psutil.process_iter():
            identity = process_identity(proc)
            if identity is None:
                continue
            current[identity] = proc

            if identity not in known:
                inspect_new_process(proc)
                try:
                    proc.cpu_percent(interval=None)
                    cpu_processes[identity] = proc
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

        # Check CPU using samples from successive polling intervals.
        for identity, proc in list(current.items()):
            try:
                cpu = proc.cpu_percent(interval=None)
                if cpu > CPU_ALERT_THRESHOLD:
                    logging.warning(
                        "HIGH CPU | PID=%s | Name=%s | CPU=%.1f%%",
                        proc.pid, proc.name(), cpu,
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        known = current

        now = time.monotonic()
        if now - last_status >= STATUS_INTERVAL_SECONDS:
            logging.info("STATUS | Running processes: %s", len(current))
            last_status = now

        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    configure_logging()
    try:
        monitor()
    except KeyboardInterrupt:
        logging.info("Process monitor stopped by user.")
