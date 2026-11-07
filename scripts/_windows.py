"""Measure native full CLI subprocesses with captured bytes and live Windows RSS.

PeakWorkingSetSize is sampled with requested 1ms waits while the child is alive;
the maximum OS high-water value observed is reported, not commit/private bytes.
Very late allocations can be missed; launcher-only queries miss the interpreter.
"""

import ctypes as C
import hashlib
import os
import platform
import subprocess
import sys
import threading
import time
import winreg
from ctypes import wintypes as W
from datetime import UTC, datetime
from pathlib import Path

root = Path(__file__).resolve().parents[1]
evidence = Path(__file__).resolve().parent


class Counters(C.Structure):
    _fields_ = [("cb", W.DWORD), ("PageFaultCount", W.DWORD)] + [
        (key, C.c_size_t)
        for key in (
            "PeakWorkingSetSize",
            "WorkingSetSize",
            "QuotaPeakPagedPoolUsage",
            "QuotaPagedPoolUsage",
            "QuotaPeakNonPagedPoolUsage",
            "QuotaNonPagedPoolUsage",
            "PagefileUsage",
            "PeakPagefileUsage",
        )
    ]


psapi = C.WinDLL("psapi", use_last_error=True)
kernel = C.WinDLL("kernel32", use_last_error=True)
psapi.GetProcessMemoryInfo.argtypes = [W.HANDLE, C.POINTER(Counters), W.DWORD]
psapi.GetProcessMemoryInfo.restype = W.BOOL
kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
kernel.OpenProcess.restype = W.HANDLE
kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
kernel.WaitForSingleObject.restype = W.DWORD
kernel.CloseHandle.argtypes = [W.HANDLE]
kernel.CloseHandle.restype = W.BOOL


class ProcessEntry(C.Structure):
    _fields_ = [
        ("dwSize", W.DWORD),
        ("cntUsage", W.DWORD),
        ("pid", W.DWORD),
        ("heap", C.c_size_t),
        ("module", W.DWORD),
        ("threads", W.DWORD),
        ("parent", W.DWORD),
        ("priority", W.LONG),
        ("flags", W.DWORD),
        ("exe", W.WCHAR * 260),
    ]


kernel.CreateToolhelp32Snapshot.argtypes = [W.DWORD, W.DWORD]
kernel.CreateToolhelp32Snapshot.restype = W.HANDLE
kernel.Process32FirstW.argtypes = [W.HANDLE, C.POINTER(ProcessEntry)]
kernel.Process32FirstW.restype = W.BOOL
kernel.Process32NextW.argtypes = [W.HANDLE, C.POINTER(ProcessEntry)]
kernel.Process32NextW.restype = W.BOOL


def children(known):
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
    if snapshot == C.c_void_p(-1).value:
        raise C.WinError(C.get_last_error())
    try:
        entry = ProcessEntry()
        entry.dwSize = C.sizeof(entry)
        parents = {}
        good = kernel.Process32FirstW(snapshot, C.byref(entry))
        while good:
            parents[entry.pid] = entry.parent
            good = kernel.Process32NextW(snapshot, C.byref(entry))
        descendants = set(known)
        while True:
            found = {pid for pid, parent in parents.items() if parent in descendants}
            if found <= descendants:
                break
            descendants.update(found)
        return descendants - set(known)
    finally:
        kernel.CloseHandle(snapshot)


def measure(command):
    wall_started = datetime.now(UTC).isoformat()
    started = time.perf_counter()
    process = subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    handle = kernel.OpenProcess(0x0400 | 0x0010 | 0x00100000, False, process.pid)
    if not handle:
        process.kill()
        process.communicate()
        raise C.WinError(C.get_last_error())
    memory = {"peak_rss_bytes": 0, "rss_samples": 0, "process_tree_peak_rss_bytes": 0}
    handles = {process.pid: handle}
    peaks = {process.pid: 0}
    failures = []

    def observe():
        try:
            next_discovery = 0.0
            while True:
                if time.perf_counter() >= next_discovery:
                    for pid in children(handles):
                        child_handle = kernel.OpenProcess(0x0400 | 0x0010 | 0x00100000, False, pid)
                        if child_handle:
                            handles[pid], peaks[pid] = child_handle, 0
                    next_discovery = time.perf_counter() + 0.02
                current_rss = 0
                for pid, live_handle in handles.items():
                    value = Counters()
                    value.cb = C.sizeof(value)
                    if psapi.GetProcessMemoryInfo(live_handle, C.byref(value), C.sizeof(value)):
                        peaks[pid] = max(peaks[pid], value.PeakWorkingSetSize)
                        current_rss += value.WorkingSetSize
                        memory["rss_samples"] += 1
                    elif kernel.WaitForSingleObject(live_handle, 0) != 0:
                        raise C.WinError(C.get_last_error())
                memory["peak_rss_bytes"] = max(peaks.values())
                memory["process_tree_peak_rss_bytes"] = max(
                    memory["process_tree_peak_rss_bytes"], current_rss
                )
                status = kernel.WaitForSingleObject(handle, 1)
                if status == 0:
                    break
                if status != 258:
                    raise C.WinError(C.get_last_error())
        except BaseException as error:
            failures.append(repr(error))

    monitor = threading.Thread(target=observe, daemon=True)
    monitor.start()
    try:
        stdout, stderr = process.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        failures.append("CLI subprocess exceeded 120-second timeout")
    elapsed = time.perf_counter() - started
    monitor.join(timeout=5)
    for live_handle in handles.values():
        kernel.CloseHandle(live_handle)
    assert not monitor.is_alive() and not failures and memory["rss_samples"] > 1, failures
    return (
        {
            "command": command,
            "cwd": str(root),
            "started_utc": wall_started,
            "seconds": elapsed,
            "exit_code": process.returncode,
            **memory,
            "stdout_bytes": len(stdout),
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_bytes": len(stderr),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "process_peak_rss_by_pid": peaks,
        },
        stdout,
        stderr,
    )


def environment():
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
    ) as key:
        cpu = winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
        nominal_mhz = winreg.QueryValueEx(key, "~MHz")[0]

    class MemoryStatus(C.Structure):
        _fields_ = [("length", W.DWORD), ("load_percent", W.DWORD)] + [
            (name, C.c_ulonglong)
            for name in (
                "total_physical",
                "available_physical",
                "total_pagefile",
                "available_pagefile",
                "total_virtual",
                "available_virtual",
                "extended",
            )
        ]

    memory = MemoryStatus()
    memory.length = C.sizeof(memory)
    kernel.GlobalMemoryStatusEx.argtypes = [C.POINTER(MemoryStatus)]
    kernel.GlobalMemoryStatusEx.restype = W.BOOL
    if not kernel.GlobalMemoryStatusEx(C.byref(memory)):
        raise C.WinError(C.get_last_error())
    source_hashes = {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((root / "src").rglob("*.py"))
    }
    return {
        "python": sys.version,
        "python_executable": sys.executable,
        "source_sha256": source_hashes,
        "dependency_lock_sha256": hashlib.sha256(
            (root / "requirements-dev.lock").read_bytes()
        ).hexdigest(),
        "os": platform.platform(),
        "windows_version": platform.win32_ver(),
        "machine": platform.machine(),
        "cpu": cpu,
        "logical_processors": os.cpu_count(),
        "nominal_mhz_registry": nominal_mhz,
        "physical_memory_bytes": memory.total_physical,
        "available_memory_bytes_at_start": memory.available_physical,
        "cache_limitations": (
            "First recorded launch per input/format, not a cold-cache claim; "
            "validation already touched inputs. No cache flush, affinity or exclusive-host claim."
        ),
        "timing_method": (
            "perf_counter before Popen through communicate; startup, read, analysis, render "
            "and pipe-byte capture included. Evidence hashing/persistence happens afterward."
        ),
        "rss_method": (
            "Maximum observed live OS PeakWorkingSetSize across launcher/interpreter descendants; "
            "requested 1ms waits, descendants discovered every 20ms. Also records maximum "
            "simultaneous tree WorkingSetSize. Late peaks/brief descendants may be missed; "
            "monitor overhead included; parent capture buffers excluded."
        ),
        "wmi_access": "Not queried; CPU registry and native memory API used instead",
    }
