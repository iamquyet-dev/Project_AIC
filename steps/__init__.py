"""Shared defaults for the numbered pipeline steps."""

import ctypes
import os
import sys


def available_memory_gb() -> float | None:
    if os.name != "nt":
        try:
            return os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") / 2**30
        except (AttributeError, OSError, ValueError):
            return None

    class MemoryStatus(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong),
                    ("total_phys", ctypes.c_ulonglong), ("avail_phys", ctypes.c_ulonglong),
                    ("total_page", ctypes.c_ulonglong), ("avail_page", ctypes.c_ulonglong),
                    ("total_virtual", ctypes.c_ulonglong), ("avail_virtual", ctypes.c_ulonglong),
                    ("avail_extended", ctypes.c_ulonglong)]

    status = MemoryStatus()
    status.length = ctypes.sizeof(status)
    if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return status.avail_phys / 2**30
    return None


def safe_default_workers() -> int:
    memory = available_memory_gb()
    memory_limit = max(1, int(memory // 4)) if memory is not None else 2
    return max(1, min(4, (os.cpu_count() or 2) - 1, memory_limit))


def resource_log(workers: int) -> str:
    memory = available_memory_gb()
    return f"workers={workers}; python={sys.executable}; available_ram_gb={memory:.2f}" if memory is not None else f"workers={workers}; python={sys.executable}; available_ram_gb=unknown"
