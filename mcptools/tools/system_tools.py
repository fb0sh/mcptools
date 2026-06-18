"""
系统工具 - 系统信息、UUID 生成、数学计算等
"""

from __future__ import annotations

import os
import platform
import uuid

from mcptools.registry import tool


@tool(name="system_info", description="获取系统基本信息")
def system_info() -> str:
    """获取系统信息"""
    import psutil  # optional

    info = {
        "Platform": platform.platform(),
        "System": platform.system(),
        "Release": platform.release(),
        "Version": platform.version(),
        "Machine": platform.machine(),
        "Processor": platform.processor(),
        "Hostname": platform.node(),
        "CPU Count": str(os.cpu_count() or 0),
        "CWD": os.getcwd(),
        "PID": str(os.getpid()),
    }

    # Try to get memory info via psutil (optional dep)
    try:
        mem = psutil.virtual_memory()
        info["Memory Total"] = f"{mem.total / 1024**3:.1f} GB"
        info["Memory Available"] = f"{mem.available / 1024**3:.1f} GB"
        info["Memory Used"] = f"{mem.used / 1024**3:.1f} GB ({mem.percent}%)"
    except ImportError:
        pass

    return "\n".join(f"{k}: {v}" for k, v in info.items())
