"""
nmap 工具 - 调用系统 nmap 执行网络扫描
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
import xml.etree.ElementTree as ET

from mcptools.registry import tool

# ── 路径 ──────────────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT = os.path.dirname(os.path.dirname(_HERE))
_NMAP_HELP = os.path.join(_PROJECT, "nmap.help")
_RESULTS_DIR = os.path.join(_PROJECT, "nmap_results")


def _ensure_results_dir() -> str:
    os.makedirs(_RESULTS_DIR, exist_ok=True)
    return _RESULTS_DIR


def _run_nmap(args: list[str], timeout: int = 300) -> str:
    """执行 nmap 命令，返回 stdout + stderr。"""
    cmd = ["nmap"] + args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = r.stdout
        if r.stderr:
            out += "\n[stderr]\n" + r.stderr
        if r.returncode != 0:
            out += f"\n[exit code: {r.returncode}]"
        return out
    except subprocess.TimeoutExpired:
        return f"Error: nmap timed out after {timeout}s"
    except FileNotFoundError:
        return "Error: nmap not found. Install with: brew install nmap"
    except Exception as e:
        return f"Error: {e}"


def _run_nmap_sudo(args: list[str], timeout: int = 300) -> str:
    """用 sudo 执行 nmap。"""
    cmd = ["sudo", "nmap"] + args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = r.stdout
        if r.stderr:
            out += "\n[stderr]\n" + r.stderr
        if r.returncode != 0:
            out += f"\n[exit code: {r.returncode}]"
        return out
    except subprocess.TimeoutExpired:
        return f"Error: nmap timed out after {timeout}s"
    except FileNotFoundError:
        return "Error: nmap not found"
    except Exception as e:
        return f"Error: {e}"


def _parse_xml_output(xml_path: str) -> dict:
    """解析 nmap XML 输出为 Python dict。"""
    tree = ET.parse(xml_path)
    root = tree.getroot()

    result = {
        "scan_info": {
            "nmap_version": root.get("version", ""),
            "args": root.get("args", ""),
            "start_time": root.get("start", ""),
            "start_str": root.get("startstr", ""),
        },
        "hosts": [],
    }

    for host in root.findall("host"):
        host_info: dict = {"status": {}, "addresses": [], "ports": [], "os": []}

        status = host.find("status")
        if status is not None:
            host_info["status"] = {
                "state": status.get("state"),
                "reason": status.get("reason"),
            }

        for addr in host.findall("address"):
            host_info["addresses"].append({
                "addr": addr.get("addr"),
                "addrtype": addr.get("addrtype"),
                "vendor": addr.get("vendor", ""),
            })

        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                port_info = {
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "state": None,
                    "service": None,
                }
                state = port.find("state")
                if state is not None:
                    port_info["state"] = state.get("state")
                service = port.find("service")
                if service is not None:
                    port_info["service"] = {
                        "name": service.get("name", ""),
                        "product": service.get("product", ""),
                        "version": service.get("version", ""),
                        "extrainfo": service.get("extrainfo", ""),
                    }
                host_info["ports"].append(port_info)

        os_elem = host.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                host_info["os"].append({
                    "name": osmatch.get("name"),
                    "accuracy": osmatch.get("accuracy"),
                })

        result["hosts"].append(host_info)

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# 1. 通用扫描
# ═══════════════════════════════════════════════════════════════════════════════


@tool(
    name="nmap_scan",
    description="执行 nmap 扫描，支持任意 nmap 参数",
)
def nmap_scan(
    target: str,
    options: str = "",
    timeout: int = 300,
    sudo: bool = False,
) -> str:
    """执行 nmap 扫描

    Args:
        target: 扫描目标（IP、域名、CIDR）
        options: nmap 选项（如 "-sV -p 22,80,443 -T4"）
        timeout: 超时秒数（默认 300）
        sudo: 是否用 sudo 执行

    Returns:
        扫描结果文本
    """
    args = options.split() if options else []
    args.append(target)
    if sudo:
        return _run_nmap_sudo(args, timeout)
    return _run_nmap(args, timeout)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. 快速扫描
# ═══════════════════════════════════════════════════════════════════════════════


@tool(
    name="nmap_quick_scan",
    description="快速扫描常用端口（Top 1000 端口）",
)
def nmap_quick_scan(
    target: str,
    sudo: bool = False,
    timeout: int = 180,
) -> str:
    """快速扫描目标常用端口

    Args:
        target: 扫描目标
        sudo: 是否用 sudo
        timeout: 超时秒数

    Returns:
        扫描结果
    """
    return nmap_scan(
        target=target,
        options="-T4 --top-ports 1000 --open",
        timeout=timeout,
        sudo=sudo,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 3. 服务版本探测
# ═══════════════════════════════════════════════════════════════════════════════


@tool(
    name="nmap_service_scan",
    description="扫描端口并探测服务版本（-sV）",
)
def nmap_service_scan(
    target: str,
    ports: str = "22,80,443,8080,3306,5432,6379,27017",
    sudo: bool = False,
    timeout: int = 300,
) -> str:
    """扫描指定端口并探测服务/版本信息

    Args:
        target: 扫描目标
        ports: 端口列表（如 "22,80,443" 或 "1-1000"）
        sudo: 是否用 sudo
        timeout: 超时秒数

    Returns:
        扫描结果
    """
    return nmap_scan(
        target=target,
        options=f"-sV -p {ports} -T4",
        timeout=timeout,
        sudo=sudo,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 4. OS 检测
# ═══════════════════════════════════════════════════════════════════════════════


@tool(
    name="nmap_os_detection",
    description="操作系统检测扫描（-O）",
)
def nmap_os_detection(
    target: str,
    sudo: bool = True,
    timeout: int = 300,
) -> str:
    """检测目标操作系统

    Args:
        target: 扫描目标
        sudo: 是否用 sudo（OS 检测需要 raw packet）
        timeout: 超时秒数

    Returns:
        扫描结果
    """
    return nmap_scan(
        target=target,
        options="-O -T4",
        timeout=timeout,
        sudo=sudo,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 5. 综合扫描
# ═══════════════════════════════════════════════════════════════════════════════


@tool(
    name="nmap_comprehensive",
    description="综合扫描：端口 + 服务版本 + OS + 默认脚本（-A）",
)
def nmap_comprehensive(
    target: str,
    sudo: bool = True,
    timeout: int = 600,
) -> str:
    """综合扫描目标

    Args:
        target: 扫描目标
        sudo: 是否用 sudo
        timeout: 超时秒数

    Returns:
        扫描结果
    """
    return nmap_scan(
        target=target,
        options="-A -T4",
        timeout=timeout,
        sudo=sudo,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Ping 扫描
# ═══════════════════════════════════════════════════════════════════════════════


@tool(
    name="nmap_ping_scan",
    description="Ping 扫描（-sn），发现局域网在线主机",
)
def nmap_ping_scan(
    target: str = "192.168.1.0/24",
    timeout: int = 120,
) -> str:
    """Ping 扫描发现在线主机

    Args:
        target: 目标网段（默认 192.168.1.0/24）
        timeout: 超时秒数

    Returns:
        在线主机列表
    """
    return nmap_scan(
        target=target,
        options="-sn -T4",
        timeout=timeout,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 7. NSE 脚本扫描
# ═══════════════════════════════════════════════════════════════════════════════


@tool(
    name="nmap_script_scan",
    description="使用 NSE 脚本扫描（如 --script=vuln,default）",
)
def nmap_script_scan(
    target: str,
    scripts: str = "default",
    ports: str = "",
    sudo: bool = False,
    timeout: int = 600,
) -> str:
    """使用 NSE 脚本扫描

    Args:
        target: 扫描目标
        scripts: 脚本类别或脚本名（如 "default", "vuln", "safe", "http-title"）
        ports: 端口（可选，默认扫描所有端口）
        sudo: 是否用 sudo
        timeout: 超时秒数

    Returns:
        扫描结果
    """
    opts = f"--script={scripts} -T4"
    if ports:
        opts += f" -p {ports}"
    return nmap_scan(
        target=target,
        options=opts,
        timeout=timeout,
        sudo=sudo,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 8. 帮助查询
# ═══════════════════════════════════════════════════════════════════════════════


@tool(
    name="nmap_help_lookup",
    description="从本地 nmap.help 文件中查询 nmap 用法说明",
)
def nmap_help_lookup(keyword: str) -> str:
    """在 nmap.help 中搜索关键词

    Args:
        keyword: 搜索关键词（如 "SYN scan", "OS detection", "-sV"）

    Returns:
        匹配的帮助段落
    """
    if not os.path.exists(_NMAP_HELP):
        return (
            "nmap.help 文件不存在。请先用 nmap_help 工具生成。\n"
            "或者直接运行: man nmap | col -b > nmap.help"
        )

    with open(_NMAP_HELP, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    kw_lower = keyword.lower()
    lines = content.split("\n")
    matched = []
    i = 0
    while i < len(lines):
        if kw_lower in lines[i].lower():
            start = max(0, i - 2)
            end = min(len(lines), i + 8)
            block = "\n".join(lines[start:end])
            matched.append(f"... (line {start + 1}) ...\n{block}")
            i = end
        else:
            i += 1

    if matched:
        return "\n\n---\n\n".join(matched[:10])
    else:
        return f"在 nmap.help 中未找到「{keyword}」"


# ═══════════════════════════════════════════════════════════════════════════════
# 9. UDP 扫描
# ═══════════════════════════════════════════════════════════════════════════════


@tool(
    name="nmap_udp_scan",
    description="UDP 端口扫描（-sU），探测 UDP 服务",
)
def nmap_udp_scan(
    target: str,
    ports: str = "53,67,68,123,137,161,162,500,514,520,1900,5353",
    sudo: bool = True,
    timeout: int = 600,
) -> str:
    """UDP 端口扫描

    UDP 扫描比 TCP 慢得多，建议只扫常用端口。
    常用 UDP 端口：53(DNS), 67/68(DHCP), 123(NTP), 137(NetBIOS),
    161/162(SNMP), 500(IKE), 514(syslog), 520(RIP), 1900(UPnP), 5353(mDNS)

    Args:
        target: 扫描目标
        ports: UDP 端口列表（默认常用 UDP 端口）
        sudo: 是否用 sudo（UDP 扫描需要 raw packet）
        timeout: 超时秒数（默认 600）

    Returns:
        扫描结果
    """
    return nmap_scan(
        target=target,
        options=f"-sU -p {ports} -T4",
        timeout=timeout,
        sudo=sudo,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 10. 写入 → check → 再写入
# ═══════════════════════════════════════════════════════════════════════════════


@tool(
    name="nmap_scan_to_file",
    description="扫描结果写入文件 → 读取验证 → 再追加（写入→check→再写入）",
)
def nmap_scan_to_file(
    target: str,
    options: str = "-T4 --open",
    label: str = "",
    sudo: bool = False,
    timeout: int = 300,
) -> str:
    """扫描结果写入文件，读取验证，再追加更多信息

    流程：
      1. 执行 nmap 扫描
      2. 将结果写入 nmap_results/<target>_<label>.txt
      3. 读取文件验证（check）
      4. 追加 XML 格式结果到同一文件

    Args:
        target: 扫描目标
        options: nmap 选项
        label: 文件标签（可选，默认用时间戳）
        sudo: 是否用 sudo
        timeout: 超时秒数

    Returns:
        操作日志
    """
    logs: list[str] = []
    results_dir = _ensure_results_dir()
    ts = time.strftime("%Y%m%d_%H%M%S")
    label_part = f"_{label}" if label else ""
    safe_target = target.replace("/", "_").replace(":", "_")
    base_name = f"{safe_target}{label_part}_{ts}"
    txt_path = os.path.join(results_dir, f"{base_name}.txt")
    xml_path = os.path.join(results_dir, f"{base_name}.xml")

    # ── 1. 写入（普通文本） ──────────────────────────────────────────────────
    args = options.split() if options else []
    args.extend([target])
    if sudo:
        raw = _run_nmap_sudo(args, timeout)
    else:
        raw = _run_nmap(args, timeout)

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(f"# nmap scan: {target}\n")
        f.write(f"# options: {options}\n")
        f.write(f"# time: {ts}\n\n")
        f.write(raw)
        f.write("\n")

    logs.append(f"[1/3] ✅ 写入 {txt_path}（{len(raw)} 字符）")

    # ── 2. check ─────────────────────────────────────────────────────────────
    with open(txt_path, "r", encoding="utf-8") as f:
        content = f.read()
    lines = content.count("\n")
    logs.append(f"[2/3] 🔍 check → {lines} 行, {len(content)} 字符")

    # ── 3. 再写入（追加 XML 格式） ──────────────────────────────────────────
    xml_args = options.split() if options else []
    xml_args.extend(["-oX", xml_path, target])
    if sudo:
        _run_nmap_sudo(xml_args, timeout)
    else:
        _run_nmap(xml_args, timeout)

    if os.path.exists(xml_path):
        parsed = _parse_xml_output(xml_path)
        with open(txt_path, "a", encoding="utf-8") as f:
            f.write("\n\n" + "=" * 60 + "\n")
            f.write("# 结构化结果 (XML 解析)\n")
            f.write("=" * 60 + "\n\n")
            f.write(json.dumps(parsed, indent=2, ensure_ascii=False))
            f.write("\n")
        logs.append(f"[3/3] ✅ 追加结构化结果 ({len(json.dumps(parsed))} 字符)")
    else:
        logs.append(f"[3/3] ⚠️  XML 文件未生成，跳过追加")

    return "\n".join(logs)


# ═══════════════════════════════════════════════════════════════════════════════
# 11. 防火墙规避扫描
# ═══════════════════════════════════════════════════════════════════════════════


@tool(
    name="nmap_firewall_evasion",
    description="防火墙/IDS 规避扫描（分片、诱饵、代理、MAC 伪造等）",
)
def nmap_firewall_evasion(
    target: str,
    technique: str = "fragment",
    decoy_count: int = 3,
    proxy: str = "",
    spoof_mac: str = "",
    source_port: int = 0,
    sudo: bool = True,
    timeout: int = 300,
) -> str:
    """防火墙/IDS 规避扫描

    Args:
        target: 扫描目标
        technique: 规避技术
            - "fragment": IP 分片 (-f)
            - "decoy": 诱饵扫描 (-D)
            - "proxy": HTTP/SOCKS4 代理 (--proxies)
            - "spoof_mac": MAC 地址伪造 (--spoof-mac)
            - "source_port": 指定源端口 (-g)
            - "badsum": 错误校验和 (--badsum)
            - "ttl": 自定义 TTL (--ttl)
            - "all": 组合多种技术
        decoy_count: 诱饵数量（仅 decoy 模式）
        proxy: 代理 URL（仅 proxy 模式，如 "http://127.0.0.1:8080"）
        spoof_mac: 伪造的 MAC（仅 spoof_mac 模式，如 "00:11:22:33:44:55"）
        source_port: 源端口（仅 source_port 模式）
        sudo: 是否用 sudo
        timeout: 超时秒数

    Returns:
        扫描结果
    """
    opts = "-T4 --open"

    if technique == "fragment":
        opts += " -f"
    elif technique == "decoy":
        decoys = ",".join([f"192.168.1.{100 + i}" for i in range(decoy_count)])
        opts += f" -D {decoys},ME"
    elif technique == "proxy":
        if not proxy:
            return "Error: proxy 模式需要提供 proxy 参数（如 http://127.0.0.1:8080）"
        opts += f" --proxies {proxy}"
    elif technique == "spoof_mac":
        if not spoof_mac:
            spoof_mac = "00:11:22:33:44:55"
        opts += f" --spoof-mac {spoof_mac}"
    elif technique == "source_port":
        port = source_port or 53
        opts += f" -g {port}"
    elif technique == "badsum":
        opts += " --badsum"
    elif technique == "ttl":
        opts += " --ttl 128"
    elif technique == "all":
        opts += " -f -D RND:5,ME --ttl 128"
    else:
        return f"Error: 未知规避技术 '{technique}'"

    return nmap_scan(
        target=target,
        options=opts,
        timeout=timeout,
        sudo=sudo,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 12. NSE 脚本管理
# ═══════════════════════════════════════════════════════════════════════════════


@tool(
    name="nmap_script_list",
    description="列出 NSE 脚本（按类别筛选）",
)
def nmap_script_list(
    category: str = "",
    search: str = "",
) -> str:
    """列出可用的 NSE 脚本

    Args:
        category: 脚本类别筛选（如 "safe", "vuln", "discovery", "default"）
                  留空列出所有类别
        search: 脚本名关键词搜索

    Returns:
        脚本列表
    """
    args = ["--script-help", "default"]
    result = _run_nmap(args, timeout=30)

    # 如果指定了 category，用 --script-help <category>
    if category:
        args = ["--script-help", category]
        result = _run_nmap(args, timeout=30)

    # 如果指定了 search 关键词，过滤结果
    if search:
        lines = result.split("\n")
        filtered = [l for l in lines if search.lower() in l.lower()]
        if filtered:
            result = f"找到 {len(filtered)} 个匹配 '{search}' 的脚本:\n\n"
            result += "\n".join(filtered[:50])
            if len(filtered) > 50:
                result += f"\n... 还有 {len(filtered) - 50} 个"
        else:
            result = f"未找到匹配 '{search}' 的脚本"

    return result


@tool(
    name="nmap_script_help",
    description="查看 NSE 脚本的详细帮助",
)
def nmap_script_help(
    script_name: str,
) -> str:
    """查看 NSE 脚本的详细帮助

    Args:
        script_name: 脚本名（如 "http-title", "ssh2-enum-algos"）

    Returns:
        脚本帮助信息
    """
    args = ["--script-help", script_name]
    return _run_nmap(args, timeout=30)


# ═══════════════════════════════════════════════════════════════════════════════
# 13. Traceroute
# ═══════════════════════════════════════════════════════════════════════════════


@tool(
    name="nmap_traceroute",
    description="路由追踪（--traceroute）",
)
def nmap_traceroute(
    target: str,
    sudo: bool = True,
    timeout: int = 300,
) -> str:
    """追踪到目标的路由路径

    Args:
        target: 目标 IP 或域名
        sudo: 是否用 sudo（traceroute 需要 raw packet）
        timeout: 超时秒数

    Returns:
        路由追踪结果
    """
    return nmap_scan(
        target=target,
        options="--traceroute -T4",
        timeout=timeout,
        sudo=sudo,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 14. 扫描结果对比
# ═══════════════════════════════════════════════════════════════════════════════


@tool(
    name="nmap_scan_diff",
    description="对比两次扫描结果的端口变化",
)
def nmap_scan_diff(
    target: str,
    options: str = "-T4 --open",
    sudo: bool = False,
    timeout: int = 300,
) -> str:
    """对同一目标执行两次扫描并对比端口变化

    流程：
      1. 第一次扫描 → 保存
      2. 等待 3 秒
      3. 第二次扫描 → 保存
      4. 对比两次结果的端口差异

    Args:
        target: 扫描目标
        options: nmap 选项
        sudo: 是否用 sudo
        timeout: 超时秒数

    Returns:
        两次扫描的端口对比
    """
    logs: list[str] = []
    results_dir = _ensure_results_dir()
    ts = time.strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_")

    # ── 第一次扫描 ──────────────────────────────────────────────────────────
    logs.append("📡 第一次扫描...")
    args = options.split() if options else []
    args.extend(["-oX", os.path.join(results_dir, f"{safe_target}_scan1_{ts}.xml"), target])
    if sudo:
        _run_nmap_sudo(args, timeout)
    else:
        _run_nmap(args, timeout)

    # ── 第二次扫描 ──────────────────────────────────────────────────────────
    logs.append("⏳ 等待 3 秒...")
    time.sleep(3)
    logs.append("📡 第二次扫描...")
    args2 = options.split() if options else []
    args2.extend(["-oX", os.path.join(results_dir, f"{safe_target}_scan2_{ts}.xml"), target])
    if sudo:
        _run_nmap_sudo(args2, timeout)
    else:
        _run_nmap(args2, timeout)

    # ── 解析对比 ────────────────────────────────────────────────────────────
    path1 = os.path.join(results_dir, f"{safe_target}_scan1_{ts}.xml")
    path2 = os.path.join(results_dir, f"{safe_target}_scan2_{ts}.xml")

    if not os.path.exists(path1) or not os.path.exists(path2):
        return "Error: XML 文件未生成"

    data1 = _parse_xml_output(path1)
    data2 = _parse_xml_output(path2)

    # 提取端口集合
    def ports_set(data: dict) -> dict:
        result: dict = {}
        for host in data.get("hosts", []):
            addrs = [a["addr"] for a in host.get("addresses", [])]
            addr_key = ",".join(addrs) if addrs else "unknown"
            result[addr_key] = {
                p["port"] + "/" + p["protocol"]: p["state"]
                for p in host.get("ports", [])
            }
        return result

    ports1 = ports_set(data1)
    ports2 = ports_set(data2)

    diff_lines: list[str] = []
    all_hosts = set(list(ports1.keys()) + list(ports2.keys()))

    for host in sorted(all_hosts):
        p1 = ports1.get(host, {})
        p2 = ports2.get(host, {})
        all_ports = set(list(p1.keys()) + list(p2.keys()))

        added = [p for p in all_ports if p not in p1]
        removed = [p for p in all_ports if p not in p2]
        changed = [p for p in all_ports if p in p1 and p in p2 and p1[p] != p2[p]]

        if added or removed or changed:
            diff_lines.append(f"\n=== {host} ===")
            if added:
                diff_lines.append(f"  🆕 新增: {', '.join(added)}")
            if removed:
                diff_lines.append(f"  ❌ 关闭: {', '.join(removed)}")
            if changed:
                for p in changed:
                    diff_lines.append(f"  🔄 {p}: {p1[p]} → {p2[p]}")
        else:
            diff_lines.append(f"\n=== {host} === 无变化")

    diff_text = "\n".join(diff_lines)

    # 写入对比结果
    diff_path = os.path.join(results_dir, f"{safe_target}_diff_{ts}.txt")
    with open(diff_path, "w", encoding="utf-8") as f:
        f.write(f"# nmap scan diff: {target}\n")
        f.write(f"# options: {options}\n")
        f.write(f"# time: {ts}\n\n")
        f.write(diff_text)
        f.write("\n")

    logs.append(f"✅ 对比结果已写入 {diff_path}")

    return "\n".join(logs) + "\n\n" + diff_text


# ═══════════════════════════════════════════════════════════════════════════════
# 15. JSON 结构化输出
# ═══════════════════════════════════════════════════════════════════════════════


@tool(
    name="nmap_scan_json",
    description="执行扫描并返回 JSON 结构化结果（适合程序化使用）",
)
def nmap_scan_json(
    target: str,
    options: str = "-T4 --open",
    sudo: bool = False,
    timeout: int = 300,
) -> str:
    """执行扫描并返回 JSON 结构化结果

    Args:
        target: 扫描目标
        options: nmap 选项
        sudo: 是否用 sudo
        timeout: 超时秒数

    Returns:
        JSON 格式的结构化扫描结果
    """
    results_dir = _ensure_results_dir()
    ts = time.strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_")
    xml_path = os.path.join(results_dir, f"{safe_target}_json_{ts}.xml")

    args = options.split() if options else []
    args.extend(["-oX", xml_path, target])

    if sudo:
        _run_nmap_sudo(args, timeout)
    else:
        _run_nmap(args, timeout)

    if not os.path.exists(xml_path):
        return json.dumps({"error": "XML 输出未生成"}, ensure_ascii=False, indent=2)

    parsed = _parse_xml_output(xml_path)
    return json.dumps(parsed, ensure_ascii=False, indent=2)