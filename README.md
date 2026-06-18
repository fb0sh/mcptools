# mcptools

一个通用的 **MCP Server**，提供开箱即用的实用工具集合，并内置了**工具注册系统**，方便你快速添加自己的工具。

---

## 架构

```
┌─────────────────────────┐      JSON-RPC over stdio/SSE      ┌──────────────────────┐
│  MCP Client             │ ◄──────────────────────────────►  │  mcptools            │
│                         │                                    │                      │
│  Claude Desktop         │                                    │  MCP Server          │
│  VS Code (Cline)        │                                    │  提供各种工具         │
│  pi / 其他 AI Agent     │                                    │  可扩展注册系统       │
└─────────────────────────┘                                    └──────────────────────┘
```

**mcptools 是 MCP Server**，不是 Client。它提供工具（`current_time`、`calculate` 等），等待 MCP Client（如 Claude Desktop）来连接和调用。

---

## 内置工具一览

### 系统工具

| 工具 | 说明 |
|------|------|
| `system_info` | 获取系统基本信息（平台、内存、CPU 等） |

### 网络扫描（nmap）

| 工具 | 说明 |
|------|------|
| `nmap_scan` | 通用 nmap 扫描，支持任意参数 |
| `nmap_quick_scan` | 快速扫描 Top 1000 端口 |
| `nmap_service_scan` | 扫描端口并探测服务版本（-sV） |
| `nmap_os_detection` | 操作系统检测（-O） |
| `nmap_comprehensive` | 综合扫描：端口 + 服务版本 + OS + 默认脚本（-A） |
| `nmap_ping_scan` | Ping 扫描（-sn），发现局域网在线主机 |
| `nmap_script_scan` | 使用 NSE 脚本扫描（如 --script=vuln） |
| `nmap_script_list` | 列出 NSE 脚本（按类别筛选） |
| `nmap_script_help` | 查看 NSE 脚本的详细帮助 |
| `nmap_udp_scan` | UDP 端口扫描（-sU） |
| `nmap_traceroute` | 路由追踪（--traceroute） |
| `nmap_firewall_evasion` | 防火墙/IDS 规避扫描（分片、诱饵、代理等） |
| `nmap_scan_json` | 执行扫描并返回 JSON 结构化结果 |
| `nmap_scan_to_file` | 扫描结果写入文件 → 读取验证 → 再追加 |
| `nmap_scan_diff` | 对比两次扫描结果的端口变化 |
| `nmap_help_lookup` | 从本地 nmap.help 文件查询 nmap 用法说明 |

---

## 快速开始

### 1. 安装

```bash
cd /Users/fb0sh/Temp/mcptools
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 2. 测试运行

```bash
# stdio 模式（默认）
mcptools

# SSE 模式（像传统 C/S）
mcptools --transport sse --port 8080
```

---

## 配置到 MCP Client

### 方式一：stdio 模式（推荐，Claude 自动管理 Server 生命周期）

Claude Desktop 会自动启动和关闭 mcptools 进程，无需手动干预。

**`claude_desktop_config.json`：**

```json
{
  "mcpServers": {
    "mcptools": {
      "command": "/Users/fb0sh/Temp/mcptools/.venv/bin/python",
      "args": ["/Users/fb0sh/Temp/mcptools/mcptools/server.py"]
    }
  }
}
```

> 使用绝对路径，不依赖系统 Python 环境。

**VS Code (Cline) 的 `.vscode/mcp.json`：**

```json
{
  "servers": {
    "mcptools": {
      "type": "stdio",
      "command": "/Users/fb0sh/Temp/mcptools/.venv/bin/python",
      "args": ["/Users/fb0sh/Temp/mcptools/mcptools/server.py"]
    }
  }
}
```

### 方式二：SSE 模式（像传统 Client-Server，需要手动启动）

```bash
# 终端 1：先手动启动 Server
mcptools --transport sse --port 8080
```

```json
// 然后配置 Client 通过地址连接
{
  "mcpServers": {
    "mcptools": {
      "url": "http://localhost:8080/sse"
    }
  }
}
```

> SSE 模式下 Server 独立运行，Client 通过网络连接，适合 Docker 部署或远程访问。

### 两种模式对比

| | stdio | SSE |
|---|---|---|
| **配置写法** | `command` + `args` | `url` |
| **谁启动 Server** | Claude Desktop 自动管理 | 你手动启动 |
| **生命周期** | Claude 管，退出自动关闭 | 你管，需要 keep-alive |
| **适用场景** | 本地开发，简单省事 | Docker、远程、自定义端口 |

---

## 添加自己的工具

### 方式一：在 `tools/` 目录下新建文件

```python
# mcptools/tools/weather_tools.py
from mcptools.registry import tool

@tool(name="get_weather", description="查询城市天气")
def get_weather(city: str, days: int = 1) -> str:
    """查询天气

    city: 城市名
    days: 预报天数（默认 1）
    """
    # 你的逻辑...
    return f"{city} 未来 {days} 天天气：晴 ☀️"
```

保存后自动生效，无需手动注册。

### 方式二：在任何地方使用装饰器

```python
from mcptools.registry import tool

@tool(name="hello", description="Say hello")
def hello(name: str) -> str:
    return f"Hello, {name}!"
```

### 方式三：直接调用注册器

```python
from mcptools.registry import registry

def my_tool(keyword: str) -> list:
    return ["result1", "result2"]

registry.register(my_tool, name="search", description="搜索关键词")
```

### 工具函数规则

- 参数类型注解会自动转为 JSON Schema（FastMCP 自动处理）
- 函数 docstring 第一行作为描述（如果没传 `description`）
- 支持同步和异步函数
- 参数 `ctx` 或 `context` 会被自动注入 FastMCP Context（用于日志、进度报告等）

---

## 作为库使用

```python
from mcptools import create_server

# 创建 Server（自动发现 tools/ 下的所有工具）
server = create_server()

# stdio 模式
server.run(transport="stdio")

# 或 SSE 模式
server.run(transport="sse")
```

---

## 项目结构

```
mcptools/
├── __init__.py          # 包入口，导出 create_server
├── __main__.py          # python -m mcptools 入口
├── registry.py          # 核心：@tool 装饰器 + ToolRegistry 注册器
├── server.py            # FastMCP 服务器 + CLI（支持 stdio/SSE）
└── tools/               # 工具模块目录（自动发现）
    ├── __init__.py
    ├── system_tools.py  # 系统工具（system_info）
    └── nmap_tools.py    # nmap 网络扫描工具集
```

---

## 依赖

- Python >= 3.11
- `mcp`（MCP Python SDK，自动安装 FastMCP）
- `psutil`（可选，`pip install mcptools[full]` 安装，提供更详细的系统信息）
