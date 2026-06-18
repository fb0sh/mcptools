"""
FastMCP 服务器创建

将注册系统中的工具绑定到 FastMCP 服务器。
FastMCP 自动处理类型推断、JSON Schema 生成和 context 注入。
"""

from __future__ import annotations

import sys

from mcp.server.fastmcp import FastMCP

from mcptools.registry import registry


def create_server(
    name: str = "mcptools",
    instructions: str = "A collection of useful MCP tools",
    discover: bool = True,
) -> FastMCP:
    """创建并配置 FastMCP 服务器

    Args:
        name: 服务器名称
        instructions: 服务器说明
        discover: 是否自动发现 mcptools.tools 模块中的工具

    Returns:
        配置好的 FastMCP 实例
    """
    server = FastMCP(name=name, instructions=instructions)

    # 自动发现工具模块
    if discover:
        try:
            import mcptools.tools  # noqa: F401
            registry.discover("mcptools.tools")
        except ImportError:
            pass

    # 将所有注册的工具绑定到 FastMCP
    # FastMCP 的 add_tool 自动处理：
    # - 类型注解 → JSON Schema
    # - context 参数检测和注入
    # - 异步/同步函数
    for tool_def in registry.tools.values():
        server.add_tool(
            tool_def.fn,
            name=tool_def.name,
            description=tool_def.description,
        )

    return server


def main():
    """CLI 入口"""
    import argparse

    parser = argparse.ArgumentParser(description="mcptools MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for SSE transport (default: 8080)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host for SSE transport (default: 0.0.0.0)",
    )

    args = parser.parse_args()

    server = create_server()

    if args.transport == "stdio":
        server.run(transport="stdio")
    else:
        print(
            f"Starting mcptools on {args.transport}://{args.host}:{args.port}",
            file=sys.stderr,
        )
        server.run(transport=args.transport)


if __name__ == "__main__":
    main()
