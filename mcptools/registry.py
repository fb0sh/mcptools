"""
工具注册系统

提供装饰器 @tool 和注册器 registry，用于收集工具函数。
实际的类型推断和 JSON Schema 生成由 FastMCP 自动完成。
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import types
from dataclasses import dataclass, field
from typing import Any, Callable


# ─── 工具定义 ─────────────────────────────────────────────────────────────────

@dataclass
class ToolDef:
    """工具定义"""
    name: str
    description: str
    fn: Callable[..., Any]


# ─── 注册器 ─────────────────────────────────────────────────────────────────

class ToolRegistry:
    """工具注册器 - 收集工具函数，schema 生成交给 FastMCP"""

    def __init__(self):
        self._tools: dict[str, ToolDef] = {}

    @property
    def tools(self) -> dict[str, ToolDef]:
        return dict(self._tools)

    def register(
        self,
        fn: Callable[..., Any],
        name: str | None = None,
        description: str | None = None,
    ) -> ToolDef:
        """注册一个工具

        Args:
            fn: 工具函数
            name: 工具名（默认使用函数名）
            description: 工具描述（默认使用 docstring 首行）

        Returns:
            ToolDef
        """
        tool_name = name or fn.__name__
        tool_desc = description or (inspect.getdoc(fn) or "").split("\n")[0].strip() or fn.__name__

        tool_def = ToolDef(
            name=tool_name,
            description=tool_desc,
            fn=fn,
        )
        self._tools[tool_name] = tool_def
        return tool_def

    def discover(self, package: str | types.ModuleType) -> list[ToolDef]:
        """自动发现包内所有模块（模块导入时 @tool 装饰器会自动注册）

        Args:
            package: 包名或模块

        Returns:
            发现的工具列表
        """
        if isinstance(package, str):
            package = importlib.import_module(package)

        discovered: list[ToolDef] = []

        if hasattr(package, "__path__"):
            for _importer, modname, _ispkg in pkgutil.walk_packages(
                package.__path__,  # type: ignore[arg-type]
                prefix=package.__name__ + ".",
            ):
                try:
                    importlib.import_module(modname)
                except Exception as e:
                    import sys
                    print(f"Warning: failed to load {modname}: {e}", file=sys.stderr)

        return discovered


# ─── 全局实例 ─────────────────────────────────────────────────────────────────

registry = ToolRegistry()


def tool(
    name: str | None = None,
    description: str | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """装饰器：注册一个工具

    Args:
        name: 工具名（默认使用函数名）
        description: 工具描述（默认使用 docstring 首行）

    Usage:
        @tool(name="hello", description="Say hello")
        def hello(name: str) -> str:
            return f"Hello, {name}!"
    """
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        registry.register(fn, name=name, description=description)
        return fn
    return decorator
