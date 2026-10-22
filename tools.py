"""The capability layer: read-only system tools, described once.

Both front-ends read this registry. The Gemini path hands TOOL_SPECS to the
model as function declarations; the MCP path serves the same dicts as
``tools/list`` entries. One source of truth means an argument the model can
ask for is always an argument the gateway knows how to validate.
"""

from __future__ import annotations

from typing import Any, Callable

from linux.files import find_files, search_text_file
from linux.processes import get_top_cpu_processes, get_top_memory_processes
from linux.system import get_system_status


CAPABILITY_TOOLS: dict[str, Callable[..., Any]] = {
    "get_system_status": get_system_status,
    "get_top_cpu_processes": get_top_cpu_processes,
    "get_top_memory_processes": get_top_memory_processes,
    "find_files": find_files,
    "search_text_file": search_text_file,
}


TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "get_system_status",
        "description": (
            "Read CPU usage, memory usage, disk usage and system uptime."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "get_top_cpu_processes",
        "description": (
            "Read the processes currently consuming the most CPU."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10,
                    "description": (
                        "Number of processes to return. "
                        "Must be between 1 and 10."
                    ),
                }
            },
        },
    },
    {
        "name": "get_top_memory_processes",
        "description": (
            "Read the processes currently consuming the most memory."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10,
                    "description": (
                        "Number of processes to return. "
                        "Must be between 1 and 10."
                    ),
                }
            },
        },
    },
    {
        "name": "find_files",
        "description": (
            "Search for files inside a directory by name substring "
            "or file extension. Read-only; does not modify the filesystem. "
            "Always provide an absolute Linux path for the directory. "
            "Common choices: /var/log for logs, /etc for configs, "
            "/home for user files, /tmp for temporary files."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "directory": {
                    "type": "string",
                    "description": (
                        "Absolute Linux path to the directory to search. "
                        "Examples: /var/log, /etc, /home, /tmp. "
                        "Do NOT use relative paths."
                    ),
                },
                "name": {
                    "type": "string",
                    "description": (
                        "Optional substring to filter file names "
                        "(e.g. 'syslog', 'nginx')."
                    ),
                },
                "extension": {
                    "type": "string",
                    "description": (
                        "Optional file extension to filter by "
                        "(e.g. '.log', '.conf', '.txt')."
                    ),
                },
            },
            "required": ["directory"],
        },
    },
    {
        "name": "search_text_file",
        "description": (
            "Search inside a single text file for lines "
            "matching a query string. Read-only."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Absolute path to the text file to search."
                    ),
                },
                "query": {
                    "type": "string",
                    "description": (
                        "The text string to search for."
                    ),
                },
            },
            "required": ["path", "query"],
        },
    },
]


TOOL_NAMES: frozenset[str] = frozenset(CAPABILITY_TOOLS)


def call_capability(name: str, arguments: dict[str, Any]) -> Any:
    """Run a registered read-only function.

    Argument names were already validated by risk_engine.classify_tool_call;
    an unregistered name is a bug, not a user error, so it raises.
    """
    if name not in CAPABILITY_TOOLS:
        raise KeyError(f"no such capability tool: {name}")
    return CAPABILITY_TOOLS[name](**arguments)
