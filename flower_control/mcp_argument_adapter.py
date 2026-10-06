"""Keep declared string arguments literal at the local FastMCP boundary.

The pinned SDK tries JSON decoding for every annotation other than plain str.
For Optional[str], that changes valid text such as "null", "[]" and "{}"
before argument validation or origin verification. Preserve these strings
while retaining the SDK's existing parsing for object and list arguments.
"""

from __future__ import annotations

from typing import Any, Union, get_args, get_origin
from types import UnionType

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.utilities.func_metadata import FuncMetadata


def _literal_string(annotation: object) -> bool:
    return annotation is str or (
        get_origin(annotation) in (Union, UnionType)
        and set(get_args(annotation)) == {str, type(None)}
    )


class LiteralStringMetadata(FuncMetadata):
    """Retain SDK validation/output conversion, changing only string parsing."""

    def pre_parse_json(self, data: dict[str, Any]) -> dict[str, Any]:
        string_fields = set()
        for name, field in self.arg_model.model_fields.items():
            if _literal_string(field.annotation):
                string_fields.add(name)
                if field.alias is not None:
                    string_fields.add(field.alias)
        protected = {
            key: value for key, value in data.items()
            if key in string_fields and isinstance(value, str)
        }
        parsed = super().pre_parse_json({
            key: value for key, value in data.items() if key not in protected
        })
        return {
            key: protected[key] if key in protected else parsed[key]
            for key in data
        }


def preserve_literal_string_arguments(server: FastMCP) -> None:
    """Adapt registered tools after registration, before serving MCP calls.

    The pinned SDK exposes function metadata through its ToolManager. Keep the
    argument model, advertised schema, output metadata and Context injection.
    Reapplying the adapter is safe; newly registered tools need another call.
    """
    for tool in server._tool_manager.list_tools():
        previous = tool.fn_metadata
        if isinstance(previous, LiteralStringMetadata):
            continue
        tool.fn_metadata = LiteralStringMetadata(**{
            name: getattr(previous, name)
            for name in type(previous).model_fields
        })
