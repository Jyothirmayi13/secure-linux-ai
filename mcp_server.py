"""Policy-gated MCP server: every agent sees the same boundary the CLI sees.

An MCP client (Claude Desktop, Cursor, Qoder, any agent runtime) can put this
in front of a Linux host and get diagnostics, decisions and signed evidence.
What it cannot get is execution. Commands are still only run by a human at the
CLI, where they are typed, confirmed and signed. That is the product stance,
not a missing feature: an agent that can act on a production box has no one to
answer for it, and this server exists so that a refusal is as auditable as an
approval.

Every tool call, allowed or refused, writes a signed audit row naming the rule
that decided it. Protocol framing is implemented directly so the gateway adds
no dependency tree to a security product.

Run:            python mcp_server.py [--policy FILE]
Self-test:      python mcp_server.py --check
Client config:  {"command": "python", "args": ["/abs/path/mcp_server.py"]}
"""

from __future__ import annotations

import argparse
import io
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, TextIO

from audit import AuditLogger
from approval import (
    ApprovalError,
    ApprovalStore,
    approval_ladder,
    mode_for,
    request_approval,
)
from evidence import (
    EvidenceError,
    build_report,
    load_or_create_identity,
    policy_fingerprint,
    sign_report,
    verify_report,
)
from gateway import (
    GatewayState,
    decide_command,
    decide_tool_call,
    gateway_state,
    resolve_policy,
    reset_state_for_tests,
    rule_suffix,
)
from policy import Policy, PolicyError
from risk_engine import CONTROL_TOOLS
from tools import CAPABILITY_TOOLS, TOOL_NAMES, TOOL_SPECS, call_capability

SERVER_NAME = "linux-ai-ssm-gateway"
SERVER_VERSION = "0.5.0"

# Newest first. A client offering none of these is told which one we speak.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

MAX_NOTE_CHARS = 200

CONTROL_TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "policy_decide",
        "description": (
            "Ask the gateway whether a shell command would be allowed, and "
            "which rule decides it. Dry run only: nothing is executed, and "
            "this server cannot execute anything at all."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The exact shell command to evaluate.",
                }
            },
            "required": ["command"],
        },
        "annotations": {
            "title": "Policy decision",
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "policy_show",
        "description": (
            "Read the effective policy: the built-in deny-by-default floor "
            "plus operator additions, with the origin of each setting and the "
            "policy fingerprint used in signed evidence."
        ),
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {
            "title": "Effective policy",
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "evidence_report",
        "description": (
            "Export this host's audit log as a signed, self-verifying evidence "
            "report. Rows are the gateway's own decisions, including refusals."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "hours": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 8760,
                    "description": "Restrict to the last N hours.",
                },
                "max_events": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "description": "Restrict to the N most recent events.",
                },
                "note": {
                    "type": "string",
                    "description": f"Context stored in the report (max {MAX_NOTE_CHARS} chars).",
                },
            },
        },
        "annotations": {
            "title": "Signed evidence report",
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "evidence_verify",
        "description": (
            "Verify an exported evidence file using only that file: hash chain, "
            "row signatures, summary cross-check and document signature."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to a report exported by this gateway.",
                }
            },
            "required": ["path"],
        },
        "annotations": {
            "title": "Verify evidence",
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "approval_request",
        "description": (
            "Open an approval request for one exact command so a human can "
            "sign it in a terminal. This server can ask; it cannot approve. "
            "Minting a token needs the host private key and a person pressing "
            "Enter, and spending one happens only in the CLI, so an agent "
            "cannot authorise its own action here. A command the gateway "
            "blocks cannot even be queued for approval."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The exact command to be approved, byte for byte.",
                },
                "ttl_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 900,
                    "description": (
                        "Ask for a shorter lifetime. The policy lifetime and "
                        "the gateway ceiling both apply, and the shortest wins."
                    ),
                },
            },
            "required": ["command"],
        },
        "annotations": {
            "title": "Request a human approval",
            "readOnlyHint": False,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "approval_list",
        "description": (
            "Read the approval ledger: which requests are open, signed, spent, "
            "void or expired. Report only - nothing here mints, spends or "
            "voids an approval."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10,
                    "description": "Most recent rows to return.",
                },
            },
        },
        "annotations": {
            "title": "Approval ledger",
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    },
]


def _json_text(value: Any) -> str:
    return json.dumps(value, indent=2, default=str)


class ProtocolError(Exception):
    """A JSON-RPC level failure, as distinct from a tool that refused."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class McpGatewayServer:
    """A minimal MCP server whose tools are the gateway's own decisions."""

    def __init__(self, state: GatewayState, policy: Policy):
        self.state = state
        self.policy = policy
        self.approvals = state.approvals
        self.client_info: dict[str, Any] = {}
        self.negotiated_version: str | None = None
        self.control_handlers: dict[str, Callable[[dict], str]] = {
            "policy_decide": self._call_policy_decide,
            "policy_show": self._call_policy_show,
            "evidence_report": self._call_evidence_report,
            "evidence_verify": self._call_evidence_verify,
            "approval_request": self._call_approval_request,
            "approval_list": self._call_approval_list,
        }

    # ------------------------------------------------------------------
    # tool surface
    # ------------------------------------------------------------------

    @property
    def audit(self):
        return self.state.audit

    @property
    def client_label(self) -> str:
        name = str(self.client_info.get("name") or "").strip()
        return f" via {name}" if name else ""

    def tools(self) -> list[dict[str, Any]]:
        capability = [
            {
                "name": spec["name"],
                "description": spec["description"],
                "inputSchema": spec["parameters"],
                "annotations": {
                    "title": spec["name"].replace("_", " "),
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "openWorldHint": False,
                },
            }
            for spec in TOOL_SPECS
        ]
        return capability + CONTROL_TOOL_SPECS

    def tool_names(self) -> set[str]:
        return {tool["name"] for tool in self.tools()}

    def _record(
        self,
        subject: str,
        decision: dict,
        status: str,
        confirmed: bool,
        reason: str,
    ) -> None:
        self.audit.log(subject, decision, status, confirmed, reason, self.policy)

    def _refusal(self, name: str, decision: dict, arguments: Any = None) -> dict:
        """A refusal is a first-class result: it names the rule and is signed."""
        message = (
            f"REFUSED by the security gateway: {decision['reason']}"
            f"{rule_suffix(decision)}\n"
            f"Policy: {self.policy.name} ({self.policy.source_label}); "
            f"risk {decision['category']} score {decision['score']}. "
            "This refusal is recorded in the signed audit log."
        )
        self._record(
            f"mcp:{name}{self.client_label} {self._brief(arguments)}",
            decision,
            "blocked",
            False,
            f"Tool call refused before execution (rule {decision.get('rule_id', '')})",
        )
        return {
            "content": [{"type": "text", "text": message}],
            "isError": True,
        }

    @staticmethod
    def _brief(arguments: Any) -> str:
        """Keep the requested arguments in the log without unbounded blobs."""
        if not isinstance(arguments, dict):
            return ""
        return json.dumps(arguments, default=str)[:200]

    # ------------------------------------------------------------------
    # individual tools
    # ------------------------------------------------------------------

    def _call_capability(self, name: str, arguments: dict) -> str:
        output = call_capability(name, arguments)
        self._record(
            f"mcp:{name}{self.client_label} {self._brief(arguments)}",
            {"category": "LOW", "score": 10, "sensitive": False,
             "reason": "Approved read-only MCP call",
             "rule_id": "baseline.tool_allow_list"},
            "executed",
            False,
            "Executed under policy without human confirmation "
            "(agent-initiated through MCP)",
        )
        return _json_text({"tool": name, "result": output})

    def _call_policy_decide(self, arguments: dict) -> str:
        command = arguments["command"]
        decision = decide_command(command, self.policy)
        self._record(
            f"mcp:policy_decide{self.client_label} {command[:200]}",
            decision,
            "queried",
            False,
            f"Dry-run decision requested by an agent "
            f"(rule {decision.get('rule_id', '')})",
        )
        return _json_text({
            "command": command,
            "allowed": not decision["blocked"],
            "requires_confirmation": decision["requires_confirmation"],
            "risk_category": decision["category"],
            "risk_score": decision["score"],
            "sensitive": decision["sensitive"],
            "matched_rule": decision.get("rule_id", ""),
            "reason": decision["reason"],
            "policy": {
                "name": self.policy.name,
                "source": self.policy.source_label,
                "fingerprint": policy_fingerprint(self.policy),
            },
            "note": (
                "Nothing was executed. This gateway exposes no execution tool; "
                "a human runs allowed commands at the CLI."
            ),
        })

    def _call_policy_show(self, arguments: dict) -> str:
        text = _json_text({
            "policy": self.policy.name,
            "source": self.policy.source_label,
            "fingerprint": policy_fingerprint(self.policy),
            "settings": [
                {"setting": setting, "value": value, "origin": origin}
                for setting, value, origin in self.policy.describe()
            ],
            "floor": "The deny-by-default floor is not configurable; a policy "
                     "file can only add restrictions.",
        })
        self._record(
            f"mcp:policy_show{self.client_label}",
            {"category": "LOW", "score": 10, "sensitive": False,
             "reason": "Effective policy read by an agent",
             "rule_id": "baseline.tool_allow_list"},
            "queried",
            False,
            "Policy read only; nothing was decided or executed",
        )
        return text

    def _call_evidence_report(self, arguments: dict) -> str:
        hours = arguments.get("hours")
        limit = arguments.get("max_events")
        note = str(arguments.get("note", ""))[:MAX_NOTE_CHARS]

        rows = self.audit.export(hours=hours, limit=limit)
        report = sign_report(
            build_report(rows, self.state.identity, self.policy, hours=hours, note=note),
            self.state.identity,
        )
        self._record(
            f"mcp:evidence_report{self.client_label} {len(rows)} event(s)",
            {"category": "LOW", "score": 10, "sensitive": False,
             "reason": "Evidence export", "rule_id": "baseline.tool_allow_list"},
            "executed",
            False,
            "Signed evidence report handed to an agent",
        )
        return _json_text(report)

    def _call_evidence_verify(self, arguments: dict) -> str:
        verdict = verify_report(arguments["path"])
        self._record(
            f"mcp:evidence_verify{self.client_label} {arguments['path']}",
            {"category": "LOW", "score": 10, "sensitive": False,
             "reason": "Evidence verification", "rule_id": "baseline.tool_allow_list"},
            "executed",
            False,
            f"Verdict ok={verdict['ok']} fully_signed={verdict['fully_signed']}",
        )
        return _json_text(verdict)

    def _call_approval_request(self, arguments: dict) -> str:
        command = arguments["command"]
        ttl = arguments.get("ttl_seconds")

        risk = decide_command(command, policy=self.policy)
        if risk["blocked"]:
            # A command that would never run cannot even be queued for a human
            # to wave through: approval shopping starts by opening a request.
            self._record(
                f"mcp:approval_request{self.client_label} {command[:200]}",
                risk,
                "blocked",
                False,
                f"Approval request refused before it was opened "
                f"(rule {risk.get('rule_id', '')})",
            )
            return _json_text({
                "opened": False,
                "reason": risk["reason"],
                "matched_rule": risk.get("rule_id", ""),
                "note": "No request exists, so there is nothing for a human "
                        "to approve. This refusal is recorded.",
            })

        if self.approvals is None:
            self._record(
                f"mcp:approval_request{self.client_label} {command[:200]}",
                {**risk, "rule_id": "approval.unavailable"},
                "blocked",
                False,
                "No approval ledger is attached to this gateway state",
            )
            return _json_text({
                "opened": False,
                "reason": "this gateway has no approval ledger attached, so "
                          "nothing can be queued for a human to sign",
            })

        try:
            request = request_approval(
                command, self.policy, self.state.identity, self.approvals,
                ttl_seconds=ttl,
                requested_by=("mcp" + self.client_label).strip(),
            )
        except ApprovalError as exc:
            return _json_text({"opened": False, "reason": str(exc)})

        self._record(
            f"mcp:approval_request{self.client_label} {command[:200]}",
            {**risk, "rule_id": "approval.requested"},
            "approval_requested",
            False,
            f"request {request['request_id']} opened by an agent; an agent "
            "cannot mint the token",
        )
        return _json_text({
            "opened": True,
            "request_id": request["request_id"],
            "command": request["subject"],
            "decision": json.loads(request["decision_json"]),
            "policy_fingerprint": request["policy_sha"],
            "expires_at": request["expires_at"],
            "approval_mode": mode_for(self.policy),
            "approval_regime": [
                {"setting": setting, "value": value}
                for setting, value in approval_ladder(self.policy)
            ],
            "note": (
                "Nothing is approved yet and nothing ran. Only a human at a "
                "terminal on this host, holding the host private key, can turn "
                "this request into a token:  python main.py --approve "
                f"{request['request_id']}  This server has no tool that mints, "
                "signs or spends an approval, so asking again does not make "
                "the command run."
            ),
        })

    def _call_approval_list(self, arguments: dict) -> str:
        limit = arguments.get("limit") or 10
        if self.approvals is None:
            return _json_text({"rows": [], "reason": "no approval ledger attached"})

        expired = self.approvals.expire_stale()
        rows = self.approvals.list(limit=limit)
        self._record(
            f"mcp:approval_list{self.client_label} {len(rows)} row(s)",
            {"category": "LOW", "score": 10, "sensitive": False,
             "reason": "Approval ledger read", "rule_id": "approval.list"},
            "queried",
            False,
            f"Ledger read by an agent; {expired} stale request(s) marked expired",
        )
        return _json_text({
            "rows": [
                {
                    "request_id": row["request_id"],
                    "state": row["state"],
                    "command": row["subject"],
                    "requested_by": row["requested_by"],
                    "issued_at": row["issued_at"],
                    "expires_at": row["expires_at"],
                    "has_token": bool(row["token_sha"]),
                }
                for row in rows
            ],
            "counts": self.approvals.counts(),
            "expired_on_this_read": expired,
            "note": "Read only. An agent can see what is waiting; only a "
                    "human can make any of it executable.",
        })

    # ------------------------------------------------------------------
    # dispatch
    # ------------------------------------------------------------------

    def call_tool(self, name: str, arguments: Any) -> dict:
        if not isinstance(arguments, dict):
            return self._refusal(
                name,
                {"reason": "Tool arguments must be an object", "category": "CRITICAL",
                 "score": 100, "sensitive": True, "blocked": True,
                 "rule_id": "baseline.tool_arguments"},
                arguments,
            )

        decision = decide_tool_call(name, arguments, self.policy)
        if decision["blocked"]:
            return self._refusal(name, decision, arguments)

        try:
            if name in CAPABILITY_TOOLS:
                text = self._call_capability(name, arguments)
            else:
                text = self.control_handlers[name](arguments)
        except Exception as exc:
            message = f"Tool {name} failed: {exc}"
            self._record(
                f"mcp:{name}{self.client_label} {self._brief(arguments)}",
                {**decision, "reason": message},
                "failed",
                False,
                f"Allowed by policy but the read itself raised: {type(exc).__name__}",
            )
            return {
                "content": [{"type": "text", "text": message}],
                "isError": True,
            }

        return {"content": [{"type": "text", "text": text}], "isError": False}

    # ------------------------------------------------------------------
    # JSON-RPC plumbing
    # ------------------------------------------------------------------

    def handle(self, message: dict) -> dict | None:
        """One request in, one response out. Notifications get no response."""
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _error(None, INVALID_REQUEST, "expected a JSON-RPC 2.0 object")

        method = message.get("method")
        identifier = message.get("id")
        params = message.get("params") or {}

        if not isinstance(method, str):
            return _error(identifier, INVALID_REQUEST, "missing method name")

        is_notification = "id" not in message

        if method == "initialize":
            result = self._initialize(params)
            return None if is_notification else _result(identifier, result)

        if method == "ping":
            return None if is_notification else _result(identifier, {})

        if method.startswith("notifications/"):
            # The spec requires no reply to a notification, and we keep no
            # session state that would change what a later call is allowed to do.
            return None

        try:
            result = self._dispatch(method, params)
        except ProtocolError as exc:
            return None if is_notification else _error(identifier, exc.code, exc.message)

        return None if is_notification else _result(identifier, result)

    def _initialize(self, params: dict) -> dict:
        requested = str(params.get("protocolVersion") or "")
        version = (
            requested
            if requested in SUPPORTED_PROTOCOL_VERSIONS
            else SUPPORTED_PROTOCOL_VERSIONS[0]
        )
        self.negotiated_version = version
        self.client_info = params.get("clientInfo") or {}
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": (
                "This server reports what the security gateway would decide, "
                "hands out signed evidence of what it decided, and lets an "
                "agent open an approval request for a human to sign. It has "
                "no tool that executes anything and no tool that mints, signs "
                "or spends an approval, so asking for a destructive action has "
                "no effect beyond the signed refusal it produces."
            ),
        }

    def _dispatch(self, method: str, params: dict) -> dict:
        if method == "tools/list":
            return {"tools": self.tools()}

        if method == "tools/call":
            name = params.get("name")
            if not isinstance(name, str) or not name:
                raise ProtocolError(INVALID_PARAMS, "tools/call needs a tool name")
            if name not in self.tool_names():
                # An agent probing for a tool the operator never granted is
                # worth a signed row, not just an error code.
                self._record(
                    f"mcp:unknown {name}{self.client_label}",
                    {"category": "CRITICAL", "score": 100, "sensitive": True,
                     "reason": f"Unapproved diagnostic tool: {name}",
                     "rule_id": "baseline.tool_name"},
                    "blocked",
                    False,
                    "Unknown tool requested by an agent",
                )
                raise ProtocolError(INVALID_PARAMS, f"unknown tool: {name}")
            return self.call_tool(name, params.get("arguments") or {})

        raise ProtocolError(METHOD_NOT_FOUND, f"method not found: {method}")


def _result(identifier: Any, payload: dict) -> dict:
    return {"jsonrpc": "2.0", "id": identifier, "result": payload}


def _error(identifier: Any, code: int, message: str, data: Any = None) -> dict:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": identifier, "error": error}


def serve_stdio(
    server: McpGatewayServer,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    log: Callable[[str], None] = None,
) -> int:
    """Newline-delimited JSON-RPC over stdio.

    stdout is reserved for protocol messages. Diagnostics go to stderr, and
    any accidental write there is why the CLI half of this project never
    prints in this module.
    """
    source = stdin or sys.stdin
    sink = stdout or sys.stdout
    note = log or (lambda text: print(text, file=sys.stderr, flush=True))

    note(
        f"{SERVER_NAME} {SERVER_VERSION} ready: "
        f"{len(server.tool_names())} tool(s), policy {server.policy.name} "
        f"({server.policy.source_label})"
    )

    for line in source:
        line = line.strip()
        if not line:
            continue

        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            sink.write(json.dumps(_error(None, PARSE_ERROR, f"invalid JSON: {exc}")) + "\n")
            sink.flush()
            continue

        try:
            response = server.handle(message)
        except Exception as exc:  # never take the transport down with us
            note(f"handler raised {type(exc).__name__}: {exc}")
            identifier = message.get("id") if isinstance(message, dict) else None
            response = _error(identifier, INTERNAL_ERROR, "internal gateway error")

        if response is not None:
            sink.write(json.dumps(response, default=str) + "\n")
            sink.flush()

    note("input stream closed; shutting down")
    return 0


def build_server(policy_path: str | None = None) -> McpGatewayServer:
    """Resolve policy and identity, failing closed."""
    policy = resolve_policy(policy_path)
    return McpGatewayServer(gateway_state(), policy)


def _sandbox_state() -> tuple[GatewayState, Path]:
    """A throwaway identity + audit log for the self-test.

    The real log is evidence: it records decisions the gateway actually made.
    A self-check is not one of those decisions, so it must not leave rows
    behind that an auditor would read as agent traffic. The approval ledger is
    sandboxed for the same reason.
    """
    home = Path(tempfile.mkdtemp(prefix="linux-ai-ssm-selfcheck-"))
    identity = load_or_create_identity(home / "identity")
    state = GatewayState(
        identity,
        AuditLogger(home / "audit.sqlite3", identity),
        ApprovalStore(home / "approvals.sqlite3"),
    )
    return state, home


def self_check(policy_path: str | None = None) -> int:
    """Drive the server in-process through a full session and print the results."""
    policy = resolve_policy(policy_path)
    sandbox, home = _sandbox_state()
    try:
        return _run_checks(sandbox, policy)
    finally:
        reset_state_for_tests(None)
        shutil.rmtree(home, ignore_errors=True)


def _run_checks(state: GatewayState, policy: Policy) -> int:
    server = McpGatewayServer(state, policy)
    checks: list[tuple[str, bool, str]] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        checks.append((label, ok, detail))

    init = server.handle({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18",
                   "capabilities": {}, "clientInfo": {"name": "self-check", "version": "0"}},
    }) or {}
    check("initialize negotiates a protocol version",
          init.get("result", {}).get("protocolVersion") == "2025-06-18", str(init)[:120])
    check("advertises tools capability",
          "tools" in init.get("result", {}).get("capabilities", {}))

    check("initialized notification gets no response",
          server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None)

    listing = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) or {}
    tools = listing.get("result", {}).get("tools", [])
    check("tools/list returns 11 policy-gated tools", len(tools) == 11, str(len(tools)))
    check("every tool declares an input schema",
          all(tool.get("inputSchema", {}).get("type") == "object" for tool in tools))
    check("no tool is advertised as destructive",
          all(tool.get("annotations", {}).get("destructiveHint") is False
              for tool in tools))
    check("every tool is read-only except the approval ledger",
          sorted(tool["name"] for tool in tools
                 if tool.get("annotations", {}).get("readOnlyHint") is not True)
          == ["approval_request"],
          str([tool["name"] for tool in tools
               if tool.get("annotations", {}).get("readOnlyHint") is not True]))

    advertised = server.tool_names()
    check("the advertised surface is exactly the capability + control planes",
          advertised == set(TOOL_NAMES) | set(CONTROL_TOOLS),
          str(sorted(advertised - TOOL_NAMES - CONTROL_TOOLS))[:120])
    check("no advertised tool claims to execute anything",
          not [name for name in advertised
               if any(word in name for word in
                      ("exec", "run", "shell", "write", "delete", "remove", "apply"))],
          str(sorted(advertised))[:160])

    denied = server.handle({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "search_text_file",
                   "arguments": {"path": "/etc/shadow", "query": "root"}},
    }) or {}
    text = denied.get("result", {}).get("content", [{}])[0].get("text", "")
    check("a read of /etc/shadow is refused by rule name",
          denied.get("result", {}).get("isError") is True and "floor.deny_path" in text,
          text.splitlines()[0] if text else str(denied)[:120])

    probe = server.handle({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "delete_files", "arguments": {}},
    }) or {}
    check("an unknown tool is an invalid-params error, not a crash",
          probe.get("error", {}).get("code") == INVALID_PARAMS, str(probe)[:120])

    bad = server.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/execute", "params": {}})
    check("an unknown method returns METHOD_NOT_FOUND",
          bad.get("error", {}).get("code") == METHOD_NOT_FOUND, str(bad)[:120])

    decided = server.handle({
        "jsonrpc": "2.0", "id": 6, "method": "tools/call",
        "params": {"name": "policy_decide", "arguments": {"command": "journalctl --vacuum-size=1"}},
    }) or {}
    body = json.loads(decided.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    check("the mutating-flag floor is visible to agents",
          body.get("allowed") is False and "mutating" in body.get("matched_rule", "").lower(),
          str(body)[:160])

    report = server.handle({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "evidence_report", "arguments": {"max_events": 5}},
    }) or {}
    payload = json.loads(report.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    check("evidence_report returns a signed document",
          "report_signature" in payload and payload.get("summary", {}).get("events", 0) > 0,
          str(payload)[:160])

    asked = server.handle({
        "jsonrpc": "2.0", "id": 8, "method": "tools/call",
        "params": {"name": "approval_request", "arguments": {"command": "uptime"}},
    }) or {}
    asked_body = json.loads(asked.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    ledger_row = server.approvals.get(request_id=asked_body.get("request_id", "")) \
        if asked_body.get("opened") else None
    check("an agent can open an approval request",
          asked_body.get("opened") is True and bool(asked_body.get("request_id")),
          str(asked_body)[:160])
    check("opening a request mints nothing",
          ledger_row is not None and ledger_row["state"] == "open"
          and not ledger_row["token_sha"],
          str(ledger_row)[:160] if ledger_row else "no row")
    check("no tool on this server grants an approval",
          not [name for name in server.tool_names()
               if any(word in name for word in ("mint", "approve", "grant", "redeem", "spend"))],
          str(sorted(server.tool_names()))[:200])

    queued = server.handle({
        "jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": {"name": "approval_request",
                   "arguments": {"command": "rm -rf /var/log"}},
    }) or {}
    queued_body = json.loads(queued.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    check("a blocked command cannot be queued for a human to wave through",
          queued_body.get("opened") is False
          and not [row for row in server.approvals.list(limit=50)
                   if row["subject"] == "rm -rf /var/log"],
          str(queued_body)[:160])

    checked = server.handle({
        "jsonrpc": "2.0", "id": 10, "method": "tools/call",
        "params": {"name": "approval_list", "arguments": {"limit": 5}},
    }) or {}
    checked_body = json.loads(checked.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    check("approval_list reports the ledger without changing any state",
          any(row["request_id"] == asked_body.get("request_id")
              for row in checked_body.get("rows", [])),
          str(checked_body)[:160])

    print()
    print("=" * 66)
    print("  MCP GATEWAY SELF-CHECK")
    print("=" * 66)
    failed = 0
    for label, ok, detail in checks:
        print(f"  [{'ok' if ok else 'XX'}] {label}")
        if not ok and detail:
            print(f"        {detail}")
        failed += 0 if ok else 1
    print("=" * 66)
    print(f"  {len(checks) - failed}/{len(checks)} checks passed")
    print("=" * 66)
    return 1 if failed else 0


def _fail_closed(kind: str, detail: str) -> int:
    """No tool list, no decisions, exit 2. A broken gateway never runs open."""
    messages = {
        "policy": "the policy could not be loaded, so no tool is offered",
        "identity": "host identity is unusable, so nothing could be signed",
    }
    print(
        f"FAIL CLOSED: {messages.get(kind, 'the gateway could not start')}.\n"
        f"{detail}",
        file=sys.stderr,
    )
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Policy-gated MCP server for the linux-ai-ssm gateway."
    )
    parser.add_argument("--policy", help="Path to a policy.yaml")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run an in-process protocol self-test and exit.",
    )
    args = parser.parse_args(argv)

    if args.check:
        try:
            return self_check(args.policy)
        except PolicyError as exc:
            return _fail_closed("policy", str(exc))
        except EvidenceError as exc:
            return _fail_closed("identity", str(exc))

    try:
        server = build_server(args.policy)
    except PolicyError as exc:
        return _fail_closed("policy", str(exc))
    except EvidenceError as exc:
        return _fail_closed("identity", str(exc))

    # The console is cp1252 on Windows and this server emits file contents with
    # arbitrary Unicode, so the protocol streams are pinned to UTF-8.
    stdin = getattr(sys.stdin, "buffer", None)
    stdout = getattr(sys.stdout, "buffer", None)

    reader = io.TextIOWrapper(stdin, encoding="utf-8", newline="\n") if stdin else sys.stdin
    writer = io.TextIOWrapper(stdout, encoding="utf-8", newline="\n", errors="replace") if stdout else sys.stdout

    return serve_stdio(server, reader, writer)


if __name__ == "__main__":
    raise SystemExit(main())
