"""Fail-closed command and prompt safety checks for the CLI boundary."""

from __future__ import annotations

import base64
import re
import shlex
import unicodedata
import urllib.parse
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from policy import BASELINE_DENY_PATHS, Policy, DEFAULT_POLICY


@dataclass(frozen=True)
class RiskAssessment:
    category: str
    score: int
    requires_confirmation: bool
    reason: str
    sensitive: bool
    blocked: bool
    rule_id: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


# These constructs make it impossible to reason safely about what subprocess
# will execute.  Tech mode deliberately supports only one, non-composed command.
_SHELL_SYNTAX = re.compile(
    r"(?:[;&|`$~]|\r|\n|>>?|<<?|\\\n|\*|\?|\[|\]|\{\}|\(\))"
)
_DESTRUCTIVE = re.compile(
    r"\b(?:rm|rmdir|unlink|shred|mkfs(?:\.[\w-]+)?|fdisk|parted|wipefs|dd|"
    r"shutdown|reboot|poweroff|halt|init|telinit|kill|killall|pkill|"
    r"userdel|groupdel|chmod|chown|chattr|mount|umount|systemctl|service|"
    r"iptables|nft|ufw|sudo|su|doas|curl|wget|nc|ncat|socat)\b",
    re.IGNORECASE,
)
_INTERPRETERS = re.compile(
    r"\b(?:sh|bash|zsh|dash|fish|env|eval|exec|source|\. |python(?:\d(?:\.\d+)?)?|"
    r"perl|ruby|node|php|lua)\b",
    re.IGNORECASE,
)
_SENSITIVE_PATHS = re.compile(
    r"(?:^|/)(?:etc/(?:shadow|sudoers(?:\.d)?|ssh)|root(?:/|$)|home/[^/]+/\.ssh|"
    r"proc/(?:kcore|sysrq-trigger)|dev/(?:sd[a-z]|nvme\d+n\d+)|boot|sys)(?:/|$)|"
    r"(?:id_rsa|authorized_keys|\.env)(?:\s|$)",
    re.IGNORECASE,
)
_PROMPT_INJECTION = re.compile(
    r"\b(?:ignore|disregard|override|bypass)\b.{0,80}\b(?:previous|prior|system|"
    r"instructions?|rules?|policy|guardrails?)\b|"
    r"\b(?:reveal|print|show|leak|exfiltrate)\b.{0,80}\b(?:system prompt|secret|api[ _-]?key|token)\b|"
    r"\b(?:you are now|developer message|jailbreak|do not follow)\b",
    re.IGNORECASE | re.DOTALL,
)
_READ_ONLY_EXECUTABLES = frozenset({
    "cat", "date", "df", "dmesg", "du", "find", "free", "grep", "head",
    "id", "ip", "journalctl", "ls", "lsblk", "lscpu", "pgrep", "ps", "pwd",
    "ss", "stat", "tail", "uname", "uptime", "whoami",
})
_UNSAFE_ARGUMENT = re.compile(r"^(?:-exec(?:dir)?|-ok(?:dir)?|-delete|--(?:in-place|output|write)|-[if])$", re.IGNORECASE)

# Being on the read-only allow-list is not the same as being read-only. Several
# allow-listed executables carry flags that write, delete, or consume state, so
# they are refused per-command rather than by the shared argument list.
_MUTATING_ARGUMENTS = {
    "ip": re.compile(
        r"^(?:add|del|delete|change|modify|replace|append|set|flush)$",
        re.IGNORECASE,
    ),
    "journalctl": re.compile(
        r"^(?:--rotate|--flush|--sync|--relinquish-var"
        r"|--vacuum-(?:size|time|files)(?:=.*)?)$",
        re.IGNORECASE,
    ),
    "dmesg": re.compile(
        r"^(?:-C|--clear|--read-clear"
        r"|--console-(?:level|on|off)(?:=.*)?)$",
        re.IGNORECASE,
    ),
    "find": re.compile(
        r"^(?:-fprint\d?|-fprintf|-flist|-F)$",
        re.IGNORECASE,
    ),
}

# The single source of truth for which arguments each policed tool accepts.
#
# Two planes share one classifier. Capability tools read the system; control
# tools report decisions and evidence. Both are argument-checked here, so an
# MCP client cannot reach a path outside read_roots by calling a control tool.
TOOL_ALLOWED_ARGS: dict[str, set[str]] = {
    "get_system_status": set(),
    "get_top_cpu_processes": {"limit"},
    "get_top_memory_processes": {"limit"},
    "find_files": {"directory", "name", "extension"},
    "search_text_file": {"path", "query"},
    "policy_decide": {"command"},
    "policy_show": set(),
    "evidence_report": {"hours", "max_events", "note"},
    "evidence_verify": {"path"},
    "approval_request": {"command", "ttl_seconds"},
    "approval_list": {"limit"},
}

# Control-plane tools answer questions about the gateway itself; capability
# tools read the host. main.py executes capability tools only, so these are
# reachable through the MCP front-end and are asserted as such by the
# self-check and the test suite.
CONTROL_TOOLS: frozenset[str] = frozenset({
    "policy_decide",
    "policy_show",
    "evidence_report",
    "evidence_verify",
    "approval_request",
    "approval_list",
})

# Integer arguments and the range that is accepted for each.
_TOOL_INTEGER_BOUNDS: dict[str, tuple[int, int]] = {
    "limit": (1, 10),
    "hours": (1, 8760),
    "max_events": (1, 500),
    # approval.py shortens this further to the policy lifetime; this range only
    # says what a well-formed request may ask for, and approval.py keeps its
    # own copy of the ceiling with a test asserting the two agree.
    "ttl_seconds": (1, 900),
}

# Arguments that name a filesystem location, so their *values* get the deny-path
# and read_roots checks above. Every tool carrying one of these is checked,
# capability or control plane alike; that is why this is keyed by argument name
# and not by tool name.
_PATH_ARGUMENTS = frozenset({"directory", "path"})


def _result(
    category: str,
    score: int,
    reason: str,
    *,
    blocked: bool = False,
    sensitive: bool = False,
    rule_id: str = "",
) -> dict:
    return RiskAssessment(
        category=category,
        score=score,
        requires_confirmation=not blocked,
        reason=reason,
        sensitive=sensitive,
        blocked=blocked,
        rule_id=rule_id,
    ).as_dict()


def _normalise(value: str) -> str:
    """Decode common hiding techniques before matching a command."""
    value = unicodedata.normalize("NFKC", value)
    value = "".join(char for char in value if char.isprintable() or char in "\r\n\t")
    value = urllib.parse.unquote(value)
    # A base64 blob is never a legitimate standalone operations command. Decode
    # it solely for inspection; decoding failures are harmless.
    for token in re.findall(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])", value):
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8", "ignore")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded:
            value += " " + decoded
    return value


def inspect_prompt(text: str, policy: Policy | None = None) -> dict:
    """Detect attempts to control the model rather than request assistance."""
    policy = policy or DEFAULT_POLICY
    normalised = _normalise(text).lower()
    if _PROMPT_INJECTION.search(normalised):
        return _result("CRITICAL", 100, "Prompt-injection pattern detected",
                       blocked=True, sensitive=True, rule_id="baseline.injection")
    for rule in policy.injection_rules:
        if rule.pattern.search(normalised):
            return _result(
                "CRITICAL", 100,
                f"Prompt-injection pattern detected: {rule.reason}",
                blocked=True, sensitive=True,
                rule_id=f"policy.injection_patterns.{rule.rule_id}",
            )
    return _result("LOW", 0, "No prompt-injection pattern detected",
                   rule_id="baseline.injection")


def _deny_rule_id(path: str) -> str:
    """Say whether a denial came from the immutable floor or from the operator."""
    origin = "floor" if path in BASELINE_DENY_PATHS else "policy"
    return f"{origin}.deny_path:{path}"


def _policy_denied(
    raw: str,
    inspected: str,
    executable: str,
    tokens: list[str],
    policy: Policy,
) -> dict | None:
    """Operator rules only ever add restrictions, and are checked last."""
    lowered = inspected.lower()

    if policy.is_denied_executable(executable):
        return _result(
            "CRITICAL", 100,
            f"'{executable}' is denied by policy",
            blocked=True, sensitive=True,
            rule_id=f"policy.deny_executables.{executable}",
        )

    for token in tokens[1:]:
        if token in policy.deny_arguments:
            return _result(
                "CRITICAL", 100,
                f"Argument '{token}' is denied by policy",
                blocked=True, sensitive=True,
                rule_id="policy.deny_arguments",
            )

    for denied in policy.effective_deny_paths:
        if denied.lower() in lowered:
            return _result(
                "CRITICAL", 100,
                f"Denied path referenced: {denied}",
                blocked=True, sensitive=True,
                rule_id=_deny_rule_id(denied),
            )

    for rule in policy.rules:
        if rule.pattern.search(lowered):
            return _result(
                "CRITICAL", 100,
                f"Policy rule '{rule.rule_id}': {rule.reason}",
                blocked=True, sensitive=True,
                rule_id=f"policy.rules.{rule.rule_id}",
            )

    return None


def classify_command(
    command: str,
    sensitive_paths: Iterable[str] | None = None,
    policy: Policy | None = None,
) -> dict:
    """Return a conservative assessment. Ambiguous commands are never runnable."""
    policy = policy or DEFAULT_POLICY

    if not isinstance(command, str) or not command.strip() or len(command) > 4096:
        return _result("CRITICAL", 100, "Empty, invalid, or oversized command",
                       blocked=True, sensitive=True, rule_id="baseline.input")

    raw = unicodedata.normalize("NFKC", command).strip()
    inspected = _normalise(raw)
    # Escaping a token is an obfuscation technique. Reject it rather than trying
    # to reproduce Bash's expansion rules.
    if "\\" in raw or _SHELL_SYNTAX.search(raw):
        return _result("CRITICAL", 100,
                       "Shell composition, expansion, or obfuscation detected",
                       blocked=True, sensitive=True, rule_id="baseline.shell_syntax")
    if inspected != raw and (_DESTRUCTIVE.search(inspected) or _SHELL_SYNTAX.search(inspected)):
        return _result("CRITICAL", 100, "Encoded dangerous shell payload detected",
                       blocked=True, sensitive=True, rule_id="baseline.encoded")

    try:
        tokens = shlex.split(raw, posix=True)
    except ValueError:
        return _result("CRITICAL", 100, "Invalid shell quoting",
                       blocked=True, sensitive=True, rule_id="baseline.quoting")
    if not tokens:
        return _result("CRITICAL", 100, "Empty command",
                       blocked=True, sensitive=True, rule_id="baseline.quoting")

    executable = tokens[0].rsplit("/", 1)[-1]
    if _INTERPRETERS.fullmatch(executable) or _INTERPRETERS.search(raw):
        return _result("CRITICAL", 100, "Interpreter or shell indirection is not allowed",
                       blocked=True, sensitive=True, rule_id="baseline.interpreter")
    if _DESTRUCTIVE.search(raw):
        return _result("CRITICAL", 100, "Destructive or network-capable command detected",
                       blocked=True, sensitive=True, rule_id="baseline.destructive")
    if (
        executable not in _READ_ONLY_EXECUTABLES
        and not policy.allowed_executable(executable)
    ):
        return _result("CRITICAL", 100, "Command is outside the read-only allow-list",
                       blocked=True, sensitive=True, rule_id="baseline.allow_list")
    if any(_UNSAFE_ARGUMENT.match(token) for token in tokens[1:]):
        return _result("CRITICAL", 100, "Command contains an unsafe option",
                       blocked=True, sensitive=True, rule_id="baseline.unsafe_argument")

    mutating = _MUTATING_ARGUMENTS.get(executable)
    if mutating and any(mutating.match(token) for token in tokens[1:]):
        offender = next(t for t in tokens[1:] if mutating.match(t))
        return _result(
            "CRITICAL", 100,
            f"'{executable} {offender}' writes or deletes; the executable is "
            "read-only only for some of its options",
            blocked=True, sensitive=True,
            rule_id="baseline.mutating_argument",
        )

    denied = _policy_denied(raw, inspected, executable, tokens, policy)
    if denied:
        return denied

    if _SENSITIVE_PATHS.search(raw):
        return _scored(_result("HIGH", 85, "Sensitive system path referenced",
                               sensitive=True, rule_id="baseline.sensitive_path"),
                       policy)
    if sensitive_paths and any(str(path).lower() in raw.lower() for path in sensitive_paths):
        return _scored(_result("HIGH", 80, "Configured sensitive resource referenced",
                               sensitive=True, rule_id="policy.sensitive_paths"),
                       policy)

    # Confirmation remains mandatory even for read-only commands; this is the
    # human-in-the-loop boundary, not a signal that a command is harmless.
    return _scored(_result("LOW", 10, "Single non-destructive command",
                           sensitive=False, rule_id="baseline.allow_list"),
                   policy)


def _scored(assessment: dict, policy: Policy) -> dict:
    """Apply the two operator knobs that can turn a 'ask the human' into a 'no'."""
    if policy.block_sensitive and assessment["sensitive"]:
        assessment = dict(assessment)
        assessment.update({
            "category": "CRITICAL",
            "score": 100,
            "blocked": True,
            "requires_confirmation": False,
            "reason": assessment["reason"] + " (policy block_sensitive=true)",
            "rule_id": "policy.block_sensitive",
        })

    if assessment["score"] > policy.max_score:
        assessment = dict(assessment)
        assessment.update({
            "category": "CRITICAL",
            "score": assessment["score"],
            "blocked": True,
            "requires_confirmation": False,
            "reason": (f"Risk score {assessment['score']} exceeds policy "
                       f"max_score {policy.max_score}"),
            "rule_id": "policy.max_score",
        })

    return assessment


def _resolve(candidate: str) -> Path | None:
    try:
        return Path(candidate).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def _under_root(candidate: Path, root: str) -> bool:
    root_path = Path.cwd() if root in (".", "") else Path(root).expanduser()
    try:
        root_path = root_path.resolve()
    except OSError:
        return False
    try:
        candidate.relative_to(root_path)
        return True
    except ValueError:
        return False


def classify_tool_call(
    tool_name: str,
    arguments: dict[str, Any],
    policy: Policy | None = None,
) -> dict:
    """Validate a diagnostic tool call, including argument VALUES.

    Checking argument names alone let the model point search_text_file at
    /etc/shadow and read it through the read-only path, bypassing every
    command-string rule. The tool boundary is checked here instead.
    """
    policy = policy or DEFAULT_POLICY

    if tool_name not in TOOL_ALLOWED_ARGS:
        return _result("CRITICAL", 100,
                       f"Unapproved diagnostic tool: {tool_name}",
                       blocked=True, sensitive=True, rule_id="baseline.tool_name")

    if not isinstance(arguments, dict):
        return _result("CRITICAL", 100, "Tool arguments must be an object",
                       blocked=True, rule_id="baseline.tool_arguments")

    unexpected = set(arguments) - TOOL_ALLOWED_ARGS[tool_name]
    if unexpected:
        return _result("CRITICAL", 100,
                       f"Unsupported argument(s): {', '.join(sorted(unexpected))}",
                       blocked=True, sensitive=True, rule_id="baseline.tool_arguments")

    for name, (low, high) in _TOOL_INTEGER_BOUNDS.items():
        if name in arguments:
            value = arguments[name]
            if type(value) is not int or not low <= value <= high:
                return _result(
                    "CRITICAL", 100,
                    f"Tool {name} must be an integer from {low} to {high}",
                    blocked=True, rule_id="baseline.tool_limit",
                )

    for key in _PATH_ARGUMENTS:
        if key not in arguments:
            continue

        value = arguments[key]
        if not isinstance(value, str) or not value.strip():
            return _result("CRITICAL", 100,
                           f"'{key}' must be a non-empty path string",
                           blocked=True, sensitive=True, rule_id="baseline.tool_path")

        resolved = _resolve(value)
        if resolved is None:
            return _result("CRITICAL", 100,
                           f"'{key}' could not be resolved as a path",
                           blocked=True, sensitive=True, rule_id="baseline.tool_path")

        posix = resolved.as_posix().lower()
        for denied in policy.effective_deny_paths:
            if denied.lower().rstrip("/") in posix:
                return _result(
                    "CRITICAL", 100,
                    f"Denied path referenced: {denied}",
                    blocked=True, sensitive=True,
                    rule_id=_deny_rule_id(denied),
                )

        if not any(_under_root(resolved, root) for root in policy.read_roots):
            return _result(
                "CRITICAL", 100,
                f"'{value}' is outside the policy read roots "
                f"({', '.join(policy.read_roots)})",
                blocked=True, sensitive=True,
                rule_id="policy.read_roots",
            )

    return _result("LOW", 10, f"Approved read-only call to {tool_name}",
                   rule_id="baseline.tool_allow_list")
