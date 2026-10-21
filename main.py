"""Secure dual-mode Linux copilot CLI behind a fail-closed policy gateway."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Annotated

# pyrefly: ignore [missing-import]
import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from evidence import (
    EvidenceError,
    build_report,
    policy_fingerprint,
    report_to_csv,
    sign_report,
    verify_report,
)
from approval import (
    ApprovalError,
    ApprovalStore,
    inspect_token,
    mint_token,
    mode_for,
    read_token_argument,
    redeem_token,
    request_approval,
    void_request,
)
from conversation import (
    load_history,
    append_turn,
    clear_history,
)
from gateway import (
    GatewayState,
    approval_database_path,
    decide_command,
    decide_tool_call,
    gateway_state,
    resolve_policy,
    screen_prompt,
)
from llm import LLMClient
from policy import (
    Policy,
    PolicyError,
    load_policy,
)
from providers import ToolCall
from tools import CAPABILITY_TOOLS, TOOL_SPECS, call_capability


# ============================================================
# APP
# ============================================================

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="A security-gated Linux operations assistant.",
)

console = Console()

# ============================================================
# GATEWAY CORE
# ============================================================

def _open_gateway() -> GatewayState:
    try:
        return gateway_state()
    except EvidenceError as exc:
        console.print(
            Panel(
                f"[bold red]Host identity is unusable, so no decision can be "
                f"recorded as signed evidence.[/]\n\n{exc}",
                title="Fail closed",
                border_style="red",
            )
        )
        raise typer.Exit(2)


STATE = _open_gateway()

IDENTITY = STATE.identity
AUDIT = STATE.audit


def _unsigned_notice() -> None:
    if not IDENTITY.has_private_key:
        console.print(
            "[dim yellow]Warning: rows are being stored without signatures "
            "(the 'cryptography' package is not installed). Run "
            "`pip install cryptography` before producing evidence.[/]"
        )


# ============================================================
# CAPABILITY TOOLS (registry lives in tools.py, shared with the MCP server)
# ============================================================


# ============================================================
# APPROVAL: the human "yes" as a signed, single-use artifact
# ============================================================

def _approvals() -> ApprovalStore:
    """The approval ledger for this host, created on first use."""
    return STATE.approvals or ApprovalStore(approval_database_path())


def _log_approval(
    status: str,
    subject: str,
    policy: Policy,
    reason: str,
    *,
    confirmed: bool = False,
) -> None:
    """Record an approval lifecycle step, including every failed one.

    The decision is recomputed rather than reused: a row saying "the human
    approved" is worth nothing if the risk picture printed beside it came from
    a different policy than the one in force now.
    """
    risk = dict(decide_command(subject, policy=policy))
    risk["rule_id"] = f"approval.{status}"
    AUDIT.log(
        f"approval:{status} {subject[:160]}",
        risk,
        status,
        confirmed,
        reason,
        policy,
    )


def _human_confirm(subject: str, decision: dict, ttl: int) -> bool:
    """The only thing that can mint an approval: a person, at this terminal."""
    console.print(
        Panel(
            f"[bold]{subject}[/]\n\n"
            f"Gateway decision: {decision['category']} "
            f"score {decision['score']} (rule {decision.get('rule_id', '')})\n"
            f"Reason: {decision['reason']}\n\n"
            f"[dim]Approving signs a token bound to these exact bytes, to this "
            f"host, to this policy fingerprint and to a {ttl}s deadline. It "
            f"buys exactly one execution, and it cannot be edited afterwards."
            f"[/]",
            title="Approval requested",
            border_style="yellow",
        )
    )
    # No glyph here: click writes this prompt with the console's own codec, and
    # a Windows cmd.exe on cp1252 raises UnicodeEncodeError on the arrow.
    return typer.confirm("  Approve and sign this?", default=False)


def _authorize_execution(subject: str, policy: Policy) -> bool:
    """Open, mint and spend one approval before one command runs.

    Interactive mode keeps the single-press experience of the old confirm and
    changes only what it leaves behind: three signed rows and a consumed
    token, instead of a boolean that vanished.
    """
    store = _approvals()

    if mode_for(policy) == "strict":
        console.print(
            "[bold red]approval.mode is strict:[/] this process will not "
            "execute a command it approved itself.\n"
            "[dim]Ask for an approval in one terminal and spend it in another:[/]\n"
            f"  python main.py --request-approval \"{subject}\"\n"
            "  python main.py --approve req-XXXXXXXX --token-out approval.token\n"
            "  python main.py --execute @approval.token"
        )
        _log_approval(
            "refused", subject, policy,
            "strict mode: execution requires a token minted by a separate "
            "human run",
        )
        return False

    try:
        request = request_approval(subject, policy, IDENTITY, store,
                                   requested_by="cli")
    except ApprovalError as exc:
        _log_approval("refused", subject, policy, str(exc))
        console.print(f"[bold red]No approval was opened:[/] {exc}")
        return False

    _log_approval(
        "requested", subject, policy,
        f"request {request['request_id']} opened; expires "
        f"{request['expires_at']}",
    )

    try:
        minted = mint_token(request["request_id"], policy, IDENTITY, store,
                            confirm=_human_confirm)
    except ApprovalError as exc:
        _log_approval("refused", subject, policy,
                      f"request {request['request_id']}: {exc}")
        console.print(f"[bold yellow]No approval:[/] {exc}")
        return False

    _log_approval(
        "minted", subject, policy,
        f"request {request['request_id']} signed by this host key "
        f"{IDENTITY.key_id}",
        confirmed=True,
    )

    try:
        redeem_token(minted["token"], subject, policy, IDENTITY, store)
    except ApprovalError as exc:
        _log_approval("refused", subject, policy,
                      f"request {request['request_id']}: {exc}")
        console.print(f"[bold red]Approval could not be spent:[/] {exc}")
        return False

    _log_approval(
        "redeemed", subject, policy,
        f"request {request['request_id']} spent; the token is now dead",
        confirmed=True,
    )
    return True


def _run_command(command: str) -> tuple[int, str]:
    """Execute one already-approved command and shape its output for display."""
    completed = subprocess.run(
        shlex.split(command, posix=True),
        shell=False,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    # Filter out noise from stderr (e.g. "Permission denied").
    _NOISE_PATTERNS = (
        "Permission denied",
        "No such file or directory",
        "Operation not permitted",
    )

    filtered_stderr = ""
    if completed.stderr:
        filtered_lines = [
            line for line in completed.stderr.splitlines()
            if not any(pattern in line for pattern in _NOISE_PATTERNS)
        ]
        filtered_stderr = "\n".join(filtered_lines).strip()

    stdout = (completed.stdout or "").strip()

    if stdout:
        return completed.returncode, stdout
    if filtered_stderr:
        return completed.returncode, filtered_stderr
    if completed.stderr:
        return completed.returncode, (
            "No results found.\n"
            "(Some directories were not accessible due to permissions.)"
        )
    return completed.returncode, "Command completed with no output."


def _fail_approval(detail: str, subject: str, policy: Policy) -> None:
    _log_approval("refused", subject, policy, detail)
    console.print(
        Panel(
            f"[bold red]Nothing was executed.[/]\n\n{detail}",
            title="Approval refused",
            border_style="red",
        )
    )
    raise typer.Exit(2)


def run_approval_request(command: str, policy: Policy, ttl: int | None) -> None:
    """Open an approval for one exact command, for a human to sign elsewhere."""
    store = _approvals()
    _unsigned_notice()
    try:
        request = request_approval(command, policy, IDENTITY, store,
                                   ttl_seconds=ttl, requested_by="cli")
    except ApprovalError as exc:
        _fail_approval(str(exc), command, policy)

    _log_approval(
        "requested", command, policy,
        f"request {request['request_id']} opened; expires {request['expires_at']}",
    )
    decision = json.loads(request["decision_json"])
    console.print(
        Panel(
            f"[bold]{command}[/]\n\n"
            f"request id: [cyan]{request['request_id']}[/]\n"
            f"gateway decision: {decision['category']} score "
            f"{decision['score']} (rule {decision['rule_id']})\n"
            f"policy fingerprint: {request['policy_sha']}\n"
            f"must be approved before: {request['expires_at']}\n\n"
            "[dim]Nothing has been approved yet. This request is not a token "
            "and runs nothing. A human signs it with:[/]  python main.py "
            f"--approve {request['request_id']}",
            title="Approval opened",
            border_style="yellow",
        )
    )
    raise typer.Exit(0)


def run_approval_approve(
    request_id: str,
    policy: Policy,
    token_out: str,
) -> None:
    """Mint the token: the human step, and the only step that can be."""
    store = _approvals()
    _unsigned_notice()
    try:
        minted = mint_token(request_id, policy, IDENTITY, store,
                            confirm=_human_confirm)
    except ApprovalError as exc:
        row = store.get(request_id=request_id)
        _fail_approval(str(exc), (row or {"subject": request_id})["subject"], policy)

    subject = minted["request"]["subject"]
    _log_approval(
        "minted", subject, policy,
        f"request {request_id} signed by this host key {IDENTITY.key_id}",
        confirmed=True,
    )

    if token_out:
        # A token is 900+ characters of base64. Printed in a panel it wraps, and
        # anything a person selects out of a terminal carries box characters and
        # smart quotes with it, so transcription is not a usable transport.
        path = Path(token_out).expanduser()
        try:
            path.write_text(minted["token"], encoding="ascii", newline="\n")
            if os.name != "nt":
                try:
                    path.chmod(0o600)
                except OSError:
                    pass
        except (OSError, UnicodeEncodeError) as exc:
            _fail_approval(
                f"the approval was signed but could not be written to "
                f"{path}: {exc}\n\nThe token is therefore in nobody's hands, "
                f"and request {request_id} stays minted. Re-run with a "
                "writable --token-out path, or void it with "
                f"--void-approval {request_id}.",
                subject,
                policy,
            )
        console.print(
            Panel(
                f"[bold]{subject}[/]\n\n"
                f"Signed by {IDENTITY.hostname} ({IDENTITY.key_id}) and written "
                f"to\n  {path}\n\n"
                f"It is one execution and it dies at {minted['expires_at']}. "
                "The token itself was not printed, so it is not sitting in this "
                "terminal's scrollback or shell history.\n\n"
                f"[dim]Spend it with:[/]  python main.py --execute @{path}\n"
                "[dim]Delete that file once it has been spent.[/]",
                title="Approval signed",
                border_style="green",
            )
        )
        raise typer.Exit(0)

    console.print(
        Panel(
            f"[bold]{subject}[/]\n\n"
            f"Copy this token to the machine and process that will run the "
            f"command. It is one execution and it dies at "
            f"{minted['expires_at']}.\n\n"
            f"[dim]{minted['token']}[/]\n\n"
            "[dim]On the executing side:[/]  python main.py --execute @token.txt\n"
            "[dim]Paste the token into token.txt rather than the command line: "
            "shell history and /proc/…/cmdline are both readable by other "
            "users.[/]\n"
            "[yellow]Prefer --token-out FILE next time. Transcribing this "
            "through a terminal usually picks up line breaks or box "
            "characters, and an altered token is refused rather than "
            "repaired.[/]",
            title="Approval signed",
            border_style="green",
        )
    )
    raise typer.Exit(0)


def run_approval_list(policy: Policy, limit: int) -> None:
    """Show the ledger: what is open, what is signed, what is already spent."""
    store = _approvals()
    store.expire_stale()
    table = Table(title="Approval ledger")
    table.add_column("request")
    table.add_column("state")
    table.add_column("command", overflow="fold")
    table.add_column("asked by")
    table.add_column("expires")
    for row in store.list(limit=limit):
        table.add_row(
            row["request_id"],
            row["state"],
            row["subject"],
            row["requested_by"],
            row["expires_at"],
        )
    console.print(table)
    counts = store.counts()
    console.print(
        "[dim]"
        + "   ".join(f"{state}={count}" for state, count in counts.items())
        + f"   ledger: {store.db_path}[/]"
    )
    raise typer.Exit(0)


def run_approval_show(token_text: str, policy: Policy) -> None:
    """Read a token without spending it: what it binds, and whether it is alive."""
    store = _approvals()
    try:
        token = read_token_argument(token_text)
        info = inspect_token(token, policy, IDENTITY, store)
    except ApprovalError as exc:
        _fail_approval(str(exc), token_text[:160], policy)
    console.print(
        Panel(
            "\n".join(f"{key}: {value}" for key, value in info.items()),
            title=f"Approval {info['request_id']}",
            border_style="green" if info["signature_valid"] else "red",
        )
    )
    if info["stored_state"] == "minted" and not info["expired"]:
        console.print("[dim]Still unspent. Reading a token never consumes it.[/]")
    raise typer.Exit(0)


def run_approval_void(request_id: str, policy: Policy) -> None:
    """Cancel an approval so it can never be spent, including a minted token."""
    store = _approvals()
    try:
        row = void_request(request_id, store, reason="voided by the operator")
    except ApprovalError as exc:
        _fail_approval(str(exc), request_id, policy)
    _log_approval(
        "voided", row["subject"], policy,
        f"request {request_id} voided; any token minted from it is dead",
    )
    console.print(
        f"[bold green]{request_id} is voided.[/] A token minted from it is now "
        "refused at redemption, and the void itself is a signed row."
    )
    raise typer.Exit(0)


def run_execute(token_text: str, policy: Policy) -> None:
    """Spend a token on the command it was minted for, once, here."""
    store = _approvals()
    _unsigned_notice()

    try:
        token = read_token_argument(token_text)
    except ApprovalError as exc:
        _fail_approval(str(exc), token_text[:160], policy)

    try:
        info = inspect_token(token, policy, IDENTITY, store)
    except ApprovalError as exc:
        _fail_approval(str(exc), "(unreadable token)", policy)

    row = store.get(request_id=info["request_id"])
    if row is None:
        _fail_approval(
            "this host's ledger has no record of that token, so there is no "
            "command text to bind it to. Approvals are not portable between "
            "machines.",
            "(no ledger record)",
            policy,
        )

    subject = row["subject"]

    try:
        redeem_token(token, subject, policy, IDENTITY, store)
    except ApprovalError as exc:
        _fail_approval(str(exc), subject, policy)

    _log_approval(
        "redeemed", subject, policy,
        f"request {row['request_id']} spent via --execute; the token is now dead",
        confirmed=True,
    )
    console.print(
        f"[bold green]Approval spent.[/] Running exactly the approved bytes:\n"
        f"[cyan]{subject}[/]"
    )

    try:
        returncode, output = _run_command(subject)
    except (OSError, subprocess.TimeoutExpired) as exc:
        _log_approval(
            "failed", subject, policy,
            f"approved and spent, but execution raised {type(exc).__name__}: {exc}",
            confirmed=True,
        )
        console.print(f"[bold red]Execution failed:[/] {exc}")
        raise typer.Exit(1)

    console.print(Panel(output, title=f"Exit code: {returncode}"))
    AUDIT.log(
        subject,
        dict(decide_command(subject, policy=policy), rule_id="approval.executed"),
        "executed",
        True,
        f"Ran under a single-use signed approval "
        f"(request {row['request_id']}); exit code {returncode}",
        policy,
    )
    raise typer.Exit(0 if returncode == 0 else 1)


# ============================================================
# SECURITY
# ============================================================

def _fail_closed(exc: PolicyError) -> None:
    console.print(
        Panel(
            f"[bold red]Policy could not be loaded, so every request is "
            f"blocked.[/]\n\n{exc}\n\n"
            "[dim]Fix the file, or run with --policy-lint to re-check it. "
            "The gateway never falls back to 'no policy'.[/]",
            title="Fail closed",
            border_style="red",
        )
    )
    raise typer.Exit(2)


def _safe_query(query: str, policy: Policy) -> bool:

    _unsigned_notice()

    risk = screen_prompt(query, policy)

    if risk["blocked"]:
        AUDIT.log(
            f"prompt: {query[:200]}",
            risk,
            "blocked",
            False,
            f"Prompt screened before the model was called (rule {risk['rule_id']})",
            policy,
        )
        console.print(
            f"[bold red]Request blocked:[/] "
            f"{risk['reason']}"
        )
        return False

    return True


def _open_llm(policy: Policy, subject: str) -> LLMClient:
    """Build the model client and record, in the audit log, who is about to
    read this host's data. A diagnosis ships the question and the contents of
    local files to the endpoint, so the endpoint belongs in the evidence.

    The row is written before the request, and its status is "attempted"
    rather than "executed": an unreachable endpoint must not be provable as a
    delivery that never happened.
    """
    llm = LLMClient(policy)
    AUDIT.log(
        f"ai:egress {llm.egress_label} {subject[:120]}",
        {
            "category": "ai_egress",
            "score": 0,
            "sensitive": not llm.local,
            "reason": "",
        },
        "attempted",
        False,
        (
            "Local endpoint only; nothing has left this machine"
            if llm.local
            else f"Question and tool results are about to be sent OFF-BOX to "
                 f"{llm.egress_label}"
        ),
        policy,
    )
    if not llm.local:
        console.print(
            f"[dim]Model endpoint (off-box): {llm.egress_label}[/]"
        )
    return llm


# ============================================================
# POLICY INSPECTION (no LLM, no execution)
# ============================================================

def run_policy_check(command: str, policy: Policy) -> None:

    """Show what the gateway would decide about a command, and why."""

    risk = decide_command(command, policy=policy)

    allowed = not risk["blocked"]
    colour = "green" if allowed else "red"
    decision = "ALLOW (requires confirmation)" if allowed else "BLOCK"

    table = Table(
        title=f"Policy decision: {decision}",
        show_header=False,
        title_style=f"bold {colour}",
    )
    table.add_column("field", style="cyan", no_wrap=True)
    table.add_column("value")
    table.add_row("command", command)
    table.add_row("decision", decision)
    table.add_row("risk category", risk["category"])
    table.add_row("risk score", str(risk["score"]))
    table.add_row("sensitive", "yes" if risk["sensitive"] else "no")
    table.add_row("matched rule", risk["rule_id"] or "-")
    table.add_row("reason", risk["reason"])
    table.add_row("policy source", policy.source_label)

    console.print(table)

    raise typer.Exit(0 if allowed else 2)


def run_policy_show(policy: Policy) -> None:

    """Print the effective policy: builtin floor plus operator additions."""

    table = Table(title="Effective policy", show_header=True)
    table.add_column("setting", style="cyan", no_wrap=True)
    table.add_column("value")
    table.add_column("origin", style="dim", no_wrap=True)

    for setting, value, origin in policy.describe():
        table.add_row(setting, value, origin)

    console.print(table)
    console.print(
        "[dim]The deny-by-default floor above is not configurable; a policy "
        "file can only add restrictions.[/]"
    )

    raise typer.Exit(0)


def run_policy_lint(policy: Policy) -> None:

    console.print(
        f"[bold green]Policy OK[/] — {policy.name} loaded from {policy.source_label}"
    )
    console.print(
        f"[dim]Read roots: {', '.join(policy.read_roots)}[/dim]\n"
        f"[dim]Custom rules: {len(policy.rules)}  "
        f"Denied paths: {len(policy.effective_deny_paths)}  "
        f"max_score: {policy.max_score}[/]"
    )

    raise typer.Exit(0)


def run_provider_show(policy: Policy) -> None:

    """Show which endpoint a diagnosis would use and who decided it.

    This makes no model call: it answers 'where does my data go' without
    sending any data anywhere.
    """
    from providers import ProviderError, choose_provider, is_loopback

    try:
        config = choose_provider(policy)
    except ProviderError as exc:
        console.print(f"[bold red]No model provider.[/] {exc}")
        raise typer.Exit(2)

    local = is_loopback(config.base_url)
    table = Table(title="Model endpoint", show_header=False)
    table.add_column("field", style="cyan", no_wrap=True)
    table.add_column("value")
    table.add_row("provider", config.name)
    table.add_row("model", config.model)
    table.add_row("endpoint", config.base_url)
    table.add_row("chosen by", config.origin)
    table.add_row(
        "policy egress rule",
        "local only (ai.allow_cloud: false)"
        if not policy.ai_allow_cloud else "cloud allowed (built-in default)",
    )
    console.print(table)
    console.print(
        "[bold green]Nothing leaves this machine.[/]" if local else
        "[bold yellow]A diagnosis sends your question and the contents of "
        "local files to that endpoint.[/]"
    )
    console.print(
        "[dim]Each model call also writes a signed 'ai:egress' audit row, so "
        "the evidence report says who saw what.[/]"
    )

    raise typer.Exit(0)


# ============================================================
# EVIDENCE (identity, signed rows, offline verification)
# ============================================================
def run_evidence_show(policy: Policy) -> None:

    """Show who is signing, what is being signed, and the log's state."""

    table = Table(title="Host evidence identity", show_header=False)
    table.add_column("field", style="cyan", no_wrap=True)
    table.add_column("value")

    for field, value in IDENTITY.describe():
        table.add_row(field, value)

    table.add_row("audit database", str(AUDIT.db_path))
    table.add_row("rows stored", str(AUDIT.count()))
    table.add_row("current policy", f"{policy.name} ({policy.source_label})")
    table.add_row("policy fingerprint", policy_fingerprint(policy))
    table.add_row("approval mode", mode_for(policy))
    table.add_row("approval ledger", str(_approvals().db_path))
    table.add_row(
        "approvals",
        ", ".join(f"{state}={count}"
                  for state, count in _approvals().counts().items() if count)
        or "(none yet)",
    )


    console.print(table)

    result = AUDIT.verify()

    if result["chain_ok"]:
        console.print(
            f"[bold green]Chain OK[/] — {result['rows']} rows recompute "
            f"cleanly; {result['signed_rows']} signed."
        )
    else:
        console.print("[bold red]Chain BROKEN[/]")
        for failure in result["failures"]:
            console.print(f"  [red]{failure}[/]")

    if result["unsigned_rows"]:
        console.print(
            f"[yellow]{result['unsigned_rows']} row(s) predate host signing "
            "and carry no signature. They still count as unsigned in a "
            "report.[/]"
        )

    console.print(
        "[dim]The actor is the OS username that ran the command. A local "
        "user can change their own username, so this proves what the "
        "gateway decided and under which policy, not a legally binding "
        "identity.[/]"
    )

    raise typer.Exit(0 if result["chain_ok"] else 2)


def run_report(
    policy: Policy,
    hours: int | None,
    limit: int | None,
    output_format: str,
    out: str | None,
    note: str,
) -> None:

    """Export the audit log as a signed, self-verifying evidence file."""

    rows = AUDIT.export(hours=hours, limit=limit)

    if not rows:
        console.print(
            "[bold yellow]No matching audit events[/] — the log is empty or "
            "the window excluded everything. An empty report is still "
            "signed, so a verifier can confirm the gateway ran and decided "
            "nothing."
        )

    report = build_report(
        rows,
        IDENTITY,
        policy,
        hours=hours,
        note=note,
    )

    try:
        report = sign_report(report, IDENTITY)
    except EvidenceError as exc:
        console.print(f"[bold red]Cannot sign the report:[/] {exc}")
        raise typer.Exit(2)

    body = (
        report_to_csv(report)
        if output_format == "csv"
        else json.dumps(report, indent=2) + "\n"
    )

    if out:
        destination = Path(out).expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(body, encoding="utf-8")
        console.print(
            f"[bold green]Evidence written[/] — {len(rows)} event(s) to "
            f"[cyan]{destination}[/]"
        )
        console.print(
            f"[dim]Verify it offline with: "
            f"python main.py --report-verify {destination.name}[/]"
        )
        if output_format == "csv":
            console.print(
                "[dim yellow]CSV is the event table only. Verification needs "
                "the JSON export.[/]"
            )
        raise typer.Exit(0)

    console.print(body)

    raise typer.Exit(0)


def run_report_verify(target: str) -> None:

    """Verify an evidence file with nothing but the file itself."""

    result = verify_report(target)

    if not result["loaded"]:
        # Nothing was read, so a check table would be theatre: every row would
        # say FAIL about a file that does not exist. Say what happened instead.
        for failure in result["failures"]:
            console.print(f"[red]{failure}[/]")
        console.print("[bold]NOT VERIFIED[/] — no evidence file was read.")
        raise typer.Exit(2)

    table = Table(title="Evidence verification", show_header=False)
    table.add_column("check", style="cyan", no_wrap=True)
    table.add_column("verdict")

    def mark(ok: bool) -> str:
        return "[green]PASS[/]" if ok else "[red]FAIL[/]"

    table.add_row("hash chain recomputed", mark(result["chain_ok"]))
    table.add_row("row signatures", mark(result["row_signatures_ok"]))
    table.add_row("summary cross-check", mark(result["summary_ok"]))
    table.add_row("document signature", mark(result["report_signature_ok"]))
    table.add_row(
        "events",
        f"{result['events']} total, {result['signed_events']} signed, "
        f"{result['unsigned_events']} unsigned",
    )
    table.add_row("host", result["host"] or "-")
    table.add_row("policy", result["policy"] or "-")
    table.add_row("scope", result.get("scope") or "-")

    console.print(table)

    if result.get("note"):
        console.print(f"[dim]{result['note']}[/]")

    for failure in result["failures"]:
        console.print(f"  [red]{failure}[/]")

    if result["ok"] and result["fully_signed"]:
        console.print(
            f"[bold green]TRUSTED[/] — all {result['events']} event(s) are "
            f"signed by {result['host']}, the chain recomputes, and this file "
            "has not been altered since it was exported."
        )
    elif result["ok"] and result["events"] == 0:
        console.print(
            "[bold cyan]AUTHENTIC, EMPTY[/] — the gateway signed a report "
            "containing no events for this window. That is a positive "
            "statement: nothing was decided and nothing was hidden."
        )
    elif result["ok"]:
        console.print(
            f"[bold yellow]AUTHENTIC, PARTLY UNPROVABLE[/] — the file is "
            f"unaltered and all {result['signed_events']} signature(s) check "
            f"out, but {result['unsigned_events']} event(s) carry no signature "
            "(written before host signing existed) and are evidence of the "
            "hash chain only."
        )
    else:
        console.print("[bold red]NOT TRUSTED[/] — see the failures above.")

    raise typer.Exit(0 if result["ok"] else 2)


# ============================================================
# TECH MODE
# ============================================================

def run_tech(query: str, policy: Policy) -> None:

    """Suggest safe Bash commands and let the user execute one."""

    if not _safe_query(query, policy):
        raise typer.Exit(2)

    if not policy.tech_enabled:
        console.print(
            "[bold red]Tech mode is disabled by policy "
            f"({policy.source}).[/]"
        )
        raise typer.Exit(2)

    if mode_for(policy) == "strict":
        console.print(
            "[yellow]approval.mode is strict: suggestions below can be "
            "reviewed but not executed from this process.[/]\n"
            "[dim]Open an approval in one terminal, sign it as a human in "
            "another, then spend it with --execute.[/]"
        )

    try:
        llm = _open_llm(policy, query)

        console.print("[cyan]⚡ Generating command suggestions...[/]")
        response = llm.tech_suggestions(query)

    except Exception as exc:

        console.print(
            f"[bold red]LLM request failed:[/] {exc}"
        )

        raise typer.Exit(1)

    # --------------------------------------------------------
    # FILTER: keep only commands that pass security checks
    # --------------------------------------------------------

    safe_suggestions = []
    blocked_count = 0

    for suggestion in response.suggestions:
        risk = decide_command(suggestion.command, policy=policy)
        if risk["blocked"]:
            # Recording the refusal is the point: the evidence trail shows
            # what the model proposed and which rule stopped it.
            AUDIT.log(
                suggestion.command,
                risk,
                "blocked",
                False,
                f"Blocked before display (rule {risk['rule_id']})",
                policy,
            )
            blocked_count += 1
        else:
            safe_suggestions.append((suggestion, risk))

    safe_suggestions = safe_suggestions[: policy.max_suggestions]

    if blocked_count:
        console.print(
            f"[bold yellow]{blocked_count} proposed command(s) were blocked "
            f"by policy and removed from the list.[/]"
        )

    if not safe_suggestions:

        console.print(
            "[bold yellow]No safe commands could be generated "
            "for this query.[/]\n"
            "[dim]Try using normal diagnostic mode instead:[/]\n"
            "  python main.py \"your query\""
        )

        return

    # --------------------------------------------------------
    # WALK THROUGH SUGGESTIONS ONE-BY-ONE
    # --------------------------------------------------------

    console.print(
        f"\n[bold cyan]Found {len(safe_suggestions)} "
        f"command suggestion(s) for your query:[/]\n"
    )

    for i, (suggestion, risk) in enumerate(safe_suggestions, 1):

        risk_color = (
            "yellow"
            if risk["category"] == "HIGH"
            else "green"
        )

        console.print(
            Panel(
                Syntax(
                    suggestion.command,
                    "bash",
                    theme="monokai",
                    word_wrap=True,
                ),
                title=f"[bold]Suggestion {i}/{len(safe_suggestions)}[/]",
                subtitle=f"[dim]{suggestion.description}[/dim]",
                border_style=risk_color,
            )
        )

        console.print(
            f"  Risk: [{risk_color}]"
            f"{risk['category']}"
            f"[/{risk_color}]  "
            f"[dim]allowed by {risk['rule_id']}[/dim]"
        )

        # One human press, but it now leaves a signed single-use artifact
        # behind instead of a boolean that vanished.
        if _authorize_execution(suggestion.command, policy):
            try:
                returncode, output = _run_command(suggestion.command)
            except (OSError, subprocess.TimeoutExpired) as exc:
                # The approval was already spent: an approval that produced a
                # failed run must not look reusable.
                _log_approval(
                    "failed", suggestion.command, policy,
                    f"approved and spent, but execution raised "
                    f"{type(exc).__name__}: {exc}",
                    confirmed=True,
                )
                console.print(f"[bold red]Execution failed:[/] {exc}")
                return

            console.print(
                Panel(
                    output,
                    title=f"Exit code: {returncode}",
                )
            )

            # Record the outcome as well as the approval; an approval with no
            # result is not evidence.
            AUDIT.log(
                suggestion.command,
                risk,
                "executed",
                True,
                f"Exit code {returncode} (rule {risk['rule_id']}), under a "
                "single-use signed approval",
                policy,
            )

            return  # Done — only run one command.

        console.print("")  # Blank line before next suggestion.

    console.print("[dim]No commands were executed.[/]")


# ============================================================
# NORMAL DIAGNOSTIC MODE
# ============================================================

def run_capability_call(call: ToolCall, policy: Policy) -> dict | list | str:
    """Decide one tool call, then run it. Every outcome is audited.

    A refusal comes back as data instead of raising, because the model asked
    for several calls at once: dropping the whole diagnosis over the one call
    policy refused would hide the results it did clear, and the model is told
    exactly which call was refused and why.
    """
    if call.name not in CAPABILITY_TOOLS:
        raise RuntimeError(
            f"Model requested an unapproved "
            f"diagnostic tool: {call.name}"
        )

    arguments = dict(call.arguments)

    decision = decide_tool_call(call.name, arguments, policy)

    if decision["blocked"]:
        AUDIT.log(
            f"{call.name} {arguments}",
            decision,
            "blocked",
            False,
            f"Tool call blocked before execution "
            f"(rule {decision['rule_id']})",
            policy,
        )
        return {
            "blocked": True,
            "reason": decision["reason"],
            "rule_id": decision["rule_id"],
        }

    # ----------------------------------------------------
    # EXECUTE ONLY OUR LOCAL READ-ONLY FUNCTION
    # ----------------------------------------------------

    try:
        output = call_capability(call.name, arguments)
    except Exception as exc:
        AUDIT.log(
            f"{call.name} {arguments}",
            decision,
            "failed",
            False,
            f"Read-only capability raised: {exc}",
            policy,
        )
        return {"error": str(exc)}

    AUDIT.log(
        f"{call.name} {arguments}",
        decision,
        "executed",
        False,
        "Read-only capability ran after the policy cleared it",
        policy,
    )
    return output


def run_normal(query: str, policy: Policy) -> None:

    """Run read-only Linux diagnosis with conversation memory."""

    if not _safe_query(query, policy):
        raise typer.Exit(2)

    # Load prior conversation context (if any).
    history = load_history()

    try:

        llm = _open_llm(policy, query)

        # ----------------------------------------------------
        # ASK THE MODEL, RUN WHAT IT EARNED, ANSWER. The loop
        # lives in llm.diagnose; every call passes through the
        # policy gate above, one row of audit per call.
        # ----------------------------------------------------

        with console.status("[cyan]🔍 Analysing your query...[/]"):
            diagnosis = llm.diagnose(
                query=query,
                tools=TOOL_SPECS,
                history=history,
                execute=lambda call: run_capability_call(call, policy),
            )

    except Exception as exc:

        console.print(
            f"[bold red]Diagnosis failed:[/] {exc}"
        )

        raise typer.Exit(1)

    # Save the exchange to history.
    append_turn("user", query)
    append_turn("model", diagnosis)

    console.print(
        Panel(
            diagnosis,
            title="Linux diagnostic copilot",
            border_style="cyan",
        )
    )


# ============================================================
# CLI DISPATCH
# ============================================================

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,

    query: Annotated[
        str | None,
        typer.Argument(
            help=(
                "Describe what is wrong with "
                "your Linux system."
            )
        ),
    ] = None,

    tech_mode: Annotated[
        bool,
        typer.Option(
            "--tech",
            help=(
                "Generate one gated Bash command "
                "instead of running diagnostics."
            ),
        ),
    ] = False,

    new_conversation: Annotated[
        bool,
        typer.Option(
            "--new",
            help=(
                "Start a fresh conversation, "
                "clearing any prior context."
            ),
        ),
    ] = False,

    reset_key: Annotated[
        bool,
        typer.Option(
            "--reset-key",
            help="Delete the .env file next to the code, which is where an "
                 "API key is stored if you put one there.",
        ),
    ] = False,

    provider_show: Annotated[
        bool,
        typer.Option(
            "--provider-show",
            help="Show which model endpoint a diagnosis would use, who chose "
                 "it, and whether host data leaves this machine. Makes no call.",
        ),
    ] = False,

    policy_path: Annotated[
        str | None,
        typer.Option(
            "--policy",
            help="Path to a policy.yaml. Defaults to policy.yaml next to "
                 "this file, then the built-in floor.",
        ),
    ] = None,

    check: Annotated[
        str | None,
        typer.Option(
            "--policy-check",
            help="Ask the gateway what it would decide about a command. "
                 "Never calls the model and never executes anything.",
        ),
    ] = None,

    show_policy: Annotated[
        bool,
        typer.Option(
            "--policy-show",
            help="Print the effective policy and where each setting came from.",
        ),
    ] = False,

    lint_policy: Annotated[
        bool,
        typer.Option(
            "--policy-lint",
            help="Validate a policy file and report the first problem.",
        ),
    ] = False,

    evidence_show: Annotated[
        bool,
        typer.Option(
            "--evidence-show",
            help="Show this host's signing identity and the audit log state.",
        ),
    ] = False,

    report: Annotated[
        bool,
        typer.Option(
            "--report",
            help="Export the audit log as a signed evidence report.",
        ),
    ] = False,

    report_verify: Annotated[
        str | None,
        typer.Option(
            "--report-verify",
            help="Verify an exported evidence file using only that file.",
        ),
    ] = None,

    last: Annotated[
        int | None,
        typer.Option(
            "--last",
            help="Restrict the report to events from the last N hours.",
            min=1,
        ),
    ] = None,

    limit: Annotated[
        int | None,
        typer.Option(
            "--limit",
            help="Restrict the report to the N most recent events.",
            min=1,
        ),
    ] = None,

    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            help="Report format: json (verifiable) or csv (spreadsheet).",
        ),
    ] = "json",

    out: Annotated[
        str | None,
        typer.Option(
            "--out",
            help="Write the report to this file instead of stdout.",
        ),
    ] = None,

    note: Annotated[
        str,
        typer.Option(
            "--note",
            help="A one-line context string stored inside the report.",
        ),
    ] = "",

    approval_request: Annotated[
        str,
        typer.Option(
            "--request-approval",
            help="Open an approval for this exact command so a human can sign "
                 "it with --approve. Runs nothing.",
        ),
    ] = "",

    approval_ttl: Annotated[
        int,
        typer.Option(
            "--approval-ttl",
            help="Shorten this approval's lifetime in seconds (0 keeps the "
                 "policy default; the gateway ceiling cannot be raised).",
            min=0,
        ),
    ] = 0,

    approve: Annotated[
        str,
        typer.Option(
            "--approve",
            help="Mint a single-use signed token for an open request id. This "
                 "is the human step and needs this terminal.",
        ),
    ] = "",

    token_out: Annotated[
        str,
        typer.Option(
            "--token-out",
            help="With --approve, write the signed token to this file instead "
                 "of printing it, so it never passes through a terminal, a "
                 "scrollback or shell history. Spend it with --execute @PATH.",
        ),
    ] = "",

    approval_list: Annotated[
        bool,
        typer.Option(
            "--approval-list",
            help="Show the approval ledger: open, signed, spent, void, expired.",
        ),
    ] = False,

    approval_show: Annotated[
        str,
        typer.Option(
            "--approval-show",
            help="Read a token -- or @file, or - for stdin -- without spending "
                 "it: what it binds to, and whether it is still alive.",
        ),
    ] = "",

    approval_void: Annotated[
        str,
        typer.Option(
            "--void-approval",
            help="Cancel an open or minted approval so it can never be spent.",
        ),
    ] = "",

    execute: Annotated[
        str,
        typer.Option(
            "--execute",
            help="Spend a signed approval token (or @file, or - for stdin) and "
                 "run the command it was minted for, once.",
        ),
    ] = "",
) -> None:

    """
    Security-gated Linux operations assistant.

    Normal mode:
        main.py "why is my system slow?"

    Tech mode:
        main.py --tech "show disk usage"
        main.py tech "show disk usage"

    Policy:
        main.py --policy-check "rm -rf /var/log"
        main.py --policy-show
        main.py --policy prod.yaml --policy-check "journalctl -xe"

    Where the model runs:
        main.py --provider-show

    Approval (a signed, single-use token binds a human yes to exact bytes):
        main.py --request-approval "df -h"
        main.py --approve req-1a2b3c4d
        main.py --approval-list
        main.py --approval-show @token.txt
        main.py --void-approval req-1a2b3c4d
        main.py --execute @token.txt

    Evidence:
        main.py --evidence-show
        main.py --report --last 24 --out evidence.json
        main.py --report-verify evidence.json
    """

    # Handle API key reset if requested.
    if reset_key:
        from pathlib import Path
        env_path = Path(__file__).resolve().parent / ".env"
        try:
            if env_path.exists():
                env_path.unlink()
                console.print(
                    "[bold yellow].env has been deleted.[/]\n"
                    "[dim]Nothing is prompted for on the next run: set "
                    "GEMINI_API_KEY (or an SSM_* provider variable) in the "
                    "environment or a new .env, or the gateway will refuse to "
                    "choose a provider.[/]"
                )
            else:
                console.print("[bold yellow]No .env file found; nothing to reset.[/]")
        except Exception as e:
            console.print(f"[bold red]Failed to reset API key: {e}[/]")

    # --------------------------------------------------------
    # EVIDENCE VERIFICATION: pure math on the file, so it runs
    # before this host's own policy is even loaded.
    # --------------------------------------------------------

    if report_verify:
        run_report_verify(report_verify)

    # --------------------------------------------------------
    # POLICY COMMANDS: inspect the boundary, never cross it.
    # --------------------------------------------------------

    if lint_policy:
        try:
            policy = (
                load_policy(policy_path)
                if policy_path
                else resolve_policy(None)
            )
        except PolicyError as exc:
            console.print(f"[bold red]Policy invalid:[/] {exc}")
            raise typer.Exit(1)
        run_policy_lint(policy)

    try:
        policy = resolve_policy(policy_path)
    except PolicyError as exc:
        _fail_closed(exc)

    if show_policy:
        run_policy_show(policy)

    if provider_show:
        run_provider_show(policy)

    if check:
        run_policy_check(check, policy)

    # --------------------------------------------------------
    # APPROVAL: the only path that can lead to execution.
    # --------------------------------------------------------

    if approval_request:
        run_approval_request(
            approval_request, policy,
            approval_ttl if approval_ttl > 0 else None,
        )

    if approve:
        run_approval_approve(approve, policy, token_out)

    if approval_void:
        run_approval_void(approval_void, policy)

    if approval_show:
        run_approval_show(approval_show, policy)

    if approval_list:
        run_approval_list(policy, limit or 20)

    if execute:
        run_execute(execute, policy)

    # --------------------------------------------------------
    # EVIDENCE: who signed what, and the exportable proof.
    # --------------------------------------------------------

    if evidence_show:
        run_evidence_show(policy)

    if report:
        if output_format not in ("json", "csv"):
            console.print(
                f"[bold red]Unknown --format {output_format!r}; "
                "use json or csv.[/]"
            )
            raise typer.Exit(2)

        run_report(policy, last, limit, output_format, out, note)

    # No query and no subcommand.
    if not query:

        if ctx.invoked_subcommand is None:

            console.print(ctx.get_help())

        return

    if new_conversation:
        clear_history()

    if tech_mode:

        run_tech(query, policy)

    else:

        run_normal(query, policy)


# ============================================================
# COMPATIBILITY DISPATCH
# ============================================================

if __name__ == "__main__":

    # Allow BOTH:
    #
    # python main.py --tech "show disk usage"
    #
    # and:
    #
    # python main.py tech "show disk usage"
    #
    # This converts the second form into the first before
    # Typer parses the arguments.

    args = sys.argv[1:]

    if args and args[0] == "tech":

        sys.argv = [
            sys.argv[0],
            "--tech",
            *args[1:],
        ]

    # Allow `main.py policy check "rm -rf /"` as well as --policy-check.
    if len(args) >= 3 and args[0] == "policy" and args[1] == "check":

        sys.argv = [
            sys.argv[0],
            "--policy-check",
            *args[2:],
        ]

    app()
