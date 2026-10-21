"""A read-only window onto the gateway, in two modes and with no write path.

Everything in this project is decided by one rule: the model asks, policy
decides, a human approves, and the host records. A web page that could do any of
those three things would become the hole in the design, so it cannot. There is
no command input, no tool call, no approve, no mint, no redeem and no execute
anywhere in this file - not because the buttons are hidden, but because the
routes do not exist.

Two modes, deliberately different in what they may see:

``--report FILE`` (or ``--serve-reports``)
    An auditor's viewer. It reads one signed evidence document and re-verifies
    the hash chain, every row signature and the document signature using only
    the key inside that file. It never opens this host's ledger, never touches
    the signing key and needs no secret, which is what makes it the mode that
    can be deployed on someone else's machine.

Local mode (the default)
    The operator's console: this host's identity, the live audit chain, the
    policy ladder and the approval ledger. It may READ those, and it binds to
    loopback only - a routable bind is refused. Serving the live ledger over a
    network interface would hand a stranger the shape of this machine's
    decisions, and a page like that is the one an attacker would target first.

Run it:
    python console.py                       # http://127.0.0.1:8788, this host
    python console.py --report report.json  # verify one file, loopback
    python console.py --serve-reports --bind 0.0.0.0 --port 8080
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from evidence import (
    EvidenceError,
    build_report,
    policy_fingerprint,
    report_to_csv,
    sign_report,
    verify_report,
)
from gateway import GatewayState, gateway_state, resolve_policy
from policy import Policy
from providers import ProviderError, choose_provider, is_loopback

# A report is a few hundred rows of text. Anything larger is not a report, and
# reading it into memory would be the DoS rather than the point.
MAX_REPORT_BYTES = 8 * 1024 * 1024

LOOPBACK_BINDS = ("127.0.0.1", "localhost", "::1")

# Uploaded reports are stored under a name this server chose, never one the
# client sent, so no path from a client can be followed.
REPORT_ID = re.compile(r"\A[0-9a-f]{32}\Z")

DEFAULT_PORT = 8788


class ConsoleError(Exception):
    """The console was asked to do something it is not allowed to do."""


# ============================================================
# VERDICT (one implementation, shared with the CLI wording)
# ============================================================

def verdict_of(result: dict) -> tuple[str, str, str]:
    """Return ``(label, css class, sentence)`` for one verification result.

    Kept separate from both the terminal and the page so the two can never
    disagree about what a report means.
    """
    if result.get("ok") and result.get("fully_signed"):
        return ("TRUSTED", "ok",
                f"All {result['events']} event(s) are signed by "
                f"{html.escape(str(result.get('host') or ''))}, the chain "
                "recomputes, and this file has not been altered since it was "
                "exported.")

    if result.get("ok") and result.get("events") == 0:
        return ("AUTHENTIC, EMPTY", "empty",
                "The gateway signed a report containing no events for this "
                "window. That is a positive statement: nothing was decided and "
                "nothing was hidden.")

    if result.get("ok"):
        return ("AUTHENTIC, PARTLY UNPROVABLE", "warn",
                f"The file is unaltered and all {result.get('signed_events')} "
                f"signature(s) check out, but {result.get('unsigned_events')} "
                "event(s) carry no signature and are evidence of the hash "
                "chain only.")

    return ("NOT TRUSTED", "bad",
            "The report did not survive verification. Every failure is listed "
            "below.")


# ============================================================
# DATA (pure reads; the page builders below only format these)
# ============================================================

def state() -> GatewayState:
    return gateway_state()


def chain_view() -> dict:
    """This host's own ledger, verified the same way a report is."""
    audit = state().audit
    check = audit.verify()
    return {
        "rows": audit.count(),
        "chain_ok": bool(check.get("chain_ok")),
        "signed_ok": bool(check.get("signed_ok")),
        "unsigned_rows": int(check.get("unsigned_rows") or 0),
        "failures": list(check.get("failures") or []),
    }


def identity_view() -> list[tuple[str, str]]:
    return [(str(field), str(value)) for field, value in state().identity.describe()]


def egress_view(policy: Policy) -> tuple[str, str]:
    """Where host data goes, without sending any of it anywhere."""
    try:
        config = choose_provider(policy)
    except ProviderError as exc:
        return "no provider resolved", str(exc).splitlines()[0]
    where = "on this machine" if is_loopback(config.base_url) else "OFF-BOX"
    return (f"{config.name} / {config.model}",
            f"{config.base_url} ({where}); chosen by {config.origin}")


def recent_rows(limit: int = 50, status: str = "",
                policy: str = "") -> list[dict]:
    """Newest-first slice of the ledger, optionally filtered.

    Filters are compared in Python over at most the stored rows, so nothing here
    can become a query an input controls.
    """
    rows = state().audit.export()
    wanted_status = (status or "").strip().lower()
    wanted_policy = (policy or "").strip().lower()
    if wanted_status:
        rows = [row for row in rows
                if str(row.get("status", "")).lower() == wanted_status]
    if wanted_policy:
        rows = [row for row in rows
                if wanted_policy in str(row.get("policy_sha", "")).lower()]
    return list(reversed(rows[-max(1, min(int(limit), 500)):]))


def approvals_view(limit: int = 25) -> dict:
    store = state().approvals
    if store is None:
        return {"rows": [], "counts": {}, "note": "no approval ledger in this state"}
    return {"rows": store.list(limit=max(1, min(int(limit), 200))),
            "counts": store.counts(), "note": ""}


def policy_view(policy: Policy) -> dict:
    return {
        "name": policy.name,
        "fingerprint": policy_fingerprint(policy),
        "rows": [(str(setting), str(value)) for setting, value, _ in
                 policy.describe()],
    }


def fresh_report(policy: Policy, note: str = "") -> dict:
    """Build and sign a report of this host's whole ledger."""
    audit = state().audit
    report = build_report(audit.export(), state().identity, policy, note=note)
    return sign_report(report, state().identity)


# ============================================================
# HTML
# ============================================================

STYLE = """
:root { color-scheme: light dark }
body { font: 15px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
       margin: 0; background: #10141a; color: #dde3ea }
header { padding: 14px 22px; border-bottom: 1px solid #2b3340;
         display: flex; gap: 18px; align-items: baseline; flex-wrap: wrap }
header b { font-size: 16px; letter-spacing: .3px }
header a { color: #8ec6ff; text-decoration: none }
main { padding: 18px 22px 40px; max-width: 1150px }
h1 { font-size: 17px; margin: 0 0 12px }
h2 { font-size: 15px; margin: 22px 0 8px; color: #9fb0c4 }
table { border-collapse: collapse; width: 100% }
th, td { text-align: left; padding: 5px 10px; border-bottom: 1px solid #222935;
         vertical-align: top; word-break: break-word }
th { color: #9fb0c4; font-weight: 600 }
.kv td:first-child { color: #9fb0c4; width: 220px }
.badge { padding: 2px 9px; border-radius: 4px; font-weight: 700 }
.ok { background: #14431f; color: #8ff0a4 }
.bad { background: #4d1418; color: #ff9ba1 }
.warn { background: #4a3a10; color: #ffd479 }
.empty { background: #14404d; color: #8fe3ff }
.muted { color: #8494a8 }
ul.failures li { color: #ff9ba1 }
form { margin: 0 0 14px }
textarea { width: 100%; height: 160px; background: #0b0f14; color: #dde3ea;
           border: 1px solid #2b3340; padding: 8px }
input, button { font: inherit; background: #0b0f14; color: #dde3ea;
                border: 1px solid #2b3340; padding: 6px 9px }
button { background: #1d2a3a; cursor: pointer }
code { color: #ffd479 }
"""

NAV_LOCAL = (("/", "overview"), ("/audit", "audit log"),
             ("/policy", "policy"), ("/approvals", "approvals"),
             ("/report.json", "signed report"))

NAV_REPORT = (("/", "verify a report"),)


def page(title: str, body: str, nav: tuple, note: str) -> str:
    links = " · ".join(
        f'<a href="{html.escape(path, quote=True)}">{html.escape(label)}</a>'
        for path, label in nav
    )
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>{STYLE}</style></head>"
        f"<body><header><b>linux-ai-ssm gateway console</b><span>{links}</span>"
        f"<span class=muted>{html.escape(note)}</span></header>"
        f"<main>{body}</main></body></html>"
    )


def kv_table(pairs: list[tuple[str, str]]) -> str:
    rows = "".join(
        f"<tr><td>{html.escape(key)}</td><td>{html.escape(value)}</td></tr>"
        for key, value in pairs
    )
    return f"<table class=kv>{rows}</table>"


def row_table(rows: list[dict]) -> str:
    if not rows:
        return "<p class=muted>Nothing in the ledger matches.</p>"
    head = "".join(f"<th>{html.escape(column)}</th>" for column in
                   ("id", "timestamp", "status", "rule", "category", "score",
                    "signed", "command / event", "reason"))
    body = ""
    for row in rows:
        body += (
            "<tr>"
            f"<td>{html.escape(str(row.get('id', '')))}</td>"
            f"<td>{html.escape(str(row.get('timestamp', '')))}</td>"
            f"<td>{html.escape(str(row.get('status', '')))}</td>"
            f"<td>{html.escape(str(row.get('rule_id', '')))}</td>"
            f"<td>{html.escape(str(row.get('category', '')))}</td>"
            f"<td>{html.escape(str(row.get('score', '')))}</td>"
            f"<td>{'yes' if row.get('signature') else 'no'}</td>"
            f"<td>{html.escape(str(row.get('command', '')))}</td>"
            f"<td>{html.escape(str(row.get('reason', '')))}</td>"
            "</tr>"
        )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def badge(label: str, css: str) -> str:
    return f"<span class='badge {css}'>{html.escape(label)}</span>"


# ============================================================
# PAGES
# ============================================================

def overview_page(policy: Policy) -> str:
    chain = chain_view()
    label = badge("CHAIN OK" if chain["chain_ok"] else "CHAIN BROKEN",
                  "ok" if chain["chain_ok"] else "bad")
    signed = badge("SIGNED" if chain["signed_ok"] else "UNSIGNED ROWS",
                   "ok" if chain["signed_ok"] else "warn")
    endpoint, detail = egress_view(policy)

    body = (
        f"<h1>host evidence {label} {signed}</h1>"
        + kv_table([
            ("audit rows", str(chain["rows"])),
            ("unsigned rows", str(chain["unsigned_rows"])),
            ("policy", policy.name),
            ("policy fingerprint", policy_fingerprint(policy)),
            ("model endpoint", endpoint),
        ])
        + f"<p class=muted>{html.escape(detail)}</p>"
        + ("<h2>what this host signs with</h2>" + kv_table(identity_view())
           + "<h2>verification</h2>"
           + ("<p class=muted>Every row's hash and signature recompute.</p>"
              if not chain["failures"] else
              "<ul class=failures>" + "".join(
                  f"<li>{html.escape(str(f))}</li>" for f in chain["failures"])
              + "</ul>")
           + "<p class=muted>Read-only by construction: this page can show "
             "decisions, and cannot make one. It binds to loopback, so only "
             "someone at this keyboard can see the live ledger.</p>")
    )
    return page("gateway console", body, NAV_LOCAL, "live ledger, loopback only")


def audit_page(query: dict) -> str:
    limit = (query.get("limit") or ["50"])[0]
    status = (query.get("status") or [""])[0]
    rows = recent_rows(limit=int(limit) if limit.isdigit() else 50, status=status)
    filters = kv_table([
        ("shown", f"{len(rows)} newest rows"),
        ("status filter", status or "all"),
    ])
    body = ("<h1>audit log</h1>" + filters
            + f'<form method=get action=/audit>'
              f'<input name=status value="{html.escape(status, quote=True)}" '
              f'placeholder="status: executed, blocked, refused, queried">'
              f'<input name=limit value="{html.escape(limit, quote=True)}" size=4>'
              f'<button>apply</button></form>'
            + row_table(rows))
    return page("audit log", body, NAV_LOCAL, "newest first, never edited")


def policy_page(policy: Policy) -> str:
    view = policy_view(policy)
    body = (f"<h1>policy: {html.escape(view['name'])}</h1>"
            + kv_table(view["rows"])
            + f"<p class=muted>Fingerprint {html.escape(view['fingerprint'])} "
              "is written into every audit row, so a report says which policy "
              "made each decision. The deny-by-default floor is not a setting "
              "and cannot be shown as one.</p>")
    return page("policy", body, NAV_LOCAL, "tighten-only")


def approvals_page() -> str:
    view = approvals_view()
    counts = ", ".join(f"{state_name}={count}"
                       for state_name, count in sorted(view["counts"].items()))
    rows = view["rows"]
    table = "<p class=muted>Nothing has been requested.</p>" if not rows else (
        "<table><thead><tr>" + "".join(
            f"<th>{html.escape(column)}</th>" for column in
            ("requested", "command", "state", "expires", "minted by",
             "has token")) + "</tr></thead><tbody>"
        + "".join(
            "<tr>"
            f"<td>{html.escape(str(row.get('issued_at', '')))}</td>"
            f"<td>{html.escape(str(row.get('command', '')))}</td>"
            f"<td>{html.escape(str(row.get('state', '')))}</td>"
            f"<td>{html.escape(str(row.get('expires_at', '')))}</td>"
            f"<td>{html.escape(str(row.get('requested_by', '')))}</td>"
            f"<td>{'yes' if row.get('token_sha') else 'no'}</td>"
            "</tr>" for row in rows)
        + "</tbody></table>")

    body = (f"<h1>approval ledger</h1><p class=muted>{html.escape(counts)}"
            f"{' — ' + html.escape(view['note']) if view['note'] else ''}</p>"
            + table
            + "<p class=muted>An approval is spent by one execution and then "
              "never again. This page cannot mint, redeem or void one: a token "
              "only means something when a human at this keyboard signs it, and "
              "no page gets to be that human.</p>")
    return page("approvals", body, NAV_LOCAL, "read-only ledger")


def verify_page(problem: str = "") -> str:
    body = (
        "<h1>verify a signed evidence report</h1>"
        "<p class=muted>Paste the report, or choose the file. The key that "
        "signed it is inside the document, so nothing here needs a secret and "
        "nothing here reads this machine's ledger.</p>"
        + (f"<p class='badge bad'>{html.escape(problem)}</p>" if problem else "")
        + "<form method=post action=/verify enctype=multipart/form-data>"
          "<input type=file name=report accept=.json,application/json>"
          "<button>verify file</button></form>"
          "<form method=post action=/verify>"
          "<textarea name=report placeholder='{&quot;report_version&quot;: ...}'></textarea>"
          "<button>verify pasted text</button></form>"
    )
    return page("verify a report", body, NAV_REPORT, "no host access")


def report_page(report_id: str, result: dict) -> str:
    label, css, sentence = verdict_of(result)
    pairs = [
        ("verdict", label),
        ("events", f"{result.get('events', 0)} total, "
                   f"{result.get('signed_events', 0)} signed, "
                   f"{result.get('unsigned_events', 0)} unsigned"),
        ("host", str(result.get("host") or "-")),
        ("policy", str(result.get("policy") or "-")),
        ("scope", str(result.get("scope") or "-")),
        ("note", str(result.get("report_note") or "-")),
        ("verified with", str(result.get("note") or "-")),
    ]
    failures = "".join(
        f"<li>{html.escape(str(failure))}</li>"
        for failure in result.get("failures") or []
    )
    body = (
        f"<h1>{badge(label, css)}</h1><p>{sentence}</p>" + kv_table(pairs)
        + (f"<ul class=failures>{failures}</ul>" if failures else "")
        + f"<p class=muted>Verification id {html.escape(report_id)}. The "
          "document is kept so this page can be re-checked; it is stored under "
          "a name this server chose, never under the uploaded filename.</p>"
    )
    return page(f"report {report_id[:8]}", body, NAV_REPORT, "verified offline")


# ============================================================
# THE SERVER
# ============================================================

class ConsoleServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    """Routes, and nothing else. Every page builder above is a pure read."""

    server_version = "gateway-console"
    sys_version = ""

    # Set by serve(): policy for local mode, uploads dir for report mode.
    local_mode: bool = True
    policy: Policy | None = None
    uploads: Path = Path()
    note: str = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        """One line per request, and never a byte of the request body."""
        sys.stderr.write("console %s - %s\n" % (
            self.address_string(), fmt % args))

    def _send(self, status: int, body: str, content_type: str,
              extra: dict[str, str] | None = None) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        # The audit rows are model-authored strings. A strict CSP is cheap and
        # removes any doubt that a stored command can execute in a viewer.
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'")
        self.send_header("Referrer-Policy", "no-referrer")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def _html(self, body: str, status: int = 200) -> None:
        self._send(status, body, "text/html; charset=utf-8")

    def _redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _not_found(self) -> None:
        self._html(page("not found", "<h1>404</h1>",
                        NAV_LOCAL if self.local_mode else NAV_REPORT, self.note),
                   404)

    def do_GET(self) -> None:  # noqa: N802 - http.server's name
        self._route("GET")

    def do_HEAD(self) -> None:  # noqa: N802
        self._route("HEAD")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if self.local_mode:
            # The operator console has one way in: read.
            self._html(page("refused", "<h1>405</h1><p class=muted>This "
                            "console accepts no input of any kind on a live "
                            "ledger.</p>", NAV_LOCAL, self.note), 405)
            return
        if parsed.path == "/verify":
            self._verify_upload()
            return
        self._not_found()

    # ----------------------------------------------------------
    # GET routing
    # ----------------------------------------------------------

    def _route(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if not self.local_mode:
            if path == "/":
                self._html(verify_page())
            elif path == "/healthz":
                self._send(200, "ok", "text/plain; charset=utf-8")
            elif re.match(r"\A/r/[0-9a-f]{32}\Z", path):
                self._render_stored(path.rsplit("/", 1)[1])
            else:
                self._not_found()
            return

        try:
            if path == "/":
                self._html(overview_page(self.policy))
            elif path == "/audit":
                self._html(audit_page(query))
            elif path == "/policy":
                self._html(policy_page(self.policy))
            elif path == "/approvals":
                self._html(approvals_page())
            elif path == "/report.json":
                report = json.dumps(fresh_report(self.policy), indent=2)
                self._send(200, report, "application/json", {
                    "Content-Disposition":
                        'attachment; filename="evidence-report.json"'})
            elif path == "/report.csv":
                self._send(200, report_to_csv(fresh_report(self.policy)),
                           "text/csv; charset=utf-8", {
                               "Content-Disposition":
                                   'attachment; filename="evidence-report.csv"'})
            elif path == "/healthz":
                self._send(200, "ok", "text/plain; charset=utf-8")
            else:
                self._not_found()
        except EvidenceError as exc:
            self._html(page("state unavailable",
                            "<h1>no trustworthy state</h1><p class=muted>"
                            + html.escape(str(exc)) + "</p>",
                            NAV_LOCAL, self.note), 500)
        except ValueError:
            self._html(page("bad request", "<h1>400</h1><p class=muted>The "
                            "query parameters are not usable.</p>",
                            NAV_LOCAL, self.note), 400)

    # ----------------------------------------------------------
    # report mode: read a document, verify it, render the verdict
    # ----------------------------------------------------------

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            raise ValueError("no body")
        if length > MAX_REPORT_BYTES:
            raise ValueError("that is larger than any evidence report")
        return self.rfile.read(length)

    def _verify_upload(self) -> None:
        try:
            text = _report_from_body(self._read_body(),
                                     self.headers.get("Content-Type") or "")
        except ValueError as exc:
            self._html(verify_page(str(exc)), 400)
            return

        report_id = uuid4().hex
        stored = self.uploads / f"{report_id}.json"
        try:
            stored.write_text(text, encoding="utf-8")
        except OSError:
            self._html(verify_page("the document could not be stored."), 500)
            return
        self._redirect(f"/r/{report_id}")

    def _render_stored(self, report_id: str) -> None:
        if not REPORT_ID.match(report_id):
            self._not_found()
            return
        path = self.uploads / f"{report_id}.json"
        if not path.is_file():
            self._not_found()
            return
        self._html(report_page(report_id, verify_report(path)))


def _report_from_body(body: bytes, content_type: str) -> str:
    """Pull the report text out of a form post, then insist it is JSON.

    The stored bytes are what the verifier reads, so an invalid document is
    refused here rather than half-rendered later.
    """
    if content_type.startswith("multipart/form-data"):
        text = _multipart_field(body, content_type, "report").decode(
            "utf-8", "replace")
    else:
        fields = parse_qs(body.decode("utf-8", "replace"))
        values = fields.get("report") or []
        if not values:
            raise ValueError("the form carried no report")
        text = values[0]

    text = text.strip()
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"that is not JSON: {exc}") from None

    if not isinstance(document, dict) or "events" not in document:
        raise ValueError(
            "no 'events' array in it: this is not a gateway evidence file"
        )
    return json.dumps(document)


def _multipart_field(body: bytes, content_type: str, field: str) -> bytes:
    match = re.search(r'boundary="?([^";,]+)"?', content_type)
    if not match:
        raise ValueError("the upload declares no multipart boundary")
    boundary = ("--" + match.group(1)).encode()
    for part in body.split(boundary):
        head, _, data = part.partition(b"\r\n\r\n")
        if f'name="{field}"'.encode() not in head:
            continue
        stripped = data.rstrip(b"\r\n")
        if not stripped.strip():
            raise ValueError("no file was chosen")
        return stripped
    raise ValueError("the form carried no report")


# ============================================================
# ENTRY
# ============================================================

def bind_for(host: str, local: bool) -> str:
    """The one network rule, in a function so it can be tested on its own.

    A live ledger is this machine's record of what it let the model see. Only
    someone at this keyboard may read it over HTTP.
    """
    if not local:
        return host
    if host not in LOOPBACK_BINDS:
        raise ConsoleError(
            f"refusing to serve the live ledger on {host!r}. Only "
            f"{', '.join(LOOPBACK_BINDS)} are allowed here: the audit log, the "
            "policy and the approval ledger describe what this machine exposed "
            "and to whom, and that is not something to hand to a network. "
            "Deploy the report viewer instead (--serve-reports), which reads no "
            "host state at all."
        )
    return host


def serve(host: str, port: int, mode: str, policy_path: str = "",
          report_file: str = "", uploads_dir: str = "console-uploads") -> int:
    """Bind and serve. Local mode never touches the uploads directory."""
    local = mode == "local"
    bind_for(host, local)

    uploads = Path()
    if not local:
        uploads = Path(uploads_dir).expanduser().resolve()
        uploads.mkdir(parents=True, exist_ok=True)

    handler = type("Bound" + Handler.__name__, (Handler,), {
        "local_mode": local,
        "uploads": uploads,
        "note": "live ledger, loopback only" if local else "no host access",
    })
    if local:
        handler.policy = resolve_policy(policy_path or None)

    if report_file:
        path = Path(report_file).expanduser()
        if not path.is_file():
            print(f"console: no such report: {path}", file=sys.stderr)
            return 2
        report_id = uuid4().hex
        (uploads / f"{report_id}.json").write_text(
            path.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"console: /r/{report_id} serves that report")

    server = ConsoleServer((host, port), handler)
    print(f"gateway console (read-only) on http://{host}:{port}/ - Ctrl-C stops")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ssm-console",
        description="Read-only console over the policy gateway: the live "
                    "ledger on loopback, or a signed evidence report anywhere.",
    )
    kind = parser.add_mutually_exclusive_group()
    kind.add_argument("--report", metavar="FILE", default="",
                      help="serve one exported evidence report for viewing")
    kind.add_argument("--serve-reports", action="store_true",
                      help="auditor mode: accept and verify uploaded reports, "
                           "reads no host state")
    parser.add_argument("--bind", default="127.0.0.1",
                        help="address to bind (live ledger: loopback only)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--policy", default="",
                        help="policy file for the live ledger view")
    parser.add_argument("--uploads", default="console-uploads",
                        help="where auditor mode keeps verified documents")
    args = parser.parse_args(argv)

    try:
        if args.report or args.serve_reports:
            return serve(args.bind, args.port, "report",
                         report_file=args.report, uploads_dir=args.uploads)
        return serve(args.bind, args.port, "local", policy_path=args.policy)
    except ConsoleError as exc:
        print(f"console: {exc}", file=sys.stderr)
        return 2
    except EvidenceError as exc:
        print(f"console: this host's state cannot be trusted: {exc}",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
