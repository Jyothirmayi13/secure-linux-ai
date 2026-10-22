# Known issues

Defects found, what happened when they were reproduced, and what is still open.
Entries stay here after they are fixed, because the interesting part of a bug in a
security boundary is usually why it was invisible.

---

## KI-01 — strict mode refused every approval request from a named MCP client

**Status:** fixed on `main`, 2026-10-21. **Severity:** high — it made the
*stricter* setting unusable over MCP, in the direction of refusing rather than
allowing.

### What failed

`request_approval()` gated the requester on an exact string match:

```python
if mode_for(policy) == "strict" and requested_by not in ("cli", "mcp"):
    raise ApprovalError(f"unknown requester {requested_by!r}")
```

The MCP facade does not send a bare `"mcp"`. It decorates the field with whatever
client completed the handshake (`mcp_server.py:483`, `mcp_server.py:275-277`):

```python
requested_by=("mcp" + self.client_label).strip()   # "mcp via Qoder"
```

So on a host with `approval.mode: strict`, any client that identified itself —
which is every real MCP client, including the ones this project is demoed with —
was met with `unknown requester 'mcp via Qoder'` and could not open an approval at
all. Strict mode exists precisely to force the request/approve split, so the
setting that adds the most control silently removed the agent's only permitted
action. Nothing was executed that should not have been; the failure was a
refusal, which is the safe direction and also a complete loss of function.

### Why it stayed invisible

Three conditions had to hold at once, and no automated run ever joined them:

1. **CI only ever loads the shipped `policy.yaml`, which is
   `approval.mode: interactive`.** The `mode_for(policy) == "strict"` test is
   false in every CI job, so the guarded line is dead code there.
2. **The unit-test server never introduced itself.** `client_label` is empty
   unless `initialize` carries a `clientInfo.name`. T57 built its sandbox server
   and called `tools/call` directly, so `requested_by` was the bare `"mcp"` —
   which the exact match accepted. A strict host running the suite alone would
   still not have reached the bad branch through T57.
3. **The one path that does decorate the requester never ran under strict.**
   `mcp_server.py --check` introduces itself as `self-check` / `label-check`, and
   T44 runs it as a subprocess — but always against the interactive policy.

Reproducing it was a matter of supplying the missing half. With `policy.yaml`
temporarily set to `strict` and the old comparison restored:

| Run | Result |
|---|---|
| strict, old comparison, T57 as originally written | **passed** — the sandbox server sends plain `mcp` |
| strict, old comparison, T57 taught to send a real `initialize` | **T44, T45, T57 failed — 60/64** |
| strict, `_requester_kind()` fix | **64/64 tests, 19/19 MCP checks** |
| interactive, `_requester_kind()` fix | **64/64 tests, 19/19 MCP checks**, `ruff` clean |

T44 and T45 failed because the self-check's own `approval_request` was refused,
which is the same defect seen from the other end.

### The fix

`approval.py` now compares the **plane** the request arrived on, not the whole
decorated label:

```python
def _requester_kind(requested_by: str) -> str:
    return requested_by.split(maxsplit=1)[0].lower() if requested_by.strip() else ""
```

`"mcp via Qoder"` and `"mcp"` are both the `mcp` plane and are accepted under
strict; `"http via something"` is still an unknown plane and is still refused,
with the full decorated value in the error so the ledger keeps saying who asked.

The test that hid it now exposes it: T57 performs the real handshake
(`rpc(server, 10, "initialize", {"clientInfo": {"name": "unit-client"}})`) and
asserts the exact stored value `requested_by == "mcp via unit-client"`, so strict
mode is exercised through a named client rather than around it. Its mode
assertion reads `shipped.approval_mode` instead of hardcoding `"interactive"`, so
the same test is meaningful on a host configured either way.

### Still open

- **CI runs one policy.** Every job loads the shipped `policy.yaml`, so a
  strict-only regression can still reach `main` unnoticed. The cheap close is a
  second suite invocation against a strict policy file, in the same matrix jobs.
- **`--check` under strict is unverified by CI** for the same reason.

### Note for whoever edits these modules

`auditor-service/` is generated, not maintained. Editing `approval.py` (or
`policy.py`, `risk_engine.py`, `gateway.py`, `evidence.py`, `audit.py`,
`console.py`, `providers.py`) makes T64 fail with `the deployed auditor service
drifted` until you run:

```bash
python deploy/make_auditor.py && python deploy/make_auditor.py --check
```

That is the guard doing its job: the deployed tree must be exactly what
`console.py` imports, and it will not be edited by hand to match.
