# Changelog

Notable changes to `secure-linux-ai`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the versions follow
Semantic Versioning. Dates are the date the work was verified on both platforms,
not the date it was started.

## [Unreleased]

### Added

- `console.py`, the read-only web console (`ssm-console`). Two modes, and no
  write path in either: the operator's mode shows this host's identity, audit
  chain, policy and approval ledger, and binds to loopback only — a routable
  `--bind` is refused with exit 2. The auditor's mode (`--serve-reports`, or
  `--report FILE`) verifies an exported evidence document using nothing but the
  key inside that file, reads no host state, and is the one that can be
  deployed. There is no command input, no tool call, and no route that mints,
  approves, redeems or executes anything; those routes do not exist.
- `verify_report()` returns the signed document's own note as `report_note`.
  The note is inside the signed core, so a viewer can repeat it as evidence
  instead of as unverified text.
- `auditor-service/`, the deployed auditor service, generated from
  `deploy/auditor/` (`Procfile`, `Dockerfile`, `requirements.txt`, card) plus
  the eight modules `console.py` imports. `deploy/make_auditor.py` writes it and,
  with `--check`, recomputes that file list from the source and fails if the
  committed copy differs by a byte — so the deployed tree cannot drift from the
  repository silently, and cannot gain a CLI, a capability tool or a model
  client without CI saying so. The service has no executor, so there is nothing
  for a request to reach. `T64` starts the staged tree with the `Procfile`'s own
  command line and every package the service does not install blocked at import.
- `render.yaml`, the deploy, at the repository root: one free Python web service
  whose root directory is `auditor-service/`, started by the same command line
  the `Procfile` carries. `--check` screens it the way it screens the `Procfile`
  and the `Dockerfile` — report mode only, no decision path, and the exact same
  start command — and `T64` parses it as YAML, because the host parses it and a
  malformed blueprint would otherwise first show up as a failed deploy. No card
  is needed for the free plan; an idle instance sleeps and wakes on the next
  request.
- The auditor service is running at `https://ssm-auditor.onrender.com`, and was
  checked against the live endpoint by hand: `/healthz` answers, `/audit`,
  `/policy`, `/approvals` and `/report.json` are 404, `POST /policy` is 404, the
  CSP/`nosniff`/`no-referrer` headers are on every page, a real signed report
  from a scratch gateway state returns **TRUSTED**, and the same document with
  one event's status rewritten and no new signature returns **NOT TRUSTED**.

### Changed

- `docs/runbook.md`, for the person who operates this on a real box: the three
  checks that answer most questions, how to hand evidence to an auditor (and why
  `--note` is authenticated rather than decorative), how to deploy the auditor
  view and the four requests to run against it afterwards, a symptom table, and
  the limits an operator is responsible for stating.
- **Retracted: `--reset-key` was documented as rotating the host signing key.**
  It does not — it deletes the `.env` holding the model API key, which is what
  its own help text and code say. `docs/quickstart.md` and the new runbook now
  describe the actual procedure (delete the identity directory whose path
  `--evidence-show` prints) and its blast radius: rows already stored stop
  verifying as this host's, while reports exported before the rotation keep
  verifying because each carries its own public key. There is no flag for this,
  and that is now written down instead of papered over with a wrong one.
- `verify_report()` no longer raises on a malformed document. A report with a
  truncated row, a non-list `events` array, or a `host` section that is a string
  comes back as not trusted with the failure named, instead of crashing halfway
  through a page. A verifier that throws leaves an auditor with no verdict.
- A diagnosis is a loop now. The model may ask for several read-only
  capabilities in one turn, and ask for more after seeing what came back, up to
  `MAX_TOOL_ROUNDS = 3` rounds. Previously a turn with more than one tool request
  was refused outright — the first real model call on Ubuntu hit exactly that.
- Every call in a round is answered on the wire. The OpenAI-compatible path used
  to reply to its first `tool_calls` entry only, so a multi-call turn would have
  been rejected by a strict server even without our own guard; each answer now
  carries the id of the call it answers, and a Gemini round carries one function
  response per call.
- A policy refusal no longer throws away the diagnosis. The refusal — reason and
  rule id included — is returned to the model as that call's result, so the
  answer states which part was refused instead of ending in an error. Before,
  the first blocked call discarded every other result the same round had earned.
  A capability that raises is reported the same way.
- Each call gets its own decision and its own signed audit row: `executed`,
  `blocked` or `failed`. `LLMClient.finish_diagnosis()` is gone, replaced by
  `LLMClient.diagnose()`, which takes the caller's policy-gated runner and owns
  the rounds; nothing in the model layer decides what may run.

### Fixed

- The human approval prompt no longer contains a non-ASCII glyph. `click` writes
  it with the console's own codec, so on a Windows terminal without UTF-8 mode
  the mint crashed with `UnicodeEncodeError` at the exact moment a person was
  being asked to confirm.
- `docs/quickstart.md` separates `--policy-lint` / `--policy-show` (which read a
  policy file) from `--policy-check` (which screens a command string); the two
  were conflated, which is what made the CI console-command step fail.
- Packaging metadata uses `license = "MIT"` instead of the deprecated
  `license = { file = ... }` table, with `setuptools>=77` as the build
  requirement.
- The repository is now named `linux-ai-ssm`. It previously ended in a literal
  `.` character, which Windows cannot put in a path, so GitHub's runner could
  never create the job's working directory and every Windows CI job died in
  `actions/checkout` before running a test. Project URLs follow the new name.

Nothing else in progress. Per-user signing keys and post-approval process
supervision are the two open design items.

## [0.4.0] - 2026-10-16

Signed, single-use approval artifacts and a provider-neutral model layer, plus
packaging so the tool can be installed instead of cloned.

### Added

- `approval.py`: an approval is an Ed25519-signed artifact bound to the SHA-256
  of the exact command, the policy fingerprint, the host key id and hostname,
  the actor, a decision snapshot, an issue time, a TTL and a nonce.
- `--request-approval`, `--approve`, `--approval-show`, `--approval-list`,
  `--void-approval`, `--execute` and `--approval-ttl` on the CLI. Minting
  requires a human confirmation **and** the host private key; the MCP front-end
  can open requests and read the ledger but has no mint, redeem or execute path.
- Single-use enforced in SQL (`WHERE nonce = ? AND state = 'minted'`,
  `rowcount == 1`), so a replayed token is refused rather than raced.
- Re-classification against the live policy at both mint and redeem; a token
  whose decision no longer matches is refused, and a refusal never consumes it.
- Expiry floor of 900 seconds; `approval.ttl_seconds` in `policy.yaml` may only
  shorten it, and `approval.mode: off` is refused like any other attempt to
  weaken the floor.
- `providers.py`: one `Turn` interface over Gemini, Ollama and any
  OpenAI-compatible server, chosen from policy plus environment
  (`SSM_PROVIDER`, `SSM_BASE_URL`, `SSM_MODEL`), with `--provider-show`.
- `policy.local-only.yaml`: a shipped policy that refuses every cloud provider,
  for hosts whose prompts must not leave the machine.
- `--token-out FILE` on `--approve`: writes the signed artifact to a file
  (`0600` on POSIX) instead of printing it, so the operator never transcribes
  900+ characters by hand.
- `pyproject.toml`: `pip install -e ".[dev]"`, `ssm` and `ssm-mcp` console
  commands, Python >=3.10, plus `LICENSE`, `SECURITY.md`, this file and
  `docs/quickstart.md`.
- GitHub Actions matrix (Ubuntu and Windows on Python 3.10, 3.13 and 3.14) that
  runs the suite, the MCP self-check, `ruff check`, an approval lifecycle
  end-to-end, the fail-closed cases, an evidence export verified after the local
  state directory is deleted, and a wheel install. A nightly leg keeps the
  unpinned dependency ranges honest.
- Tests `T54`-`T58`: regime tighten-only, lifecycle and single-use,
  tamper/replay/cross-host/borrowed-ledger/keyless/void handling, MCP cannot
  grant, and the CLI gate with both token transports. 58/58 on both platforms;
  `mcp_server.py --check` 19/19 on both.

### Changed

- Approval state lives in `approvals.sqlite3` (transitions are legitimate
  there); the audit database stays append-only evidence.
- `--approval-list` now prints `state=count` totals and the ledger path it read.

### Fixed

- `--approval-ttl`'s own default value was rejected by the argument parser
  (`min=1` against a default of `0`), which made every invocation of `main.py`
  fail before it could read an option. Now `min=0`.
- A token copied from the terminal picked up the panel's box-drawing characters
  and failed base64 decoding. Found by a human doing the copy-paste workflow on
  Windows; `--token-out` removes the transcription step, and the printed form
  now warns that manual copying corrupts it.
- Commands that fail to start (`WinError 2`, a missing binary) are logged as
  `approval:failed` after spending the token, instead of leaving the ledger with
  a redeemed approval and no outcome.

## [0.3.0] - 2026-10-16

### Added

- `mcp_server.py`: a stdio JSON-RPC MCP front-end with no third-party
  dependency, so an agent can ask the gateway rather than persuade it. Eleven
  tools: five capability tools plus `policy_decide`, `policy_show`,
  `evidence_report`, `evidence_verify`, `approval_request`, `approval_list`.
- Every agent-initiated read is policy-checked before execution and audited as
  agent-initiated, with the reason stated in the row rather than implied.
- `gateway.py` and `tools.py` extracted so the CLI, the MCP server and the model
  path share one decision core and one capability registry.
- `--check` on the MCP server: 13 in-process protocol checks, later 19, run
  inside the test suite on both platforms.
- Tests `T36`-`T53`.

### Known gap

- Only one real MCP client has been exercised so far (Qoder on Windows). Claude
  Desktop, Cursor and any Linux-hosted agent runtime are untested.

## [0.2.0] - 2026-10-16

### Added

- `evidence.py`: per-host Ed25519 identity, canonical JSON, signed rows and
  offline-verifiable reports; `audit.py` hash-chained rows.
- `--report`, `--report-verify`, `--evidence-show`, `--reset-key`, `--note`.
- Legacy audit databases migrate and still verify.
- Tests `T26`-`T35`.

## [0.1.0] - 2026-10-16

### Added

- `policy.py`: operator `policy.yaml` that can only tighten an immutable
  deny-by-default floor; `risk_engine.py` rewritten to evaluate against it.
- Fail-closed loading, per-command mutating-flag refusals, path-value
  validation for the diagnostic tools, and `max_score` / `block_sensitive`.
- `--policy`, `--policy-check`, `--policy-show`, `--policy-lint`.
- Tests `T17`-`T25`.

## [0.0.1] - 2026-08-23

### Added

- The original ungated assistant: Gemini tool calling, five read-only Linux
  capability tools, tech mode, and a first regex refusal list (tests `T01`-`T16`).
