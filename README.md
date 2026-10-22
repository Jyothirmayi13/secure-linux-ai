# Secure Linux AI
[![tests](https://github.com/Jyothirmayi13/secure-linux-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/Jyothirmayi13/secure-linux-ai/actions/workflows/ci.yml)

A security-gated Linux operations assistant.

## Architecture

User/AI -> Security Gateway (deny-by-default policy floor) -> Risk Engine ->
single-use signed approval token -> allow-list -> psutil/Linux ->
hash-chained, Ed25519-signed audit log -> answer + self-verifying evidence report

## Install
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```
This installs three commands: `ssm`, `ssm-mcp` and `ssm-console`.

## Safe commands

- show system status
- show top cpu processes
- show top memory processes
- find files
- search text in a file

Medium-risk operations require confirmation.
Commands outside the allow-list and critical operations are blocked.

## Model keys

Without a key the gateway refuses a cloud provider rather than silently skipping
it. Put your own in `.env` (untracked; `.env.example` shows the shape), or point
`SSM_BASE_URL` at a local OpenAI-compatible server. Nothing in this repository
ships a key.

## Test

```bash
python run_tests.py            # 64 tests, no network, no API key
python mcp_server.py --check   # 19 protocol checks
ruff check .
```

## Where to read more

- `docs/quickstart.md` - install, the first command, the policy knobs, the deploy.
- `docs/runbook.md` - the operator's three checks, exporting evidence, deploying
  your own auditor view, and the documented limits.
- `SECURITY.md` - what is enforced, what the project deliberately does not claim,
  and how to report a vulnerability.
- `CHANGELOG.md` - what changed and what was retracted.
- `.github/workflows/ci.yml` - the same 64 tests on ubuntu and windows, across
  Python 3.10, 3.13 and 3.14, plus the tracked-file hygiene and drift guards.

The auditor view runs at https://ssm-auditor.onrender.com - drop in a report and
get a verdict. It has no executor, so there is nothing for a request to reach.

Verdicts are one of four words, everywhere: `TRUSTED`, `AUTHENTIC, EMPTY`,
`AUTHENTIC, PARTLY UNPROVABLE`, `NOT TRUSTED`.

