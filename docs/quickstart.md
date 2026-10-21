# Quickstart

Five minutes to a running gateway, then the two workflows that make it a
security product: an approval an agent cannot grant itself, and a report a third
party can verify without your database.

## Requirements

- Python 3.10 or newer (CI runs 3.10, 3.13 and 3.14).
- Linux is the target platform; the CLI, the test suite and the MCP server also
  run on Windows, which is how this repo is developed.
- `cryptography` is required for signed evidence. Without it the gateway warns
  and stores unsigned rows.

## Install

From a clone (recommended — `policy.yaml` is resolved next to the code, so an
editable install keeps your edits live):

```bash
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Then:

```bash
cp .env.example .env            # and put your model key in it, or leave it empty
ssm --policy-lint               # validate the policy file
ssm --policy-show               # the effective policy, setting by setting
ssm --provider-show
```

`--policy-lint` answers one question: is this policy file usable? It exits 0 with
the read roots, rule count and denied-path count, or exits 1 naming the first
problem — unparsable YAML, an `approval.mode` of `off`, a TTL longer than the
floor. `--policy-show` prints the policy that is actually in force and where
every setting came from, so a file that silently fails to tighten something is
still visible.

`--policy-check` is a different tool: it screens a **command string** the way the
gateway would, without calling the model and without executing anything.

```bash
ssm --policy-check "df -h"                    # ALLOW, requires confirmation
ssm --policy-check "rm -rf /var/log"          # BLOCK, exit 2
ssm --policy prod.yaml --policy-check "journalctl -xe"
```

`--provider-show` names the model provider that was chosen and why, from
`SSM_PROVIDER`, `SSM_BASE_URL`, `SSM_MODEL` and the keys present in the
environment. A cloud provider with no key is refused before any request, not
silently skipped.

## Ask a question

```bash
ssm "why is this box slow since the cron change"
ssm --tech "list the units that failed at boot"     # one gated command instead
```

The model may request only the five read-only capability tools. Each request is
run through the same decision core as a typed command, and each answer —
allowed, refused, or blocked before the model was called — is a signed row.

## The approval lifecycle

`request → approve (human) → verify → spend`. Execute nothing you have not
read.

```bash
ssm --request-approval "journalctl -u nginx --since '2 hours ago'" | tail -5
ssm --approve req-XXXXXXXX --token-out approval.token
ssm --approval-show @approval.token          # inspect without spending
ssm --execute @approval.token                # runs the exact approved bytes
ssm --execute @approval.token                # refused: already redeemed
ssm --approval-list                          # state counts and the ledger path
del approval.token                            # Windows cmd; rm on Linux
```

Why it behaves the way it does:

- `--approve` prompts for a human `y` and signs with the host private key. An
  agent over MCP can create the request and read the ledger, and has **no**
  path to mint, redeem or execute.
- `--token-out FILE` writes the artifact instead of printing it, so nobody
  transcribes 900+ base64 characters; on POSIX it is created `0600`.
- The token is bound to that command's hash, the policy fingerprint, this host's
  key id and hostname, the actor and a decision snapshot. Editing one character,
  replaying it, or carrying it to another machine fails — and a failed check
  does **not** consume it.
- `approval.ttl_seconds` may only shorten the floor; the default is 120 seconds.
- If the command's risk classification changes between mint and redeem, the
  token is refused rather than honoured.

## Prove what happened

```bash
ssm --report --out evidence-window.json --limit 50
ssm --report-verify evidence-window.json
```

The report carries its own public key, so verification needs no database, no
network and no trust in the machine that exported it. A report whose first row
is not row 1 is labelled a **window** and states how many earlier rows were
excluded — never present a window as a complete history.

## Look at it in a browser

The console is read-only in the strict sense: it has no command field, no tool
call, and no route that mints, approves, redeems or executes anything. A page
that could grant consent would be the hole in the design, so the routes do not
exist. It has two modes because an operator and an auditor are allowed to see
different things.

Operator view — this host's identity, live audit chain, policy and approval
ledger, loopback only:

```bash
ssm-console                       # http://127.0.0.1:8788/
ssm-console --policy policy.yaml --port 9000
ssm-console --bind 0.0.0.0        # exits 2: the live ledger never goes on a NIC
```

`GET /report.json` and `/report.csv` export the same signed document the CLI
exports, so a browser session and a terminal session produce identical evidence.

Auditor view — one exported report, verified with the key inside the file. It
reads no host state and needs no secret, which is what makes it safe to run on
someone else's machine or in a container:

```bash
ssm-console --report evidence-window.json --bind 0.0.0.0 --port 8080
ssm-console --serve-reports --bind 0.0.0.0 --port 8080   # upload or paste
```

Both modes answer a verdict in the same words the CLI uses — `TRUSTED`,
`AUTHENTIC, EMPTY`, `AUTHENTIC, PARTLY UNPROVABLE`, `NOT TRUSTED` — and the
page lists every failure rather than summarising them away. Uploaded documents
are stored under a name the server chose (`uuid4().hex`), never under the
filename that arrived, and a body larger than 8 MiB is refused before a single
byte of it is read.

## Deploy the auditor view on its own machine

`auditor-service/` is the deployed service, and it is a generated directory:
the eight modules `console.py` actually imports, plus `deploy/auditor/`'s
`Procfile`, `Dockerfile`, `requirements.txt` and card. Two dependencies —
`cryptography` and `pyyaml` — and nothing else. No CLI, no capability tools, no
model client, no `psutil`. A host with no executor cannot be argued into
running something.

Generate it, or prove it, never edit it:

```bash
python deploy/make_auditor.py            # rewrite auditor-service/
python deploy/make_auditor.py --check    # verify it, change nothing
```

`--check` recomputes `console.py`'s import closure from the source, rebuilds
into a temporary directory, and fails if the committed copy differs by a byte,
if the dependency list no longer matches what is imported, if the start command
names anything but report mode, or if `google.genai` ever moves from inside a
function up to module scope — which would silently make the service need a model
SDK. It screens `render.yaml` too, and requires that blueprint to start the exact
command the `Procfile` runs. CI runs it on every push. `T64` goes further: it
launches the staged tree **using the `Procfile`'s own command line** with
`google`, `typer`, `rich`, `psutil`, `dotenv`, `mcp` and `openai` blocked at
import, uploads a real signed report, and requires `TRUSTED` on the verdict page
and a 404 on `/audit`.

The start command is the one mode that is safe to routably bind:

```
web: python app/console.py --serve-reports --bind 0.0.0.0 --port $PORT --uploads ./uploads
```

`render.yaml` in the repository root is the deploy: a free Python web service
whose root directory is `auditor-service/`, so the tree that ships is exactly the
twelve files above — no evidence export, no `.env`, no ledger can be picked up by
accident. Any other buildpack host that reads a `Procfile` runs the same line,
and a container host builds `Dockerfile`, which runs it on port 7860.

The running service is `https://ssm-auditor.onrender.com`. Checked against it by
hand: `/healthz` answers, `/audit`, `/policy`, `/approvals` and `/report.json`
are 404, a real signed report uploaded from a scratch gateway state comes back
**TRUSTED**, and the same document with one event's status rewritten and no new
signature comes back **NOT TRUSTED**. That last pair is the point — the endpoint
verifies, it does not agree. `T64` proves the same file set and the same command
line on every push, because the deployed instance is not a test runner.

Stated limits: no Docker engine exists on the development machines, so the
`Dockerfile` path is proven by running the tree it copies, not by `docker
build`. A free instance goes to sleep after fifteen idle minutes, and its disk is
ephemeral — verdict URLs live until the next restart, which is fine for an
auditor who keeps the report. And the service has no authentication — which is
only defensible because report mode reads no host state at all.

## Use it as an MCP server

Client configuration (Qoder, Claude Desktop, Cursor, any MCP runtime):

```json
{
  "mcpServers": {
    "linux-ai-ssm-gateway": {
      "command": "/abs/path/to/.venv/bin/python",
      "args": ["/abs/path/to/mcp_server.py"]
    }
  }
}
```

Use absolute paths for both. Eleven tools are advertised: five capability
tools (`get_system_status`, `get_top_cpu_processes`, `get_top_memory_processes`,
`find_files`, `search_text_file`) and six control tools (`policy_decide`,
`policy_show`, `evidence_report`, `evidence_verify`, `approval_request`,
`approval_list`). Self-test the framing without a client:

```bash
python mcp_server.py --check
```

## Keep prompts on the machine

```bash
ssm --policy policy.local-only.yaml "why is disk pressure rising"
```

`policy.local-only.yaml` refuses every cloud provider and calls a local
OpenAI-compatible server instead (`SSM_BASE_URL`, e.g. Ollama on
`http://127.0.0.1:11434/v1`). With no local server listening it refuses to call
anything and names the endpoint it tried. Every cloud call that does happen is
recorded as a signed `ai_egress` row.

## Tighten the policy

`policy.yaml` can only make the gateway stricter. The floor in `policy.py`
cannot be weakened from config — `approval.mode: off`, a TTL longer than the
900-second floor, or a removed deny entry are all refused at load, and an
unparsable file exits `2` instead of falling back to "no policy".

The knobs that matter most: `max_score` (shipped `100`; set `80` to refuse every
HIGH-risk command without asking), `block_sensitive`, `read_roots` (this
**replaces** the built-in list; credential deny paths always apply on top), and
the `rules:` block, whose patterns name the rule that refused a request.

## Run the tests

```bash
python run_tests.py            # 64 tests, no network and no API key required
python mcp_server.py --check   # 19 protocol checks
ruff check .
```

## Reset

```bash
ssm --reset-key                      # deletes .env next to the code
rm -rf ~/.local/state/linux-ai-ssm   # identity, audit.sqlite3, approvals.sqlite3
```

`--reset-key` is about the **model** key and nothing else: it deletes the `.env`
where an API key may be stored, tells you it did, and leaves the host identity
alone. The signing key has no reset flag. To change it, delete the identity
directory that `ssm --evidence-show` names — and accept that rows already stored
were signed by the key that is now gone, so they stop verifying as this host's.
Reports exported while that key was in force keep verifying, because each one
carries its own public key.

Deleting the state directory deletes the evidence. That is the operator's
choice, not the gateway's, and nothing in the tool does it for you.

## Troubleshooting

- `UnicodeEncodeError` on a Windows console: the terminal is cp1252; run
  `set PYTHONUTF8=1` in that window.
- `--execute @file` says the token is not valid base64: the file contains
  something other than the token (a copied panel, a stray newline). Re-mint it
  with `--token-out`.
- A `WinError 2` / "file not found" right after "Approval spent": the approved
  binary does not exist on this PATH. The token was genuinely consumed and the
  outcome is logged as `approval:failed`; re-request against a real command.
- `Host identity is unusable`: the identity directory is half-written. The
  gateway refuses to produce rows that look signed. Fix the directory, or delete
  it and let a new key be created — which orphans the signatures already stored.
