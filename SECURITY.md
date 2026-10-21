# Security policy

This project is a **decision boundary with a receipt**, not a sandbox. Reading
this file tells you exactly which attacks it changes the outcome of, and which
it does not touch. Overstating the second list would make the first one
unusable, so it is written as it is.

## What is actually enforced

| Property | How it is enforced | Where it is checked |
| --- | --- | --- |
| Deny by default | An immutable floor of refused executables and mutating flags lives in code, not config | `policy.py`, `risk_engine.py` |
| Config can only tighten | `approval.mode: off`, a longer TTL, or a removed floor entry is refused at load | `policy.py` |
| Fail closed | An unparsable `policy.yaml` or an unusable host identity exits `2` before anything runs | `main.py`, `mcp_server.py` |
| Human approval to execute | Minting requires an interactive `confirm` **and** the host Ed25519 private key | `approval.py`, `main.py` |
| Approval is single-use | `UPDATE approvals SET state='redeemed' WHERE nonce=? AND state='minted'` and `rowcount == 1`; the database, not a read-then-write, decides | `approval.py` |
| Approval cannot be reused elsewhere | Token binds the SHA-256 of the exact subject, the policy fingerprint, the key id + hostname, the actor, and a decision snapshot re-checked at redeem | `approval.py` |
| Decisions are evidence | Every allowed, blocked, confirmed, refused and failed event is an append-only row signed over canonical JSON | `audit.py`, `evidence.py` |
| Evidence is verifiable offline | The report carries its own public key; a verifier needs no database and no network | `evidence.py` |
| An agent cannot grant itself permission | Over MCP, `approval_request` and `approval_list` exist; mint, redeem and execute have no MCP path at all | `mcp_server.py` |

`run_tests.py` (58 tests) and `mcp_server.py --check` (19 checks) assert every
row of that table, on Windows and Linux.

## What it deliberately does **not** claim

- **Not a hardware-backed approval.** `--approve` requires a typed `y`, and any
  process that can write to that CLI's stdin can type it — CI does exactly this
  (`echo y |`). The prompt proves a human was in the loop only insofar as the
  terminal is a human's. What an agent cannot do is reach the mint at all: over
  MCP there is no `--approve`, no redeem and no execute path.
- **Not privilege separation.** The gateway runs as the invoking user and can
  do anything that user can do. It restricts *what the model asks for*, not
  what a determined local user can run.
- **Not human identification.** The actor recorded in every row is the OS
  username. A local user can rename their account. Evidence therefore proves
  *which host, which policy, which decision, unaltered* — never *which person*.
  There is deliberately no `--as NAME` flag: a flag that lets the caller pick
  the actor manufactures false attribution.
- **Not a container.** After an approved command starts, its children, its file
  writes and its network use are not supervised. Approval covers the exact
  approved bytes, nothing more.
- **Not a defence against a lying MCP client.** `clientInfo.name` is written by
  the client, so an audit row naming a client proves which configured client
  asked, not which binary or which human. The row is still signed by the host,
  which is the part that cannot be forged.
- **Not per-user keys yet.** Two people sharing one host share one signing key,
  so they cannot be distinguished cryptographically.
- **Not a complete history filter.** A report exported for a window that starts
  after row 1 is labelled `window` and the verifier is told how many earlier
  rows were excluded — but it cannot see them. Never present a window as the
  whole history.
- **Not a network egress control.** When a query is answered by a cloud model,
  the prompt and the tool results leave the machine. That is recorded as a
  signed `ai_egress` row, and `policy.local-only.yaml` is the way to refuse it.
- **Not verified on macOS.** `psutil` supports it, but the shipped `read_roots`
  and deny-path list are Linux-shaped.

## Reporting a vulnerability

Open a **private security advisory**:

`https://github.com/Jyothirmayi13/linux-ai-ssm/security/advisories/new`

Do not file a public issue. Expected first response within 7 days; a fix or a
written disagreement within 30. Include the output of `ssm --policy-show` and
`ssm --report-verify` if the report involves policy loading or evidence.

## If a credential was committed

Deleting the file does not remove it. Anything ever committed stays in that
repository's history and in every clone of it. Rotate the credential at the
provider first, then treat the key as public: rewrite history only after the
old value is dead. `.gitignore` excludes `.env` and includes `.env.example` so
the pattern is not repeated.

## Hardening checklist for an operator

1. Run the gateway under a dedicated, low-privilege account.
2. Replace `read_roots` in `policy.yaml` with the smallest set of directories
   the diagnosis actually needs; credential deny paths always apply on top.
3. Lower `max_score` (the shipped value is `100`; `80` refuses every HIGH-risk
   command without asking).
4. Shorten `approval.ttl_seconds` and keep `mode: interactive`.
5. Keep `~/.local/state/linux-ai-ssm/` (the identity key, the audit database
   and `approvals.sqlite3`) on a filesystem the model path cannot write.
6. Use `policy.local-only.yaml` on any host whose prompts must not leave it.
