# Operator runbook

For whoever runs the gateway on a real box and has to answer three questions
without opening a database: what did the model see, what did it get to do, and
can you prove it. Every command below is the installed `ssm` script; from a
clone it is `python main.py`. State lives in `~/.local/state/linux-ai-ssm/` —
the host key pair, `audit.sqlite3`, `approvals.sqlite3`.

## The three checks that answer most questions

```bash
ssm --evidence-show      # this host's signing identity and the audit state
ssm --policy-show        # the policy actually in force, setting by setting
ssm --approval-list      # open, signed, spent, void, expired
```

`--evidence-show` is the health check: it prints `Chain OK — N rows recompute
cleanly; M signed.`, or `Chain BROKEN` followed by every failure it found, plus a
line naming any row that predates host signing. It also prints the policy
fingerprint in force, the audit and approval database paths, and the identity
directory. `--policy-show` is the answer to "did my edit take effect" — it prints
where each setting came from, so a file that fails to tighten something is still
visible. `--approval-list` is the answer to "is anything waiting that I forgot
about"; an open approval is a command someone can still sign, so close the ones
you do not want.

```bash
ssm --void-approval req-XXXXXXXX     # makes a token unusable, and is itself logged
```

## Before you hand anything to an auditor

```bash
ssm --report --out evidence-2026-10-20.json \
    --note "week of the nginx incident, host web-03" \
    --last 24
ssm --report-verify evidence-2026-10-20.json
```

Write a `--note`. It is stored inside the signed core, so it is authenticated
evidence rather than a filename someone typed, and a year later it is the only
thing that says which machine and which week you meant.

Verify it yourself before you send it, with the verifier and nothing else — no
database, no network. Then choose the delivery:

- `ssm --report-verify FILE` on their machine, if they will run the tool;
- upload it to the deployed auditor, `https://ssm-auditor.onrender.com`, if they
  will not. The auditor reads no state from your host: the document carries its
  own public key, and the verdict page appears at an unguessable `/r/<id>`.

Keep the `.json`. The verdict page is a reading room, not a record; on a free
instance its disk is ephemeral, and the file is what survives.

A report whose first row is not row 1 is a **window**, and says how many earlier
rows were excluded. Never present a window as a complete history — the tool will
label it correctly if you let it, and `--limit` / `--last` are how you make
windows by accident.

## Deploying your own auditor view

The deployed service is a generated directory; never edit it by hand.

```bash
python deploy/make_auditor.py --check
```

That must print `auditor service checks pass: 8 modules, 2 dependencies, 12
files`. It recomputes what `console.py` actually imports, rebuilds the tree in a
temporary directory and compares SHA-256 digests against `auditor-service/`, so
a deployed tree that quietly gained the CLI, a capability tool or a model client
fails here rather than in production. `render.yaml` is screened by the same
command: report mode only, the generated directory as its root, and the exact
start command the `Procfile` carries.

To run it somewhere: `render.yaml` deploys it as a free Render web service; any
host that reads a `Procfile` runs the same line; `Dockerfile` builds it for a
container host. Point the host's root directory at `auditor-service/` — that is
what keeps an evidence export, a `.env` or a ledger out of the image by
accident.

Four checks after it starts, all of which should be boring:

```bash
curl -s $URL/healthz                        # ok
curl -s -o /dev/null -w '%{http_code}\n' $URL/audit      # 404
curl -s -o /dev/null -w '%{http_code}\n' $URL/policy     # 404
curl -s -o /dev/null -w '%{http_code}\n' $URL/report.json # 404
```

Then prove it verifies instead of agreeing: upload a real report and expect
`TRUSTED`; open that file in an editor, change one row's `status`, save it
without re-signing, upload the copy and expect **`NOT TRUSTED`** with the failure
listed. If a one-field forgery still passes, stop and treat the deployment as
broken.

## When something looks wrong

| What you see | What it means | What to do |
|---|---|---|
| `Chain BROKEN` (`--evidence-show`) or the `CHAIN BROKEN` badge (console) | a stored row's hash does not recompute from its predecessor | the ledger was edited, moved or truncated. Do not "fix" it — export the report, let it say `NOT TRUSTED`, and find out who touched the file |
| `N row(s) predate host signing`, or the `UNSIGNED ROWS` badge | `cryptography` was missing when those rows were written, or the identity directory was half-written at the time | install `cryptography` and fix the identity directory. The old rows stay unsigned — that is the honest record of when the host could not sign |
| `NOT TRUSTED` on a report you exported | the file changed after export, or it was never this host's | read the failure list on the page — it names every row, it does not summarise |
| `AUTHENTIC, PARTLY UNPROVABLE` | the file is intact but some rows carry no signature | honest output for a pre-signing ledger; say so rather than re-exporting until it looks clean |
| exit `2` from anything at startup | fail-closed: unparsable policy, `approval.mode: off`, TTL below the floor, unusable identity | fix the file. There is no "run anyway" flag, by design |
| `refused: already redeemed` | one approval buys one execution | re-request. A spent token is spent |
| `WinError 2` right after *Approval spent* | the approved binary is not on PATH | the token was genuinely consumed and the failure is logged as `approval:failed`; request again against a command that exists |
| a provider refusal naming an endpoint | a cloud provider was chosen with no key, or `policy.local-only.yaml` forbids egress | that is the rule working; `ssm --provider-show` says what would be used and why |
| the console exits 2 on `--bind 0.0.0.0` | you asked the **operator** view to serve a live ledger on a NIC | it will not. Deploy the auditor view instead |
| the auditor refuses an upload | no body, over 8 MiB, not JSON, or no `events` array | it refused before reading the bytes; check you exported a report and not a CSV |

## Changing the host signing key

There is no flag for this, and that is deliberate — the key is what the evidence
is. `ssm --reset-key` is **not** it: that option deletes the `.env` file holding
your model API key and says so; it never touches the host identity.

To change the signing key, delete the identity directory whose path
`ssm --evidence-show` prints, and the next run creates a new one:

```bash
ssm --evidence-show | grep -i ident   # read the path first
rm -rf ~/.local/state/linux-ai-ssm/identity
```

Understand the blast radius before you do it: rows already stored were signed by
the key that is now gone, so they stop verifying as this host's. Reports you
exported *before* rotating keep verifying, because each carries its own public
key — which is the reason to export evidence before a rotation rather than after
one. Date the rotation in the `--note` of the next report so a reader can see why
the key id changed.

Deleting the whole state directory deletes the evidence. That is an operator
decision with no confirmation step, so export first.

## Limits you are responsible for stating

- **macOS is untested.** Linux and Windows are what the suite runs on.
- The actor recorded in a row is an **OS username**, not a person. There are no
  per-user keys and no identity provider behind it.
- An approved command's **children are unsupervised**. Approval covers the exact
  bytes that were approved.
- `policy.yaml` can only tighten. The deny-by-default floor is in code and
  refuses to be weakened from config.
- The deployed auditor has **no authentication**. That is survivable only
  because report mode reads no host state; if you add a route that reads
  anything local, the reasoning dies with it.
- A free instance sleeps after fifteen idle minutes and its disk is ephemeral.

## What "verified" means in this repository

`python run_tests.py` is 64 tests, needs no network and no API key, and covers
the policy floor, the approval lifecycle, the evidence chain, the MCP facade,
both console modes and the deployed file set. `python mcp_server.py --check` is
19 protocol checks. `testing.txt` is the running record of what has actually been
observed on which machine, including the claims that were retracted — read its
last entries before repeating a claim about this project in public.
