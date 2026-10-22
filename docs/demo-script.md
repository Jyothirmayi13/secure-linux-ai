# The recorded run

One continuous path from a question asked by a model to a report that verifies on
a machine with no memory of producing it. Record it in this order; the order is
the argument. Two windows are on screen for the whole run: **Qoder**, where the
agent works through the MCP connector, and a **terminal**, where the human signs.
Nothing in the terminal window is ever done from the agent side, and that
separation is the thing being shown.

State lives in `~/.local/state/linux-ai-ssm/` — the host key pair,
`audit.sqlite3`, `approvals.sqlite3`. From an installed package the commands are
`ssm`; from a clone they are `python main.py`.

## Pre-flight (do not record this)

```bash
cd ~/secure-linux-ai
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env          # your own key, never someone else's
python run_tests.py           # 64 tests, no network, no key needed
python mcp_server.py --check  # 19 protocol checks
ruff check .
```

All three must be clean. Then set the terminal to 16–18 pt, make Qoder and the
terminal the same height side by side, and check the connector is live by listing
its tools: eleven, five read-only diagnostics and six control tools, with no
`approve`, no `mint` and no `execute` among them.

Start recording here.

## Step 1 — the agent reads the host

In Qoder, ask: *"What is this machine doing right now, and what is using the
most memory?"*

The agent should call `get_system_status` and `get_top_memory_processes` and
answer from the results. Let it finish. This is the part that is easy, and it is
here only so the next step has something to be measured against.

## Step 2 — the agent asks for something it must not get

Ask: *"Clear out /var/log to free space."*

Expect `policy_decide` with `command: "rm -rf /var/log"`, returning blocked with
the rule named. The refusal is not a prompt-injection trip and not a policy.yaml
rule — it is the floor in code:

```
category CRITICAL · score 100 · blocked true · rule baseline.destructive
reason: Destructive or network-capable command detected
```

Read the rule id on screen. Then confirm the same thing from the terminal so the
operator and the agent can be seen getting the identical answer:

```bash
ssm policy check "rm -rf /var/log"
```

If the agent instead asks you "should I proceed?" without calling the tool, ask
it to check the policy. It has no way to skip the check and still get an answer.

## Step 3 — the agent opens an approval and discovers it cannot close one

Ask: *"Then just run `df -h` so we can see actual disk usage."*

`df -h` is allowed by the floor (`baseline.allow_list`, LOW, score 10) but every
execution still needs a signed human approval. The agent's only move is
`approval_request`, which returns a request id and stops there. Let the viewer
see the agent state plainly that it is waiting on a human and cannot proceed.

Prove the gap rather than asserting it:

```bash
ssm --approval-list          # the request is sitting in state "open"
```

## Step 4 — a human signs, in the other window

Switch to the terminal. This is the only step that requires this machine and this
operator, and it is the point of the whole run.

```bash
ssm --approve req-XXXXXXXX --token-out /tmp/approved.tok
ssm --approval-show @/tmp/approved.tok
```

`--token-out` keeps the token out of the terminal, the scrollback and shell
history. `--approval-show` is a query: it prints what the token binds to —
command hash, policy fingerprint, key id and hostname, actor, deadline — and
leaves it unspent. Read the bindings on screen.

## Step 5 — spend it once, then try again

```bash
ssm --execute @/tmp/approved.tok     # df -h runs, output appears
ssm --execute @/tmp/approved.tok     # refused
```

The second attempt must fail with:

```
this approval is redeemed, so it cannot be redeemed. A token buys one execution,
and this one has already spent it.
```

That is enforced by the ledger row, not by reading a field and then writing it,
so two processes racing to spend one approval still produce one execution.

## Step 6 — a token that is altered, and a token that ran out

Both refusals happen **before** the ledger is touched, so neither attempt burns
the approval. Show that by re-listing after each one.

### The altered token

```bash
ssm --request-approval "df -h"
ssm --approve <that id> --token-out /tmp/edited.tok
ssm --approval-show @/tmp/edited.tok          # signature valid, state minted
```

A token is `ssm-approval-1-` followed by one base64url blob — there is no
separator to cut on. Open `/tmp/edited.tok` and change **one character near the
end** of it, which is inside the signature field, then:

```bash
ssm --execute @/tmp/edited.tok                # refused
ssm --approval-list                           # the request is still "minted"
```

Expect `this token's signature does not validate against this host's key. Either
it was not minted here or it was altered after minting.` A character changed
earlier in the blob may instead fail as unreadable JSON or a missing signed
field; the message differs, the outcome does not. The suite tries six such edits
in a row and then asserts the row is still `minted` — one refusal is not a
discount on a real spend.

### The token that ran out

```bash
ssm --request-approval "df -h" --approval-ttl 20
ssm --approve <that id> --token-out /tmp/short.tok
sleep 25
ssm --execute @/tmp/short.tok                 # refused: expired
ssm --approval-list                           # still not redeemed
```

The expiry refusal reads `this approval expired at <iso>; consent that ran out is
not consent`. Both checks sit ahead of the ledger write in `redeem_token`, which
is why a failed attempt is not a discount on a real one — show the state
afterwards rather than only the refusal.

Then void what is left over so nothing spendable is lying around:

```bash
ssm --void-approval <remaining request id>
```

## Step 7 — export, then verify on a host that has forgotten everything

```bash
ssm --report --out /tmp/run-report.json --note "recorded run, <hostname>, <date>"
ssm --report-verify /tmp/run-report.json      # TRUSTED, while state is still here
```

No `--last`: a window reports how many earlier rows it left out, and a complete
chain from row 1 is the stronger artefact. Put the context in `--note` rather than
in the filename — the note sits inside the signed core, so it is authenticated
rather than typed.

Now take it away from the host that wrote it. Do **not** move or delete the real
state directory — it holds the signing key and the ledger, and a `mv` onto a path
the tool has already recreated lands the whole thing one level too deep. Run the
verifier with `HOME` pointing somewhere empty instead. That is the same claim,
reversibly:

```bash
rm -rf /tmp/other-host                       # only ever this scratch directory
HOME=/tmp/other-host ssm --report-verify /tmp/run-report.json   # still TRUSTED
```

`/tmp/other-host` is a machine that has never seen this project: no identity, no
`audit.sqlite3`, no `approvals.sqlite3`. The verifier reads none of them, because
the document carries its own public key.

## Step 8 — someone else verifies it in a browser

Open `https://ssm-auditor.onrender.com`, upload `/tmp/run-report.json`, and let
the verdict page render at its unguessable `/r/<id>`. Then copy the report, open
the copy, change one row's `status`, save without re-signing, and upload that.
Expect **`NOT TRUSTED`** with the failing rows listed by number.

Both pages on screen at once is the strongest frame in the run: same key, same
tool, opposite verdicts, and the difference is one edited byte.

If the instance is asleep, wait it out rather than cutting — a cold start is
honest and a cut is not.

## Step 9 — close on the repository

End on the public repo's Actions page with the matrix green, then stop recording.
The tests and the CI are the reason any of the above is reproducible by someone
who is not you.

## If a step fails

Stop the recording. Fix the cause, or write the failure into
`docs/labelled-run.md` as a difference, and start that step over. Do not cut
around a failure and do not present a step that misfired as one that worked — the
project's whole claim is that its record is trustworthy, and a doctored run of it
would contradict that better than any missing feature.
