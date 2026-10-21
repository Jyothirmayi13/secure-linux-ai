# Verification rounds

Work that needs a machine which did not write this code. Everything here is
something a second or third person can do independently, on their own host, with
their own key, and each round produces an artefact that belongs in
`docs/labelled-run.md`.

Before starting:

- Clone the **public** repository: `https://github.com/Jyothirmayi13/secure-linux-ai`.
  Nothing else is shared with you, deliberately.
- Put **your own** model key in `.env`. Never copy anyone else's `.env`, and never
  commit yours — `.gitignore` covers it, and CI fails the build if a tracked `.env`
  ever appears.
- Open issues and pull requests. Do not push directly.
- If something refuses to work, that is a result worth recording. A round where
  nothing failed is either a lucky round or a shallow one.

## Round A — cold install on a machine with no history

The point is to find out what the install is like for someone who is not the
author, which is the only version of that question still answerable.

```bash
git clone https://github.com/Jyothirmayi13/secure-linux-ai && cd secure-linux-ai
python3 --version                      # 3.10 through 3.14
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env                   # your key
python run_tests.py                    # expect 64/64
python mcp_server.py --check           # expect 19/19
ruff check .
ssm --policy-show
ssm --evidence-show
```

`--evidence-show` on a fresh host should report a chain of zero rows and a newly
created identity. Record the exact `python3 --version`, the distro and version,
and anything the README did not tell you — an extra package, a step that had to
happen in a different order, a command that printed nothing useful.

**Expected:** all four green with no intervention. **Evidence:** the transcript,
plus the output of `pip freeze > /tmp/roundA-pipfreeze.txt`.

## Round B — the full run on your own host

Follow `docs/demo-script.md` end to end on your machine. Your host generates its
own Ed25519 identity, so the report you export is signed by a key that has never
touched anyone else's system, and it still verifies.

Fill in the R-0x table in `docs/labelled-run.md` from what you actually saw. Steps
7, 8 and 10 (edited token, expired token, verify with the state directory moved
away) are the ones that are easy to skip and hard to reconstruct later.

## Round C — the cross-host refusal (needs two people, two machines)

This is the one result nobody can produce alone, and it is the strongest evidence
that a token is consent rather than a capability.

1. On host **1**, open a request and mint it, but do not spend it:
   ```bash
   ssm --request-approval "df -h"
   ssm --approve req-XXXXXXXX --token-out /tmp/portable.tok
   ```
2. Copy `/tmp/portable.tok` to host **2** — any way you like.
3. On host **2**, spend it:
   ```bash
   ssm --execute @/tmp/portable.tok
   ```

**Expected:** refusal, naming both machines:

```
this approval was minted on <host1> (<key_id>) and this host is <host2>
(<key_id>). A token is not portable between machines.
```

The token is cryptographically valid, correctly formatted, unexpired and bound to
a command the floor allows. It fails purely because the signing identity differs.
Record both hostnames and both key ids (`ssm --evidence-show` prints them), then
go back to host 1 and spend it there to show it was never consumed by the attempt.

**Evidence:** both terminals in frame, or two screenshots with the key ids visible.

## Round D — the container

`auditor-service/Dockerfile` builds the deployed auditor view — report mode only,
no CLI, no capability tools, no model client and no host ledger in the image. It
has never been built by anyone, so right now it is an untested artefact and the
project says so.

```bash
git clone https://github.com/Jyothirmayi13/secure-linux-ai && cd secure-linux-ai
python deploy/make_auditor.py --check    # must pass before you build from it
cd auditor-service
docker build -t ssm-auditor .
docker run --rm -p 7860:7860 ssm-auditor
```

In a second shell:

```bash
curl -s http://127.0.0.1:7860/healthz                                   # ok
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:7860/audit    # expect 404
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:7860/policy   # expect 404
```

Then open `http://127.0.0.1:7860`, upload a real report and expect `TRUSTED`. The
port is 7860 unless the platform sets `$PORT`; the two 404s are the point — a
container that can serve a verdict page must not be able to serve a live ledger.

**Expected:** either a working container, or a build failure. A failure is a
correct outcome — record the log and open an issue; do not delete the Dockerfile
or call the round passed. **Evidence:** the build log and the three curl outputs.

## Round E — prove the auditor verifies instead of agreeing

Take any `TRUSTED` report and make four copies. In each, change exactly one thing:

| Copy | Change | Expected verdict |
|---|---|---|
| 1 | one row's `status` | `NOT TRUSTED` |
| 2 | one row's `payload` | `NOT TRUSTED` |
| 3 | delete the last row | `NOT TRUSTED` |
| 4 | the `note` inside the signed core | `NOT TRUSTED` |

Upload each to `https://ssm-auditor.onrender.com`. A one-field forgery that still
passes means the deployment is broken — open an issue immediately rather than
continuing the round.

Also record the four verdict words as they appear: `TRUSTED`, `AUTHENTIC, EMPTY`,
`AUTHENTIC, PARTLY UNPROVABLE`, `NOT TRUSTED`. The third one is what an honest
output looks like when a host could not sign its own history, and a reviewer
should see that the tool reports it instead of hiding it.

## Round F — read the docs as a stranger

Open `README.md`, `docs/quickstart.md`, `docs/runbook.md` and `docs/demo-script.md`.
Type **every** command exactly as printed, in a fresh shell, and file an issue for
each one that does not work. Do not edit the files — the wording is owned
elsewhere, and a correction you describe is more useful than one you silently
apply.

Check specifically: does every linked file exist, does every flag exist in
`ssm --help`, does every quoted output string match what the tool actually
prints, and is every number the tool actually prints?

## Round G — if you have a Mac

The suite has never run on Darwin. One `python run_tests.py` there is either a new
data point or a bug report about something platform-specific in path handling,
file locking or the subprocess layer. Both are worth more than the sentence
"macOS untested" that is in the docs today.

## What to send back

For each round: the labelled-run table filled in, the transcript or screenshots
named after the round, and one paragraph on anything that surprised you. Open one
issue per round rather than one combined issue, so they can be closed separately.
