# Evidence Report Verifier

A read-only viewer for the signed evidence reports produced by
[secure-linux-ai](https://github.com/Jyothirmayi13/secure-linux-ai), a policy-gated
gateway that lets an AI assistant ask to run read-only Linux commands and
records every decision — including every refusal — in a hash-chained audit
ledger signed by the host.

This directory is the whole deployed service: one `Procfile`, one
`requirements.txt`, one `Dockerfile`, and the eight modules under `app/`.

**What it does.** You hand it one `evidence-*.json` file. It recomputes the
row-by-row hash chain, checks each row's Ed25519 signature against the public
key carried inside the document, and checks the document signature over the
whole signed section. Then it renders one verdict:

- `TRUSTED` — every event is signed, the chain recomputes, nothing changed since export.
- `AUTHENTIC, EMPTY` — the gateway signed a report with no events in that window.
- `AUTHENTIC, PARTLY UNPROVABLE` — unaltered and authentic, but some rows carry no signature.
- `NOT TRUSTED` — with every specific failure listed.

No database, no network call back to the machine that produced the report, and
no trust in that machine are required: the report proves itself. The wording is
identical to `ssm --report-verify` on the terminal, because both read the same
`verdict_of()`.

**What it cannot do.** This service holds no host ledger, no policy signing key,
no approval tokens, and no execution path. It runs eight Python modules and two
dependencies — no CLI, no capability tools, no `psutil`, no model client. There
is no `/audit`, no `/policy`, no `/approvals` and no `/report.json` here; those
routes exist only in the operator view, which refuses to bind anything but
loopback. Every `POST` in this deployment is either a report to verify or a 405.
Uploads are stored under a random 32-hex name chosen by the server, never under
their filename, and pages are served with `Content-Security-Policy: default-src
'none'` and `X-Content-Type-Options: nosniff`, because the commands inside a
report are model-authored strings.

**Getting a report to verify.** On the machine that ran the gateway:

```bash
ssm --report --out evidence-window.json --limit 50   # a window, and it says so
ssm --report                                          # the whole ledger
```

A report whose first row is not row 1 is labelled a **window** and states how
many earlier rows were excluded. Verification is the same either way; the
difference is what the document can honestly claim.

**Limits, stated plainly.** There is no sign-in and the service is public. That
is acceptable here only because there is no host state to reach: a visitor can
upload a document and read the verdict for a document at an unguessable URL.
Anyone can upload a *forged* report and see `NOT TRUSTED` — that is the service
working, not a way around it. Uploaded files live on the service's ephemeral
disk and are lost on restart or redeploy; nothing is written to a database, and
the request log records one line per request with no byte of any body. On a free
PaaS tier the instance sleeps when idle, so the first request after a pause
takes a few seconds.

**How to run it.** `render.yaml` at the repository root deploys this directory
as a free web service: 0.1 CPU, 512 MB, no card, an `onrender.com` URL, and a
spin-down after fifteen idle minutes that costs the next visitor a few seconds
of wake-up. Any other buildpack host (one that reads a `Procfile`) starts `web:`
directly; the app binds `$PORT` and answers `GET /healthz`. Container hosts build
`Dockerfile` and run the same command on port 7860. Locally, from this directory:

```bash
pip install -r requirements.txt
python app/console.py --serve-reports --bind 127.0.0.1 --port 8080
```

Source, tests and the verification spec:
[github.com/Jyothirmayi13/linux-ai-ssm](https://github.com/Jyothirmayi13/linux-ai-ssm)
(`console.py`, `evidence.py`, `deploy/auditor/`).
