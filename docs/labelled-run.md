# Labelled runs

One record per scenario: the input that was specified, the result that was
expected, the result that actually happened, and the artefact that proves it.
Where the three disagree, the difference is written out instead of smoothed over.
Fill a row only from something you watched happen — a transcript, a screenshot,
or the file itself. An empty cell is a run that has not happened; that is a real
answer and a placeholder is not.

The scenario below is the one this project is assessed against, quoted as given:

> One conversation ends in a signed, offline-verifiable history. An agent in
> Qoder, over the live MCP connector, asks for diagnostics and gets them; asks
> for `rm -rf /var/log` and is refused with the rule id named; opens an approval
> for a read-only command, which a human mints at the CLI and spends exactly once
> — the second attempt is refused as redeemed, and an edited or expired token is
> refused without being consumed. Then the report exports and verifies on a
> machine whose local state directory has been deleted. 58 automated tests and 19
> MCP protocol checks pass on Windows and Ubuntu 26.04.

Each clause is its own case, because each one can fail alone.

## R-01 — host: `RAVI`, OS: Ubuntu 26.04.1 LTS under WSL on Windows, date: 2026-10-22, run by: Jyothirmayi

| # | Specified input | Expected result | Actual result | Evidence |
|---|---|---|---|---|
| 1 | In Qoder, over the live MCP connector: ask for system status and the top memory consumers | `get_system_status` and `get_top_memory_processes` return; the agent answers from them; nothing is executed outside the gateway | | |
| 2 | Ask for `/var/log` to be cleared | `policy_decide` returns `blocked: true`, `score: 100`, `rule_id: baseline.destructive`, reason `Destructive or network-capable command detected` | | |
| 3 | Ask for `df -h` | `approval_request` returns a request id in state `open`; the agent has no tool that mints, spends or executes, and says it is waiting on a human | | |
| 4 | Human: `ssm --approve <id> --token-out /tmp/approved.tok` | A signed token bound to command hash, policy fingerprint, key id + hostname, actor and deadline | | |
| 5 | `ssm --execute @/tmp/approved.tok` | `df -h` runs once; the row moves to `redeemed` | | |
| 6 | `ssm --execute @/tmp/approved.tok` again | Refused: `this approval is redeemed, so it cannot be redeemed. A token buys one execution, and this one has already spent it.` Nothing runs | | |
| 7 | One character edited near the end of a minted token, then spent | Refused as a signature or payload-integrity failure. Ledger row still `minted` — not consumed | | |
| 8 | Token minted with `--approval-ttl 20`, spent after 25 s | Refused: `this approval expired at <iso>; consent that ran out is not consent`. Row still `minted` | | |
| 9 | Export the full chain, then verify it locally | `TRUSTED`, chain recomputes, every row signed | **Done 2026-10-22.** `python3 main.py --report --out "/mnt/c/Users/Ravi kumar/Downloads/run-report.json" --note "host RAVI (WSL), audit history through 2026-10-19, exported 2026-10-22"`, then `--report-verify` on the same file → `TRUSTED`. No `--last`, so the report is the complete history rather than a window | 24 events, 24 signed, 0 unsigned; host `RAVI` `sha256:c8fdb35c2b280c22558a99ea35da1515`; policy `default` `sha256:11bb409abe0c2b39e07f648eb8b99b79e8089e7858ec82b5ffe939110de4c268` |
| 10 | `HOME=/tmp/other-host ssm --report-verify …`, a home with no identity and no ledgers | Still `TRUSTED` — the document carries its own public key and reads no local state | | |
| 11 | Upload the report to the deployed auditor | `TRUSTED` verdict page at `/r/<id>` | **Done 2026-10-22.** `TRUSTED`, read back independently by a second person over plain HTTPS with no login and no access to the host that made it | `https://ssm-auditor.onrender.com/r/a48272e9b802424f86fc1c9795e3e38f` |
| 12 | Upload a copy with one row's `status` edited | `NOT TRUSTED`, with the failing rows named | **Done 2026-10-22.** `NOT TRUSTED`, two failures listed and neither summarised: `event 1: event_hash does not match its own contents (edited row, id 1)` and `the document signature does not validate: this file was changed after it was exported`. Host, policy fingerprint and note are identical to row 11, so the only difference between the two pages is one edited field | `https://ssm-auditor.onrender.com/r/029241d4ab314ab19eeb71144c296403` |
| 13 | `python run_tests.py` / `python mcp_server.py --check` / `ruff check .` on this host | `<N>/64`, `<N>/19`, clean | | |

Steps 7, 8 and 10 are the three most often skipped and the three that carry the
argument. Do not let a run count as complete without them.

**R-01 status as of 2026-10-22:** rows 9, 11 and 12 are done and evidenced above.
Rows 1–8, 10 and 13 have not been performed on this host and are deliberately
left blank — an empty cell means the run has not happened, not that it passed.
The host is recorded as `Ubuntu 26.04.1 LTS` from `lsb_release -ds` on
`RAVI`, and `ssm` resolves to `.venv/bin/ssm`, so the CLI rows below are run as
`ssm …`. What is still to capture is row 10, the one that proves verification
needs nothing but the file.

## Differences already known — state these, do not quietly correct them

- **64 tests, not 58.** The suite grew past the number in the brief. Report the
  count this host actually prints, which is out of 64.
- **`ubuntu-latest`, not a pinned 26.04, in CI.** `.github/workflows/ci.yml`
  declares the matrix as `os: [ubuntu-latest, windows-latest]` × Python
  `3.10 / 3.13 / 3.14`. The runner image line in any job log is the only
  authority on which Ubuntu that was on the day; read it before repeating a
  version number. The interactive run in R-01 is a separate fact and a stronger
  one: its host reports `Ubuntu 26.04.1 LTS` from `lsb_release -ds`, so the
  "Ubuntu 26.04" in the brief is true of the machine the agent was used on, and
  `ubuntu-latest` is what CI promised.
- **The local-model path is stub-verified.** The OpenAI-compatible provider
  (Ollama, LM Studio, vLLM) is tested against a local stub, not a real Ollama
  server. Say it that way.
- **macOS is untested.** Linux and Windows are what the suite runs on.
- **The actor is an OS username**, not a person — no per-user keys, no identity
  provider behind it.
- **The deployed auditor has no authentication.** That is survivable only because
  report mode reads no host state; adding any route that reads local files breaks
  the reasoning, not just the config.
- **An approved command's children are unsupervised.** Approval covers the exact
  bytes that were approved.
- **`auditor-service/Dockerfile` has not been built.** Until someone builds it, it
  is an untested artefact, not a deployment option. See Round D of
  `docs/verification-rounds.md`.
- **Verdict pages are temporary.** Uploads land on the free instance's
  container-local disk, so an id disappears when that container is replaced: a
  page that served `TRUSTED` on 2026-10-21 returned `404` on 2026-10-22, while
  the two ids above were still `200` when checked at 09:55 IST on 2026-10-22. The
  signed file is the evidence; the URL is a convenience. Re-open both links
  immediately before relying on them, and keep `run-report.json` itself as the
  artefact.

## R-02 onward — one record per machine, per person

A run by someone who did not write the code is a different kind of evidence, so
it gets its own heading rather than a tick in R-01's table. Copy the table above,
change the host line, and note anything that behaved differently — a fresh
install that needed an extra step is a finding about the installer, not a
formatting problem.

| Run | Host / OS | Runner | Steps complete | Tests | Checks | Notable differences |
|---|---|---|---|---|---|---|
| R-01 | | | | | | |
| R-02 | | | | | | |
| R-03 | | | | | | |

Link each run to its transcript or screenshots rather than summarising them into
the table.
