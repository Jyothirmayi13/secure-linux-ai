# Try the verifier without trusting anyone

Two documents, thirty seconds, no installation.

**`sample-report.json`** — a real evidence report, produced by this software on a
throwaway test host with its own one-off signing key. It is not anyone's production
history, and it says so in its own signed note.

**`sample-tampered.json`** — the same document with one row's `status` changed from
`executed` to `blocked`, and nothing else. Not re-signed.

Open <https://ssm-auditor.onrender.com>, upload each in turn, and compare the two
verdicts. Both pages are worth reading closely:

| | honest file | edited file |
| --- | --- | --- |
| verdict | `TRUSTED` | `NOT TRUSTED` |
| events | 8 total, 8 signed, 0 unsigned | **8 total, 8 signed, 0 unsigned** |
| failures | none | `event 2: event_hash does not match its own contents` and `the document signature does not validate` |

That middle row is the point. The tampered file still contains eight valid
signatures — nothing is missing, nothing is unsigned. What changed is that the
contents no longer match what was signed, and the row's own hash no longer matches
the row. A log that only proves *who wrote an entry* can be edited from the inside;
this one cannot, because each entry carries a code derived from its own contents and
from the entry before it.

The verifier needs nothing from the machine that made the report. It reads the public
key out of the document and does the arithmetic. You can confirm that locally too:

```bash
ssm --report-verify sample-report.json     # TRUSTED
ssm --report-verify sample-tampered.json   # NOT TRUSTED, event 2
```

Or with no state at all, which is the same claim from a stranger's machine:

```bash
HOME=/tmp/no-such-host ssm --report-verify sample-report.json
```

## Regenerating these

They are checked in so the demo works offline, but they are ordinary output:

```bash
HOME=$(mktemp -d)                       # a throwaway host: its own key, its own ledger
ssm --request-approval "df -h"
ssm --approve <request id> --token-out /tmp/t.tok
ssm --execute @/tmp/t.tok
ssm --report --out sample-report.json --note "sample document from a throwaway test host; not a production run"
```

Then edit one `status` value in a copy without re-signing it.
