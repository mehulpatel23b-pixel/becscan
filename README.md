# becscan

**Catch business email compromise across the whole thread, not one message at a time.**

A BEC attempt is built to survive a per-message check. The first mail is a real supplier with a
real invoice. The second one is a reply in the same thread that says "our bank details have
changed". Every message on its own looks plausible. The thread is where the lie becomes visible:
one display name writing from two domains, a Reply-To pointing somewhere else, an authentication
failure, and payment pressure with a request for discretion.

`becscan` reads a thread of raw `.eml` files, correlates the participants and reports the seams.

<p>
  <img src="https://img.shields.io/badge/python-3.8%2B-0d1117?style=flat-square&logo=python&logoColor=39D353" alt="python" />
  <img src="https://img.shields.io/badge/runtime%20dependencies-zero-0d1117?style=flat-square" alt="zero dependencies" />
  <img src="https://img.shields.io/badge/network-none-0d1117?style=flat-square" alt="no network" />
  <img src="https://img.shields.io/badge/scope-thread%20level-0d1117?style=flat-square" alt="thread level" />
  <img src="https://img.shields.io/badge/license-MIT-0d1117?style=flat-square" alt="MIT" />
</p>

## Why

Single-message scanners are the standard defence and BEC walks straight past them:

- The attacker replies inside a real thread, so the subject, the recipients and the quote all match.
- The display name is copied exactly. Only the domain differs, and nobody reads the domain.
- The payload is a sentence, not an attachment or a link, so URL reputation has nothing to score.
- The request is authorised by the pressure it creates: pay today, keep it quiet, do not call.

All of that is detectable, but only if you look at the messages together.

## Install

One file, standard library only.

```bash
git clone https://github.com/mehulpatel23b-pixel/becscan.git
cd becscan
python3 becscan.py --help
```

## Usage

```bash
# a whole exported thread
python3 becscan.py examples/

# specific messages, in the order they arrived
python3 becscan.py 01-supplier-invoice.eml 02-changed-bank-details.eml

# JSON for a ticket or a SOAR playbook
python3 becscan.py examples/ --json

# gate a mail-triage pipeline
python3 becscan.py examples/ --fail-on high
```

Message **order matters** for the reply-chain checks, so pass them in mailbox order (numbered file
names work). Participant and language checks are order independent.

Sample output:

```text
becscan 1.0.0
subject : invoice inv-2291 for october
messages: 2   domains: acme-supplies.com, acme-supplies.net
risk    : 100/100  grade F  gate FAIL

SEVERITY RULE                           WHERE            DETAIL
----------------------------------------------------------------------------------------
CRITICAL BC-BANK-DETAILS-CHANGE         02-changed-bank  message asks to change or supply bank details
CRITICAL BC-DISPLAY-NAME-REUSE          thread           'priya sharma' writes from more than one domain
CRITICAL BC-LOOKALIKE-DOMAIN            thread           acme-supplies.com is one edit away from acme-supplies.net
HIGH     BC-AUTH-FAIL                   02-changed-bank  authentication failed: dmarc=fail, spf=fail
HIGH     BC-REPLYTO-MISMATCH            02-changed-bank  Reply-To points at intl-collect.example
HIGH     BC-PRESSURE-COMBO              02-changed-bank  payment language plus urgency plus a request for discretion
```

## Rules

| Rule | Severity | What it catches |
| :-- | :-- | :-- |
| `BC-BANK-DETAILS-CHANGE` | critical | bank-details change language with a numeric identifier present |
| `BC-DISPLAY-NAME-REUSE` | critical | one display name writing from two different domains inside a thread |
| `BC-LOOKALIKE-DOMAIN` | critical | two thread domains whose labels are one edit apart |
| `BC-REPLYTO-MISMATCH` | high | Reply-To sits on a different domain than From |
| `BC-AUTH-FAIL` | high | the message's own `Authentication-Results` shows a DMARC/SPF/DKIM failure |
| `BC-PRESSURE-COMBO` | high | payment language + urgency + a request for discretion |
| `BC-INVOICE-WITH-BANK-CHANGE` | high | invoice attachment combined with a bank-details change |
| `BC-PAYMENT-URGENCY` | medium | payment language pushed with urgency alone |
| `BC-FREEMAIL-IN-THREAD` | medium | a free mailbox appears inside a business thread |
| `BC-BROKEN-REPLY-CHAIN` | low | "Re:" with no `In-Reply-To` or `References`, a fresh mail dressed as a reply |
| `BC-DATE-OUT-OF-ORDER` | low | date is earlier than the message it follows |
| `BC-NO-AUTH-RESULTS` | low | no `Authentication-Results` header in the export |

## Scoring and exit codes

Weights are critical 40, high 22, medium 10, low 4, capped at 100. Grade A is 0-10, B to 25,
C to 45, D to 65, E to 85, F above.

| Code | Meaning |
| :-- | :-- |
| `0` | Nothing at or above `--fail-on` (default `high`) |
| `1` | Threshold breached: treat the thread as an active BEC |
| `2` | No `.eml` files, or nothing readable |

## Design

- **Thread level.** The value is correlation, so the tool never judges a message alone.
- **Evidence you can quote.** Each finding names the file, the two domains, or the exact failure
  string, so it survives being pasted into a ticket.
- **No network, no rendering.** Headers and bodies only, so a hostile message cannot do anything.
- **Honest severities.** A missing `Authentication-Results` header is `low`, because exports drop
  headers all the time.

## What to do with a hit

1. Do not reply and do not pay from anything in the thread.
2. Call the supplier on a number you already have, never one supplied in the mail.
3. Report it to your Finance and Security teams with the exporting filenames intact.

## Ethics

Triage of mail that was reported to you or exported from your own mailbox. Read-only, offline, and
it stores nothing.

## License

MIT. See [LICENSE](LICENSE).
