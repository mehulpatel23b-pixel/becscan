#!/usr/bin/env python3
"""becscan - catch business email compromise across a whole email thread.

BEC is rarely one suspicious message. It is a real thread, a real supplier, and then a reply
that says "our bank details have changed". Any single message looks ordinary; the thread is
where the lie shows.

becscan reads a thread of raw `.eml` files and correlates the participants, the reply chain,
the authentication results and the language of the request.

Zero dependencies. Pure standard library. No network.
"""

from __future__ import annotations

import argparse
import email
import email.policy
import glob
import json
import os
import re
import sys
from email.utils import parseaddr, parsedate_to_datetime, getaddresses

__version__ = "1.0.0"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_WEIGHT = {"critical": 40, "high": 22, "medium": 10, "low": 4, "info": 0}
GRADES = [(10, "A"), (25, "B"), (45, "C"), (65, "D"), (85, "E"), (999, "F")]

FREE_MAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "hotmail.com", "outlook.com",
    "live.com", "aol.com", "proton.me", "protonmail.com", "icloud.com", "mail.ru",
    "yandex.com", "yandex.ru", "gmx.com", "gmx.net", "zoho.com", "rediffmail.com",
    "163.com", "qq.com", "naver.com",
}

BANK_CHANGE = (
    r"bank details? (?:have |has )?chang", r"new (?:bank|account) details", r"update(?:d)? (?:our|my) bank",
    r"changed (?:our|my) bank", r"new account number", r"new (?:iban|account)",
    r"remittance (?:details|account)", r"payment instructions? (?:have )?chang",
    r"please (?:use|update) (?:the|these) (?:new )?(?:account|banking)",
    r"beneficiary account", r"sort code", r"routing number", r"swift code",
)
BANK_DATA = (
    r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b",             # IBAN
    r"\b\d{8,18}\b",                                  # long account-ish number
    r"\b\d{2}-\d{2}-\d{2}\b",                         # UK sort code
    r"\b\d{9}\b",                                     # US routing number
)
PAYMENT = (r"wire transfer", r"bank transfer", r"remittance", r"invoice", r"payment", r"funds",
           r"outstanding balance", r"proforma")
URGENCY = (r"\burgent\b", r"immediately", r"asap", r"right away", r"today", r"before (?:close|eod)",
           r"time[- ]sensitive", r"final notice", r"overdue", r"act now")
SECRECY = (r"confidential", r"between (?:us|you and me)", r"do not (?:discuss|tell|inform)",
           r"don'?t (?:tell|mention|call)", r"discreet", r"keep this (?:quiet|private)",
           r"no need to (?:call|verify)")

MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in", "co.jp", "com.au",
    "net.au", "org.au", "co.nz", "co.za", "com.br", "com.mx", "com.tr", "com.sg", "com.hk",
    "co.kr", "com.cn", "com.tw", "com.ar", "com.co", "com.my", "co.id", "com.ph", "com.vn",
}


class ThreadError(Exception):
    """Raised when a thread cannot be read."""


def registrable(host):
    if not host:
        return ""
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def edit_distance(left, right, limit=3):
    """Small Levenshtein with an early exit, enough for lookalike detection."""
    if abs(len(left) - len(right)) > limit:
        return limit + 1
    previous = list(range(len(right) + 1))
    for i, lchar in enumerate(left, 1):
        current = [i]
        for j, rchar in enumerate(right, 1):
            cost = 0 if lchar == rchar else 1
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost))
        if min(current) > limit:
            return limit + 1
        previous = current
    return previous[-1]


def body_text(message):
    parts = []
    for part in message.walk():
        if part.get_content_type() in ("text/plain", "text/html") and not part.get_filename():
            try:
                payload = part.get_payload(decode=True)
            except Exception:  # noqa: BLE001 - body is best effort
                continue
            if payload:
                parts.append(payload.decode(part.get_content_charset() or "utf-8", "replace"))
    return "\n".join(parts)


def parse_email(path):
    try:
        with open(path, "rb") as handle:
            message = email.message_from_binary_file(handle, policy=email.policy.compat32)
    except OSError as exc:
        raise ThreadError("%s: %s" % (path, exc)) from exc
    from_name, from_addr = parseaddr(message.get("From", "") or "")
    reply_name, reply_addr = parseaddr(message.get("Reply-To", "") or "")
    try:
        when = parsedate_to_datetime(message.get("Date", ""))
    except (TypeError, ValueError):
        when = None
    references = (message.get("References", "") or "").split()
    attachments = [part.get_filename() for part in message.walk() if part.get_filename()]
    return {
        "file": os.path.basename(path),
        "path": path,
        "from_name": from_name.strip(),
        "from_addr": from_addr.strip().lower(),
        "from_domain": registrable(from_addr.split("@")[-1] if "@" in from_addr else ""),
        "reply_to": reply_addr.strip().lower(),
        "reply_domain": registrable(reply_addr.split("@")[-1] if "@" in reply_addr else ""),
        "to": [addr.lower() for _n, addr in getaddresses([message.get("To", "") or ""]) if addr],
        "subject": (message.get("Subject", "") or "").strip(),
        "date": when,
        "message_id": (message.get("Message-ID", "") or "").strip(),
        "in_reply_to": (message.get("In-Reply-To", "") or "").strip(),
        "references": references,
        "auth": (message.get("Authentication-Results", "") or "").lower(),
        "body": body_text(message),
        "attachments": attachments,
    }


def norm_subject(subject):
    return re.sub(r"^((re|fw|fwd|aw|sv)\s*:\s*)+", "", (subject or "").lower()).strip()


def analyse(messages):
    """Return findings for a whole thread."""
    found = []

    def add(sev, code, detail, fix, where=""):
        found.append({"severity": sev, "code": code, "where": where, "detail": detail, "fix": fix})

    ordered = sorted(messages, key=lambda m: (m["date"] is None, m["date"] or 0))
    domains = sorted({m["from_domain"] for m in ordered if m["from_domain"]})

    for message in ordered:
        label = message["file"]
        body = message["body"].lower()

        if message["reply_domain"] and message["from_domain"] and \
                message["reply_domain"] != message["from_domain"]:
            add("high", "BC-REPLYTO-MISMATCH",
                "Reply-To points at %s while From is %s"
                % (message["reply_domain"], message["from_domain"]),
                "Replies go to a different organisation than the one that appears to be writing. "
                "Strip Reply-To or treat the sender as untrusted.", label)

        if message["from_domain"] in FREE_MAIL and any(d not in FREE_MAIL for d in domains):
            add("medium", "BC-FREEMAIL-IN-THREAD",
                "sender uses a free mailbox (%s) inside a business thread" % message["from_domain"],
                "Suppliers write from their own domain. Ask for a callback on a known number.", label)

        if not message["auth"]:
            add("low", "BC-NO-AUTH-RESULTS",
                "no Authentication-Results header: authenticity cannot be checked from the file",
                "Pull the full headers from the recipient mailbox before you trust the sender.", label)
        else:
            failures = [token for token in ("dmarc=fail", "spf=fail", "dkim=fail") if token in message["auth"]]
            if failures:
                add("high", "BC-AUTH-FAIL",
                    "authentication failed: %s" % ", ".join(failures),
                    "The sender did not authenticate for this domain. Treat the message as forged.",
                    label)

        bank_language = [p for p in BANK_CHANGE if re.search(p, body)]
        bank_values = [p for p in BANK_DATA if re.search(p, body, re.I)]
        if bank_language and (bank_values or re.search(r"account", body)):
            add("critical", "BC-BANK-DETAILS-CHANGE",
                "message asks to change or supply bank details, with %d numeric identifier(s) present"
                % len(bank_values),
                "Never act on bank changes from email. Verify by calling a number you already hold, "
                "never one supplied in the thread.", label)

        payment = [p for p in PAYMENT if re.search(p, body)]
        urgency = [p for p in URGENCY if re.search(p, body)]
        secrecy = [p for p in SECRECY if re.search(p, body)]
        if len(payment) >= 2 and urgency and secrecy:
            add("high", "BC-PRESSURE-COMBO",
                "payment language plus urgency plus a request for discretion",
                "Manufactured urgency with secrecy is the signature of a BEC push. Verify out of band.",
                label)
        elif len(payment) >= 2 and urgency:
            add("medium", "BC-PAYMENT-URGENCY",
                "payment request pushed with urgency (%s)" % ", ".join(sorted(set(urgency))[:3]),
                "Check the invoice against the purchase order, and call the supplier.", label)

        if any(name.lower().endswith((".pdf", ".xls", ".xlsx", ".doc", ".docx", ".zip", ".htm", ".html"))
               for name in message["attachments"]) and bank_language:
            add("high", "BC-INVOICE-WITH-BANK-CHANGE",
                "invoice attachment combined with a bank-details change",
                "This is the classic invoice-fraud shape. Do not pay from this document.", label)

    # display-name impersonation across the thread
    by_name = {}
    for message in ordered:
        if message["from_name"]:
            by_name.setdefault(message["from_name"].lower(), set()).add(message["from_domain"] or "unknown")
    for name, seen_domains in by_name.items():
        if len(seen_domains) > 1:
            add("critical", "BC-DISPLAY-NAME-REUSE",
                "'%s' writes from more than one domain: %s" % (name, ", ".join(sorted(seen_domains))),
                "One display name, two domains, is impersonation inside a live thread. "
                "Confirm the participant list before replying.", "thread")

    for index, left in enumerate(domains):
        for right in domains[index + 1:]:
            if left == right:
                continue
            left_label = left.split(".")[0]
            right_label = right.split(".")[0]
            distance = edit_distance(left_label, right_label)
            if distance <= 1 or (registrable(left) == registrable(right) and left != right):
                add("critical", "BC-LOOKALIKE-DOMAIN",
                    "%s is one edit away from %s" % (left, right),
                    "Lookalike domains inside one thread mean a supplier is being imitated. "
                    "Compare the exact sending addresses, not the display names.", "thread")

    # reply-chain integrity, judged in the order the messages were given us (mailbox order),
    # because a date-sorted list can never look out of order
    previous = None
    for message in messages:
        if previous is not None:
            same_subject = norm_subject(message["subject"]) == norm_subject(previous["subject"])
            looks_like_reply = bool(re.match(r"^\s*re\s*:", message["subject"], re.I))
            if same_subject and looks_like_reply and not message["in_reply_to"] and not message["references"]:
                add("low", "BC-BROKEN-REPLY-CHAIN",
                    "message looks like a reply but carries no In-Reply-To or References header",
                    "A reply that does not thread is often a fresh message dressed up as continuation.",
                    message["file"])
            if previous["date"] and message["date"] and message["date"] < previous["date"]:
                add("low", "BC-DATE-OUT-OF-ORDER",
                    "date is earlier than the message it follows in the thread",
                    "Check the Received headers: forged dates hide the true order of events.",
                    message["file"])
        previous = message

    found.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["code"]))
    return found, ordered


def score(findings):
    total = min(100, sum(SEVERITY_WEIGHT[f["severity"]] for f in findings))
    return total, next(g for threshold, g in GRADES if total <= threshold)


def build_report(messages, errors=None):
    findings, ordered = analyse(messages)
    risk, grade = score(findings)
    counts = {sev: sum(1 for f in findings if f["severity"] == sev)
              for sev in ("critical", "high", "medium", "low", "info")}
    return {
        "summary": {
            "messages": len(ordered),
            "participants": sorted({m["from_addr"] for m in ordered if m["from_addr"]}),
            "domains": sorted({m["from_domain"] for m in ordered if m["from_domain"]}),
            "subject": norm_subject(ordered[0]["subject"]) if ordered else "",
            "flags": len(findings),
            "risk": risk,
            "grade": grade,
            "counts": counts,
            "gate": "FAIL" if counts["critical"] or counts["high"] else "PASS",
        },
        "messages": [dict(m, date=m["date"].isoformat() if m["date"] else None) for m in ordered],
        "findings": findings,
        **({"errors": errors} if errors else {}),
    }


def render(payload):
    s, lines = payload["summary"], []
    lines.append("becscan %s" % __version__)
    lines.append("subject : %s" % (s["subject"] or "(none)"))
    lines.append("messages: %d   domains: %s" % (s["messages"], ", ".join(s["domains"]) or "unknown"))
    lines.append("risk    : %d/100  grade %s  gate %s" % (s["risk"], s["grade"], s["gate"]))
    lines.append("")
    lines.append("thread")
    lines.append("-" * 104)
    for message in payload["messages"]:
        lines.append("  %s  %-34s %-28s %s"
                     % ((message["date"] or "unknown")[:16],
                        ("%s <%s>" % (message["from_name"], message["from_addr"]))[:34],
                        message["from_domain"][:28], message["file"]))
    lines.append("")
    if payload["findings"]:
        lines.append("%-8s %-30s %-16s %s" % ("SEVERITY", "RULE", "WHERE", "DETAIL"))
        lines.append("-" * 104)
        for f in payload["findings"]:
            lines.append("%-8s %-30s %-16s %s"
                         % (f["severity"].upper(), f["code"], f["where"][:16], f["detail"]))
        lines.append("")
        lines.append("fixes")
        lines.append("-" * 104)
        for f in payload["findings"]:
            if f["severity"] in ("critical", "high"):
                lines.append("[%s] %s  %s" % (f["severity"][:4].upper(), f["code"], f["where"]))
                lines.append("      %s" % f["fix"])
    else:
        lines.append("no findings: the thread looks consistent")
    return "\n".join(lines)


def collect(paths):
    files = []
    for path in paths:
        if os.path.isdir(path):
            files.extend(sorted(glob.glob(os.path.join(path, "*.eml"))))
        elif os.path.isfile(path):
            files.append(path)
        else:
            raise ThreadError("%s: no such file or directory" % path)
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="becscan",
        description="Correlate a raw email thread and flag business email compromise signals.")
    parser.add_argument("paths", nargs="+", help="one or more .eml files, or a directory of them")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--fail-on", default="high",
                        choices=["critical", "high", "medium", "low", "info", "none"],
                        help="lowest severity that fails the run (default high)")
    parser.add_argument("--version", action="version", version="becscan " + __version__)
    args = parser.parse_args(argv)

    errors, messages = [], []
    try:
        files = collect(args.paths)
    except ThreadError as exc:
        sys.stderr.write("becscan: %s\n" % exc)
        return 2
    if not files:
        sys.stderr.write("becscan: no .eml files found\n")
        return 2

    for path in files:
        try:
            messages.append(parse_email(path))
        except ThreadError as exc:
            errors.append(str(exc))
    if not messages:
        for err in errors:
            sys.stderr.write("becscan: %s\n" % err)
        return 2

    payload = build_report(messages, errors or None)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render(payload))
        for err in errors:
            print("warning: %s" % err, file=sys.stderr)

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f["severity"]] <= threshold for f in payload["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
