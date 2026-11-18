"""Tests for becscan. Run: python3 -m pytest -q  (offline, no network)"""

import json
import os
import sys
from email.message import EmailMessage

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import becscan as bs  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLES = os.path.join(os.path.dirname(HERE), "examples")


def write_eml(tmp_path, name, headers, body="Hello.", attachment=None):
    message = EmailMessage()
    for key, value in headers.items():
        message[key] = value
    message.set_content(body)
    if attachment:
        message.add_attachment(attachment[1], maintype="application", subtype="pdf",
                               filename=attachment[0])
    path = tmp_path / name
    path.write_bytes(bytes(message))
    return str(path)


GOOD_AUTH = "mx.example.com; dkim=pass; spf=pass; dmarc=pass"


def test_parse_email_extracts_thread_fields(tmp_path):
    path = write_eml(tmp_path, "a.eml", {
        "From": "Priya Sharma <priya.sharma@acme-supplies.com>",
        "To": "accounts@example.com",
        "Subject": "Re: Fwd: Invoice INV-2291",
        "Date": "Mon, 16 Nov 2026 10:02:11 +0530",
        "Message-ID": "<a@acme-supplies.com>",
        "Reply-To": "billing@acme-supplies.com",
        "Authentication-Results": GOOD_AUTH,
    })
    message = bs.parse_email(path)
    assert message["from_name"] == "Priya Sharma"
    assert message["from_addr"] == "priya.sharma@acme-supplies.com"
    assert message["from_domain"] == "acme-supplies.com"
    assert message["reply_domain"] == "acme-supplies.com"
    assert message["subject"] == "Re: Fwd: Invoice INV-2291"
    assert message["date"] is not None
    assert bs.norm_subject(message["subject"]) == "invoice inv-2291"


def test_sample_thread_is_a_confirmed_bec():
    files = bs.collect([EXAMPLES])
    messages = [bs.parse_email(path) for path in files]
    found, ordered = bs.analyse(messages)
    codes = {f["code"] for f in found}
    assert {
        "BC-BANK-DETAILS-CHANGE", "BC-DISPLAY-NAME-REUSE", "BC-LOOKALIKE-DOMAIN",
        "BC-REPLYTO-MISMATCH", "BC-PRESSURE-COMBO", "BC-INVOICE-WITH-BANK-CHANGE",
        "BC-AUTH-FAIL",
    } <= codes
    assert [m["file"] for m in ordered] == sorted(m["file"] for m in ordered)
    assert bs.main([EXAMPLES]) == 1


def test_clean_thread_has_no_high_findings(tmp_path):
    one = write_eml(tmp_path, "one.eml", {
        "From": "Priya Sharma <priya.sharma@acme-supplies.com>",
        "To": "accounts@example.com",
        "Subject": "Invoice INV-2291",
        "Date": "Mon, 16 Nov 2026 10:00:00 +0530",
        "Message-ID": "<one@acme-supplies.com>",
        "Authentication-Results": GOOD_AUTH,
    }, body="Please find the invoice attached. Payment in 30 days as usual.")
    two = write_eml(tmp_path, "two.eml", {
        "From": "Priya Sharma <priya.sharma@acme-supplies.com>",
        "To": "accounts@example.com",
        "Subject": "Re: Invoice INV-2291",
        "Date": "Mon, 16 Nov 2026 11:00:00 +0530",
        "Message-ID": "<two@acme-supplies.com>",
        "In-Reply-To": "<one@acme-supplies.com>",
        "Message-ID ": "",
        "Authentication-Results": GOOD_AUTH,
    }, body="Thanks, received. Will process on the normal cycle.")
    messages = [bs.parse_email(one), bs.parse_email(two)]
    found, _ordered = bs.analyse(messages)
    assert not [f for f in found if f["severity"] in ("critical", "high")]
    assert bs.main([one, two]) == 0


def test_freemail_sender_in_business_thread(tmp_path):
    one = write_eml(tmp_path, "corp.eml", {
        "From": "Priya Sharma <priya@acme-supplies.com>", "Subject": "Invoice",
        "Date": "Mon, 16 Nov 2026 10:00:00 +0530", "Authentication-Results": GOOD_AUTH,
    }, body="Invoice attached.")
    two = write_eml(tmp_path, "free.eml", {
        "From": "Priya Sharma <priya.sharma99@gmail.com>", "Subject": "Re: Invoice",
        "Date": "Mon, 16 Nov 2026 12:00:00 +0530", "Authentication-Results": GOOD_AUTH,
    }, body="Following up on the invoice.")
    found, _ordered = bs.analyse([bs.parse_email(one), bs.parse_email(two)])
    assert "BC-FREEMAIL-IN-THREAD" in {f["code"] for f in found}


def test_auth_failure_and_missing_header(tmp_path):
    failing = write_eml(tmp_path, "fail.eml", {
        "From": "a@acme-supplies.com", "Subject": "x",
        "Authentication-Results": "mx; spf=fail; dmarc=fail",
    })
    missing = write_eml(tmp_path, "missing.eml", {"From": "b@acme-supplies.com", "Subject": "x"})
    found, _ordered = bs.analyse([bs.parse_email(failing), bs.parse_email(missing)])
    codes = {f["code"] for f in found}
    assert "BC-AUTH-FAIL" in codes
    assert "BC-NO-AUTH-RESULTS" in codes


def test_broken_reply_chain_and_date_order(tmp_path):
    first = write_eml(tmp_path, "first.eml", {
        "From": "a@acme-supplies.com", "Subject": "Invoice",
        "Date": "Mon, 16 Nov 2026 12:00:00 +0530", "Authentication-Results": GOOD_AUTH,
    }, body="invoice")
    second = write_eml(tmp_path, "second.eml", {
        "From": "b@acme-supplies.com", "Subject": "Re: Invoice",
        "Date": "Mon, 16 Nov 2026 09:00:00 +0530", "Authentication-Results": GOOD_AUTH,
    }, body="reply without threading headers")
    found, _ordered = bs.analyse([bs.parse_email(first), bs.parse_email(second)])
    codes = {f["code"] for f in found}
    assert "BC-BROKEN-REPLY-CHAIN" in codes
    assert "BC-DATE-OUT-OF-ORDER" in codes


def test_helpers():
    assert bs.registrable("mail.acme-supplies.co.uk") == "acme-supplies.co.uk"
    assert bs.edit_distance("acme", "acme") == 0
    assert bs.edit_distance("acme", "acrme") == 1
    assert bs.edit_distance("acme", "zzzz") > 2
    assert bs.norm_subject("RE: FW: Re: subject line") == "subject line"


def test_cli_json_and_errors(tmp_path, capsys):
    assert bs.main([EXAMPLES, "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["gate"] == "FAIL"
    assert payload["summary"]["messages"] == 2
    assert payload["messages"][0]["date"]
    assert payload["findings"]

    assert bs.main(["/no/such/thread.eml"]) == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    assert bs.main([str(empty)]) == 2


def test_fail_on_none_disables_gate():
    assert bs.main([EXAMPLES, "--fail-on", "none"]) == 0


def test_single_message_thread(tmp_path):
    path = write_eml(tmp_path, "single.eml", {
        "From": "Someone <someone@example.com>", "Subject": "Hello",
        "Authentication-Results": GOOD_AUTH,
    }, body="Just saying hello.")
    assert bs.main([path]) == 0
