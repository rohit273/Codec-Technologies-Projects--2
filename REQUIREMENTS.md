# Requirements

## Functional
FR-01 parse local `.eml`; FR-02 extract sender/reply-to/subject/date/body/authentication results; FR-03 extract URLs without visiting; FR-04 detect reply-to mismatch; FR-05 read auth failure indicators; FR-06 heuristic score; FR-07 JSON/CSV export; FR-08 opt-in lookup of existing VirusTotal URL reports.

## Non-functional
Python 3.10+; standard library in default mode; no external network by default; API keys via environment variables; clear errors; no message content execution.

## Out of scope
SMTP/IMAP integration, quarantine, independent SPF/DKIM verification, attachment detonation, browser automation, automatic blocking, calibrated probability output.
