# Email Security Gateway with Phishing Detection

A local defensive prototype that parses `.eml` messages, reviews existing authentication-result headers, inspects URLs **without opening them**, applies explainable phishing heuristics, and produces JSON/CSV reports.

**Scope:** this is not an SMTP gateway and does not deliver, block, or quarantine email. It does not independently verify SPF/DKIM/DMARC; it reads `Authentication-Results` supplied by a receiving system. VirusTotal lookup is optional, off by default, and can disclose URLs to a third party.

## Features
- Parse local `.eml` files using Python's email parser
- Extract sender, reply-to, subject, auth results, body text, and URLs
- Flag reply-to mismatch, auth failure indicators, URL shorteners, IP-literal hosts, urgency language, and suspicious URL wording
- Optional lookup of an **existing** VirusTotal URL report; never submits new URLs
- Explainable score, JSON/CSV reports, synthetic sample emails, tests

## Requirements
Python 3.10+. Core uses standard library only. Optional VirusTotal mode uses `requests` from `requirements-optional.txt`.

## Quick start
Windows:
```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python src\analyze_email.py --input data\sample_phishing.eml --out reports\demo
```
Linux/macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
python src/analyze_email.py --input data/sample_phishing.eml --out reports/demo
python src/analyze_email.py --input data/sample_legitimate.eml --out reports/legitimate-demo
```
Tests: `python -m unittest discover -s tests -v`

## Optional VirusTotal lookup
Review the provider's terms and your data-sharing policy first. A lookup may disclose the URL. Do not query URLs with private reset tokens, internal hostnames, or other sensitive data. Install `pip install -r requirements-optional.txt`, set `VT_API_KEY` in your shell, then run:
```bash
python src/analyze_email.py --input data/sample_phishing.eml --out reports/vt-demo --virustotal
```
The program queries an existing URL report only; a 404 is reported as not found and the URL is not submitted. Never commit API keys.

## Methodology
1. Acquire a local `.eml` file with permission.
2. Parse headers and safe text/MIME parts; attachments are not executed.
3. Extract URLs without visiting or resolving them.
4. Read any existing `Authentication-Results` header.
5. Apply explainable heuristic checks and calculate a capped score.
6. Optionally query existing URL reputation after privacy review.
7. Export findings and ask a human analyst to validate context before taking action.

## Scoring
+2 reply-to domain mismatch; +2 SPF/DKIM/DMARC fail or SPF softfail text in auth header; +2 IP-literal URL or known shortener; +1 urgency/credential request; +1 brand-like display name mismatch; +1 suspicious URL wording. High >=5, medium >=3, otherwise low. This is not a probability.

## Limitations and safety
No live mail integration, independent SPF/DKIM verification, attachment detonation, browser automation, or automatic blocking. Heuristics may produce false positives and negatives. The optional reputation lookup contacts VirusTotal and requires an explicit opt-in. Production deployment requires secure ingestion, robust authentication verification, access control, audit logging, attachment scanning, policy tuning, and mail-platform integration.

## Repository map
`src/analyze_email.py` · `data/` · `docs/` · `tests/` · `reports/`
