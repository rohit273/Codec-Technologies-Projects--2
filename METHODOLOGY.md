# Methodology

1. **Authorized sample:** use local `.eml` samples you have permission to analyze.
2. **Safe parsing:** parse headers and MIME text; never execute attachments or message content.
3. **URL extraction:** extract URL strings but do not open, resolve, or download them.
4. **Authentication context:** read the existing `Authentication-Results` header; this is not independent verification.
5. **Heuristics:** examine reply-to mismatch, authentication failure text, urgency language, brand-like display names, and URL characteristics.
6. **Optional reputation:** after privacy review, query an existing VirusTotal URL report; do not submit new URLs.
7. **Scoring/reporting:** produce a capped, explainable score and JSON/CSV results.
8. **Human review:** validate context and false positives before any blocking/escalation.
