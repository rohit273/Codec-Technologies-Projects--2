# Test plan

| ID | Test | Expected |
|---|---|---|
| E-01 | Parse synthetic phishing sample | Headers and URL extracted |
| E-02 | Reply-to differs from sender | Mismatch finding |
| E-03 | Authentication-Results contains fail | Failure finding |
| E-04 | URL has IP literal | Flag generated without visit |
| E-05 | Compare phishing and legitimate samples | Phishing sample higher score |
| E-06 | Missing VT key | Error only when VT option used |
| E-07 | Output directory absent | Directory created |
