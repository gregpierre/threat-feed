# threat-feed

A daily digest of vulnerabilities newly added to CISA's
[Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
ranked by [EPSS](https://www.first.org/epss/) exploit-probability score.

A GitHub Action runs `digest.py` every morning. When CISA has added
entries since the last run, it writes a digest to `digests/YYYY/` and
updates the table below. Days with nothing new produce no commit.

## Latest

<!-- latest:start -->
**2026-10-30**: 4 new, full digest in [`digests/2026/2026-10-30.md`](digests/2026/2026-10-30.md)

| CVE | Vendor / product | EPSS |
|---|---|---|
| CVE-2026-97229 | GitLab Community Edition and Enterprise Edition | 26.6% (p98) |
| CVE-2026-76418 | Cisco Secure Firewall ASA Software and Cisco Secure FTD Software | 0.9% (p60) |
| CVE-2026-111357 | Ivanti Connect Secure | 0.3% (p25) |
| CVE-2026-118527 | Ivanti Connect Secure | n/a |
<!-- latest:end -->

## How it works

- **Source:** CISA KEV JSON feed: vendor, product, required action, remediation due date, ransomware use
- **Enrichment:** FIRST EPSS API: probability of exploitation in the next 30 days, plus percentile
- **State:** `state/seen.json` tracks CVE IDs already reported, so each entry appears once
- **No dependencies:** Python standard library only

Run it locally:

```sh
python3 digest.py
```
