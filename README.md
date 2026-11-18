# threat-feed

A daily digest of vulnerabilities newly added to CISA's
[Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
ranked by [EPSS](https://www.first.org/epss/) exploit-probability score.

A GitHub Action runs `digest.py` every morning. When CISA has added
entries since the last run, it writes a digest to `digests/YYYY/` and
updates the table below. Days with nothing new produce no commit.

## Latest

<!-- latest:start -->
**2026-11-18**: 4 new, full digest in [`digests/2026/2026-11-18.md`](digests/2026/2026-11-18.md)

| CVE | Vendor / product | EPSS |
|---|---|---|
| CVE-2026-40217 | BerriAI LiteLLM | 17.0% (p97) |
| CVE-2026-90817 | Vanderbilt University Research Electronic Data Capture (REDCap) | 3.7% (p90) |
| CVE-2024-10441 | Synology DiskStation Manager (DSM) | 1.3% (p70) |
| CVE-2026-90436 | Apache Axis | 1.1% (p67) |
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
