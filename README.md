# threat-feed

A daily digest of vulnerabilities newly added to CISA's
[Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
ranked by [EPSS](https://www.first.org/epss/) exploit-probability score.

A GitHub Action runs `digest.py` every morning. When CISA has added
entries since the last run, it writes a digest to `digests/YYYY/` and
updates the table below. Days with nothing new produce no commit.

## Latest

<!-- latest:start -->
**2026-10-21**: 6 new, full digest in [`digests/2026/2026-10-21.md`](digests/2026/2026-10-21.md)

| CVE | Vendor / product | EPSS |
|---|---|---|
| CVE-2026-106931 | EG Secure Solutions SiteGuard Server Edition | 1.4% (p72) |
| CVE-2026-96656 | Plex Media Server | 0.8% (p55) |
| CVE-2026-96654 | Plex Media Server | 0.4% (p36) |
| CVE-2026-96652 | Plex Media Server | 0.4% (p35) |
| CVE-2026-96655 | Plex Media Server | 0.4% (p35) |
| CVE-2026-110936 | Siemens Software Center | 0.3% (p17) |
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
