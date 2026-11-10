# threat-feed

A daily digest of vulnerabilities newly added to CISA's
[Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
ranked by [EPSS](https://www.first.org/epss/) exploit-probability score.

A GitHub Action runs `digest.py` every morning. When CISA has added
entries since the last run, it writes a digest to `digests/YYYY/` and
updates the table below. Days with nothing new produce no commit.

## Latest

<!-- latest:start -->
**2026-11-10**: 6 new, full digest in [`digests/2026/2026-11-10.md`](digests/2026/2026-11-10.md)

| CVE | Vendor / product | EPSS |
|---|---|---|
| CVE-2026-116606 | Barracuda Networks Barracuda Email Security Gateway (ESG) | 1.6% (p76) |
| CVE-2026-111560 | Barracuda Networks Multiple Products | 1.1% (p65) |
| CVE-2026-20320 | Cisco BroadWorks | 0.4% (p33) |
| CVE-2026-111793 | Openwave Messaging Limited Webtop Media Transcoder | 0.3% (p20) |
| CVE-2026-124194 | Microsoft Office | n/a |
| CVE-2026-125350 | Google Chromium | n/a |
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
