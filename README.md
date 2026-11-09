# threat-feed

A daily digest of vulnerabilities newly added to CISA's
[Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
ranked by [EPSS](https://www.first.org/epss/) exploit-probability score.

A GitHub Action runs `digest.py` every morning. When CISA has added
entries since the last run, it writes a digest to `digests/YYYY/` and
updates the table below. Days with nothing new produce no commit.

## Latest

<!-- latest:start -->
**2026-11-09**: 4 new, full digest in [`digests/2026/2026-11-09.md`](digests/2026/2026-11-09.md)

| CVE | Vendor / product | EPSS |
|---|---|---|
| CVE-2026-116779 | SignalWire FreeSwitch | 1.3% (p71) |
| CVE-2026-123158 | OpenBSD OpenSSH | 1.0% (p63) |
| CVE-2026-123218 | IBM Aspera Faspex | 0.4% (p34) |
| CVE-2026-102895 | GPUStack GPUStack | 0.3% (p26) |
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
