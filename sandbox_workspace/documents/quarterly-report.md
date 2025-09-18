# Quarterly Engineering Report — FY26 Q3

**Classification:** Internal — approved for analysis
**Author:** Platform Engineering

## Summary
Through the third quarter the platform team reduced median API latency from
412 ms to 188 ms. Availability held at 99.97 % across the three regional
cells. The on-call rotation absorbed 214 pages, of which 61 were related to
the storage migration in July.

## Highlights
- The connection pool rewrite removed a long standing tail-latency problem.
- Automated rollback for schema migrations cut recovery time by 74 %.
- Three of the five remaining SLO breaches trace back to a single shared
  metrics exporter, which is scheduled for replacement in Q4.

## Known issues
- Nightly index rebuilds still contend with the reporting workload between
  01:00 and 03:00 UTC.
- The customer-facing status page still relies on a manual runbook.

## Next quarter
1. Replace the metrics exporter.
2. Move index rebuilds to a dedicated worker pool.
3. Automate the status page runbook.
