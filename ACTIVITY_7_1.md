# Activity 7.1 - Redesign one referencing relationship as embedded

**Relationship:** `sightings -> indicators` (+ `sightings -> sources`).
**Goal:** decide *which source says an indicator is an actual threat* in one read.

```js
threat_verdicts {
  _id: "ipv4:1.2.3.4", type: "ipv4", value: "1.2.3.4",
  score: 91, verdict: "Actual threat", sighting_count: 3,
  sightings: [ { source_id: "feodo", source_name: "abuse.ch Feodo Tracker", reliability: "A",
                 weight: 0.95, confidence: 90, observed_at: ISODate() } ]   // capped at 50
}
```
Built with one aggregation: sightings -> `$lookup` sources -> `$group` by indicator -> `$reduce`
(noisy-OR score = 1 - PRODUCT(1 - weight x confidence/100)) -> `$merge` into threat_verdicts.

**Faster:** "is this IP an actual threat?" (1 document, 1 index seek instead of 2 `$lookup`s);
"top 25 threats" dashboard (index on `score` instead of grouping every sighting); showing all evidence
for an IP with no joins.

**Harder:** a source's reliability changes -> `updateMany` with `arrayFilters` across thousands of
documents and every score must be recomputed (referenced: update 1 source document); "all sightings from
source X in the last 7 days" needs `$elemMatch` + `$unwind` (referenced: one indexed count); the array grows
with every feed import, so it must be capped (subset pattern) to stay far from 16 MB; data is duplicated,
so it can go stale between rebuilds.

**Decision:** keep sightings referenced as the source of truth and use threat_verdicts as a read-optimised
copy rebuilt after each import. Measured timings: `python labs/lab7_1/activity_7_1_embedded_redesign.py`.
