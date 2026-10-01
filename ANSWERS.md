# Lab 7.1 - Analyze a Production Schema (answers)

The "production" system is this CTI platform (database `cti_platform`, dump in `dump/cti_platform.archive.gz`).
Run `python labs/lab7_1/lab_01_production_schema.py --dump` to regenerate every table with your own numbers.

## 1. Embedding vs referencing
| Relationship | Pattern | Cardinality |
|---|---|---|
| sources.feed, sources.stats | Embedded | 1:1 |
| reports.classification | Embedded | 1:1 |
| reports.tags, reports.entities.malware | Embedded | 1:few (bounded) |
| threat_actors.aliases | Embedded | 1:few |
| vulnerabilities.kev | Embedded | 1:1 |
| ingest_runs.results | Embedded | 1:~45 (one per source) |
| ip_lookups.result | Embedded | 1:1 snapshot (TTL) |
| reports.source_id -> sources | Reference | N:1 |
| reports.cve_ids -> vulnerabilities | Reference | N:M |
| reports.actor_ids -> threat_actors | Reference | N:M |
| reports.indicator_ids -> indicators | Reference | N:M |
| sightings.indicator_id -> indicators | Reference | N:1 (unbounded) |
| sightings.source_id -> sources | Reference | N:1 |
| sightings.report_id -> reports | Reference | N:1 |

Rule used: embed what is small, bounded and always read together with the parent; reference what is
shared by many documents, changes independently, is queried on its own, or grows without limit.

## 2. Why each reference was not embedded, and the embedded alternative
- **reports.source_id**: thousands of reports share one source, and a source's reliability rating changes.
  Embedded alternative: `source: {name, reliability, weight}` copied into every report - faster listing,
  but a reliability change becomes `updateMany` over thousands of reports.
- **reports.cve_ids**: one CVE appears in many reports, and its CISA KEV status is updated separately.
  Embedded alternative: `vulnerabilities: [{cve, vendor, product, kev_added}]` in each report - duplicated and goes stale.
- **reports.actor_ids**: an actor profile (aliases, origin, motivation) is shared.
  Embedded alternative: the full profile copied into every report that names the actor.
- **reports.indicator_ids**: an IOC is looked up on its own (IP intelligence page) and appears in many reports.
  Embedded alternative: indicator objects inside reports - every IP lookup would then scan all reports.
- **sightings.indicator_id / source_id**: a busy IP is re-listed by feeds every day, so the list is unbounded.
  Embedded alternative: `indicators.sightings[]` - fast reads, but the array grows toward 16 MB. This is
  exactly the Activity 7.1 redesign (with a cap of 50).
- **sightings.report_id**: links an IOC back to the report; embedding would duplicate report text.

The script also prints one real report rebuilt with all references embedded and compares its BSON size.

## 3. Document size ($bsonSize)
Pipeline: `{$project: {s: {$bsonSize: "$$ROOT"}}}, {$group: {_id: null, avg: {$avg: "$s"}, max: {$max: "$s"}}}`
per collection. Typical result: reports ~1.5-3 KB, indicators/sightings ~150-300 B, largest document a few KB,
i.e. far below 0.1 % of the 16,777,216-byte limit - **no document approaches 16 MB**. The only risk would be
embedding sightings (about 160 B each, so ~100,000 sightings = 16 MB), which is why they are referenced.
