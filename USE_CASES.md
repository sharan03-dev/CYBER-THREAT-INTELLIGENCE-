# MongoDB use cases and design patterns (classroom update)

The classroom table lists six use cases where MongoDB fits and the design pattern for each. All six are
implemented in the Kavach CTI platform, so each one is a real collection you can query, not a toy example.

| # | Use case | Why MongoDB fits | Design pattern | Where in Kavach CTI |
|---|---|---|---|---|
| 1 | Content Management | Varied content types, nested structures | Embedded documents for content blocks | `briefings.blocks[]` |
| 2 | Product Catalog | Heterogeneous attributes per category | Schema validation with flexible fields | `$jsonSchema` validator on `indicators` |
| 3 | User Profiles | Read-heavy, self-contained data | Embed preferences, reference activity history | `analysts.preferences` + `lookup_history.analyst_id` |
| 4 | IoT Data Ingestion | High write throughput, time-series | Time-series collections (MongoDB 5.0+) | `feed_telemetry` |
| 5 | Real-time Analytics | Aggregation framework for rollups | Pre-aggregated buckets + raw data | `report_stats_daily` + `reports` |
| 6 | Mobile Apps | Offline sync, flexible schema | Change streams for sync, embedded local data | `/api/stream` + copy in the browser |

Run everything and get your own numbers:
```bash
python labs/use_cases/use_case_patterns.py            # all six, results also on the website: #/usecases
python labs/use_cases/watch_reports.py --demo         # use case 6 live in the terminal
```

---

## 1. Content Management -> embedded content blocks
A daily threat briefing is a page made of blocks of different shapes. Each block is an embedded
sub-document with its own fields, kept in order inside one document:
```js
briefings {
  _id: "briefing:2026-10-01", title, status: "published", version: 3,
  author_id: "default",                                      // reference -> analysts
  blocks: [
    { order: 0, type: "heading",       level: 1, text: "Daily threat briefing - 01 Oct 2026" },
    { order: 1, type: "summary",       text: "58 reports analysed: 21 actual threats ..." },
    { order: 2, type: "report_list",   title, items: [ { report_id, title, url, severity, category } ] },
    { order: 3, type: "cve_table",     title, rows:  [ { cve, mentions, kev: true } ] },
    { order: 4, type: "actor_callout", title, actors: [ { actor_id, name, mentions } ] },
    { order: 5, type: "ioc_list",      title, indicator_ids: [ "ipv4:..." ] },
    { order: 6, type: "note",          style: "tip", text }
  ]
}
```
**Why it fits:** the whole page is one read; a new block type (for example a chart) needs no migration;
nested blocks can still be queried, e.g. `{blocks: {$elemMatch: {type: "cve_table", "rows.kev": true}}}`
(multikey index on `blocks.type`). The array is bounded (7 blocks, each list capped), so the document stays a few KB.
In SQL this would be a `pages` table plus one table per block type joined with a polymorphic key.

## 2. Product Catalog -> schema validation with flexible fields
Indicators are the platform's "catalog": every category has different attributes.

| type | specific fields |
|---|---|
| ipv4 | `ip_int` (for range queries) |
| cidr | `range_start`, `range_end`, `prefix`, `size` |
| ipv6, domain, url, sha256, sha1, md5 | none beyond the core |

The validator enforces the shared core and the per-category rule, but **does not** set
`additionalProperties: false`, so new optional attributes are allowed:
```js
db.runCommand({ collMod: "indicators", validationLevel: "moderate", validationAction: "error",
  validator: { $jsonSchema: {
    bsonType: "object", required: ["type", "value"],
    properties: { type: { enum: ["ipv4","ipv6","cidr","domain","url","sha256","sha1","md5"] },
                  value: { bsonType: "string", minLength: 1 },
                  ip_int: { bsonType: ["int","long"], minimum: 0 }, prefix: { bsonType: ["int","long"], maximum: 32 } },
    anyOf: [ { properties: { type: { enum: [/* every type except cidr */] } } },
             { required: ["range_start", "range_end", "prefix"] } ]      // a CIDR must carry its range
}}})
```
The script inserts five test documents: missing `value`, unknown `type` and a CIDR without its range are
**rejected** (error code 121, "Document failed validation"); an IPv4 with an extra `asn` field and a complete
CIDR are **accepted**. `moderate` means old documents that do not match are not blocked when they are updated.

## 3. User Profiles -> embed preferences, reference activity history
```js
analysts { _id: "default", name, role,
  preferences: { theme: "dark", default_days: 30, min_severity: "High", notify_actual_threats: true,
                 watchlist: { ips: [], cves: [], actors: [] } } }        // embedded, each list capped at 50
lookup_history { ip, at, verdict, score, country, analyst_id: "default" } // referenced, index {analyst_id, at}
```
**Embedded:** preferences are small, owned by one analyst and needed on every page view, so one `find_one`
returns everything (a few hundred bytes). **Referenced:** the IP lookup history grows with every check and
is unbounded, so it lives in its own collection and is paged with the `{analyst_id: 1, at: -1}` index
(`IXSCAN`, no collection scan). Embedding it would push the profile toward 16 MB and slow every profile read.

## 4. IoT Data Ingestion -> time-series collection
Each threat feed is treated like a sensor: every fetch writes one measurement.
```js
db.createCollection("feed_telemetry", {
  timeseries: { timeField: "ts", metaField: "meta", granularity: "minutes" },
  expireAfterSeconds: 7776000 })                                         // 90 days
{ ts: ISODate(), meta: { source_id: "feodo" }, ok: true, status: "ok", items: 312 }
```
MongoDB groups measurements with the same `meta` into compressed buckets, so storage and index size are much
smaller than one document per event, and old data expires automatically. The script also writes the same
stream of observation events (ids from real sightings) into a time-series collection and a regular collection
and compares writes per second, disk + index size and an hourly `$dateTrunc` rollup.

## 5. Real-time Analytics -> pre-aggregated buckets + raw data
```js
report_stats_daily { _id: "2026-10-01", day: ISODate("2026-10-01"), total: 58,
  severity: { High: 21, Medium: 25, ... }, category: { Ransomware: 9, ... },
  verdict: { "Actual threat": 21, ... }, sources: { bleepingcomputer: 6, ... } }
```
Every newly inserted report increments its day's bucket with one upsert
(`$inc: {total: 1, "severity.High": 1, ...}`). The Overview page's "severity per day" chart reads about 30
bucket documents instead of grouping every report. The raw `reports` stay as the source of truth for
drill-down and for `rebuild_buckets()` (one aggregation that recomputes all buckets, used after a reset).
The script compares both approaches and checks that their totals match.

## 6. Mobile Apps -> change streams for sync, embedded local data
`GET /api/stream` is a Server-Sent Events endpoint. On a replica set it opens
`db.reports.watch([{$match: {operationType: "insert"}}])` and sends each new report with its **resume token**
as the event id. The browser stores the newest reports and the token locally (the "embedded local data"),
so the Use cases page still shows them when the server is offline. After reconnecting, the browser sends
the token back (`Last-Event-ID`) and the server resumes the change stream from that point: only the
reports missed while offline are sent. If the token is too old for the oplog, the server starts fresh and
tells the client to resync.

Change streams read the oplog, which exists only on a replica set. A default Homebrew MongoDB is a standalone
server, so the platform falls back to polling (`_id > last seen ObjectId`) until you enable a one-node replica set:
```bash
# Apple Silicon: /opt/homebrew/etc/mongod.conf   Intel: /usr/local/etc/mongod.conf  - add:
replication:
  replSetName: rs0
brew services restart mongodb-community@8.0
mongosh --eval 'rs.initiate({_id: "rs0", members: [{_id: 0, host: "localhost:27017"}]})'
```
The script then proves offline sync on a scratch collection: it reads one event, saves the token, "goes offline"
while two documents are inserted, reconnects with `resume_after` and receives exactly those two.

---

## Summary
| Pattern | When to choose it | Cost |
|---|---|---|
| Embedded content blocks | parts always read together, varied shapes, bounded | large or shared parts must be referenced |
| Validation + flexible fields | different attributes per category but a shared core | rules must be kept in step with the code |
| Embed preferences / reference history | small owned data vs unbounded history | history needs a second (indexed) query |
| Time-series collection | append-only measurements over time | updates/deletes of single measurements are limited |
| Pre-aggregated buckets | dashboards read the same rollups often | an extra write per event; rebuild if they drift |
| Change streams + local copy | clients that go offline and must catch up | needs a replica set; tokens expire with the oplog |
