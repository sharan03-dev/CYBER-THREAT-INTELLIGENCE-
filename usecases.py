"""MongoDB use cases (classroom update) - the six "where MongoDB fits" patterns, applied to Kavach CTI.

| # | Use case              | Why MongoDB fits                         | Design pattern                                   | In this project                                     |
|---|-----------------------|------------------------------------------|--------------------------------------------------|-----------------------------------------------------|
| 1 | Content management    | Varied content types, nested structures  | Embedded documents for content blocks            | briefings.blocks[] (heading, report list, CVE table) |
| 2 | Product catalog       | Heterogeneous attributes per category    | Schema validation with flexible fields           | $jsonSchema on indicators (per-type fields)          |
| 3 | User profiles         | Read-heavy, self-contained data          | Embed preferences, reference activity history    | analysts.preferences + lookup_history.analyst_id     |
| 4 | IoT data ingestion    | High write throughput, time-series       | Time-series collections (MongoDB 5.0+)           | feed_telemetry (every feed fetch = one measurement)  |
| 5 | Real-time analytics   | Aggregation framework for rollups        | Pre-aggregated buckets + raw data                | report_stats_daily buckets + raw reports             |
| 6 | Mobile apps           | Offline sync, flexible schema            | Change streams for sync, embedded local data     | /api/stream (change stream + resume token) + browser copy |

Used by the website (Use cases page, /api/usecases/*) and by labs/use_cases/use_case_patterns.py.
"""
import random
import time
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from pymongo import ASCENDING, DESCENDING, InsertOne, ReplaceOne, UpdateOne
from pymongo.errors import CollectionInvalid, OperationFailure, PyMongoError, WriteError

UTC = timezone.utc
DEFAULT_ANALYST = "default"
INDICATOR_TYPES = ["ipv4", "ipv6", "cidr", "domain", "url", "sha256", "sha1", "md5"]
SEVERITIES = ["Low", "Medium", "High", "Critical"]

USE_CASES = [
    {"n": 1, "key": "content", "use_case": "Content Management", "why": "Varied content types, nested structures",
     "pattern": "Embedded documents for content blocks", "collection": "briefings",
     "where": "Daily threat briefings: one document holds an ordered blocks[] array of different block types "
              "(heading, summary, report list, CVE table, IOC list, actor callout, note)."},
    {"n": 2, "key": "catalog", "use_case": "Product Catalog", "why": "Heterogeneous attributes per category",
     "pattern": "Schema validation with flexible fields", "collection": "indicators",
     "where": "Indicators are the 'catalog': every type has different fields (ipv4 has ip_int, cidr has "
              "range_start/range_end/prefix, hashes have none). A $jsonSchema validator enforces the shared core "
              "and the per-type rules but still allows extra fields."},
    {"n": 3, "key": "profiles", "use_case": "User Profiles", "why": "Read-heavy, self-contained data",
     "pattern": "Embed preferences, reference activity history", "collection": "analysts",
     "where": "An analyst profile embeds preferences and a bounded watchlist (read in one document); the "
              "unbounded IP lookup history stays in lookup_history and points back with analyst_id."},
    {"n": 4, "key": "timeseries", "use_case": "IoT Data Ingestion", "why": "High write throughput, time-series",
     "pattern": "Time-series collections (MongoDB 5.0+)", "collection": "feed_telemetry",
     "where": "Threat feeds are the 'sensors': every fetch writes a measurement {ts, meta:{source_id}, items, "
              "status} into a time-series collection with automatic 90-day expiry."},
    {"n": 5, "key": "analytics", "use_case": "Real-time Analytics", "why": "Aggregation framework for rollups",
     "pattern": "Pre-aggregated buckets + raw data", "collection": "report_stats_daily",
     "where": "Each new report $inc-s a per-day bucket (counts by severity, category, verdict, source). The "
              "Overview chart reads the buckets; raw reports stay for drill-down and for rebuilding buckets."},
    {"n": 6, "key": "sync", "use_case": "Mobile Apps", "why": "Offline sync, flexible schema",
     "pattern": "Change streams for sync, embedded local data", "collection": "reports (change stream)",
     "where": "The browser keeps a local copy of the newest threats and a resume token; /api/stream pushes new "
              "reports from a change stream and resumes where the client left off after being offline."},
]


def now():
    return datetime.now(UTC)


def _key(s):
    """Field-name safe key for bucket maps (no dots, no leading $)."""
    s = str(s if s not in (None, "") else "unknown").replace(".", "_")
    return "_" + s[1:] if s.startswith("$") else s


def _ms(t0):
    return round((time.perf_counter() - t0) * 1000, 2)


# ===================================================================== setup (safe to run many times)
INDICATOR_VALIDATOR = {"$jsonSchema": {
    "bsonType": "object",
    "title": "Indicator (flexible catalog item)",
    "required": ["type", "value"],
    "properties": {
        "type": {"enum": INDICATOR_TYPES, "description": "indicator category"},
        "value": {"bsonType": "string", "minLength": 1},
        "tags": {"bsonType": "array", "items": {"bsonType": "string"}},
        "first_seen": {"bsonType": "date"},
        "last_seen": {"bsonType": "date"},
        "ip_int": {"bsonType": ["int", "long"], "minimum": 0},
        "range_start": {"bsonType": ["int", "long"], "minimum": 0},
        "range_end": {"bsonType": ["int", "long"], "minimum": 0},
        "prefix": {"bsonType": ["int", "long"], "minimum": 0, "maximum": 32},
        "size": {"bsonType": ["int", "long"], "minimum": 1},
    },
    # per-category rule: a CIDR range must carry its numeric range; every other type may omit it
    "anyOf": [
        {"properties": {"type": {"enum": [t for t in INDICATOR_TYPES if t != "cidr"]}}},
        {"required": ["range_start", "range_end", "prefix"]},
    ],
    # no "additionalProperties: false" -> new attributes (asn, country, malware family ...) are allowed
}}


def ensure(db):
    """Create the collections, indexes and validator the six use cases need."""
    names = set(db.list_collection_names())
    out = {}
    # 2. catalog: validator on indicators (moderate = legacy invalid docs are not blocked on update)
    try:
        if "indicators" not in names:
            db.create_collection("indicators")
        db.command("collMod", "indicators", validator=INDICATOR_VALIDATOR,
                   validationLevel="moderate", validationAction="error")
        out["validator"] = True
    except PyMongoError as exc:
        out["validator"] = f"{type(exc).__name__}: {exc}"
    # 4. time-series collection for feed telemetry
    if "feed_telemetry" not in names:
        try:
            db.create_collection("feed_telemetry",
                                 timeseries={"timeField": "ts", "metaField": "meta", "granularity": "minutes"},
                                 expireAfterSeconds=90 * 24 * 3600)
        except (CollectionInvalid, OperationFailure) as exc:
            out["timeseries"] = str(exc)
    try:
        db.feed_telemetry.create_index([("meta.source_id", ASCENDING), ("ts", DESCENDING)])
    except PyMongoError:
        pass
    # 1. content, 3. profiles, 5. analytics
    db.briefings.create_index([("date", DESCENDING)])
    db.briefings.create_index([("blocks.type", ASCENDING)])
    db.lookup_history.create_index([("analyst_id", ASCENDING), ("at", DESCENDING)])
    db.report_stats_daily.create_index([("day", DESCENDING)])
    ensure_analyst(db)
    return out


# ===================================================================== 1. content management
def build_briefing(db, hours=24, author_id=DEFAULT_ANALYST):
    """One document with an ordered array of embedded, differently-shaped content blocks."""
    since = now() - timedelta(hours=hours)
    window = {"published_at": {"$gte": since}}
    if db.reports.count_documents(window) < 5:            # quiet day / old dataset: use the newest 60 reports
        newest = list(db.reports.find({}, {"_id": 1}).sort("published_at", -1).limit(60))
        window = {"_id": {"$in": [r["_id"] for r in newest]}}
    f = list(db.reports.aggregate([{"$match": window}, {"$facet": {
        "total": [{"$count": "n"}],
        "verdict": [{"$group": {"_id": "$classification.verdict", "n": {"$sum": 1}}}],
        "top": [{"$match": {"classification.verdict": "Actual threat"}}, {"$sort": {"published_at": -1}},
                {"$limit": 6}, {"$project": {"title": 1, "url": 1, "source_id": 1, "published_at": 1,
                                             "classification.severity": 1, "classification.category": 1}}],
        "cves": [{"$unwind": "$cve_ids"}, {"$group": {"_id": "$cve_ids", "n": {"$sum": 1}}},
                 {"$sort": {"n": -1, "_id": -1}}, {"$limit": 8}],
        "actors": [{"$unwind": "$actor_ids"}, {"$group": {"_id": "$actor_ids", "n": {"$sum": 1}}},
                   {"$sort": {"n": -1}}, {"$limit": 5}],
        "iocs": [{"$unwind": "$indicator_ids"}, {"$group": {"_id": "$indicator_ids"}}, {"$limit": 15}],
        "cats": [{"$group": {"_id": "$classification.category", "n": {"$sum": 1}}}, {"$sort": {"n": -1}},
                 {"$limit": 3}],
    }}]))[0]
    total = f["total"][0]["n"] if f["total"] else 0
    verdict = {x["_id"]: x["n"] for x in f["verdict"] if x["_id"]}
    kev = {v["_id"] for v in db.vulnerabilities.find({"_id": {"$in": [c["_id"] for c in f["cves"]]},
                                                      "kev": {"$exists": True}}, {"_id": 1})}
    names = {a["_id"]: a.get("name", a["_id"]) for a in db.threat_actors.find(
        {"_id": {"$in": [a["_id"] for a in f["actors"]]}}, {"name": 1})}
    day = now().strftime("%Y-%m-%d")
    blocks = [
        {"type": "heading", "level": 1, "text": f"Daily threat briefing - {now().strftime('%d %b %Y')}"},
        {"type": "summary", "text": (f"{total} reports analysed: {verdict.get('Actual threat', 0)} actual threats, "
                                     f"{verdict.get('Potential threat', 0)} potential, "
                                     f"{verdict.get('Informational', 0)} informational. Main themes: "
                                     + ", ".join(c["_id"] or "General security" for c in f["cats"]) + ".")},
        {"type": "report_list", "title": "Top actual threats",
         "items": [{"report_id": r["_id"], "title": r["title"], "url": r["url"], "source_id": r.get("source_id"),
                    "severity": r.get("classification", {}).get("severity"),
                    "category": r.get("classification", {}).get("category")} for r in f["top"]]},
        {"type": "cve_table", "title": "Most mentioned CVEs",
         "rows": [{"cve": c["_id"], "mentions": c["n"], "kev": c["_id"] in kev} for c in f["cves"]]},
        {"type": "actor_callout", "title": "Threat actors in the news",
         "actors": [{"actor_id": a["_id"], "name": names.get(a["_id"], a["_id"]), "mentions": a["n"]}
                    for a in f["actors"]]},
        {"type": "ioc_list", "title": "Indicators to block", "indicator_ids": [i["_id"] for i in f["iocs"]]},
        {"type": "note", "style": "tip",
         "text": "Check any listed IP on the IP intelligence page before blocking shared infrastructure."},
    ]
    blocks = [b for b in blocks if b.get("items") or b.get("rows") or b.get("actors") or b.get("indicator_ids")
              or b["type"] in ("heading", "summary", "note")]
    for i, b in enumerate(blocks):
        b["order"] = i
    db.briefings.update_one({"_id": f"briefing:{day}"}, {
        "$set": {"date": now().replace(hour=0, minute=0, second=0, microsecond=0), "title": blocks[0]["text"],
                 "status": "published", "author_id": author_id,       # REFERENCE -> analysts._id
                 "blocks": blocks, "updated_at": now()},                 # EMBEDDED content blocks (bounded)
        "$setOnInsert": {"created_at": now()}, "$inc": {"version": 1}}, upsert=True)
    return db.briefings.find_one({"_id": f"briefing:{day}"})


def latest_briefing(db):
    return db.briefings.find_one({}, sort=[("date", -1)])


def demo_content(db):
    t0 = time.perf_counter()
    b = build_briefing(db)
    build_ms = _ms(t0)
    t0 = time.perf_counter()
    db.briefings.find_one({"_id": b["_id"]})
    read_ms = _ms(t0)
    with_cves = db.briefings.count_documents({"blocks": {"$elemMatch": {"type": "cve_table",
                                                                         "rows.kev": True}}})
    size = next(db.briefings.aggregate([{"$match": {"_id": b["_id"]}}, {"$project": {"s": {"$bsonSize": "$$ROOT"}}}]))
    return {"briefing_id": b["_id"], "version": b.get("version"), "blocks": len(b["blocks"]),
            "block_types": [x["type"] for x in b["blocks"]], "build_ms": build_ms, "read_ms": read_ms,
            "bson_bytes": size["s"], "briefings_with_kev_cve_table": with_cves,
            "query": "{blocks: {$elemMatch: {type: 'cve_table', 'rows.kev': true}}}",
            "takeaway": "The whole page (7 block types, nested lists) is one read; adding a new block type "
                        "needs no schema migration."}


# ===================================================================== 2. product catalog
def demo_catalog(db):
    opts = next(iter(db.command("listCollections", filter={"name": "indicators"})["cursor"]["firstBatch"]), {})
    validator_on = bool(opts.get("options", {}).get("validator"))
    shapes = list(db.indicators.aggregate([
        {"$sample": {"size": 4000}},
        {"$project": {"type": 1, "k": {"$map": {"input": {"$objectToArray": "$$ROOT"}, "in": "$$this.k"}}}},
        {"$group": {"_id": "$type", "n": {"$sum": 1}, "fields": {"$addToSet": "$k"}}},
        {"$project": {"n": 1, "fields": {"$reduce": {"input": "$fields", "initialValue": [],
                                                     "in": {"$setUnion": ["$$value", "$$this"]}}}}},
        {"$sort": {"n": -1}}]))
    tests, demo_id = [], "demo:validator-test"
    cases = [
        ("missing value", {"_id": demo_id, "type": "ipv4"}),
        ("unknown type", {"_id": demo_id, "type": "bitcoin-wallet", "value": "bc1q..."}),
        ("cidr without range", {"_id": demo_id, "type": "cidr", "value": "203.0.113.0/24"}),
        ("ipv4 + extra field asn", {"_id": demo_id, "type": "ipv4", "value": "203.0.113.7",
                                    "ip_int": 3405803783, "asn": 64500, "first_seen": now()}),
        ("cidr with range", {"_id": demo_id, "type": "cidr", "value": "203.0.113.0/24", "range_start": 3405803776,
                             "range_end": 3405804031, "prefix": 24, "size": 256}),
    ]
    for label, doc in cases:
        db.indicators.delete_one({"_id": demo_id})
        try:
            db.indicators.insert_one(doc)
            tests.append({"case": label, "accepted": True, "detail": "inserted"})
        except WriteError as exc:
            reason = ""
            info = (exc.details or {}).get("errInfo", {}).get("details", {})
            for rule in info.get("schemaRulesNotSatisfied", [])[:1]:
                reason = rule.get("operatorName", "")
                if rule.get("missingProperties"):
                    reason += " missing " + ",".join(rule["missingProperties"])
                for p in rule.get("propertiesNotSatisfied", [])[:1]:
                    reason += f" {p.get('propertyName')}"
            tests.append({"case": label, "accepted": False, "detail": f"code {exc.code} {reason}".strip()})
    db.indicators.delete_one({"_id": demo_id})
    return {"validator_enabled": validator_on, "validation_level": "moderate", "validation_action": "error",
            "shapes": [{"type": s["_id"], "sampled": s["n"], "fields": sorted(s["fields"])} for s in shapes],
            "tests": tests,
            "takeaway": "One collection, different attributes per indicator type; the validator rejects broken "
                        "documents (code 121) while still accepting new optional fields such as asn."}


# ===================================================================== 3. user profiles
def ensure_analyst(db, analyst_id=DEFAULT_ANALYST):
    db.analysts.update_one({"_id": analyst_id}, {"$setOnInsert": {
        "name": "SOC analyst", "role": "Tier 1 analyst", "created_at": now(),
        "preferences": {                                          # EMBEDDED: small, read on every page view
            "theme": "dark", "default_days": 30, "min_severity": "High", "notify_actual_threats": True,
            "watchlist": {"ips": [], "cves": [], "actors": []},     # bounded: max 50 each
        }}}, upsert=True)
    db.lookup_history.update_many({"analyst_id": {"$exists": False}}, {"$set": {"analyst_id": analyst_id}})


def get_profile(db, analyst_id=DEFAULT_ANALYST, activity=15):
    prof = db.analysts.find_one({"_id": analyst_id})
    if not prof:
        ensure_analyst(db, analyst_id)
        prof = db.analysts.find_one({"_id": analyst_id})
    hist = list(db.lookup_history.find({"analyst_id": analyst_id}, {"_id": 0, "ip": 1, "at": 1, "verdict": 1,
                                                                    "score": 1}).sort("at", -1).limit(activity))
    prof["activity"] = hist                                       # REFERENCED history, fetched on demand
    prof["activity_total"] = db.lookup_history.count_documents({"analyst_id": analyst_id})
    return prof


def update_preferences(db, prefs, analyst_id=DEFAULT_ANALYST):
    upd = {}
    if prefs.get("theme") in ("dark", "light"):
        upd["preferences.theme"] = prefs["theme"]
    if prefs.get("min_severity") in SEVERITIES:
        upd["preferences.min_severity"] = prefs["min_severity"]
    if isinstance(prefs.get("default_days"), int) and 1 <= prefs["default_days"] <= 365:
        upd["preferences.default_days"] = prefs["default_days"]
    if isinstance(prefs.get("notify_actual_threats"), bool):
        upd["preferences.notify_actual_threats"] = prefs["notify_actual_threats"]
    for k in ("ips", "cves", "actors"):
        v = (prefs.get("watchlist") or {}).get(k)
        if isinstance(v, list):
            clean = []
            for x in v:
                x = str(x).strip()[:80]
                x = x.upper() if k == "cves" else x
                if x and x not in clean:
                    clean.append(x)
            upd[f"preferences.watchlist.{k}"] = clean[:50]       # cap keeps the profile document small
    if upd:
        upd["updated_at"] = now()
        db.analysts.update_one({"_id": analyst_id}, {"$set": upd}, upsert=True)
    return get_profile(db, analyst_id)


def demo_profiles(db):
    ensure_analyst(db)
    t0 = time.perf_counter()
    for _ in range(200):
        db.analysts.find_one({"_id": DEFAULT_ANALYST}, {"preferences": 1})
    prof_ms = round(_ms(t0) / 200, 3)
    t0 = time.perf_counter()
    hist = list(db.lookup_history.find({"analyst_id": DEFAULT_ANALYST}).sort("at", -1).limit(20))
    hist_ms = _ms(t0)
    plan = db.lookup_history.find({"analyst_id": DEFAULT_ANALYST}).sort("at", -1).limit(20).explain()
    winning = plan.get("queryPlanner", {}).get("winningPlan", {})
    stages = []
    node = winning.get("queryPlan", winning)
    while isinstance(node, dict) and node:
        stages.append(node.get("stage"))
        node = node.get("inputStage", {})
    size = next(db.analysts.aggregate([{"$match": {"_id": DEFAULT_ANALYST}},
                                       {"$project": {"s": {"$bsonSize": "$$ROOT"}}}]))["s"]
    return {"profile_read_ms": prof_ms, "profile_bytes": size,
            "activity_total": db.lookup_history.count_documents({"analyst_id": DEFAULT_ANALYST}),
            "activity_page_ms": hist_ms, "activity_page_size": len(hist),
            "activity_plan": " <- ".join(s for s in stages if s),
            "takeaway": "Preferences come with the profile in one tiny read; history grows without limit, so it "
                        "is referenced and paged with the {analyst_id, at} index."}


# ===================================================================== 4. IoT-style ingestion (time-series)
def record_telemetry(db, source_id, status, items=None, error=None, duration_ms=None):
    """Called after every feed fetch (ingest._mark_source). Never raises."""
    try:
        doc = {"ts": now(), "meta": {"source_id": source_id}, "ok": status == "ok", "status": status}
        if items is not None:
            doc["items"] = int(items)
        if duration_ms is not None:
            doc["duration_ms"] = duration_ms
        if error:
            doc["error"] = str(error)[:200]
        db.feed_telemetry.insert_one(doc)
    except Exception:  # telemetry must never break ingestion
        pass


def telemetry_summary(db, hours=24 * 7):
    since = now() - timedelta(hours=hours)
    try:
        rows = list(db.feed_telemetry.aggregate([
            {"$match": {"ts": {"$gte": since}}},
            {"$group": {"_id": {"$dateTrunc": {"date": "$ts", "unit": "hour"}},
                        "fetches": {"$sum": 1}, "errors": {"$sum": {"$cond": ["$ok", 0, 1]}},
                        "items": {"$sum": {"$ifNull": ["$items", 0]}}}},
            {"$sort": {"_id": 1}}]))
    except PyMongoError:
        rows = []
    return [{"hour": r["_id"], "fetches": r["fetches"], "errors": r["errors"], "items": r["items"]} for r in rows]


def _coll_size(db, name):
    try:
        s = next(db[name].aggregate([{"$collStats": {"storageStats": {}}}]))["storageStats"]
        return {"storage": s.get("storageSize", 0), "index": s.get("totalIndexSize", 0),
                "buckets": (s.get("timeseries") or {}).get("bucketCount")}
    except (PyMongoError, StopIteration):
        st = db.command("collStats", name)
        return {"storage": st.get("storageSize", 0), "index": st.get("totalIndexSize", 0),
                "buckets": (st.get("timeseries") or {}).get("bucketCount")}


def demo_timeseries(db, events=20000, batch=2000):
    """Write the same observation stream into a time-series and a regular collection and compare."""
    events = max(2000, min(int(events), 500000))
    ids = [s["indicator_id"] + "|" + s["source_id"] for s in db.sightings.aggregate([
        {"$sample": {"size": min(events, 5000)}}, {"$project": {"indicator_id": 1, "source_id": 1}}])]
    if not ids:
        ids = [f"ipv4:198.51.100.{i}|demo" for i in range(1, 255)]
    rnd = random.Random(7)
    start = now() - timedelta(days=7)
    docs = []
    for i in range(events):
        iid, src = rnd.choice(ids).rsplit("|", 1)
        docs.append({"ts": start + timedelta(seconds=i * (7 * 86400 / events)),
                     "meta": {"source_id": src, "type": iid.split(":", 1)[0]},
                     "indicator_id": iid, "confidence": rnd.randint(40, 100)})
    for c in ("ts_bench_events", "ts_bench_plain"):
        db.drop_collection(c)
    db.create_collection("ts_bench_events", timeseries={"timeField": "ts", "metaField": "meta",
                                                        "granularity": "seconds"})
    db.ts_bench_plain.create_index([("meta.source_id", ASCENDING), ("ts", ASCENDING)])
    out = {"events": events, "batch": batch}
    for name in ("ts_bench_events", "ts_bench_plain"):
        t0 = time.perf_counter()
        for i in range(0, events, batch):
            db[name].insert_many([dict(d) for d in docs[i:i + batch]], ordered=False)
        secs = time.perf_counter() - t0
        q0 = time.perf_counter()
        hourly = list(db[name].aggregate([
            {"$match": {"ts": {"$gte": now() - timedelta(days=2)}}},
            {"$group": {"_id": {"s": "$meta.source_id", "h": {"$dateTrunc": {"date": "$ts", "unit": "hour"}}},
                        "n": {"$sum": 1}, "avg_conf": {"$avg": "$confidence"}}}]))
        out[name] = {"seconds": round(secs, 2), "writes_per_sec": round(events / secs) if secs else None,
                     "rollup_ms": _ms(q0), "rollup_groups": len(hourly), **_coll_size(db, name)}
    ts, pl = out["ts_bench_events"], out["ts_bench_plain"]
    out["storage_saving_pct"] = round(100 * (1 - (ts["storage"] + ts["index"]) /
                                             max(1, pl["storage"] + pl["index"])), 1)
    for c in ("ts_bench_events", "ts_bench_plain"):
        db.drop_collection(c)
    out["feed_telemetry_points"] = db.feed_telemetry.count_documents({})
    out["takeaway"] = ("Time-series collections group measurements into compressed buckets per meta value, so "
                       "they need far less disk and index space than one document per event.")
    return out


# ===================================================================== 5. real-time analytics (buckets)
def bump_buckets(db, reports):
    """Incremental rollup: called for every newly inserted report (ingest._store_reports)."""
    ops = []
    for r in reports:
        p = r.get("published_at")
        if not isinstance(p, datetime):
            continue
        c = r.get("classification") or {}
        day = p.astimezone(UTC) if p.tzinfo else p.replace(tzinfo=UTC)
        ops.append(UpdateOne({"_id": day.strftime("%Y-%m-%d")}, {
            "$setOnInsert": {"day": day.replace(hour=0, minute=0, second=0, microsecond=0)},
            "$set": {"updated_at": now()},
            "$inc": {"total": 1, f"severity.{_key(c.get('severity'))}": 1,
                     f"category.{_key(c.get('category'))}": 1, f"verdict.{_key(c.get('verdict'))}": 1,
                     f"sources.{_key(r.get('source_id'))}": 1}}, upsert=True))
    if ops:
        try:
            db.report_stats_daily.bulk_write(ops, ordered=False)
        except PyMongoError:
            pass
    return len(ops)


def rebuild_buckets(db):
    """Full rebuild from the raw reports (after a reset, or to repair drift)."""
    t0 = time.perf_counter()
    rows = db.reports.aggregate([
        {"$match": {"published_at": {"$type": "date"}}},
        {"$group": {"_id": {"d": {"$dateToString": {"format": "%Y-%m-%d", "date": "$published_at"}},
                            "s": "$classification.severity", "c": "$classification.category",
                            "v": "$classification.verdict", "src": "$source_id"}, "n": {"$sum": 1}}}],
        allowDiskUse=True)
    days = {}
    for r in rows:
        k = r["_id"]
        b = days.setdefault(k["d"], {"_id": k["d"], "day": datetime.strptime(k["d"], "%Y-%m-%d").replace(tzinfo=UTC),
                                     "total": 0, "severity": {}, "category": {}, "verdict": {}, "sources": {}})
        b["total"] += r["n"]
        for field, val in (("severity", k.get("s")), ("category", k.get("c")), ("verdict", k.get("v")),
                           ("sources", k.get("src"))):
            b[field][_key(val)] = b[field].get(_key(val), 0) + r["n"]
    ts = now()
    ops = [ReplaceOne({"_id": d}, {**b, "updated_at": ts, "rebuilt": True}, upsert=True) for d, b in days.items()]
    for i in range(0, len(ops), 1000):
        db.report_stats_daily.bulk_write(ops[i:i + 1000], ordered=False)
    removed = db.report_stats_daily.delete_many({"_id": {"$nin": list(days)}}).deleted_count
    return {"buckets": len(days), "removed": removed, "seconds": round(time.perf_counter() - t0, 2)}


def per_day_from_buckets(db, days=30):
    since = (now() - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
    out = []
    for b in db.report_stats_daily.find({"day": {"$gte": since}}, {"severity": 1}):
        for sev, n in (b.get("severity") or {}).items():
            if sev in SEVERITIES:
                out.append({"day": b["_id"], "severity": sev, "n": n})
    return out


def demo_analytics(db, days=90):
    if db.report_stats_daily.estimated_document_count() == 0:
        rebuild_buckets(db)
    since = now() - timedelta(days=days)
    raw_pipe = [{"$match": {"published_at": {"$gte": since}}},
                {"$group": {"_id": {"d": {"$dateToString": {"format": "%Y-%m-%d", "date": "$published_at"}},
                                    "s": "$classification.severity"}, "n": {"$sum": 1}}}]
    t0 = time.perf_counter()
    for _ in range(5):
        raw = list(db.reports.aggregate(raw_pipe))
    raw_ms = round(_ms(t0) / 5, 2)
    t0 = time.perf_counter()
    for _ in range(5):
        bk = list(db.report_stats_daily.find({"day": {"$gte": since.replace(hour=0, minute=0, second=0,
                                                                             microsecond=0)}}, {"severity": 1}))
    bucket_ms = round(_ms(t0) / 5, 2)
    raw_docs = db.reports.count_documents({"published_at": {"$gte": since}})
    raw_total = sum(r["n"] for r in raw)
    bucket_total = sum(sum((b.get("severity") or {}).values()) for b in bk)
    latest = db.report_stats_daily.find_one({}, sort=[("day", -1)])
    return {"days": days, "raw_reports_scanned": raw_docs, "raw_ms": raw_ms, "bucket_docs_read": len(bk),
            "bucket_ms": bucket_ms, "speedup": round(raw_ms / bucket_ms, 1) if bucket_ms else None,
            "totals_match": raw_total == bucket_total, "raw_total": raw_total, "bucket_total": bucket_total,
            "latest_bucket": latest,
            "takeaway": "The dashboard reads one small bucket per day instead of grouping every report; the raw "
                        "reports stay available for drill-down and for rebuild_buckets()."}


# ===================================================================== 6. mobile apps (change streams + sync)
SYNC_FIELDS = {"title": 1, "url": 1, "source_id": 1, "published_at": 1, "classification.severity": 1,
               "classification.verdict": 1, "classification.category": 1, "cve_ids": 1}


def is_replica_set(client):
    try:
        return bool(client.admin.command("hello").get("setName"))
    except Exception:
        return False


def _card(doc):
    c = doc.get("classification") or {}
    return {"id": str(doc["_id"]), "title": doc.get("title"), "url": doc.get("url"),
            "source_id": doc.get("source_id"), "published_at": doc.get("published_at"),
            "severity": c.get("severity"), "verdict": c.get("verdict"), "category": c.get("category"),
            "cve_ids": (doc.get("cve_ids") or [])[:4]}


class ReportSync:
    """Pushes newly inserted reports to a client.

    mode "change_stream": db.reports.watch() on a replica set; the event id is the resume token, so a client
    that was offline reconnects with it and receives everything it missed.
    mode "polling": standalone server fallback (change streams need a replica set): _id > last ObjectId.
    """

    def __init__(self, db, resume=""):
        self.db, self.cs, self.mode, self.resync = db, None, "polling", False
        self.last_oid = None
        resume = resume or ""
        if resume.startswith("poll:"):
            try:
                self.last_oid = ObjectId(resume[5:])
            except Exception:
                self.last_oid = None
        pipeline = [{"$match": {"operationType": "insert"}}]
        try:
            kw = {"max_await_time_ms": 1000}
            if resume.startswith("cs:"):
                kw["resume_after"] = {"_data": resume[3:]}
            try:
                self.cs = db.reports.watch(pipeline, **kw)
            except OperationFailure as exc:
                if "resume_after" not in kw or exc.code == 40573:
                    raise
                self.resync = True                             # token too old (oplog rolled over): start fresh
                kw.pop("resume_after")
                self.cs = db.reports.watch(pipeline, **kw)
            self.mode = "change_stream"
        except OperationFailure:                               # 40573: not a replica set
            self.cs = None
        if self.mode == "polling" and self.last_oid is None:
            newest = db.reports.find_one({}, {"_id": 1}, sort=[("_id", -1)])
            self.last_oid = newest["_id"] if newest else ObjectId.from_datetime(now())

    def token(self):
        if self.mode == "change_stream":
            t = self.cs.resume_token if self.cs else None
            return f"cs:{t['_data']}" if t and "_data" in t else ""
        return f"poll:{self.last_oid}"

    def next_batch(self, wait_s=2.0):
        """Blocks up to ~wait_s. Returns a list of (token, card)."""
        out = []
        if self.mode == "change_stream":
            end = time.time() + wait_s
            while time.time() < end and len(out) < 50:
                ev = self.cs.try_next()
                if ev is None:
                    if out:
                        break
                    continue
                full = ev.get("fullDocument") or {}
                out.append((f"cs:{ev['_id']['_data']}", _card(full)))
            return out
        rows = list(self.db.reports.find({"_id": {"$gt": self.last_oid}}, SYNC_FIELDS).sort("_id", 1).limit(50))
        for r in rows:
            self.last_oid = r["_id"]
            out.append((f"poll:{r['_id']}", _card(r)))
        if not rows:
            time.sleep(wait_s)
        return out

    def close(self):
        try:
            if self.cs:
                self.cs.close()
        except Exception:
            pass


def demo_sync(db, client):
    """On a replica set: prove resume-after-offline on a scratch collection. Otherwise explain the setup."""
    rs = is_replica_set(client)
    out = {"replica_set": rs, "mode": "change_stream" if rs else "polling fallback"}
    if not rs:
        out["how_to_enable"] = [
            "Add to the mongod config (Apple Silicon: /opt/homebrew/etc/mongod.conf, Intel: /usr/local/etc/mongod.conf):",
            "replication:\n  replSetName: rs0",
            "brew services restart mongodb-community@8.0",
            "mongosh --eval 'rs.initiate({_id: \"rs0\", members: [{_id: 0, host: \"localhost:27017\"}]})'",
        ]
        out["takeaway"] = ("Change streams read the oplog, which only exists on a replica set. Until then the "
                           "website syncs by polling _id > last seen, with the same client-side offline copy.")
        return out
    c = db.sync_demo
    c.drop()
    db.create_collection("sync_demo")
    with c.watch([{"$match": {"operationType": "insert"}}], max_await_time_ms=500) as cs:
        t0 = time.perf_counter()
        c.insert_one({"title": "device online - report 1", "at": now()})
        ev = None
        while ev is None and time.perf_counter() - t0 < 5:
            ev = cs.try_next()
        out["first_event_latency_ms"] = _ms(t0)
        token = cs.resume_token
    # the "phone" goes offline: two reports arrive while nobody is listening
    c.insert_many([{"title": "while offline - report 2", "at": now()},
                   {"title": "while offline - report 3", "at": now()}])
    missed = []
    with c.watch([{"$match": {"operationType": "insert"}}], resume_after=token, max_await_time_ms=500) as cs:
        t0 = time.perf_counter()
        while len(missed) < 2 and time.perf_counter() - t0 < 5:
            ev = cs.try_next()
            if ev:
                missed.append(ev["fullDocument"]["title"])
    c.drop()
    out.update({"resumed_events": missed, "resume_ok": len(missed) == 2,
                "takeaway": "After reconnecting with the saved resume token the client received exactly the "
                            "reports it missed while offline - no full re-download."})
    return out


# ===================================================================== status + run all
def status(db, client):
    names = set(db.list_collection_names())
    info = {c["name"]: c for c in db.list_collections()}
    ts_opts = (info.get("feed_telemetry", {}).get("options") or {}).get("timeseries")
    return {
        "use_cases": USE_CASES,
        "collections": {
            "briefings": db.briefings.estimated_document_count() if "briefings" in names else 0,
            "indicators_validator": bool((info.get("indicators", {}).get("options") or {}).get("validator")),
            "analysts": db.analysts.estimated_document_count() if "analysts" in names else 0,
            "feed_telemetry": db.feed_telemetry.count_documents({}) if "feed_telemetry" in names else 0,
            "feed_telemetry_timeseries": ts_opts,
            "report_stats_daily": db.report_stats_daily.estimated_document_count() if "report_stats_daily" in names else 0,
            "replica_set": is_replica_set(client),
        },
        "telemetry": telemetry_summary(db, hours=72),
        "results": db.lab_results.find_one({"_id": "use_cases"}) or {},
    }


DEMOS = {"content": demo_content, "catalog": demo_catalog, "profiles": demo_profiles,
         "timeseries": demo_timeseries, "analytics": demo_analytics, "sync": demo_sync}


def run_all(db, client, events=20000, only=None, log=None):
    ensure(db)
    results = {"_id": "use_cases", "ran_at": now()}
    for uc in USE_CASES:
        k = uc["key"]
        if only and k not in only:
            continue
        t0 = time.perf_counter()
        try:
            if k == "timeseries":
                r = demo_timeseries(db, events=events)
            elif k == "sync":
                r = demo_sync(db, client)
            else:
                r = DEMOS[k](db)
            r["ok"] = True
        except Exception as exc:  # report the problem on the page instead of failing everything
            r = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        r["seconds"] = round(time.perf_counter() - t0, 2)
        results[k] = r
        if log:
            log(uc, r)
    prev = db.lab_results.find_one({"_id": "use_cases"}) or {}
    merged = {**prev, **results}
    db.lab_results.replace_one({"_id": "use_cases"}, merged, upsert=True)
    return merged
