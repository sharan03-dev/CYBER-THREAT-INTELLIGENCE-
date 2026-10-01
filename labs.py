"""Lab logic shared by the website (Schema lab / Cache lab pages) and the lab scripts in /labs.

Lab 7.1   relationships() + detect_relationships() + bson_stats()
Act. 7.1  build_embedded() + run_activity_71()   (embedded redesign: 'is this source an actual threat?')
Lab 7.2   cache_snapshot() + hit_ratio() + random_reads()
"""
import random
import time
from datetime import datetime, timedelta, timezone

from bson import ObjectId

from . import config

UTC = timezone.utc
LIMIT = config.BSON_LIMIT

# ============================================================== Lab 7.1 - documented design decisions
RELATIONSHIPS = [
    # collection, field, kind, target, cardinality, why, embedded alternative / note
    ("sources", "feed", "embedded", None, "1:1",
     "Feed URL + format are only ever read together with the source.", None),
    ("sources", "stats", "embedded", None, "1:1",
     "Last fetch status is a few small fields updated in place.", None),
    ("reports", "classification", "embedded", None, "1:1",
     "Computed once at ingest and shown on every report card; never queried on its own.", None),
    ("reports", "tags", "embedded", None, "1:few (<=10)",
     "Bounded list of short strings, filtered with a multikey index.", None),
    ("reports", "entities.malware", "embedded", None, "1:few (<=8)",
     "Just names extracted from the text; bounded and read with the report.", None),
    ("threat_actors", "aliases", "embedded", None, "1:few",
     "An actor has a handful of aliases; searched with a multikey index.", None),
    ("vulnerabilities", "kev", "embedded", None, "1:1",
     "CISA KEV details belong to exactly one CVE.", None),
    ("ingest_runs", "results", "embedded", None, "1:~45",
     "One entry per source per run - bounded by the number of sources.", None),
    ("ip_lookups", "result", "embedded", None, "1:1",
     "A cached snapshot; expires with a TTL index.", None),
    ("reports", "source_id", "reference", "sources", "N:1",
     "Thousands of reports share one source; the source's reliability rating changes and must change in ONE place.",
     "Embed {name, reliability, weight} in every report -> faster report listing, but a reliability downgrade "
     "becomes updateMany over thousands of reports."),
    ("reports", "cve_ids", "reference", "vulnerabilities", "N:M",
     "A CVE appears in many reports and its KEV status is updated independently of any report.",
     "Embed [{cve, vendor, product, kev_added}] in each report -> duplicated KEV data that goes stale."),
    ("reports", "actor_ids", "reference", "threat_actors", "N:M",
     "Actors are shared entities with their own profile (aliases, origin, motivation).",
     "Embed actor profiles inside each report -> the same profile copied into hundreds of documents."),
    ("reports", "indicator_ids", "reference", "indicators", "N:M",
     "An IOC (IP, domain, hash) is looked up on its own and can appear in many reports.",
     "Embed full indicator objects -> every IP lookup would have to scan the reports collection."),
    ("sightings", "indicator_id", "reference", "indicators", "N:1",
     "Unbounded: a busy IP is re-listed by feeds every day. Embedding would grow the indicator toward 16 MB.",
     "Embed sightings[] inside each indicator -> this is exactly Activity 7.1 (threat_verdicts collection)."),
    ("sightings", "source_id", "reference", "sources", "N:1",
     "Each sighting records which feed saw the IOC; feeds are few and shared.",
     "Embed a source snapshot in each sighting (done in the Activity 7.1 redesign)."),
    ("briefings", "blocks", "embedded", None, "1:few (<=7)",
     "Use case 1 (content management): ordered content blocks of different shapes, always rendered together.", None),
    ("analysts", "preferences", "embedded", None, "1:1",
     "Use case 3 (user profiles): small, read on every page view, updated in place.", None),
    ("lookup_history", "analyst_id", "reference", "analysts", "N:1",
     "Use case 3: activity history is unbounded, so it points back to the profile instead of living inside it.",
     "Embed history[] in the analyst -> grows forever toward 16 MB."),
    ("briefings", "author_id", "reference", "analysts", "N:1",
     "A briefing names its author; the author's profile is not copied.", None),
    ("sightings", "report_id", "reference", "reports", "N:1",
     "Links an IOC sighting back to the report that mentioned it.", "Embed report title -> duplicated text."),
]


def relationships():
    return [{"collection": c, "field": f, "kind": k, "target": t, "cardinality": card, "why": why,
             "alternative": alt} for c, f, k, t, card, why, alt in RELATIONSHIPS]


# ============================================================== Lab 7.1 - automatic detection
REF_TARGET_HINTS = {"source_id": "sources", "indicator_id": "indicators", "indicator_ids": "indicators",
                    "cve_ids": "vulnerabilities", "actor_ids": "threat_actors", "report_id": "reports",
                    "analyst_id": "analysts", "author_id": "analysts"}
PLATFORM_COLLECTIONS = ["sources", "reports", "indicators", "sightings", "vulnerabilities", "threat_actors",
                        "annual_reports", "ip_lookups", "lookup_history", "ingest_runs", "threat_verdicts",
                        "briefings", "analysts", "report_stats_daily"]


def _walk(doc, prefix=""):
    for k, v in doc.items():
        path = f"{prefix}{k}"
        yield path, v
        if isinstance(v, dict) and len(path.split(".")) < 2:
            yield from _walk(v, path + ".")


def detect_relationships(db, sample=150):
    """Inspect real documents: objects/arrays = embedding, *_id(s) fields whose values exist as _id in
    another collection = referencing. Also reports referential integrity (% of references that resolve)."""
    names = set(db.list_collection_names())
    found = []
    for coll in [c for c in PLATFORM_COLLECTIONS if c in names]:
        docs = list(db[coll].aggregate([{"$sample": {"size": sample}}]))
        if not docs:
            continue
        fields = {}
        for d in docs:
            for path, v in _walk(d):
                if path == "_id":
                    continue
                fields.setdefault(path, []).append(v)
        for path, values in fields.items():
            leaf = path.split(".")[-1]
            nonnull = [v for v in values if v is not None]
            if not nonnull:
                continue
            if leaf in REF_TARGET_HINTS or leaf.endswith("_id") or leaf.endswith("_ids"):
                target = REF_TARGET_HINTS.get(leaf)
                ids = []
                for v in nonnull:
                    ids.extend(v if isinstance(v, list) else [v])
                ids = ids[:300]
                resolved = db[target].count_documents({"_id": {"$in": ids}}) if target and ids else 0
                uniq = len(set(map(str, ids)))
                found.append({"collection": coll, "field": path, "kind": "reference", "target": target,
                              "sampled_refs": len(ids), "resolved_pct": round(100 * resolved / uniq, 1) if uniq else None})
            elif all(isinstance(v, dict) for v in nonnull) and "." not in path:
                found.append({"collection": coll, "field": path, "kind": "embedded", "shape": "sub-document",
                              "avg_keys": round(sum(len(v) for v in nonnull) / len(nonnull), 1)})
            elif all(isinstance(v, list) for v in nonnull):
                lens = [len(v) for v in nonnull]
                inner = next((type(x).__name__ for v in nonnull for x in v), "empty")
                found.append({"collection": coll, "field": path, "kind": "embedded",
                              "shape": f"array of {'sub-documents' if inner == 'dict' else inner}",
                              "avg_len": round(sum(lens) / len(lens), 1), "max_len": max(lens)})
    return found


def bson_stats(db, collections=None):
    """$bsonSize per collection: average / max / min / total, and the distance to the 16 MB limit."""
    names = set(db.list_collection_names())
    rows = []
    for coll in collections or [c for c in PLATFORM_COLLECTIONS if c in names]:
        if coll not in names:
            continue
        agg = list(db[coll].aggregate([
            {"$project": {"s": {"$bsonSize": "$$ROOT"}}},
            {"$group": {"_id": None, "count": {"$sum": 1}, "avg": {"$avg": "$s"}, "max": {"$max": "$s"},
                        "min": {"$min": "$s"}, "total": {"$sum": "$s"}}},
        ], allowDiskUse=True))
        if not agg:
            rows.append({"collection": coll, "count": 0})
            continue
        a = agg[0]
        largest = list(db[coll].aggregate([{"$project": {"s": {"$bsonSize": "$$ROOT"}}},
                                           {"$sort": {"s": -1}}, {"$limit": 1}], allowDiskUse=True))
        rows.append({"collection": coll, "count": a["count"], "avg_bytes": round(a["avg"], 1), "max_bytes": a["max"],
                     "min_bytes": a["min"], "total_bytes": a["total"],
                     "max_pct_of_16mb": round(100 * a["max"] / LIMIT, 5),
                     "largest_id": str(largest[0]["_id"]) if largest else None,
                     "status": "OK" if a["max"] < LIMIT * 0.10 else "WATCH" if a["max"] < LIMIT * 0.5 else "DANGER"})
    return rows


# ============================================================== Activity 7.1 - embedded redesign
def build_embedded(db, cap=50):
    """sightings (+ source reliability) embedded INSIDE each indicator -> collection threat_verdicts.
    Score = noisy-OR: 1 - PRODUCT(1 - weight_source * confidence/100). 'Actual threat' when >= 70."""
    t = time.perf_counter()
    pipeline = [
        {"$match": {"source_id": {"$nin": ["analyst-lookups"]}}},
        {"$lookup": {"from": "sources", "localField": "source_id", "foreignField": "_id",
                     "pipeline": [{"$project": {"name": 1, "reliability": 1, "weight": 1}}], "as": "src"}},
        {"$set": {"src": {"$first": "$src"}}},
        {"$sort": {"observed_at": -1}},
        {"$group": {
            "_id": "$indicator_id",
            "sighting_count": {"$sum": 1},
            "sightings": {"$push": {"source_id": "$source_id", "source_name": "$src.name",
                                    "reliability": "$src.reliability", "weight": {"$ifNull": ["$src.weight", 0.5]},
                                    "observed_at": "$observed_at", "confidence": {"$ifNull": ["$confidence", 50]},
                                    "report_id": "$report_id"}},
        }},
        {"$set": {
            "type": {"$arrayElemAt": [{"$split": ["$_id", ":"]}, 0]},
            "value": {"$substrCP": ["$_id", {"$add": [{"$indexOfCP": ["$_id", ":"]}, 1]}, 300]},
            "sightings": {"$slice": ["$sightings", cap]},        # subset pattern: cap the array
            "not_threat_prob": {"$reduce": {"input": "$sightings", "initialValue": 1, "in": {
                "$multiply": ["$$value", {"$subtract": [1, {"$multiply": ["$$this.weight",
                                                                            {"$divide": ["$$this.confidence", 100]}]}]}]}}},
        }},
        {"$set": {"score": {"$round": [{"$multiply": [100, {"$subtract": [1, "$not_threat_prob"]}]}, 0]}}},
        {"$set": {"verdict": {"$switch": {"branches": [
            {"case": {"$gte": ["$score", 70]}, "then": "Actual threat"},
            {"case": {"$gte": ["$score", 40]}, "then": "Possible threat"}], "default": "Weak signal"}},
            "computed_at": "$$NOW"}},
        {"$unset": "not_threat_prob"},
        {"$merge": {"into": "threat_verdicts", "whenMatched": "replace", "whenNotMatched": "insert"}},
    ]
    db.threat_verdicts.drop()
    db.sightings.aggregate(pipeline, allowDiskUse=True)
    db.threat_verdicts.create_index([("score", -1)])
    db.threat_verdicts.create_index([("sightings.source_id", 1), ("sightings.observed_at", -1)])
    return {"documents": db.threat_verdicts.estimated_document_count(), "seconds": round(time.perf_counter() - t, 2)}


def referenced_decision_pipeline(iid):
    return [
        {"$match": {"_id": iid}},
        {"$lookup": {"from": "sightings", "localField": "_id", "foreignField": "indicator_id", "as": "s",
                     "pipeline": [{"$match": {"source_id": {"$ne": "analyst-lookups"}}},
                                  {"$lookup": {"from": "sources", "localField": "source_id", "foreignField": "_id",
                                               "as": "src", "pipeline": [{"$project": {"weight": 1, "name": 1}}]}},
                                  {"$set": {"weight": {"$ifNull": [{"$first": "$src.weight"}, 0.5]}}}]}},
        {"$set": {"p": {"$reduce": {"input": "$s", "initialValue": 1, "in": {"$multiply": ["$$value", {
            "$subtract": [1, {"$multiply": ["$$this.weight", {"$divide": [{"$ifNull": ["$$this.confidence", 50]}, 100]}]}]}]}}}}},
        {"$project": {"value": 1, "sightings": {"$size": "$s"},
                      "score": {"$round": [{"$multiply": [100, {"$subtract": [1, "$p"]}]}, 0]}}},
    ]


def _ms(fn, repeat):
    t = time.perf_counter()
    for _ in range(repeat):
        fn()
    return round((time.perf_counter() - t) * 1000 / repeat, 3)


def run_activity_71(db, n=200, rebuild=True):
    out = {"ran_at": datetime.now(UTC)}
    if rebuild or "threat_verdicts" not in db.list_collection_names():
        out["build"] = build_embedded(db)
    ids = [d["_id"] for d in db.threat_verdicts.aggregate([{"$sample": {"size": n}}, {"$project": {"_id": 1}}])]
    if not ids:
        return {**out, "error": "No sightings yet - run backend/scripts/setup_database.py first."}

    # Q1 - decide whether ONE indicator is an actual threat
    it = iter(ids * 3)
    ref_ms = _ms(lambda: list(db.indicators.aggregate(referenced_decision_pipeline(next(it)))), len(ids))
    it2 = iter(ids * 3)
    emb_ms = _ms(lambda: db.threat_verdicts.find_one({"_id": next(it2)}, {"score": 1, "verdict": 1}), len(ids))
    ex = db.threat_verdicts.find({"_id": ids[0]}).explain()
    emb_docs = ex.get("executionStats", {}).get("totalDocsExamined", 1)
    avg_sightings = round(db.sightings.count_documents({"indicator_id": {"$in": ids}}) / len(ids), 2)

    # Q2 - top 25 actual threats
    top_ref = lambda: list(db.sightings.aggregate([
        {"$match": {"source_id": {"$ne": "analyst-lookups"}}},
        {"$lookup": {"from": "sources", "localField": "source_id", "foreignField": "_id", "as": "src",
                     "pipeline": [{"$project": {"weight": 1}}]}},
        {"$group": {"_id": "$indicator_id", "p": {"$push": {"$subtract": [1, {"$multiply": [
            {"$ifNull": [{"$first": "$src.weight"}, 0.5]}, {"$divide": [{"$ifNull": ["$confidence", 50]}, 100]}]}]}}}},
        {"$set": {"score": {"$multiply": [100, {"$subtract": [1, {"$reduce": {"input": "$p", "initialValue": 1,
                                                                              "in": {"$multiply": ["$$value", "$$this"]}}}]}]}}},
        {"$sort": {"score": -1}}, {"$limit": 25}], allowDiskUse=True))
    top_emb = lambda: list(db.threat_verdicts.find({}, {"value": 1, "score": 1}).sort("score", -1).limit(25))
    q2_ref, q2_emb = _ms(top_ref, 3), _ms(top_emb, 20)

    # H1 - a source's reliability changes (e.g. analysts downgrade blocklist.de from C to D)
    src_id = "blocklist_de" if db.sources.find_one({"_id": "blocklist_de"}) else db.sightings.find_one()["source_id"]
    old = db.sources.find_one({"_id": src_id}, {"reliability": 1, "weight": 1}) or {"reliability": "C", "weight": 0.6}
    t = time.perf_counter()
    r1 = db.sources.update_one({"_id": src_id}, {"$set": {"reliability": "D", "weight": 0.4}})
    h1_ref_ms = round((time.perf_counter() - t) * 1000, 2)
    t = time.perf_counter()
    r2 = db.threat_verdicts.update_many({"sightings.source_id": src_id},
                                        {"$set": {"sightings.$[s].reliability": "D", "sightings.$[s].weight": 0.4}},
                                        array_filters=[{"s.source_id": src_id}])
    h1_emb_ms = round((time.perf_counter() - t) * 1000, 2)
    # revert both (scores in threat_verdicts would ALSO need recomputing - another cost of embedding)
    db.sources.update_one({"_id": src_id}, {"$set": {"reliability": old.get("reliability"), "weight": old.get("weight")}})
    db.threat_verdicts.update_many({"sightings.source_id": src_id},
                                   {"$set": {"sightings.$[s].reliability": old.get("reliability"),
                                             "sightings.$[s].weight": old.get("weight")}},
                                   array_filters=[{"s.source_id": src_id}])

    # H2 - all sightings from one source in the last 7 days
    since = datetime.now(UTC) - timedelta(days=7)
    h2_ref = lambda: db.sightings.count_documents({"source_id": src_id, "observed_at": {"$gte": since}})
    h2_emb = lambda: list(db.threat_verdicts.aggregate([
        {"$match": {"sightings": {"$elemMatch": {"source_id": src_id, "observed_at": {"$gte": since}}}}},
        {"$unwind": "$sightings"},
        {"$match": {"sightings.source_id": src_id, "sightings.observed_at": {"$gte": since}}},
        {"$count": "n"}]))
    h2_ref_ms, h2_emb_ms = _ms(h2_ref, 5), _ms(h2_emb, 5)

    # growth / 16 MB
    size = list(db.threat_verdicts.aggregate([
        {"$project": {"s": {"$bsonSize": "$$ROOT"}, "n": {"$size": "$sightings"}, "c": "$sighting_count"}},
        {"$group": {"_id": None, "avg": {"$avg": "$s"}, "max": {"$max": "$s"}, "max_n": {"$max": "$n"},
                    "max_c": {"$max": "$c"}, "per": {"$avg": {"$divide": ["$s", {"$max": ["$n", 1]}]}}}}]))[0]
    per_sighting = max(40, size["per"])
    out.update({
        "sample_size": len(ids), "source_changed": src_id,
        "faster": [
            {"query": "Is this IP an actual threat? (one indicator)", "referenced_ms": ref_ms, "embedded_ms": emb_ms,
             "referenced_reads": f"1 indicator + {avg_sightings} sightings + their sources (2 x $lookup)",
             "embedded_reads": f"{emb_docs} document, 1 index seek"},
            {"query": "Top 25 actual threats (dashboard)", "referenced_ms": q2_ref, "embedded_ms": q2_emb,
             "referenced_reads": f"all {db.sightings.estimated_document_count():,} sightings grouped",
             "embedded_reads": "25 documents via index on score"},
        ],
        "harder": [
            {"operation": f"Source reliability downgraded ({src_id} to D)", "referenced_ms": h1_ref_ms,
             "embedded_ms": h1_emb_ms, "referenced_docs": r1.modified_count, "embedded_docs": r2.modified_count,
             "note": "and every embedded score must be recomputed too"},
            {"operation": f"All sightings from {src_id} in the last 7 days", "referenced_ms": h2_ref_ms,
             "embedded_ms": h2_emb_ms, "note": "embedded needs $elemMatch + $unwind; referenced is one indexed count"},
        ],
        "size": {"avg_bytes": round(size["avg"]), "max_bytes": size["max"], "max_embedded_sightings": size["max_n"],
                 "max_total_sightings": size["max_c"], "bytes_per_sighting": round(per_sighting),
                 "sightings_to_reach_16mb": int(LIMIT / per_sighting)},
    })
    db.lab_results.replace_one({"_id": "activity_7_1"}, {"_id": "activity_7_1", **out}, upsert=True)
    return out


# ============================================================== Lab 7.2 - WiredTiger cache
def pick(cache: dict, *names, default=0):
    for n in names:
        if n in cache:
            return cache[n]
    return default


def cache_counters(status):
    c = status.get("wiredTiger", {}).get("cache", {})
    return {
        "max_bytes": pick(c, "maximum bytes configured"),
        "used_bytes": pick(c, "bytes currently in the cache"),
        "dirty_bytes": pick(c, "tracked dirty bytes in the cache"),
        "pages_requested": pick(c, "pages requested from the cache"),
        "pages_read": pick(c, "pages read into cache"),
        "bytes_read": pick(c, "bytes read into cache"),
        "evicted_unmodified": pick(c, "unmodified pages evicted"),
        "evicted_modified": pick(c, "modified pages evicted"),
        "evicted_by_app": pick(c, "pages evicted by application threads",
                               "eviction pages evicted by application threads"),
        "pages_in_cache": pick(c, "pages currently held in the cache"),
    }


def hit_ratio(prev, cur):
    """Interval hit ratio = 1 - (pages read from disk into cache / pages requested from the cache)."""
    req = cur["pages_requested"] - prev["pages_requested"]
    miss = cur["pages_read"] - prev["pages_read"]
    if req <= 0:
        return None
    return max(0.0, min(1.0, 1 - miss / req))


def coll_storage(db, coll):
    try:
        st = list(db[coll].aggregate([{"$collStats": {"storageStats": {}}}]))[0]["storageStats"]
    except Exception:
        return None
    wt_cache = st.get("wiredTiger", {}).get("cache", {})
    idx_cache = sum(v.get("cache", {}).get("bytes currently in the cache", 0)
                    for v in (st.get("indexDetails") or {}).values())
    return {"count": st.get("count", 0), "size": st.get("size", 0), "avg_obj": st.get("avgObjSize", 0),
            "storage_size": st.get("storageSize", 0), "index_size": st.get("totalIndexSize", 0),
            "in_cache": wt_cache.get("bytes currently in the cache", 0), "index_in_cache": idx_cache}


def cache_snapshot(client, lab_db, coll="ws_reports"):
    status = client.admin.command("serverStatus")
    cnt = cache_counters(status)
    cs = coll_storage(lab_db, coll) if coll in lab_db.list_collection_names() else None
    snap = {
        "at": datetime.now(UTC), "version": status.get("version"), "uptime_s": status.get("uptime"),
        "counters": cnt,
        "used_pct": round(100 * cnt["used_bytes"] / cnt["max_bytes"], 2) if cnt["max_bytes"] else None,
        "dirty_pct": round(100 * cnt["dirty_bytes"] / cnt["max_bytes"], 3) if cnt["max_bytes"] else None,
        "hit_ratio_since_start": round(1 - cnt["pages_read"] / cnt["pages_requested"], 5) if cnt["pages_requested"] else None,
        "collection": cs,
    }
    if cs and cs["size"]:
        ws = cs["size"] + cs["index_size"]
        snap["working_set"] = {
            "estimate_bytes": ws,
            "cache_bytes": cnt["max_bytes"],
            "fits": ws <= 0.8 * cnt["max_bytes"],   # WiredTiger starts evicting at 80% full (eviction_target)
            "ratio_of_cache": round(ws / cnt["max_bytes"], 3) if cnt["max_bytes"] else None,
            "collection_in_cache_pct": round(100 * cs["in_cache"] / cs["size"], 2),
            "index_in_cache_pct": round(100 * cs["index_in_cache"] / cs["index_size"], 2) if cs["index_size"] else None,
        }
    return snap


def random_reads(client, lab_db, coll="ws_reports", seconds=20, interval=2.0):
    col = lab_db[coll]
    n = col.estimated_document_count()
    if not n:
        return {"error": "Run labs/lab7_2/lab_02_working_set_analysis.py first to insert the 100,000 documents."}
    prev = cache_counters(client.admin.command("serverStatus"))
    series, reads, t_end = [], 0, time.perf_counter() + seconds
    t_next, t0 = time.perf_counter() + interval, time.perf_counter()
    lat = []
    while time.perf_counter() < t_end:
        t = time.perf_counter()
        col.find_one({"seq": random.randrange(n)}, {"_id": 0, "seq": 1, "payload": 1})
        lat.append(time.perf_counter() - t)
        reads += 1
        if time.perf_counter() >= t_next:
            cur = cache_counters(client.admin.command("serverStatus"))
            series.append({"t": round(time.perf_counter() - t0, 1), "hit_ratio": hit_ratio(prev, cur),
                           "reads": reads, "avg_ms": round(1000 * sum(lat) / len(lat), 3),
                           "used_mb": round(cur["used_bytes"] / 1048576, 1),
                           "pages_read": cur["pages_read"] - prev["pages_read"]})
            prev, lat, t_next = cur, [], time.perf_counter() + interval
    return {"reads": reads, "seconds": seconds, "series": series}


def to_jsonable(o):
    if isinstance(o, dict):
        return {k: to_jsonable(v) for k, v in o.items()}
    if isinstance(o, list):
        return [to_jsonable(v) for v in o]
    if isinstance(o, ObjectId):
        return str(o)
    return o
