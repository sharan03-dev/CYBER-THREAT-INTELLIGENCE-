"""CTI Platform - FastAPI backend.

Run from the project root:   python -m uvicorn backend.app.main:app --reload --port 8000
Then open                   http://127.0.0.1:8000
"""
import asyncio
import json
import re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pymongo.errors import OperationFailure, PyMongoError, ServerSelectionTimeoutError

from . import config, ingest, ipintel, labs, usecases
from .classifier import ALL_CATEGORIES, classify
from .db import client, ensure_indexes, get_db, get_lab_db, ping
from .ioc import CVE_RX, extract, indicator_id, parse_ip

UTC = timezone.utc
J = labs.to_jsonable
STATE = {"ingest": {"running": False, "started_at": None, "finished_at": None, "result": None, "error": None}}
_cache = {}


def cached(key, seconds, fn):
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < seconds:
        return hit[1]
    val = fn()
    _cache[key] = (time.time(), val)
    return val


@asynccontextmanager
async def lifespan(app):
    if await run_in_threadpool(ping):
        try:
            await run_in_threadpool(ensure_indexes)
            db = get_db()
            if db.report_stats_daily.estimated_document_count() == 0 and db.reports.estimated_document_count():
                await run_in_threadpool(usecases.rebuild_buckets, db)   # use case 5: first-time rollup
        except Exception as exc:  # never block the website because of an index problem
            print("[warn] could not create indexes:", exc)
    else:
        print("\n[!] MongoDB is not reachable at", config.MONGO_URI,
              "\n    Start it with:  brew services start mongodb-community@8.0\n")
    yield


app = FastAPI(title="CTI Platform API", version="1.0", lifespan=lifespan)
class GZipExceptStream:
    """GZip everything except the Server-Sent Events stream (older Starlette versions would buffer it)."""

    def __init__(self, app):
        self.app, self.gz = app, GZipMiddleware(app, minimum_size=800)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path") == "/api/stream":
            return await self.app(scope, receive, send)
        return await self.gz(scope, receive, send)


app.add_middleware(GZipExceptStream)


@app.exception_handler(ServerSelectionTimeoutError)
async def mongo_down(_req, _exc):
    return JSONResponse(status_code=503, content={
        "detail": "MongoDB is not running. In Terminal run: brew services start mongodb-community@8.0"})


def _sources_map(db):
    return cached("sources_map", 30, lambda: {s["_id"]: {"name": s["name"], "reliability": s.get("reliability"),
                                                          "homepage": s.get("homepage")}
                                              for s in db.sources.find({}, {"name": 1, "reliability": 1, "homepage": 1})})


def _report_card(r, smap):
    c = r.get("classification", {})
    return {"id": str(r["_id"]), "title": r["title"], "url": r["url"], "summary": r.get("summary", "")[:420],
            "published_at": r.get("published_at"), "source_id": r.get("source_id"),
            "source": smap.get(r.get("source_id"), {}).get("name", r.get("source_id")),
            "category": c.get("category"), "severity": c.get("severity"), "verdict": c.get("verdict"),
            "confidence": c.get("confidence"), "admiralty": c.get("admiralty"), "tags": r.get("tags", []),
            "cve_ids": r.get("cve_ids", [])[:6], "actor_ids": r.get("actor_ids", [])[:4],
            "ioc_count": len(r.get("indicator_ids", [])), "score": r.get("score")}


CARD_FIELDS = {"title": 1, "url": 1, "summary": 1, "published_at": 1, "source_id": 1, "classification.category": 1,
               "classification.severity": 1, "classification.verdict": 1, "classification.confidence": 1,
               "classification.admiralty": 1, "tags": 1, "cve_ids": 1, "actor_ids": 1, "indicator_ids": 1}


# ======================================================================== health / overview
@app.get("/api/health")
def health():
    ok = ping()
    out = {"mongodb": ok, "uri": config.MONGO_URI, "db": config.DB_NAME, "time": datetime.now(UTC)}
    if ok:
        db = get_db()
        out["version"] = client().server_info().get("version")
        out["reports"] = db.reports.estimated_document_count()
        out["indicators"] = db.indicators.estimated_document_count()
        out["needs_setup"] = out["reports"] == 0 and out["indicators"] == 0
    return out


@app.get("/api/overview")
def overview(days: int = 30):
    db = get_db()

    def build():
        since = datetime.now(UTC) - timedelta(days=days)
        f = list(db.reports.aggregate([{"$facet": {
            "by_category": [{"$group": {"_id": "$classification.category", "n": {"$sum": 1}}}, {"$sort": {"n": -1}}],
            "by_severity": [{"$group": {"_id": "$classification.severity", "n": {"$sum": 1}}}],
            "by_verdict": [{"$group": {"_id": "$classification.verdict", "n": {"$sum": 1}}}],
            "per_day": [{"$match": {"published_at": {"$gte": since}}},
                        {"$group": {"_id": {"d": {"$dateToString": {"format": "%Y-%m-%d", "date": "$published_at"}},
                                            "s": "$classification.severity"}, "n": {"$sum": 1}}}],
            "top_cves": [{"$unwind": "$cve_ids"}, {"$group": {"_id": "$cve_ids", "n": {"$sum": 1}}},
                         {"$sort": {"n": -1, "_id": -1}}, {"$limit": 8}],
            "top_actors": [{"$unwind": "$actor_ids"}, {"$group": {"_id": "$actor_ids", "n": {"$sum": 1}}},
                           {"$sort": {"n": -1}}, {"$limit": 8},
                           {"$lookup": {"from": "threat_actors", "localField": "_id", "foreignField": "_id",
                                        "as": "a"}}],
            "latest_threats": [{"$match": {"classification.verdict": "Actual threat"}},
                               {"$sort": {"published_at": -1}}, {"$limit": 7}, {"$project": CARD_FIELDS}],
        }}], allowDiskUse=True))[0]
        smap = _sources_map(db)
        kev_cves = {v["_id"]: v["kev"] for v in db.vulnerabilities.find(
            {"_id": {"$in": [c["_id"] for c in f["top_cves"]]}, "kev": {"$exists": True}}, {"kev.product": 1, "kev.vendor": 1})}
        src = list(db.sources.find({}, {"name": 1, "kind": 1, "reliability": 1, "stats": 1, "homepage": 1}))
        return {
            "counts": {
                "reports": db.reports.estimated_document_count(),
                "indicators": db.indicators.estimated_document_count(),
                "sightings": db.sightings.estimated_document_count(),
                "kev": db.vulnerabilities.count_documents({"kev": {"$exists": True}}),
                "lookups": db.lookup_history.estimated_document_count(),
                "annual_reports": db.annual_reports.estimated_document_count(),
                "sources_ok": sum(1 for s in src if (s.get("stats") or {}).get("last_status") == "ok"),
                "sources_total": len(src),
            },
            "by_category": [{"name": x["_id"] or "General security", "n": x["n"]} for x in f["by_category"]],
            "by_severity": {x["_id"]: x["n"] for x in f["by_severity"] if x["_id"]},
            "by_verdict": {x["_id"]: x["n"] for x in f["by_verdict"] if x["_id"]},
            # use case 5: read the pre-aggregated daily buckets when they exist, raw reports otherwise
            "per_day": (usecases.per_day_from_buckets(db, days) if db.report_stats_daily.estimated_document_count()
                        else [{"day": x["_id"]["d"], "severity": x["_id"]["s"], "n": x["n"]} for x in f["per_day"]]),
            "per_day_source": "report_stats_daily" if db.report_stats_daily.estimated_document_count() else "reports",
            "top_cves": [{"cve": x["_id"], "n": x["n"], "kev": kev_cves.get(x["_id"])} for x in f["top_cves"]],
            "top_actors": [{"id": x["_id"], "n": x["n"], "name": (x["a"][0]["name"] if x["a"] else x["_id"]),
                            "type": (x["a"][0].get("type") if x["a"] else None),
                            "origin": (x["a"][0].get("origin") if x["a"] else None)} for x in f["top_actors"]],
            "latest_threats": [_report_card(r, smap) for r in f["latest_threats"]],
            "sources": [{"id": s["_id"], "name": s["name"], "kind": s.get("kind"), "reliability": s.get("reliability"),
                         "status": (s.get("stats") or {}).get("last_status"), "items": (s.get("stats") or {}).get("items"),
                         "last_fetch": (s.get("stats") or {}).get("last_fetch"),
                         "error": (s.get("stats") or {}).get("last_error")} for s in src],
            "recent_lookups": ipintel.recent_lookups(db, 8),
            "last_ingest": J(db.ingest_runs.find_one({}, {"results": 0}, sort=[("started_at", -1)])),
        }

    return J(cached(f"overview:{days}", 15, build))


# ======================================================================== reports / search
def _build_filter(q, category, severity, verdict, source, days):
    filt, mode = {}, "all"
    if q and q.strip():
        qs = q.strip()
        if CVE_RX.fullmatch(qs):
            filt["cve_ids"], mode = qs.upper(), "cve"
        elif parse_ip(qs):
            ip = parse_ip(qs)
            filt["indicator_ids"], mode = indicator_id(f"ipv{ip.version}", str(ip)), "ip"
        else:
            filt["$text"], mode = {"$search": qs}, "text"
    if category:
        filt["classification.category"] = {"$in": category.split("|")}
    if severity:
        filt["classification.severity"] = {"$in": severity.split("|")}
    if verdict:
        filt["classification.verdict"] = {"$in": verdict.split("|")}
    if source:
        filt["source_id"] = {"$in": source.split("|")}
    if days:
        filt["published_at"] = {"$gte": datetime.now(UTC) - timedelta(days=days)}
    return filt, mode


@app.get("/api/reports")
def reports(q: str = "", category: str = "", severity: str = "", verdict: str = "", source: str = "",
            days: int = 0, page: int = Query(1, ge=1), limit: int = Query(20, ge=1, le=100), sort: str = "relevance"):
    db = get_db()
    filt, mode = _build_filter(q, category, severity, verdict, source, days)
    proj = dict(CARD_FIELDS)
    t = time.perf_counter()
    try:
        if mode == "text":
            proj["score"] = {"$meta": "textScore"}
            order = [("score", {"$meta": "textScore"}), ("published_at", -1)] if sort == "relevance" else [("published_at", -1)]
        else:
            order = [("published_at", -1 if sort != "oldest" else 1)]
        total = db.reports.count_documents(filt)
        rows = list(db.reports.find(filt, proj).sort(order).skip((page - 1) * limit).limit(limit))
    except OperationFailure:  # text index missing -> fall back to a regex search
        filt.pop("$text", None)
        filt["$or"] = [{"title": {"$regex": re.escape(q), "$options": "i"}},
                       {"summary": {"$regex": re.escape(q), "$options": "i"}}]
        total = db.reports.count_documents(filt)
        rows = list(db.reports.find(filt, CARD_FIELDS).sort("published_at", -1).skip((page - 1) * limit).limit(limit))
        mode = "regex"
    smap = _sources_map(db)
    return J({"total": total, "page": page, "limit": limit, "mode": mode,
              "took_ms": round((time.perf_counter() - t) * 1000, 1),
              "results": [_report_card(r, smap) for r in rows]})


@app.get("/api/facets")
def facets():
    db = get_db()

    def build():
        f = list(db.reports.aggregate([{"$facet": {
            "category": [{"$group": {"_id": "$classification.category", "n": {"$sum": 1}}}, {"$sort": {"n": -1}}],
            "severity": [{"$group": {"_id": "$classification.severity", "n": {"$sum": 1}}}],
            "verdict": [{"$group": {"_id": "$classification.verdict", "n": {"$sum": 1}}}],
            "source": [{"$group": {"_id": "$source_id", "n": {"$sum": 1}}}, {"$sort": {"n": -1}}],
        }}]))[0]
        smap = _sources_map(db)
        return {k: [{"value": x["_id"], "n": x["n"],
                     **({"label": smap.get(x["_id"], {}).get("name", x["_id"])} if k == "source" else {})}
                    for x in v if x["_id"]] for k, v in f.items()}

    return cached("facets", 20, build)


@app.get("/api/reports/{rid}")
def report_detail(rid: str):
    db = get_db()
    try:
        oid = ObjectId(rid)
    except InvalidId:
        raise HTTPException(404, "Report not found")
    rows = list(db.reports.aggregate([
        {"$match": {"_id": oid}},
        {"$lookup": {"from": "sources", "localField": "source_id", "foreignField": "_id", "as": "source"}},
        {"$lookup": {"from": "vulnerabilities", "localField": "cve_ids", "foreignField": "_id", "as": "cves"}},
        {"$lookup": {"from": "threat_actors", "localField": "actor_ids", "foreignField": "_id", "as": "actors"}},
        {"$lookup": {"from": "indicators", "localField": "indicator_ids", "foreignField": "_id", "as": "indicators"}},
        {"$set": {"source": {"$first": "$source"}}},
    ]))
    if not rows:
        raise HTTPException(404, "Report not found")
    r = rows[0]
    related = list(db.reports.find({"_id": {"$ne": oid}, "$or": [
        {"cve_ids": {"$in": r.get("cve_ids", [])}} if r.get("cve_ids") else {"_id": None},
        {"actor_ids": {"$in": r.get("actor_ids", [])}} if r.get("actor_ids") else {"_id": None},
    ]}, CARD_FIELDS).sort("published_at", -1).limit(5))
    smap = _sources_map(db)
    r["related"] = [_report_card(x, smap) for x in related]
    r["id"] = str(r.pop("_id"))
    return J(r)


# ======================================================================== classification
@app.post("/api/classify")
def classify_text(payload: dict = Body(...)):
    text = str(payload.get("text", ""))[:20000]
    if len(text.strip()) < 8:
        raise HTTPException(400, "Paste at least a sentence of text to classify.")
    rel = payload.get("reliability", "C")
    db = get_db()
    iocs = extract(text)
    kev = [v["_id"] for v in db.vulnerabilities.find({"_id": {"$in": iocs["cves"]}, "kev": {"$exists": True}}, {"_id": 1})]
    actors = [aid for aid, rx in ingest.build_actor_matchers(db) if rx.search(text)]
    names = {a["_id"]: a for a in db.threat_actors.find({"_id": {"$in": actors}}, {"name": 1, "origin": 1, "type": 1})}
    n_ioc = len(iocs["ips"]) + len(iocs["domains"]) + len(iocs["hashes"]) + len(iocs["urls"])
    cls = classify(text, reliability=rel if rel in "ABCDEF" else "C", ioc_count=n_ioc,
                   cve_count=len(iocs["cves"]), kev_count=len(kev), actor_count=len(actors))
    return J({**cls, "iocs": {**iocs, "hashes": [{"type": t, "value": v} for t, v in iocs["hashes"]]},
              "kev": kev, "actors": [{"id": a, **names.get(a, {})} for a in actors],
              "all_categories": ALL_CATEGORIES})


# ======================================================================== IP intelligence
@app.get("/api/ip/{ip:path}")
async def ip_lookup(ip: str, refresh: bool = False):
    try:
        return J(await ipintel.lookup(get_db(), ip, refresh=refresh))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.get("/api/ip-examples")
def ip_examples():
    """Real IPs from the imported feeds so the demo always has something interesting to check."""
    db = get_db()

    def build():
        out = []

        def first(source, label, sort=None):
            s = db.sightings.find_one({"source_id": source, "report_id": {"$exists": False}}, sort=sort)
            if s:
                kind, value = s["indicator_id"].split(":", 1)
                if kind == "cidr":
                    import ipaddress
                    value = str(ipaddress.ip_network(value).network_address + 1)
                out.append({"ip": value, "label": label})

        first("feodo", "botnet C2")
        first("ipsum", "on many blacklists", sort=[("detail.hits", -1)])
        first("spamhaus_drop", "hijacked network")
        first("tor_exits", "Tor exit")
        first("sample-data", "demo")
        out += [{"ip": "8.8.8.8", "label": "Google DNS"}, {"ip": "192.168.1.10", "label": "private"}]
        return out

    return cached("ip_examples", 300, build)


@app.get("/api/lookups/recent")
def recent(limit: int = 12):
    return J(ipintel.recent_lookups(get_db(), limit))


@app.get("/api/indicators")
def indicators(q: str = "", type: str = "", limit: int = Query(25, le=100)):
    db = get_db()
    filt = {}
    if type:
        filt["type"] = type
    if q:
        filt["value"] = {"$regex": "^" + re.escape(q.strip())}
    rows = list(db.indicators.find(filt, {"type": 1, "value": 1, "tags": 1, "first_seen": 1, "last_seen": 1})
                .sort("last_seen", -1).limit(limit))
    return J({"results": [{"id": r["_id"], **{k: r.get(k) for k in ("type", "value", "tags", "first_seen", "last_seen")}}
                          for r in rows]})


# ======================================================================== sources / ingest
@app.get("/api/sources")
def sources():
    return J(list(get_db().sources.find({}).sort([("kind", 1), ("name", 1)])))


async def _run_ingest(what):
    st = STATE["ingest"]
    st.update(running=True, started_at=datetime.now(UTC), error=None, result=None)
    db = get_db()
    started = datetime.now(UTC)
    logs = []
    try:
        result = {}
        if what in ("news", "all"):
            result["news"] = await ingest.ingest_news(db, log=logs.append)
            await run_in_threadpool(ingest.log_run, db, "news", started, result["news"])
        if what in ("feeds", "all"):
            result["feeds"] = await run_in_threadpool(ingest.import_ioc_feeds, db, None, logs.append)
        if what in ("annual", "all"):
            r = await run_in_threadpool(ingest.import_annual_reports, db, None, logs.append)
            result["annual"] = {"status": r["status"], "items": r.get("items"), "new": len(r.get("new", []))}
        result["log"] = logs
        st["result"] = result
        _cache.clear()
    except Exception as exc:
        st["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        st.update(running=False, finished_at=datetime.now(UTC))


@app.post("/api/ingest")
async def start_ingest(payload: dict = Body(default={})):
    what = payload.get("what", "news")
    if STATE["ingest"]["running"]:
        return {"started": False, "message": "An update is already running."}
    asyncio.create_task(_run_ingest(what))
    return {"started": True, "what": what}


@app.get("/api/ingest/status")
def ingest_status():
    return J(STATE["ingest"])


@app.get("/api/annual-reports")
def annual_reports(q: str = "", year: int = 0, limit: int = Query(30, le=200)):
    filt = {}
    if q:
        filt["$or"] = [{"title": {"$regex": re.escape(q), "$options": "i"}},
                       {"organization": {"$regex": re.escape(q), "$options": "i"}}]
    if year:
        filt["year"] = year
    rows = list(get_db().annual_reports.find(filt).sort([("year", -1), ("organization", 1)]).limit(limit))
    return J({"results": rows, "total": get_db().annual_reports.count_documents(filt)})


# ======================================================================== Lab 7.1
@app.get("/api/lab71/schema")
def lab71_schema(fresh: bool = False):
    db = get_db()

    def build():
        names = set(db.list_collection_names())
        counts = {c: db[c].estimated_document_count() for c in labs.PLATFORM_COLLECTIONS if c in names}
        return {"relationships": labs.relationships(), "detected": labs.detect_relationships(db, sample=80),
                "bson": labs.bson_stats(db), "counts": counts, "limit_bytes": config.BSON_LIMIT,
                "computed_at": datetime.now(UTC)}

    if fresh:
        _cache.pop("lab71", None)
    return J(cached("lab71", 120, build))


@app.get("/api/lab71/activity")
def lab71_activity():
    return J(get_db().lab_results.find_one({"_id": "activity_7_1"}) or {})


@app.post("/api/lab71/activity/run")
async def lab71_run():
    return J(await run_in_threadpool(labs.run_activity_71, get_db(), 150, True))


# ======================================================================== Lab 7.2
@app.get("/api/lab72/cache")
def lab72_cache():
    return J(labs.cache_snapshot(client(), get_lab_db()))


@app.get("/api/lab72/metrics")
def lab72_metrics(limit: int = Query(180, le=2000)):
    rows = list(get_db().cache_metrics.find({}, {"_id": 0}).sort("$natural", -1).limit(limit))
    return J(list(reversed(rows)))


@app.get("/api/lab72/results")
def lab72_results():
    return J(get_db().lab_results.find_one({"_id": "lab_7_2"}) or {})


@app.post("/api/lab72/random-reads")
async def lab72_reads(payload: dict = Body(default={})):
    seconds = max(4, min(int(payload.get("seconds", 16)), 60))
    return J(await run_in_threadpool(labs.random_reads, client(), get_lab_db(), "ws_reports", seconds, 2.0))


# ======================================================================== MongoDB use cases (classroom update)
@app.get("/api/usecases")
def usecases_status():
    return J(usecases.status(get_db(), client()))


@app.post("/api/usecases/run")
async def usecases_run(payload: dict = Body(default={})):
    only = payload.get("only")
    only = [only] if isinstance(only, str) else only
    events = max(2000, min(int(payload.get("events", 20000)), 200000))
    res = await run_in_threadpool(usecases.run_all, get_db(), client(), events, only)
    _cache.clear()
    return J(res)


@app.get("/api/briefings/latest")
def briefing_latest(rebuild: bool = False):
    db = get_db()
    b = usecases.build_briefing(db) if rebuild else (usecases.latest_briefing(db) or usecases.build_briefing(db))
    return J(b)


@app.get("/api/profile")
def profile():
    return J(usecases.get_profile(get_db()))


@app.put("/api/profile/preferences")
def profile_prefs(payload: dict = Body(...)):
    return J(usecases.update_preferences(get_db(), payload))


@app.post("/api/analytics/rebuild")
async def analytics_rebuild():
    r = await run_in_threadpool(usecases.rebuild_buckets, get_db())
    _cache.clear()
    return r


@app.get("/api/telemetry")
def telemetry(hours: int = Query(72, ge=1, le=24 * 90)):
    return J(usecases.telemetry_summary(get_db(), hours))


def _iso(o):
    return o.isoformat() if hasattr(o, "isoformat") else str(o)


@app.get("/api/stream")
async def stream(request: Request, resume: str = ""):
    """Server-Sent Events: new reports from a change stream (replica set) or polling (standalone).
    Every event id is a resume token; the browser sends it back (Last-Event-ID) after being offline."""
    token = request.headers.get("last-event-id") or resume

    async def gen():
        sync = await run_in_threadpool(usecases.ReportSync, get_db(), token)
        try:
            hello = {"mode": sync.mode, "resync": sync.resync, "token": sync.token()}
            yield f"event: hello\ndata: {json.dumps(hello)}\nretry: 5000\n\n"
            idle = 0
            while not await request.is_disconnected():
                batch = await run_in_threadpool(sync.next_batch, 2.0)
                for tok, card in batch:
                    yield f"id: {tok}\nevent: report\ndata: {json.dumps(J(card), default=_iso)}\n\n"
                idle = 0 if batch else idle + 1
                if idle >= 8:                       # keep proxies from closing an idle connection
                    idle = 0
                    yield ": ping\n\n"
        except PyMongoError as exc:
            yield f"event: error\ndata: {json.dumps({'error': str(exc)[:200]})}\n\n"
        finally:
            sync.close()

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ======================================================================== frontend (must be last)
app.mount("/", StaticFiles(directory=str(config.FRONTEND_DIR), html=True), name="frontend")
