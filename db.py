"""MongoDB connection + index definitions for the CTI platform."""
from pymongo import ASCENDING, DESCENDING, TEXT, MongoClient
from pymongo.errors import CollectionInvalid, OperationFailure

from . import config

_client = None


def client() -> MongoClient:
    global _client
    if _client is None:
        _client = MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=4000, appname="cti-platform", tz_aware=True)
    return _client


def get_db():
    return client()[config.DB_NAME]


def get_lab_db():
    return client()[config.LAB72_DB]


def ping() -> bool:
    try:
        client().admin.command("ping")
        return True
    except Exception:
        return False


def _safe_index(coll, keys, **kw):
    try:
        coll.create_index(keys, **kw)
    except OperationFailure as exc:  # an equivalent index already exists with other options
        if exc.code not in (85, 86) and "already exists" not in str(exc):
            raise


def ensure_indexes(db=None):
    """Create every index the platform relies on (safe to run many times)."""
    db = db if db is not None else get_db()

    _safe_index(db.sources, [("kind", ASCENDING)])

    r = db.reports
    _safe_index(r, [("url", ASCENDING)], unique=True, name="url_unique")
    _safe_index(r, [("title", TEXT), ("summary", TEXT), ("tags", TEXT)],
                weights={"title": 10, "tags": 5, "summary": 2},
                name="report_text", default_language="english")
    _safe_index(r, [("published_at", DESCENDING)])
    _safe_index(r, [("classification.category", ASCENDING), ("published_at", DESCENDING)])
    _safe_index(r, [("classification.verdict", ASCENDING), ("published_at", DESCENDING)])
    _safe_index(r, [("classification.severity", ASCENDING)])
    _safe_index(r, [("source_id", ASCENDING), ("published_at", DESCENDING)])
    _safe_index(r, [("cve_ids", ASCENDING)])
    _safe_index(r, [("actor_ids", ASCENDING)])
    _safe_index(r, [("indicator_ids", ASCENDING)])

    i = db.indicators
    _safe_index(i, [("type", ASCENDING), ("value", ASCENDING)], unique=True)
    _safe_index(i, [("range_start", ASCENDING), ("range_end", ASCENDING)],
                partialFilterExpression={"type": "cidr"}, name="cidr_range")
    _safe_index(i, [("last_seen", DESCENDING)])

    s = db.sightings
    _safe_index(s, [("indicator_id", ASCENDING)])
    _safe_index(s, [("source_id", ASCENDING), ("observed_at", DESCENDING)])
    _safe_index(s, [("report_id", ASCENDING)], sparse=True)

    _safe_index(db.threat_actors, [("aliases", ASCENDING)])
    _safe_index(db.vulnerabilities, [("kev.date_added", DESCENDING)])
    _safe_index(db.annual_reports, [("year", DESCENDING), ("category", ASCENDING)])
    _safe_index(db.ingest_runs, [("started_at", DESCENDING)])
    # TTL index: cached IP lookups are deleted automatically after N hours
    _safe_index(db.ip_lookups, [("created_at", ASCENDING)],
                expireAfterSeconds=int(config.LOOKUP_CACHE_HOURS * 3600), name="ttl_created_at")
    _safe_index(db.lookup_history, [("ip", ASCENDING), ("at", DESCENDING)])
    _safe_index(db.lookup_history, [("at", DESCENDING)])

    # Capped collection = fixed-size ring buffer for Activity 7.2 monitor samples
    try:
        db.create_collection("cache_metrics", capped=True, size=8 * 1024 * 1024, max=20000)
    except (CollectionInvalid, OperationFailure, NotImplementedError):
        pass

    # Classroom update: the six MongoDB use-case patterns (validator, time-series, buckets, profiles, briefings)
    try:
        from . import usecases
        usecases.ensure(db)
    except Exception as exc:  # never block startup
        print("[warn] use-case setup:", exc)
    return True
