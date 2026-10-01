"""Data collection for the CTI platform.

  seed_catalog()          sources + threat actors
  import_ioc_feeds()      IP / CIDR / URL / hash feeds  -> indicators + sightings
  import_kev()            CISA Known Exploited Vulnerabilities -> vulnerabilities
  ingest_news()           ~30 security RSS feeds (the feeds ctidigest.com aggregates) -> reports
  discover_ctidigest()    best-effort: read ctidigest.com itself (feed list, JSON data)
  import_annual_reports() awesome-annual-security-reports README -> annual_reports (Lab 7.2 dataset)
"""
import asyncio
import csv
import html
import io
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import feedparser
import httpx
from bs4 import BeautifulSoup
from pymongo import UpdateOne
from pymongo.errors import BulkWriteError

from . import catalog, config, usecases
from .classifier import classify, tags_from
from .ioc import cidr_range, extract, indicator_id, ip_to_int, parse_ip

UTC = timezone.utc
HEADERS = {"User-Agent": config.USER_AGENT, "Accept": "*/*"}


def now():
    return datetime.now(UTC)


# ======================================================================= catalog
def seed_catalog(db):
    ops = []
    for sid, name, home, feed, rel in catalog.NEWS_SOURCES:
        ops.append(_source_op(sid, name, "news", home, feed, rel, "rss", ""))
    for sid, name, home, url, rel, fmt, points, tag, desc in catalog.IOC_FEEDS:
        ops.append(_source_op(sid, name, "ioc-feed", home, url, rel, fmt, desc, points=points, tag=tag))
    for sid, name, kind, home, url, rel, desc in catalog.OTHER_SOURCES:
        ops.append(_source_op(sid, name, kind, home, url, rel, "json" if url.endswith(".json") else "html", desc))
    db.sources.bulk_write(ops, ordered=False)

    aops = []
    for aid, name, typ, origin, motive, aliases in catalog.THREAT_ACTORS:
        aops.append(UpdateOne({"_id": aid}, {"$set": {
            "name": name, "type": typ, "origin": origin, "motivation": motive,
            "aliases": aliases,                          # EMBEDDED: small, bounded, read with the actor
        }, "$setOnInsert": {"created_at": now()}}, upsert=True))
    db.threat_actors.bulk_write(aops, ordered=False)
    return {"sources": len(ops), "actors": len(aops)}


def _source_op(sid, name, kind, home, url, rel, fmt, desc, points=None, tag=None):
    doc = {
        "name": name, "kind": kind, "homepage": home, "description": desc,
        "reliability": rel,
        "reliability_text": catalog.RELIABILITY_TEXT[rel],
        "weight": catalog.RELIABILITY_WEIGHT[rel],
        "feed": {"url": url, "format": fmt},              # EMBEDDED 1:1 config
    }
    if points is not None:
        doc["threat_points"] = points
        doc["tag"] = tag
    return UpdateOne({"_id": sid}, {"$set": doc, "$setOnInsert": {
        "stats": {"items": 0, "last_fetch": None, "last_status": "never", "last_error": None},  # EMBEDDED 1:1
        "created_at": now()}}, upsert=True)


def _mark_source(db, sid, status, items=None, error=None, extra=None):
    upd = {"stats.last_fetch": now(), "stats.last_status": status, "stats.last_error": error}
    if items is not None:
        upd["stats.items"] = items
    if extra:
        upd.update(extra)
    db.sources.update_one({"_id": sid}, {"$set": upd})
    usecases.record_telemetry(db, sid, status, items=items, error=error)   # use case 4: time-series measurement


# ======================================================================= IOC feeds - parsers
def parse_plain_list(text: str):
    """ipset / netset files: one IP or CIDR per line, '#' comments."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line.split()[0])
    return out


def parse_ipsum(text: str, min_hits: int = 2):
    out = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit() and int(parts[1]) >= min_hits:
            out.append((parts[0], int(parts[1])))
    return out


def parse_threatfox(payload):
    out = []
    items = payload.values() if isinstance(payload, dict) else payload
    for group in items:
        for it in (group if isinstance(group, list) else [group]):
            if not isinstance(it, dict):
                continue
            val, typ = str(it.get("ioc_value") or it.get("ioc") or ""), str(it.get("ioc_type") or "")
            kind = None
            if typ == "ip:port":
                val = val.rsplit(":", 1)[0]
                kind = "ip"
            elif typ == "domain":
                kind = "domain"
            elif typ == "url":
                kind = "url"
            elif typ.endswith("_hash"):
                kind = typ.split("_")[0]
            if not kind or not val:
                continue
            out.append({"kind": kind, "value": val.strip(), "confidence": int(it.get("confidence_level") or 50),
                        "detail": {"threat": it.get("threat_type"), "malware": it.get("malware_printable"),
                                   "tags": it.get("tags")}})
    return out


def parse_urlhaus(text: str):
    rows = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    out = []
    for row in csv.reader(io.StringIO("\n".join(rows))):
        if len(row) < 7:
            continue
        url, status, threat, tags = row[2], row[3], row[5], row[6]
        out.append({"kind": "url", "value": url, "confidence": 80 if status == "online" else 60,
                    "detail": {"threat": threat, "status": status, "tags": tags}})
        host = urlparse(url).hostname or ""
        ip = parse_ip(host)
        if ip and ip.is_global:
            out.append({"kind": "ip", "value": str(ip), "confidence": 70,
                        "detail": {"threat": threat, "from_url": url[:200]}})
    return out


def _indicator_doc(kind, value, allow_nonglobal=False):
    """Returns (indicator_id, $setOnInsert fields) or None if invalid."""
    if kind == "ip":
        ip = parse_ip(value)
        if not ip or (not ip.is_global and not allow_nonglobal):
            return None
        t = f"ipv{ip.version}"
        base = {"type": t, "value": str(ip)}
        if ip.version == 4:
            base["ip_int"] = ip_to_int(ip)
        return indicator_id(t, str(ip)), base
    if kind == "cidr":
        try:
            net, start, end = cidr_range(value)
        except ValueError:
            return None
        if net.version != 4 or not net.is_global:   # skip bogon/private ranges that some lists include
            return None
        if net.prefixlen == 32:
            return _indicator_doc("ip", str(net.network_address))
        return indicator_id("cidr", str(net)), {"type": "cidr", "value": str(net), "range_start": start,
                                                "range_end": end, "prefix": net.prefixlen,
                                                "size": end - start + 1}
    if kind in ("domain", "url", "sha256", "sha1", "md5"):
        v = value.strip().lower() if kind != "url" else value.strip()
        return indicator_id(kind, v), {"type": kind, "value": v}
    return None


def _write_feed(db, source_id, tag, records, run_at, chunk=4000, allow_nonglobal=False):
    """records: list of (kind, value, confidence, detail). Upserts indicators + sightings."""
    written = 0
    for i in range(0, len(records), chunk):
        ind_ops, sig_ops = [], []
        for kind, value, conf, detail in records[i:i + chunk]:
            made = _indicator_doc(kind, value, allow_nonglobal)
            if not made:
                continue
            iid, base = made
            ind_ops.append(UpdateOne({"_id": iid}, {
                "$setOnInsert": {**base, "first_seen": run_at},
                "$set": {"last_seen": run_at},
                "$addToSet": {"tags": tag},
            }, upsert=True))
            sig_ops.append(UpdateOne({"_id": f"{iid}|{source_id}"}, {
                "$setOnInsert": {"indicator_id": iid, "source_id": source_id, "first_observed": run_at},
                "$set": {"observed_at": run_at, "confidence": conf, "detail": detail},
            }, upsert=True))
        if ind_ops:
            db.indicators.bulk_write(ind_ops, ordered=False)
            db.sightings.bulk_write(sig_ops, ordered=False)
            written += len(sig_ops)
    # anything this feed no longer lists is removed (the indicator itself stays as history)
    db.sightings.delete_many({"source_id": source_id, "report_id": {"$exists": False},
                              "observed_at": {"$lt": run_at}})
    return written


def import_ioc_feeds(db, only=None, log=print):
    results = []
    with httpx.Client(headers=HEADERS, timeout=config.HTTP_TIMEOUT * 2, follow_redirects=True) as http:
        for sid, name, _home, url, rel, fmt, _pts, tag, _desc in catalog.IOC_FEEDS:
            if only and sid not in only:
                continue
            run_at = now()
            try:
                resp = http.get(url)
                resp.raise_for_status()
                if fmt == "ipsum":
                    recs = [("ip", ip, min(100, 30 + hits * 10), {"hits": hits})
                            for ip, hits in parse_ipsum(resp.text, config.IPSUM_MIN_HITS)]
                elif fmt in ("ipset", "netset"):
                    recs = [("cidr" if "/" in v else "ip", v, 90 if rel == "A" else 75 if rel == "B" else 60, {})
                            for v in parse_plain_list(resp.text)]
                elif fmt == "threatfox":
                    recs = [(r["kind"], r["value"], r["confidence"], r["detail"]) for r in parse_threatfox(resp.json())]
                elif fmt == "urlhaus":
                    recs = [(r["kind"], r["value"], r["confidence"], r["detail"]) for r in parse_urlhaus(resp.text)]
                else:
                    recs = []
                n = _write_feed(db, sid, tag, recs, run_at)
                _mark_source(db, sid, "ok", items=n)
                results.append({"source": sid, "status": "ok", "items": n})
                log(f"  [ok]   {name:<42} {n:>7,} indicators")
            except Exception as exc:  # network errors must never stop the whole import
                msg = f"{type(exc).__name__}: {str(exc)[:160]}"
                _mark_source(db, sid, "error", error=msg)
                results.append({"source": sid, "status": "error", "error": msg})
                log(f"  [skip] {name:<42} {msg[:70]}")
    return results


# ======================================================================= CISA KEV
def import_kev(db, log=print):
    src = next(s for s in catalog.OTHER_SOURCES if s[0] == "cisa-kev")
    try:
        resp = httpx.get(src[4], headers=HEADERS, timeout=config.HTTP_TIMEOUT * 2, follow_redirects=True)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        ops = []
        for v in vulns:
            cve = (v.get("cveID") or "").upper()
            if not cve:
                continue
            ops.append(UpdateOne({"_id": cve}, {"$set": {"kev": {        # EMBEDDED 1:1 sub-document
                "vendor": v.get("vendorProject"), "product": v.get("product"),
                "name": v.get("vulnerabilityName"), "date_added": _date(v.get("dateAdded")),
                "due_date": _date(v.get("dueDate")), "ransomware_use": v.get("knownRansomwareCampaignUse"),
                "description": (v.get("shortDescription") or "")[:600], "cwes": v.get("cwes") or [],
            }}, "$setOnInsert": {"first_seen": now(), "report_count": 0}}, upsert=True))
        for i in range(0, len(ops), 1000):
            db.vulnerabilities.bulk_write(ops[i:i + 1000], ordered=False)
        _mark_source(db, "cisa-kev", "ok", items=len(ops))
        log(f"  [ok]   CISA KEV catalogue                         {len(ops):>7,} CVEs")
        return {"status": "ok", "items": len(ops)}
    except Exception as exc:
        msg = f"{type(exc).__name__}: {str(exc)[:160]}"
        _mark_source(db, "cisa-kev", "error", error=msg)
        log(f"  [skip] CISA KEV catalogue                         {msg[:70]}")
        return {"status": "error", "error": msg}


def _date(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=UTC)
    except (TypeError, ValueError):
        return None


# ======================================================================= news / reports
_GENERIC_ACTOR_WORDS = {"play", "agenda", "medusa", "snake", "reaper", "zinc", "mercury", "interlock", "lynx",
                        "barium", "strontium", "iridium", "holmium", "phosphorus", "thallium", "elbrus",
                        "callisto", "leviathan", "elfin", "world leaks", "safepay", "akira", "the dukes",
                        "clop", "rhysida", "medusalocker", "greenbottle", "hafnium", "ethereal panda"}


def build_actor_matchers(db):
    matchers = []
    for a in db.threat_actors.find({}, {"name": 1, "aliases": 1}):
        pats = []
        for n in [a["name"], *a.get("aliases", [])]:
            esc = re.escape(n)
            if n.lower() in _GENERIC_ACTOR_WORDS or len(n) <= 4:
                pats.append(rf"\b{esc}\s+(?:ransomware|group|gang|operators?|actors?|hackers?|apt)\b")
            else:
                pats.append(rf"(?<![\w-]){esc}(?![\w-])")
        matchers.append((a["_id"], re.compile("|".join(pats), re.IGNORECASE)))
    return matchers


_TRACKING = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "ref", "rss", "_hsenc", "_hsmi"}


def normalize_url(u: str) -> str:
    try:
        p = urlparse(u.strip())
        q = [(k, v) for k, v in parse_qsl(p.query) if k.lower() not in _TRACKING]
        return urlunparse((p.scheme, p.netloc.lower(), p.path, "", urlencode(q), ""))
    except Exception:
        return u.strip()


def _clean(htmltext: str, limit: int) -> str:
    if not htmltext:
        return ""
    txt = BeautifulSoup(htmltext, "html.parser").get_text(" ", strip=True)
    txt = re.sub(r"\s+", " ", html.unescape(txt)).strip()
    txt = re.sub(r"The post .{0,200} appeared first on .{0,80}\.?$", "", txt).strip()
    return txt[:limit]


def parse_feed_entries(content: bytes, limit: int):
    feed = feedparser.parse(content)
    items = []
    for e in feed.entries[:limit]:
        link = e.get("link") or e.get("id") or ""
        title = _clean(e.get("title", ""), 300)
        if not link.startswith("http") or not title:
            continue
        raw = e.get("summary") or ""
        if not raw and e.get("content"):
            raw = e["content"][0].get("value", "")
        t = e.get("published_parsed") or e.get("updated_parsed")
        pub = datetime(*t[:6], tzinfo=UTC) if t else now()
        if pub > now() + timedelta(days=1):
            pub = now()
        items.append({"url": normalize_url(link), "title": title, "summary": _clean(raw, 900),
                      "raw": raw[:6000], "published_at": pub,
                      "authors": [a.get("name") for a in e.get("authors", []) if a.get("name")][:3]})
    return items


def build_report(db, item, source_id, reliability, actor_matchers, kev_cache):
    text = f"{item['title']}. {item['summary']}"
    iocs = extract(text + " " + BeautifulSoup(item.get("raw", ""), "html.parser").get_text(" "), item.get("raw", ""),
                   allow_doc=source_id == "sample-data")
    cves = iocs["cves"]
    kev_hits = [c for c in cves if kev_cache.get(c)]
    actors = [aid for aid, rx in actor_matchers if rx.search(text)]
    ind_ids = ([indicator_id("ipv4" if ":" not in ip else "ipv6", ip) for ip in iocs["ips"]]
               + [indicator_id("domain", d) for d in iocs["domains"]]
               + [indicator_id("url", u) for u in iocs["urls"]]
               + [indicator_id(k, h) for k, h in iocs["hashes"]])
    cls = classify(text, reliability=reliability, ioc_count=len(ind_ids), cve_count=len(cves),
                   kev_count=len(kev_hits), actor_count=len(actors))
    doc = {
        "source_id": source_id,                       # REFERENCE -> sources._id   (many reports : 1 source)
        "url": item["url"],
        "title": item["title"],
        "summary": item["summary"],
        "authors": item.get("authors", []),
        "published_at": item["published_at"],
        "fetched_at": now(),
        "tags": tags_from(cls, ["kev"] if kev_hits else []),   # EMBEDDED array (bounded, small)
        "classification": cls,                        # EMBEDDED sub-document (1:1, always read with report)
        "entities": {"malware": _malware_names(text)},  # EMBEDDED bounded list of names
        "cve_ids": cves,                              # REFERENCE -> vulnerabilities._id  (N:M)
        "actor_ids": actors,                          # REFERENCE -> threat_actors._id    (N:M)
        "indicator_ids": ind_ids[:60],                # REFERENCE -> indicators._id       (N:M)
    }
    return doc, iocs


_MALWARE_RX = re.compile(
    r"\b(Lumma(?:C2| Stealer)?|RedLine|Vidar|Emotet|QakBot|IcedID|Bumblebee|Latrodectus|AsyncRAT|Remcos|"
    r"njRAT|Agent ?Tesla|FormBook|Mirai|Cobalt Strike|Sliver|Pikabot|DarkGate|StealC|Amadey|SmokeLoader|"
    r"XWorm|Atomic Stealer|AMOS|SocGholish|GootLoader|PlugX|ShadowPad|Raspberry Robin|Rhadamanthys)\b", re.I)


def _malware_names(text):
    return sorted({m.group(1) for m in _MALWARE_RX.finditer(text)})[:8]


def _store_reports(db, docs_iocs, source_id):
    """Insert new reports, then link their indicators, sightings and CVEs."""
    if not docs_iocs:
        return 0
    urls = [d["url"] for d, _ in docs_iocs]
    existing = {r["url"] for r in db.reports.find({"url": {"$in": urls}}, {"url": 1})}
    fresh = [(d, i) for d, i in docs_iocs if d["url"] not in existing]
    if not fresh:
        return 0
    seen, uniq = set(), []
    for d, i in fresh:
        if d["url"] not in seen:
            seen.add(d["url"])
            uniq.append((d, i))
    try:
        res = db.reports.insert_many([d for d, _ in uniq], ordered=False)
        inserted = set(res.inserted_ids)
    except BulkWriteError as bwe:  # a parallel run inserted the same URL
        inserted = {d.get("_id") for d, _ in uniq} - {e["op"].get("_id") for e in bwe.details.get("writeErrors", [])}
    ts = now()
    ind_ops, sig_ops, cve_ops = [], [], []
    for d, iocs in uniq:
        if d.get("_id") not in inserted:
            continue
        rid = d["_id"]
        for iid in d["indicator_ids"]:
            kind, value = iid.split(":", 1)
            base = {"type": kind, "value": value}
            if kind == "ipv4":
                base["ip_int"] = ip_to_int(value)
            ind_ops.append(UpdateOne({"_id": iid}, {"$setOnInsert": {**base, "first_seen": ts},
                                                    "$set": {"last_seen": ts}, "$addToSet": {"tags": "reported"}},
                                     upsert=True))
            sig_ops.append(UpdateOne({"_id": f"{iid}|{source_id}|{rid}"}, {"$setOnInsert": {
                "indicator_id": iid, "source_id": source_id, "report_id": rid,   # REFERENCES (fact table)
                "first_observed": ts, "observed_at": d["published_at"], "confidence": 70,
                "detail": {"title": d["title"][:140]}}}, upsert=True))
        for cve in d["cve_ids"]:
            cve_ops.append(UpdateOne({"_id": cve}, {"$setOnInsert": {"first_seen": ts},
                                                    "$set": {"last_seen": ts}, "$inc": {"report_count": 1}},
                                     upsert=True))
    if ind_ops:
        db.indicators.bulk_write(ind_ops, ordered=False)
        db.sightings.bulk_write(sig_ops, ordered=False)
    if cve_ops:
        db.vulnerabilities.bulk_write(cve_ops, ordered=False)
    usecases.bump_buckets(db, [d for d, _ in uniq if d.get("_id") in inserted])   # use case 5: rollup buckets
    return len(inserted)


async def _fetch(client, url):
    r = await client.get(url)
    r.raise_for_status()
    return r


async def ingest_news(db, only=None, limit=None, log=print):
    limit = limit or config.NEWS_ITEMS_PER_FEED
    matchers = build_actor_matchers(db)
    kev_cache = {v["_id"]: True for v in db.vulnerabilities.find({"kev": {"$exists": True}}, {"_id": 1})}
    sources = list(db.sources.find({"kind": "news", **({"_id": {"$in": list(only)}} if only else {})}))
    sem = asyncio.Semaphore(8)
    results = []

    async with httpx.AsyncClient(headers=HEADERS, timeout=config.HTTP_TIMEOUT, follow_redirects=True) as http:
        async def one(src):
            async with sem:
                try:
                    resp = await _fetch(http, src["feed"]["url"])
                    items = parse_feed_entries(resp.content, limit)
                    return src, items, None
                except Exception as exc:
                    return src, [], f"{type(exc).__name__}: {str(exc)[:140]}"

        fetched = await asyncio.gather(*(one(s) for s in sources))

    total_new = 0
    for src, items, err in fetched:
        if err:
            _mark_source(db, src["_id"], "error", error=err)
            results.append({"source": src["_id"], "status": "error", "error": err})
            log(f"  [skip] {src['name']:<42} {err[:70]}")
            continue
        docs = [build_report(db, it, src["_id"], src.get("reliability", "C"), matchers, kev_cache) for it in items]
        new = _store_reports(db, docs, src["_id"])
        total = db.reports.count_documents({"source_id": src["_id"]})
        _mark_source(db, src["_id"], "ok", items=total)
        total_new += new
        results.append({"source": src["_id"], "status": "ok", "fetched": len(items), "new": new})
        log(f"  [ok]   {src['name']:<42} {len(items):>3} items, {new:>3} new")
    return {"new_reports": total_new, "results": results}


# ======================================================================= ctidigest.com (best effort)
_URL_IN_JS = re.compile(r"""["'`]((?:https?:)?//[^"'`\s]+|/[A-Za-z0-9_\-./]+)["'`]""")


async def discover_ctidigest(db, log=print):
    """Reads ctidigest.com's own page + scripts, looking for (a) the RSS feeds it aggregates and
    (b) any JSON it loads (news items / IOC database). Anything found is added to MongoDB."""
    base = "https://ctidigest.com/"
    found = {"feeds_added": 0, "json_endpoints": 0, "reports": 0, "indicators": 0, "status": "ok"}
    try:
        async with httpx.AsyncClient(headers=HEADERS, timeout=config.HTTP_TIMEOUT, follow_redirects=True) as http:
            home = await _fetch(http, base)
            soup = BeautifulSoup(home.text, "html.parser")
            blobs = [home.text]
            for s in soup.find_all("script", src=True)[:8]:
                try:
                    blobs.append((await _fetch(http, urljoin(base, s["src"]))).text)
                except Exception:
                    pass
            cands = set()
            for blob in blobs:
                for m in _URL_IN_JS.finditer(blob):
                    cands.add(urljoin(base, m.group(1)))
            feed_urls = {c for c in cands if re.search(r"(/feed/?$|/rss|\.rss$|atom|\.xml$|feedburner)", c, re.I)
                         and "ctidigest" not in c}
            json_urls = [c for c in cands if urlparse(c).netloc.endswith(("ctidigest.com", "pages.dev"))
                         and re.search(r"(\.json$|/api/|/data/)", c)][:12]

            known = {s["feed"]["url"] for s in db.sources.find({"kind": "news"}, {"feed.url": 1})}
            for fu in sorted(feed_urls - known)[:40]:
                host = urlparse(fu).netloc.replace("www.", "")
                sid = "ctid-" + re.sub(r"[^a-z0-9]+", "-", host.lower()).strip("-")
                db.sources.update_one({"_id": sid}, {"$setOnInsert": {
                    "name": host, "kind": "news", "homepage": f"https://{host}/", "reliability": "C",
                    "reliability_text": catalog.RELIABILITY_TEXT["C"], "weight": catalog.RELIABILITY_WEIGHT["C"],
                    "description": "Feed discovered on ctidigest.com", "discovered_from": "ctidigest",
                    "feed": {"url": fu, "format": "rss"},
                    "stats": {"items": 0, "last_fetch": None, "last_status": "never", "last_error": None},
                    "created_at": now()}}, upsert=True)
                found["feeds_added"] += 1

            matchers = build_actor_matchers(db)
            for ju in json_urls:
                try:
                    data = (await _fetch(http, ju)).json()
                except Exception:
                    continue
                found["json_endpoints"] += 1
                arts, iocs = _walk_json(data)
                if arts:
                    items = [{"url": normalize_url(a.get("link") or a.get("url")), "title": _clean(str(a.get("title")), 300),
                              "summary": _clean(str(a.get("description") or a.get("summary") or ""), 900),
                              "raw": str(a.get("description") or ""),
                              "published_at": _any_date(a.get("pubDate") or a.get("published") or a.get("date")),
                              "authors": []} for a in arts[:500]]
                    docs = [build_report(db, it, "ctidigest", "B", matchers, {}) for it in items if it["title"]]
                    found["reports"] += _store_reports(db, docs, "ctidigest")
                if iocs:
                    recs = []
                    for i in iocs[:20000]:
                        val = str(i.get("indicator") or i.get("ioc") or i.get("value") or "")
                        typ = str(i.get("type") or "").lower()
                        kind = "ip" if "ip" in typ else "domain" if "domain" in typ else "url" if "url" in typ else \
                            "sha256" if "256" in typ else "md5" if "md5" in typ else None
                        if kind and val:
                            recs.append((kind, val, int(i.get("confidence") or 60), {"category": i.get("category")}))
                    found["indicators"] += _write_feed(db, "ctidigest", "ctidigest", recs, now()) if recs else 0
        _mark_source(db, "ctidigest", "ok", items=found["reports"] + found["indicators"],
                     extra={"stats.discovery": found})
    except Exception as exc:
        found["status"] = f"error: {type(exc).__name__}: {str(exc)[:120]}"
        _mark_source(db, "ctidigest", "error", error=found["status"])
    log(f"  [{'ok' if found['status'] == 'ok' else 'skip'}]   ctidigest.com discovery: {found}")
    return found


def _walk_json(data, depth=0):
    arts, iocs = [], []
    if depth > 4:
        return arts, iocs
    if isinstance(data, list) and data and isinstance(data[0], dict):
        keys = set(data[0].keys())
        if "title" in keys and ({"link", "url"} & keys):
            return [d for d in data if isinstance(d, dict)], []
        if {"indicator", "ioc", "value"} & keys and "type" in keys:
            return [], [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        for v in data.values():
            a, i = _walk_json(v, depth + 1)
            arts += a
            iocs += i
    return arts, iocs


def _any_date(v):
    if not v:
        return now()
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%d"):
        try:
            d = datetime.strptime(str(v).replace("Z", "+0000"), fmt)
            return d if d.tzinfo else d.replace(tzinfo=UTC)
        except ValueError:
            continue
    return now()


# ======================================================================= annual security reports
ANNUAL_RX = re.compile(r"^- \[(?P<org>[^\]]+)\]\((?P<site>[^)]*)\) - \[(?P<title>[^\]]+)\]\((?P<path>[^)]*)\) "
                       r"\((?P<year>\d{4})\) - (?P<summary>.+)$")
ANNUAL_BASE = "https://github.com/jacobdjwilson/awesome-annual-security-reports/blob/main/"


def parse_annual_readme(text: str):
    section = category = None
    out = []
    for line in text.splitlines():
        if line.startswith("## "):
            section = line[3:].strip()
        elif line.startswith("### "):
            category = line[4:].strip()
        elif line.startswith("- [") and section in ("Analysis Reports", "Survey Reports"):
            m = ANNUAL_RX.match(line.strip())
            if not m:
                continue
            d = m.groupdict()
            slug = re.sub(r"[^a-z0-9]+", "-", f"{d['org']}-{d['title']}-{d['year']}".lower()).strip("-")
            out.append({"_id": slug, "organization": d["org"], "org_url": d["site"], "title": d["title"],
                        "year": int(d["year"]), "category": category, "report_type": section.split()[0],
                        "pdf_url": urljoin(ANNUAL_BASE, d["path"]), "summary": d["summary"][:1500]})
    return out


def import_annual_reports(db, text=None, log=print):
    src = next(s for s in catalog.OTHER_SOURCES if s[0] == "annual-security-reports")
    try:
        if text is None:
            r = httpx.get(src[4], headers=HEADERS, timeout=config.HTTP_TIMEOUT * 2, follow_redirects=True)
            r.raise_for_status()
            text = r.text
        items = parse_annual_readme(text)
        existing = {d["_id"] for d in db.annual_reports.find({}, {"_id": 1})}
        new = [i for i in items if i["_id"] not in existing]
        ts = now()
        if items:
            db.annual_reports.bulk_write([UpdateOne({"_id": i["_id"]}, {"$set": i, "$setOnInsert": {"first_seen": ts}},
                                                    upsert=True) for i in items], ordered=False)
        _mark_source(db, "annual-security-reports", "ok", items=len(items))
        log(f"  [ok]   Annual security reports list               {len(items):>7,} reports ({len(new)} new)")
        return {"status": "ok", "items": len(items), "new": new}
    except Exception as exc:
        msg = f"{type(exc).__name__}: {str(exc)[:160]}"
        _mark_source(db, "annual-security-reports", "error", error=msg)
        log(f"  [skip] Annual security reports list               {msg[:70]}")
        return {"status": "error", "error": msg, "new": []}


# ======================================================================= offline sample
def load_sample_data(db, log=print):
    path = Path(config.DATA_DIR) / "sample_reports.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    matchers = build_actor_matchers(db)
    base = now()
    items = []
    for n, r in enumerate(data["reports"]):
        items.append({"url": r["url"], "title": r["title"], "summary": r["summary"], "raw": r["summary"],
                      "published_at": base - timedelta(hours=7 * n + 1), "authors": []})
    docs = [build_report(db, it, "sample-data", "F", matchers, {}) for it in items]
    n_rep = _store_reports(db, docs, "sample-data")
    recs = [("ip", i["ip"], i["confidence"], {"note": i["note"]}) for i in data["indicators"]]
    n_ind = _write_feed(db, "sample-data", "demo", recs, now(), allow_nonglobal=True)
    _mark_source(db, "sample-data", "ok", items=n_rep + n_ind)
    log(f"  [ok]   Offline sample data                        {n_rep} reports, {n_ind} demo indicators")
    return {"reports": n_rep, "indicators": n_ind}


def log_run(db, kind, started, payload):
    db.ingest_runs.insert_one({"kind": kind, "started_at": started, "finished_at": now(),
                               "results": payload.get("results", []),    # EMBEDDED bounded (~40 sources)
                               "new_reports": payload.get("new_reports", 0)})
