"""IP intelligence: give it ANY IP (even one never seen before) and it returns a verdict.

Evidence comes from two places:
  1. Local MongoDB  - 10+ threat feeds imported by setup (sightings), CIDR blocklists (range query),
                      IPs mentioned inside threat reports, earlier lookups.
  2. Live services  - ip-api.com (geo / ASN / proxy / hosting), Shodan InternetDB (open ports, CVEs),
                      GreyNoise Community (scanner or benign service), plus AbuseIPDB / VirusTotal /
                      AlienVault OTX when you add a free API key to .env.

Each piece of evidence adds (or removes) points; the total 0-100 gives the verdict.
Every point is shown in the UI, so the verdict is always explainable.
"""
import asyncio
import socket
import time
from datetime import datetime, timezone

import httpx

from . import config
from .ioc import describe_non_global, indicator_id, parse_ip

UTC = timezone.utc
KNOWN_BENIGN = {
    "8.8.8.8": "Google Public DNS", "8.8.4.4": "Google Public DNS", "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS", "9.9.9.9": "Quad9 DNS", "149.112.112.112": "Quad9 DNS",
    "208.67.222.222": "Cisco OpenDNS", "208.67.220.220": "Cisco OpenDNS",
    "2001:4860:4860::8888": "Google Public DNS", "2606:4700:4700::1111": "Cloudflare DNS",
}
VERDICTS = [(70, "Malicious"), (40, "Suspicious"), (15, "Low risk"), (0, "No known threat")]


def _now():
    return datetime.now(UTC)


# ------------------------------------------------------------------ local evidence (MongoDB)
def local_intel(db, ip) -> dict:
    iid = indicator_id(f"ipv{ip.version}", str(ip))
    indicator = db.indicators.find_one({"_id": iid})
    sightings = list(db.sightings.find({"indicator_id": iid}))
    cidrs = []
    if ip.version == 4:
        n = int(ip)
        cidrs = list(db.indicators.find({"type": "cidr", "range_start": {"$lte": n}, "range_end": {"$gte": n}},
                                        {"value": 1, "prefix": 1}).limit(25))
        if cidrs:
            cid = {c["_id"]: c["value"] for c in cidrs}
            for s in db.sightings.find({"indicator_id": {"$in": list(cid)}}):
                s["via_cidr"] = cid[s["indicator_id"]]
                sightings.append(s)
    src_ids = sorted({s["source_id"] for s in sightings})
    sources = {s["_id"]: s for s in db.sources.find({"_id": {"$in": src_ids}},
                                                   {"name": 1, "reliability": 1, "threat_points": 1, "tag": 1,
                                                    "homepage": 1, "description": 1, "kind": 1})}
    rep_ids = [s["report_id"] for s in sightings if s.get("report_id")]
    reports = list(db.reports.find({"_id": {"$in": rep_ids}},
                                   {"title": 1, "url": 1, "published_at": 1, "source_id": 1,
                                    "classification.category": 1, "classification.severity": 1}).limit(10))
    hist = list(db.lookup_history.find({"ip": str(ip)}, {"at": 1}).sort("at", 1).limit(1))
    times = db.lookup_history.count_documents({"ip": str(ip)})
    return {"indicator": indicator, "sightings": sightings, "sources": sources, "reports": reports,
            "cidrs": cidrs, "times_checked": times, "first_checked": hist[0]["at"] if hist else None}


# ------------------------------------------------------------------ live evidence
async def _timed(name, coro):
    t = time.perf_counter()
    try:
        status, data = await coro
    except httpx.TimeoutException:
        status, data = "error", {"error": "timed out"}
    except Exception as exc:
        status, data = "error", {"error": f"{type(exc).__name__}: {str(exc)[:120]}"}
    return name, {"status": status, "data": data, "ms": round((time.perf_counter() - t) * 1000)}


async def _ipapi(http, ip):
    fields = "status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    r = await http.get(f"http://ip-api.com/json/{ip}", params={"fields": fields})
    j = r.json()
    if j.get("status") != "success":
        return "no-data", {"error": j.get("message")}
    return "ok", j


async def _internetdb(http, ip):
    r = await http.get(f"https://internetdb.shodan.io/{ip}")
    if r.status_code == 404:
        return "no-data", {}
    r.raise_for_status()
    return "ok", r.json()


async def _greynoise(http, ip):
    headers = {"key": config.GREYNOISE_KEY} if config.GREYNOISE_KEY else {}
    r = await http.get(f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
    if r.status_code == 404:
        return "no-data", r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    if r.status_code == 429:
        return "error", {"error": "daily free limit reached (add GREYNOISE_API_KEY to .env)"}
    r.raise_for_status()
    return "ok", r.json()


async def _abuseipdb(http, ip):
    if not config.ABUSEIPDB_KEY:
        return "skipped", {"error": "add ABUSEIPDB_API_KEY to .env to enable"}
    r = await http.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 90},
                       headers={"Key": config.ABUSEIPDB_KEY, "Accept": "application/json"})
    r.raise_for_status()
    return "ok", r.json().get("data", {})


async def _virustotal(http, ip):
    if not config.VIRUSTOTAL_KEY:
        return "skipped", {"error": "add VIRUSTOTAL_API_KEY to .env to enable"}
    r = await http.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                       headers={"x-apikey": config.VIRUSTOTAL_KEY})
    if r.status_code == 404:
        return "no-data", {}
    r.raise_for_status()
    a = r.json().get("data", {}).get("attributes", {})
    return "ok", {"stats": a.get("last_analysis_stats", {}), "reputation": a.get("reputation"),
                  "as_owner": a.get("as_owner"), "country": a.get("country")}


async def _otx(http, ip, version):
    if not config.OTX_KEY:
        return "skipped", {"error": "add OTX_API_KEY to .env to enable"}
    r = await http.get(f"https://otx.alienvault.com/api/v1/indicators/IPv{version}/{ip}/general",
                       headers={"X-OTX-API-KEY": config.OTX_KEY})
    r.raise_for_status()
    p = r.json().get("pulse_info", {})
    return "ok", {"pulses": p.get("count", 0), "names": [x.get("name") for x in p.get("pulses", [])[:5]]}


async def _rdns(ip):
    try:
        host = await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, ip), timeout=2.5)
        return "ok", {"hostname": host[0]}
    except (socket.herror, socket.gaierror, OSError):
        return "no-data", {}


# ------------------------------------------------------------------ scoring
def score(ip_str, local, live):
    factors = []

    def add(points, label, source, detail=""):
        factors.append({"points": int(round(points)), "label": label, "source": source, "detail": detail})

    now = _now()
    feed_sources, report_sightings = {}, []
    for s in local["sightings"]:
        if s.get("report_id"):
            report_sightings.append(s)
            continue
        feed_sources.setdefault(s["source_id"], []).append(s)

    for sid, sights in feed_sources.items():
        src = local["sources"].get(sid, {"name": sid, "threat_points": 20})
        s = max(sights, key=lambda x: x.get("observed_at") or datetime(1970, 1, 1, tzinfo=UTC))
        if sid == "analyst-lookups":
            continue
        obs = s.get("observed_at")
        age_days = (now - obs.replace(tzinfo=UTC)).days if obs else 0
        decay = 0.5 if age_days > 14 else 1.0
        if sid == "ipsum":
            hits = (s.get("detail") or {}).get("hits", 1)
            pts = min(10 + 7 * hits, 50)
            label = f"Listed on {hits} public blacklists (IPsum)"
        elif sid == "sample-data":
            pts, label = s.get("confidence", 60) * 0.8, "Demo indicator (offline sample data)"
        else:
            pts = src.get("threat_points") or 20
            label = f"Listed by {src.get('name', sid)}"
        if s.get("via_cidr"):
            pts *= 0.8
            label += f" - inside blocked network {s['via_cidr']}"
        detail = src.get("description", "")
        if (s.get("detail") or {}).get("malware"):
            detail = f"Malware: {s['detail']['malware']} - {detail}"
        if decay < 1:
            detail += f" (listing is {age_days} days old, weight halved)"
        add(pts * decay, label, src.get("name", sid), detail)

    if report_sightings:
        n = len({s["report_id"] for s in report_sightings})
        add(min(20 + 5 * (n - 1), 30), f"Named as an indicator in {n} threat report(s)", "CTI reports",
            "; ".join(r["title"][:80] for r in local["reports"][:3]))

    gn = live.get("greynoise", {})
    if gn.get("status") == "ok":
        d = gn["data"]
        cls = d.get("classification")
        if d.get("riot") or cls == "benign":
            add(-40, f"GreyNoise: known benign service ({d.get('name') or 'business service'})", "GreyNoise",
                "Common business service or benign scanner - traffic from it is usually expected")
        elif cls == "malicious":
            add(35, "GreyNoise: observed attacking the internet (malicious)", "GreyNoise",
                f"Last seen {d.get('last_seen', '?')}")
        elif d.get("noise"):
            add(10, "GreyNoise: mass internet scanner", "GreyNoise", f"Last seen {d.get('last_seen', '?')}")

    ab = live.get("abuseipdb", {})
    if ab.get("status") == "ok":
        c = ab["data"].get("abuseConfidenceScore", 0) or 0
        if c:
            add(min(c * 0.5, 50), f"AbuseIPDB confidence {c}% ({ab['data'].get('totalReports', 0)} reports)", "AbuseIPDB")
        if ab["data"].get("isWhitelisted"):
            add(-30, "AbuseIPDB: whitelisted", "AbuseIPDB")

    vt = live.get("virustotal", {})
    if vt.get("status") == "ok":
        m = vt["data"].get("stats", {}).get("malicious", 0) or 0
        if m:
            add(min(10 * m, 50), f"VirusTotal: {m} security vendors flag it malicious", "VirusTotal")

    otx = live.get("otx", {})
    if otx.get("status") == "ok" and otx["data"].get("pulses"):
        p = otx["data"]["pulses"]
        add(min(5 * p, 25), f"AlienVault OTX: in {p} threat pulse(s)", "AlienVault OTX",
            "; ".join(n for n in otx["data"].get("names", []) if n))

    idb = live.get("internetdb", {})
    if idb.get("status") == "ok":
        d = idb["data"]
        vulns, tags = d.get("vulns", []) or [], set(d.get("tags", []) or [])
        if vulns:
            add(min(3 * len(vulns), 15), f"Exposes {len(vulns)} known-vulnerable service(s)", "Shodan InternetDB",
                "Risky and easy to hijack, but not proof of malicious activity: " + ", ".join(vulns[:6]))
        if tags & {"c2", "malware", "compromised"}:
            add(35, f"Shodan tags: {', '.join(sorted(tags & {'c2', 'malware', 'compromised'}))}", "Shodan InternetDB")
        if "honeypot" in tags:
            add(-10, "Shodan: looks like a honeypot", "Shodan InternetDB")

    geo = live.get("ipapi", {})
    if geo.get("status") == "ok":
        d = geo["data"]
        if d.get("proxy"):
            add(10, "Proxy / VPN / Tor exit (ip-api)", "ip-api.com", "Hides the real origin of traffic")
        if d.get("hosting"):
            add(5, "Hosted in a data centre", "ip-api.com",
                "Servers in data centres are where most scanners and C2 servers live; homes are not")

    if ip_str in KNOWN_BENIGN:
        add(-40, f"Known public infrastructure: {KNOWN_BENIGN[ip_str]}", "Built-in allow list")

    total = max(0, min(100, sum(f["points"] for f in factors)))
    verdict = next(label for limit, label in VERDICTS if total >= limit)
    answered = sum(1 for v in live.values() if v["status"] in ("ok", "no-data")) + 1  # +1 = local DB
    if not local["sightings"] and answered <= 1 and total == 0:
        verdict = "Unknown"
    factors.sort(key=lambda f: -abs(f["points"]))
    return total, verdict, factors


def _summary(verdict, score_, factors, local):
    pos = [f for f in factors if f["points"] > 0]
    feeds = [f for f in pos if f["label"].startswith("Listed")]
    if verdict == "Malicious":
        lead = f"High-confidence threat: {len(feeds)} threat feed(s) list this IP" if feeds else "High-confidence threat"
    elif verdict == "Suspicious":
        lead = "Suspicious - some evidence of malicious activity"
    elif verdict == "Low risk":
        lead = "Low risk - weak or indirect signals only"
    elif verdict == "Unknown":
        return "No intelligence source could be reached; check your internet connection and try again."
    else:
        lead = "No known threat - none of the checked sources report malicious activity"
    top = [f["label"] for f in pos[:2]]
    return lead + (". Strongest evidence: " + "; ".join(top) + "." if top else ".")


# ------------------------------------------------------------------ public entry point
def _clean_sightings(local):
    out = []
    for s in local["sightings"]:
        src = local["sources"].get(s["source_id"], {})
        out.append({"source_id": s["source_id"], "source": src.get("name", s["source_id"]),
                    "reliability": src.get("reliability"), "observed_at": s.get("observed_at"),
                    "first_observed": s.get("first_observed"), "confidence": s.get("confidence"),
                    "via_cidr": s.get("via_cidr"), "report_id": str(s["report_id"]) if s.get("report_id") else None,
                    "detail": s.get("detail")})
    return out


async def lookup(db, raw: str, refresh: bool = False) -> dict:
    t0 = time.perf_counter()
    ip = parse_ip(raw or "")
    if not ip:
        raise ValueError("That is not a valid IPv4 or IPv6 address.")
    ip_str = str(ip)

    if not refresh:
        cached = await asyncio.to_thread(db.ip_lookups.find_one, {"_id": ip_str})
        if cached:
            res = cached["result"]
            res["cached"] = True
            res["took_ms"] = round((time.perf_counter() - t0) * 1000)
            await asyncio.to_thread(_record_history, db, res)
            return res

    local = await asyncio.to_thread(local_intel, db, ip)
    if not ip.is_global:  # bogon lists contain private ranges; they say nothing about a private host
        local["sightings"] = [s for s in local["sightings"] if not s.get("via_cidr")]
        local["cidrs"] = []

    live = {}
    note = None
    if ip.is_global:
        async with httpx.AsyncClient(timeout=6.0, headers={"User-Agent": config.USER_AGENT},
                                     follow_redirects=True) as http:
            jobs = [
                _timed("ipapi", _ipapi(http, ip_str)),
                _timed("internetdb", _internetdb(http, ip_str)),
                _timed("greynoise", _greynoise(http, ip_str)) if ip.version == 4 else _timed("greynoise", _skip("IPv4 only")),
                _timed("abuseipdb", _abuseipdb(http, ip_str)),
                _timed("virustotal", _virustotal(http, ip_str)),
                _timed("otx", _otx(http, ip_str, ip.version)),
                _timed("rdns", _rdns(ip_str)),
            ]
            live = dict(await asyncio.gather(*jobs))
    else:
        note = describe_non_global(ip)

    total, verdict, factors = score(ip_str, local, live)
    if not ip.is_global and not local["sightings"]:
        verdict = "Private / reserved"

    geo = live.get("ipapi", {}).get("data", {}) if live.get("ipapi", {}).get("status") == "ok" else {}
    idb = live.get("internetdb", {}).get("data", {}) if live.get("internetdb", {}).get("status") == "ok" else {}
    gn = live.get("greynoise", {}).get("data", {}) if live.get("greynoise", {}).get("status") in ("ok", "no-data") else {}
    ind = local["indicator"] or {}

    checks = [{"source": "Local threat database", "status": "hit" if local["sightings"] else "clean",
               "detail": f"{len({s['source_id'] for s in local['sightings']})} source(s), "
                         f"{len(local['cidrs'])} blocked network(s)", "ms": None}]
    names = {"ipapi": "ip-api.com geolocation", "internetdb": "Shodan InternetDB", "greynoise": "GreyNoise Community",
             "abuseipdb": "AbuseIPDB", "virustotal": "VirusTotal", "otx": "AlienVault OTX", "rdns": "Reverse DNS"}
    for key, label in names.items():
        if key in live:
            v = live[key]
            checks.append({"source": label, "status": v["status"], "ms": v["ms"],
                           "detail": (v["data"] or {}).get("error") or (v["data"] or {}).get("message") or ""})

    result = {
        "ip": ip_str, "version": ip.version, "is_global": ip.is_global, "range_note": note,
        "verdict": verdict, "score": total, "summary": _summary(verdict, total, factors, local) if not note or local["sightings"] else note,
        "factors": factors, "checks": checks,
        "geo": {k: geo.get(k) for k in ("country", "countryCode", "regionName", "city", "lat", "lon", "timezone",
                                         "isp", "org", "as", "asname", "mobile", "proxy", "hosting")} if geo else None,
        "hostname": live.get("rdns", {}).get("data", {}).get("hostname") or geo.get("reverse") or None,
        "network": {"ports": idb.get("ports", []), "hostnames": idb.get("hostnames", []), "cpes": idb.get("cpes", []),
                    "vulns": idb.get("vulns", []), "tags": idb.get("tags", [])} if idb else None,
        "greynoise": {k: gn.get(k) for k in ("noise", "riot", "classification", "name", "last_seen", "link")} if gn else None,
        "abuseipdb": live.get("abuseipdb", {}).get("data") if live.get("abuseipdb", {}).get("status") == "ok" else None,
        "virustotal": live.get("virustotal", {}).get("data") if live.get("virustotal", {}).get("status") == "ok" else None,
        "local": {
            "sightings": _clean_sightings(local),
            "cidrs": [c["value"] for c in local["cidrs"]],
            "reports": [{"id": str(r["_id"]), "title": r["title"], "url": r.get("url"),
                         "published_at": r.get("published_at"), "source_id": r.get("source_id"),
                         "category": r.get("classification", {}).get("category"),
                         "severity": r.get("classification", {}).get("severity")} for r in local["reports"]],
            "first_seen": ind.get("first_seen"), "last_seen": ind.get("last_seen"), "tags": ind.get("tags", []),
        },
        "history": {"times_checked": local["times_checked"] + 1, "first_checked": local["first_checked"]},
        "looked_up_at": _now(), "cached": False,
    }
    result["took_ms"] = round((time.perf_counter() - t0) * 1000)
    await asyncio.to_thread(_persist, db, result)
    return result


async def _skip(reason):
    return "skipped", {"error": reason}


def _record_history(db, res):
    db.lookup_history.insert_one({"ip": res["ip"], "at": _now(), "verdict": res["verdict"], "score": res["score"],
                                  "country": (res.get("geo") or {}).get("countryCode"),
                                  "analyst_id": "default"})   # REFERENCE -> analysts._id (use case 3)


def _persist(db, result):
    db.ip_lookups.replace_one({"_id": result["ip"]}, {"_id": result["ip"], "result": result, "created_at": _now()},
                              upsert=True)
    _record_history(db, result)
    # the platform learns: an IP it judged malicious becomes a local indicator (never used for its own score)
    if result["score"] >= 70 and result["is_global"]:
        iid = indicator_id(f"ipv{result['version']}", result["ip"])
        base = {"type": f"ipv{result['version']}", "value": result["ip"]}
        if result["version"] == 4:
            base["ip_int"] = int(parse_ip(result["ip"]))
        ts = _now()
        db.indicators.update_one({"_id": iid}, {"$setOnInsert": {**base, "first_seen": ts},
                                                "$set": {"last_seen": ts}, "$addToSet": {"tags": "analyst-flagged"}},
                                 upsert=True)
        db.sightings.update_one({"_id": f"{iid}|analyst-lookups"}, {
            "$setOnInsert": {"indicator_id": iid, "source_id": "analyst-lookups", "first_observed": ts},
            "$set": {"observed_at": ts, "confidence": result["score"], "detail": {"verdict": result["verdict"]}}},
            upsert=True)


def recent_lookups(db, limit=12):
    pipe = [{"$sort": {"at": -1}}, {"$limit": 400},
            {"$group": {"_id": "$ip", "at": {"$first": "$at"}, "verdict": {"$first": "$verdict"},
                        "score": {"$first": "$score"}, "country": {"$first": "$country"}, "times": {"$sum": 1}}},
            {"$sort": {"at": -1}}, {"$limit": limit}]
    return [{"ip": d["_id"], **{k: d[k] for k in ("at", "verdict", "score", "country", "times")}}
            for d in db.lookup_history.aggregate(pipe)]
