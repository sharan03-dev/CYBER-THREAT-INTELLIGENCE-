"""Explainable threat classification.

Every report (or any pasted text) gets:
  * category      - the main threat type, plus a score for every other category
  * severity      - Critical / High / Medium / Low, from concrete signals
  * verdict       - "Actual threat" / "Potential threat" / "Informational"
  * admiralty     - reliability letter of the source + credibility digit (e.g. "B2")
  * signals       - the exact words/phrases that produced the result (so it can be explained)

Rule-based on purpose: every decision can be traced to a matched phrase, which is what an
analyst (and an examiner) needs. No training data or GPU required.
"""
import re

from .catalog import RELIABILITY_WEIGHT

_F = re.IGNORECASE

CATEGORY_RULES = {
    "Ransomware": [
        (r"\bransomware\b", 4), (r"\bransom\s+(?:note|demand|payment)s?\b", 2),
        (r"\b(?:lockbit|alphv|blackcat|akira|qilin|cl0p|black\s?basta|rhysida|ransomhub|bianlian|8base|"
         r"conti|hunters\s+international|inc\s+ransom|dragonforce|safepay|interlock|medusa\s+ransomware|"
         r"play\s+ransomware|gunra|warlock|sinobi|kawa4096)\b", 3),
        (r"\bdouble[-\s]extortion\b", 3), (r"\bRaaS\b", 3), (r"\bextort(?:ion|ed|s)?\b", 2),
        (r"\bencrypt(?:ed|s|ing)?\s+(?:files|systems|servers|data|devices)\b", 2),
        (r"\b(?:data\s+)?leak\s+site\b", 2),
    ],
    "Nation-state / APT": [
        (r"\bAPT\s?-?\d{1,3}\b", 4), (r"\bstate[-\s](?:sponsored|backed|linked|aligned)\b", 4),
        (r"\bnation[-\s]state\b", 4), (r"\b(?:cyber[-\s]?)?espionage\b", 3),
        (r"\b(?:lazarus|kimsuky|andariel|scarcruft|volt\s+typhoon|salt\s+typhoon|flax\s+typhoon|silk\s+typhoon|"
         r"mustang\s+panda|sandworm|fancy\s+bear|cozy\s+bear|turla|gamaredon|muddywater|charming\s+kitten|"
         r"oilrig|midnight\s+blizzard|forest\s+blizzard|star\s+blizzard|seashell\s+blizzard|apt41|winnti|"
         r"transparent\s+tribe|sidewinder|unc\d{3,4}|\w+\s+(?:typhoon|blizzard|sandstorm|sleet))\b", 3),
        (r"\b(?:chinese|russian|north\s+korean|iranian|pakistani|belarusian)\b[^.]{0,40}"
         r"\b(?:hackers?|actors?|group|apt|operatives|spies)\b", 3),
        (r"\bthreat\s+actors?\b", 1), (r"\bcyber\s?war(?:fare)?\b", 2),
    ],
    "Phishing & social engineering": [
        (r"\bphish(?:ing|ers?|ed)?\b", 4), (r"\bspear[-\s]?phishing\b", 3),
        (r"\b(?:smishing|vishing|quishing)\b", 3), (r"\bbusiness\s+email\s+compromise\b|\bBEC\b", 3),
        (r"\bcredential\s+(?:harvesting|theft|phishing|stealing)\b", 3), (r"\bsocial\s+engineering\b", 3),
        (r"\b(?:fake|spoofed|lookalike|malicious)\s+(?:login|websites?|sites?|pages?|domains?|emails?|captcha)\b", 2),
        (r"\blures?\b", 1), (r"\bClickFix\b|\bFileFix\b", 3),
        (r"\bAitM\b|\badversary[-\s]in[-\s]the[-\s]middle\b", 3), (r"\bMFA\s+(?:fatigue|bombing|bypass)\b", 2),
        (r"\bscam(?:s|mers)?\b", 2),
    ],
    "Vulnerability & exploit": [
        (r"\bCVE-\d{4}-\d{4,7}\b", 3), (r"\bzero[-\s]?days?\b|\b0-?days?\b", 4),
        (r"\bexploit(?:ed|s|ation|ing)?\b", 3), (r"\bvulnerabilit(?:y|ies)\b", 2),
        (r"\bremote\s+code\s+execution\b|\bRCE\b", 3), (r"\bprivilege\s+escalation\b", 2),
        (r"\bflaws?\b|\bbugs?\b", 2), (r"\bKEV\b|\bknown\s+exploited\b", 3),
        (r"\bproof[-\s]of[-\s]concept\b|\bPoC\b", 2), (r"\bauthentication\s+bypass\b", 3),
        (r"\b(?:SQL|command|code|prompt)\s+injection\b", 2), (r"\bpatch(?:es|ed)?\b|\bsecurity\s+updates?\b", 1),
    ],
    "Malware & botnets": [
        (r"\bmalware\b", 3), (r"\b(?:info)?stealers?\b", 3), (r"\btrojan(?:s|ized)?\b", 3),
        (r"\bbotnets?\b", 3), (r"\bbackdoor(?:s|ed)?\b", 3), (r"\bremote\s+access\s+trojan\b|\bRATs?\b", 3),
        (r"\b(?:spyware|rootkit|wiper|worm|dropper|keylogger|cryptominer|cryptojacking|loader)s?\b", 3),
        (r"\b(?:lumma|redline|vidar|raccoon|emotet|qakbot|qbot|icedid|bumblebee|latrodectus|asyncrat|remcos|"
         r"njrat|agent\s?tesla|formbook|mirai|cobalt\s+strike|sliver|pikabot|darkgate|stealc|amadey|"
         r"smokeloader|xworm|atomic\s+stealer|amos|socgholish|gootloader)\b", 3),
        (r"\bcommand[-\s]and[-\s]control\b|\bC2\b|\bC&C\b", 2),
        (r"\bbrute[-\s]?forc\w*\b", 3), (r"\bcompromised\s+(?:hosts?|servers?|devices?|routers?|accounts?)\b", 2),
    ],
    "Data breach & leak": [
        (r"\bdata\s+breach(?:es)?\b", 4), (r"\bbreach(?:ed|es)?\b", 3), (r"\bleak(?:ed|s)?\b", 2),
        (r"\bexposed\b[^.]{0,40}\b(?:data|records|database|information|credentials|details)\b", 3),
        (r"\b(?:stolen|exfiltrated|leaked)\s+(?:data|records|files|credentials|information)\b", 3),
        (r"\b\d[\d,.]*\s*(?:million|billion|k)?\s+(?:customers|users|records|accounts|patients|people|individuals)\b", 2),
        (r"\bdata\s+(?:theft|exposure|leak)\b", 3), (r"\bhacked\b", 2), (r"\bcyber\s?attack\b", 1),
    ],
    "Supply chain": [
        (r"\bsupply[-\s]chain\b", 4),
        (r"\b(?:npm|PyPI|RubyGems|NuGet|crates\.io|Maven|Open\s?VSX|Docker\s+Hub|VS\s?Code\s+extensions?)\b", 2),
        (r"\bmalicious\s+(?:packages?|librar(?:y|ies)|extensions?|dependenc(?:y|ies)|updates?|plugins?)\b", 4),
        (r"\btyposquat(?:ting|ted|s)?\b", 3), (r"\bthird[-\s]party\b", 1),
        (r"\bcompromised\s+(?:update|package|build|repository|repo|pipeline|library|vendor)\b", 3),
        (r"\bGitHub\s+Actions?\b", 2), (r"\bdependency\s+confusion\b", 3),
    ],
    "DDoS": [
        (r"\bDDoS\b|\bdistributed\s+denial[-\s]of[-\s]service\b", 5), (r"\bdenial[-\s]of[-\s]service\b", 3),
        (r"\b\d+(?:\.\d+)?\s*(?:Tbps|Gbps|Mpps|Bpps)\b", 3), (r"\bamplification\b", 2),
    ],
    "Cloud & identity": [
        (r"\b(?:AWS|Azure|Entra\s+ID|Google\s+Cloud|GCP|Microsoft\s+365|M365|Okta|Salesforce|Snowflake|SaaS|"
         r"Kubernetes|S3\s+buckets?)\b", 2),
        (r"\bOAuth\b", 2), (r"\b(?:token|session|cookie)\s+(?:theft|hijacking|stealing)\b", 3),
        (r"\bmisconfigur(?:ed|ation|ations)\b", 3), (r"\bidentity\b", 1),
        (r"\bSSO\b|\bsingle\s+sign[-\s]on\b", 2), (r"\bcloud\b", 1), (r"\b(?:access|API)\s+keys?\b", 2),
    ],
    "Mobile": [
        (r"\bAndroid\b", 3), (r"\biOS\b|\biPhones?\b", 3),
        (r"\bmobile\s+(?:malware|apps?|devices?|banking)\b", 3), (r"\bAPKs?\b", 3),
        (r"\bGoogle\s+Play\b", 2), (r"\bbanking\s+trojan\b", 2),
    ],
    "AI & emerging tech": [
        (r"\b(?:AI|artificial\s+intelligence|LLMs?|large\s+language\s+models?|GenAI|generative\s+AI|agentic|AI\s+agents?)\b", 2),
        (r"\bdeepfakes?\b", 4), (r"\bprompt\s+injection\b", 4),
        (r"\b(?:ChatGPT|Gemini|Claude|Copilot|OpenAI|MCP\s+servers?)\b", 2), (r"\bjailbreak(?:s|ing)?\b", 2),
        (r"\bquantum\b", 2),
    ],
    "Policy & law enforcement": [
        (r"\b(?:arrest(?:ed|s)?|extradit(?:ed|ion)|indict(?:ed|ment)|sentenced|charged|pleads?\s+guilty)\b", 3),
        (r"\b(?:Europol|FBI|Interpol|Department\s+of\s+Justice|DoJ|law\s+enforcement|police)\b", 2),
        (r"\btake\s?down\b|\bseized\b|\bdismantled\b|\bdisrupt(?:ed|s)\b", 3),
        (r"\b(?:sanction(?:s|ed)|regulations?|legislation|GDPR|NIS2|compliance|fined)\b", 2),
        (r"\b(?:guidance|framework|best\s+practices|webinar|podcast|survey|report\s+finds)\b", 1),
    ],
}

ACTIONABLE = {
    "Ransomware", "Nation-state / APT", "Phishing & social engineering", "Vulnerability & exploit",
    "Malware & botnets", "Data breach & leak", "Supply chain", "DDoS", "Cloud & identity", "Mobile",
}
ALL_CATEGORIES = list(CATEGORY_RULES) + ["General security"]

SEVERITY_RULES = [
    (r"\bactively\s+exploited\b|\bexploited\s+in\s+the\s+wild\b|\bunder\s+(?:active\s+)?(?:exploitation|attack)\b|\bin[-\s]the[-\s]wild\b", 4, "exploited in the wild"),
    (r"\bzero[-\s]?days?\b|\b0-?days?\b", 4, "zero-day"),
    (r"\bKEV\b|\bknown\s+exploited\s+vulnerabilit", 3, "listed in CISA KEV"),
    (r"\bCVSS[^.]{0,20}\b(?:9\.\d|10(?:\.0)?)\b|\bcritical\b[^.]{0,40}\b(?:flaw|vulnerabilit|bug|RCE|severity)", 3, "critical severity"),
    (r"\bremote\s+code\s+execution\b|\bRCE\b", 2, "remote code execution"),
    (r"\bransomware\b|\bwiper\b", 3, "ransomware / destructive malware"),
    (r"\bDDoS\b|\bdenial[-\s]of[-\s]service\b|\b\d+(?:\.\d+)?\s*Tbps\b", 2, "large DDoS"),
    (r"\bMFA\s+bypass|\bbypass(?:es|ing)?\s+MFA\b|\bsession\s+(?:cookies?|tokens?)\b|\bcredentials?\b", 1, "credential theft"),
    (r"\bnation[-\s]state\b|\bstate[-\s]sponsored\b|\bAPT\s?\d", 2, "nation-state actor"),
    (r"\b\d[\d,.]*\s*(?:million|billion)\b", 2, "large scale (millions)"),
    (r"\bmalicious\s+(?:packages?|updates?)\b|\bsupply[-\s]chain\s+attack\b", 2, "supply-chain compromise"),
    (r"\b(?:hospitals?|healthcare|energy|water|pipeline|power\s+grid|critical\s+infrastructure|telecom)\b", 1, "critical sector"),
    (r"\b(?:patch\s+now|urgent(?:ly)?|emergency)\b", 1, "urgent patching"),
    (r"\bmalware\b|\bphishing\b|\bbotnet\b|\bbackdoor\b|\btrojan\b|\bstealer\b|\bbrute[-\s]?force\b", 2, "active campaign"),
]

_compiled = {c: [(re.compile(p, _F), w) for p, w in rules] for c, rules in CATEGORY_RULES.items()}
_sev_compiled = [(re.compile(p, _F), w, label) for p, w, label in SEVERITY_RULES]


def _severity_label(points: int) -> str:
    if points >= 8:
        return "Critical"
    if points >= 4:
        return "High"
    if points >= 2:
        return "Medium"
    return "Low"


def classify(text: str, *, reliability: str = "C", ioc_count: int = 0, cve_count: int = 0,
             kev_count: int = 0, actor_count: int = 0) -> dict:
    text = text or ""
    scores, signals = {}, []
    for cat, rules in _compiled.items():
        total = 0
        for rx, weight in rules:
            m = rx.search(text)
            if m:
                total += weight
                signals.append({"category": cat, "match": m.group(0)[:60], "weight": weight})
        if total:
            scores[cat] = total

    if scores:
        # prefer actionable categories when scores tie (a breach article that mentions police is a breach)
        primary = max(scores, key=lambda c: (scores[c], c in ACTIONABLE))
    else:
        primary = "General security"
    total_score = sum(scores.values()) or 1
    categories = sorted(
        ({"name": c, "score": s, "share": round(s / total_score, 3)} for c, s in scores.items()),
        key=lambda x: -x["score"],
    )

    # severity
    sev_points, sev_signals = 0, []
    for rx, weight, label in _sev_compiled:
        if rx.search(text):
            sev_points += weight
            sev_signals.append(label)
    if kev_count:
        sev_points += 3
        sev_signals.append(f"{kev_count} CVE(s) in CISA KEV")
    if primary not in ACTIONABLE:
        sev_points -= 2
    severity = _severity_label(sev_points)

    # "is this an actual threat?" - evidence x source reliability
    actionable_score = sum(s for c, s in scores.items() if c in ACTIONABLE)
    strength = min(1.0, actionable_score / 7.0)
    evidence = 0.0
    evidence += 0.15 if ioc_count else 0
    evidence += 0.10 if cve_count else 0
    evidence += 0.20 if kev_count else 0
    evidence += 0.10 if actor_count else 0
    evidence += {"Critical": 0.15, "High": 0.10}.get(severity, 0)
    rel_w = RELIABILITY_WEIGHT.get(reliability, 0.5)
    confidence = round(min(1.0, strength * 0.7 + evidence) * (0.55 + 0.45 * rel_w), 3)
    if primary in ACTIONABLE and confidence >= 0.50:
        verdict = "Actual threat"
    elif actionable_score and confidence >= 0.28:
        verdict = "Potential threat"
    else:
        verdict = "Informational"

    # Admiralty credibility digit: 1 confirmed ... 6 cannot be judged
    if kev_count:
        credibility = 1
    elif ioc_count or cve_count:
        credibility = 2
    elif actionable_score >= 4:
        credibility = 3
    elif actionable_score:
        credibility = 4
    else:
        credibility = 6

    return {
        "category": primary,
        "categories": categories[:6],
        "severity": severity,
        "severity_points": sev_points,
        "severity_signals": sev_signals,
        "verdict": verdict,
        "confidence": confidence,
        "actionable": primary in ACTIONABLE,
        "admiralty": f"{reliability}{credibility}",
        "signals": signals[:14],
        "model": "cti-rules-v2",
    }


def tags_from(classification: dict, extra=None) -> list:
    tags = {c["name"].split(" ")[0].lower().strip("&/") for c in classification.get("categories", [])[:3]}
    for s in classification.get("severity_signals", []):
        if s in ("zero-day", "exploited in the wild", "remote code execution", "supply-chain compromise"):
            tags.add(s.replace(" ", "-"))
    for t in extra or []:
        tags.add(t.lower())
    return sorted(t for t in tags if t)[:10]
