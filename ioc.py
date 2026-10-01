"""Indicator-of-compromise helpers: refang text, extract IOCs, IP maths."""
import ipaddress
import re

IPV4_RX = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
CVE_RX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
SHA256_RX = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RX = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RX = re.compile(r"\b[a-fA-F0-9]{32}\b")
DEFANGED_DOMAIN_RX = re.compile(r"\b((?:[a-z0-9-]+(?:\[\.\]|\(\.\)|\{\.\}))+[a-z]{2,24})\b", re.IGNORECASE)
DEFANGED_URL_RX = re.compile(r"\bhxxps?\[?:\]?//[^\s\"'<>]+", re.IGNORECASE)


def refang(value: str) -> str:
    v = value.strip()
    v = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]", ".", v, flags=re.IGNORECASE)
    v = re.sub(r"\[:\]", ":", v)
    v = re.sub(r"^hxxp", "http", v, flags=re.IGNORECASE)
    return v


def parse_ip(value: str):
    """Return an ipaddress object or None. Accepts defanged input like 1.2.3[.]4."""
    try:
        return ipaddress.ip_address(refang(value).strip("[] "))
    except ValueError:
        return None


def ip_to_int(ip) -> int:
    return int(ipaddress.IPv4Address(str(ip)))


def cidr_range(cidr: str):
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    return net, int(net.network_address), int(net.broadcast_address)


def describe_non_global(ip) -> str:
    """Human explanation for an address that is not routable on the public internet."""
    if ip.is_loopback:
        return "Loopback address - it always points back to your own computer."
    if ip.is_link_local:
        return "Link-local address - only valid on the local network segment."
    if ip.is_multicast:
        return "Multicast address - used for one-to-many delivery, not a single host."
    if ip.is_unspecified:
        return "Unspecified address (0.0.0.0 / ::) - means 'any' or 'no address'."
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return "Carrier-grade NAT space (RFC 6598) - shared by an ISP, not publicly routable."
    doc_nets = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
    if any(ip.version == n.version and ip in n for n in doc_nets):
        return "Documentation range (TEST-NET) - reserved for examples, never used on the internet."
    if ip.is_private:
        return "Private address (RFC 1918 / ULA) - used inside home and office networks, invisible to the internet."
    if ip.is_reserved:
        return "Reserved address block - not assigned for public use."
    return "Not a globally routable address."


def extract(text: str, raw_text: str = "", allow_doc: bool = False) -> dict:
    """Extract IOCs from report text. Only *defanged* domains/URLs are taken, which avoids
    turning every normal link in an article into an 'indicator'."""
    text = text or ""
    raw = raw_text or text
    ips, cves, hashes, domains, urls = set(), set(), set(), set(), set()
    for m in IPV4_RX.finditer(refang(text)):
        ip = parse_ip(m.group(0))
        if ip and (ip.is_global or (allow_doc and ip.is_private and ip.version == 4 and not ip.is_loopback)):
            ips.add(str(ip))
    for m in CVE_RX.finditer(text):
        cves.add(m.group(0).upper())
    for rx, kind in ((SHA256_RX, "sha256"), (SHA1_RX, "sha1"), (MD5_RX, "md5")):
        for m in rx.finditer(text):
            if not any(m.group(0).lower() in h[1] for h in hashes):
                hashes.add((kind, m.group(0).lower()))
    for m in DEFANGED_DOMAIN_RX.finditer(raw):
        domains.add(refang(m.group(1)).lower())
    for m in DEFANGED_URL_RX.finditer(raw):
        urls.add(refang(m.group(0)))
    return {
        "ips": sorted(ips)[:50],
        "cves": sorted(cves)[:30],
        "hashes": sorted(hashes)[:30],
        "domains": sorted(domains)[:30],
        "urls": sorted(urls)[:20],
    }


def indicator_id(kind: str, value: str) -> str:
    """Natural key used as indicators._id and referenced from sightings/reports."""
    return f"{kind}:{value}"
