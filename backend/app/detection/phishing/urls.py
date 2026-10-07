"""URL extraction and static analysis. No DNS lookups and no requests are ever made here."""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from app.detection.phishing.brands import BRAND_DOMAINS, SECOND_LEVEL_SUFFIXES

MAX_LINKS = 200
_URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'\])]+)""")
_TEXT_DOMAIN_RE = re.compile(r"(?i)(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})")
_NUMERIC_HOST_RE = re.compile(r"(?i)(0x[0-9a-f]+|\d+)")


@dataclass
class Link:
    url: str
    scheme: str
    host: str
    domain: str
    has_userinfo: bool
    text: str | None = None


def is_ip_host(host: str) -> bool:
    if _NUMERIC_HOST_RE.fullmatch(host):  # decimal/hex-encoded IPv4 such as 3232235777
        return True
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registered_domain(host: str) -> str:
    """Approximate registrable domain without a public-suffix list (see SECOND_LEVEL_SUFFIXES)."""
    host = host.lower().rstrip(".")
    if is_ip_host(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def defang(url: str) -> str:
    """Make a URL inert in output (evidence strings) so it cannot be clicked by accident."""
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def _make_link(url: str, text: str | None) -> Link | None:
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return None
    if not host or parts.scheme.lower() not in {"http", "https"}:
        return None
    host = host.lower().rstrip(".")
    return Link(
        url=url[:500],
        scheme=parts.scheme.lower(),
        host=host,
        domain=registered_domain(host),
        has_userinfo="@" in parts.netloc,
        text=text,
    )


def extract_links(text: str, html: str | None) -> list[Link]:
    links: dict[str, Link] = {}
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = str(a["href"]).strip()
            if href.lower().startswith(("http://", "https://")):
                link = _make_link(href, a.get_text(" ", strip=True)[:200] or None)
                if link:
                    links.setdefault(link.url, link)
    for match in _URL_RE.findall(text):
        url = match.rstrip(".,;:!?)")
        if url.lower().startswith("www."):
            url = "http://" + url
        link = _make_link(url, None)
        if link:
            links.setdefault(link.url, link)
    return list(links.values())[:MAX_LINKS]


def brand_lookalike(link: Link) -> str | None:
    """A known brand name appears as a whole token in the host but the domain isn't the brand's."""
    tokens = set(re.split(r"[-_.]", link.host))
    for brand, legit in BRAND_DOMAINS.items():
        if brand in tokens and link.domain not in legit:
            return brand
    return None


def text_domain_mismatch(link: Link) -> str | None:
    """Anchor text shows one domain while the href points to another."""
    if not link.text:
        return None
    m = _TEXT_DOMAIN_RE.search(link.text)
    if m and registered_domain(m.group(1)) != link.domain:
        return m.group(1).lower()
    return None
