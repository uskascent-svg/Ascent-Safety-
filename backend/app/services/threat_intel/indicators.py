"""Validate and normalise indicators BEFORE anything is sent to a third party."""

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

TYPES = ("ip", "domain", "url", "hash")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_INTERNAL_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".localhost",
    ".home.arpa",
    ".corp",
    ".intranet",
)


class IndicatorError(ValueError):
    pass


def _ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        raise IndicatorError("Not a valid IP address") from None
    if not ip.is_global:
        raise IndicatorError(
            "Private, loopback and reserved addresses are never sent to external services"
        )
    return str(ip)


def _domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(domain) or domain.endswith(_INTERNAL_SUFFIXES):
        raise IndicatorError("Not a valid public domain name")
    return domain


def _url(value: str) -> str:
    value = value.strip()
    if len(value) > 2000:
        raise IndicatorError("URL is too long")
    try:
        parts = urlsplit(value)
        host = parts.hostname
    except ValueError:
        raise IndicatorError("Not a valid URL") from None
    if parts.scheme.lower() not in {"http", "https"} or not host:
        raise IndicatorError("Only http(s) URLs with a host are supported")
    try:
        _ip(host)
    except IndicatorError:
        _domain(host)  # raises if it is neither a public IP nor a public domain
    return urlunsplit(parts._replace(fragment=""))  # fragments never reach servers


def _hash(value: str) -> str:
    value = value.strip().lower()
    if not re.fullmatch(r"[a-f0-9]{64}", value):
        raise IndicatorError("Only SHA-256 file hashes (64 hex characters) are supported")
    return value


def normalize(indicator: str, indicator_type: str) -> str:
    if indicator_type == "ip":
        return _ip(indicator)
    if indicator_type == "domain":
        return _domain(indicator)
    if indicator_type == "url":
        return _url(indicator)
    if indicator_type == "hash":
        return _hash(indicator)
    raise IndicatorError(f"Unsupported indicator type: {indicator_type}")
