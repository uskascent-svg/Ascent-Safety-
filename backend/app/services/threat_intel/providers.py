"""Provider clients. Read-only lookups: nothing is ever submitted for scanning, and no indicator
is visited. API keys come from settings and are only ever sent in request headers."""

import base64
from urllib.parse import quote

import httpx

from app.core.config import get_settings
from app.services.threat_intel.base import IntelResult, Provider, check_http, failure

# Verdict thresholds (documented heuristics, tune to your risk appetite)
VT_MALICIOUS_MIN = 3  # engines flagging as malicious
ABUSE_MALICIOUS_MIN = 75  # AbuseIPDB confidence score
ABUSE_SUSPICIOUS_MIN = 25


def vt_url_id(url: str) -> str:
    """VirusTotal identifies a URL by its unpadded URL-safe base64."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class VirusTotal(Provider):
    name = "virustotal"
    types = ("ip", "domain", "url", "hash")

    def enabled(self) -> bool:
        return bool(get_settings().virustotal_api_key)

    def lookup(self, client: httpx.Client, indicator: str, itype: str) -> IntelResult:
        path = {
            "ip": f"ip_addresses/{indicator}",
            "domain": f"domains/{indicator}",
            "url": f"urls/{vt_url_id(indicator)}",
            "hash": f"files/{indicator}",
        }[itype]
        resp = client.get(
            f"https://www.virustotal.com/api/v3/{path}",
            headers={"x-apikey": get_settings().virustotal_api_key or ""},
        )
        if (err := check_http(self.name, indicator, itype, resp)) is not None:
            return err
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        malicious, suspicious = stats.get("malicious", 0), stats.get("suspicious", 0)
        if malicious >= VT_MALICIOUS_MIN:
            verdict = "malicious"
        elif malicious or suspicious:
            verdict = "suspicious"
        elif stats.get("harmless", 0) or stats.get("undetected", 0):
            verdict = "clean"
        else:
            verdict = "unknown"
        detail = {k: stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected")}
        return IntelResult(self.name, indicator, itype, "ok", verdict, detail)


class AbuseIPDB(Provider):
    name = "abuseipdb"
    types = ("ip",)

    def enabled(self) -> bool:
        return bool(get_settings().abuseipdb_api_key)

    def lookup(self, client: httpx.Client, indicator: str, itype: str) -> IntelResult:
        resp = client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": indicator, "maxAgeInDays": 90},
            headers={"Key": get_settings().abuseipdb_api_key or "", "Accept": "application/json"},
        )
        if (err := check_http(self.name, indicator, itype, resp)) is not None:
            return err
        data = resp.json()["data"]
        score = int(data["abuseConfidenceScore"])
        verdict = (
            "malicious"
            if score >= ABUSE_MALICIOUS_MIN
            else "suspicious" if score >= ABUSE_SUSPICIOUS_MIN else "clean"
        )
        detail = {
            "abuse_confidence_score": score,
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
        }
        return IntelResult(self.name, indicator, itype, "ok", verdict, detail)


class URLhaus(Provider):
    name = "urlhaus"
    types = ("ip", "domain", "url", "hash")

    def enabled(self) -> bool:
        return bool(get_settings().urlhaus_auth_key)

    def lookup(self, client: httpx.Client, indicator: str, itype: str) -> IntelResult:
        endpoint, field = {
            "url": ("url", "url"),
            "hash": ("payload", "sha256_hash"),
        }.get(itype, ("host", "host"))
        resp = client.post(
            f"https://urlhaus-api.abuse.ch/v1/{endpoint}/",
            data={field: indicator},
            headers={"Auth-Key": get_settings().urlhaus_auth_key or ""},
        )
        if (err := check_http(self.name, indicator, itype, resp)) is not None:
            return err
        body = resp.json()
        status = body.get("query_status")
        if status in {"no_results", "hash_not_found"}:
            return IntelResult(self.name, indicator, itype, "not_found", "unknown")
        if status != "ok":
            return failure(
                self.name, indicator, itype, "error", f"Unexpected query status: {status}"
            )
        # A URLhaus listing means the URL/host has been used to distribute malware.
        if itype == "url":
            detail = {
                "url_status": body.get("url_status"),
                "threat": body.get("threat"),
                "tags": body.get("tags") or [],
            }
        elif itype == "hash":
            detail = {
                "file_type": body.get("file_type"),
                "signature": body.get("signature"),
                "url_count": body.get("url_count"),
            }
        else:
            detail = {
                "url_count": body.get("url_count"),
                "blacklists": body.get("blacklists") or {},
            }
        return IntelResult(self.name, indicator, itype, "ok", "malicious", detail)


class OTX(Provider):
    name = "otx"
    types = ("ip", "domain", "url", "hash")

    def enabled(self) -> bool:
        return bool(get_settings().otx_api_key)

    def lookup(self, client: httpx.Client, indicator: str, itype: str) -> IntelResult:
        kind = {
            "ip": "IPv6" if ":" in indicator else "IPv4",
            "domain": "domain",
            "url": "url",
            "hash": "file",
        }[itype]
        resp = client.get(
            f"https://otx.alienvault.com/api/v1/indicators/{kind}/{quote(indicator, safe='')}/general",
            headers={"X-OTX-API-KEY": get_settings().otx_api_key or ""},
        )
        if (err := check_http(self.name, indicator, itype, resp)) is not None:
            return err
        count = int(resp.json().get("pulse_info", {}).get("count", 0))
        # Pulses are community threat reports of varying quality: mention != malicious, so at most
        # "suspicious". Zero pulses is not evidence of safety, so it stays "unknown".
        return IntelResult(
            self.name,
            indicator,
            itype,
            "ok",
            "suspicious" if count else "unknown",
            {"pulse_count": count},
        )


ALL_PROVIDERS: list[Provider] = [VirusTotal(), AbuseIPDB(), URLhaus(), OTX()]
