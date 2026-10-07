import httpx
import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.models import AuditLog, ThreatIntelCache
from app.services.threat_intel import aggregator
from app.services.threat_intel.indicators import IndicatorError, normalize
from app.services.threat_intel.providers import vt_url_id
from tests.test_events import analyst, event, ingest  # noqa: F401
from tests.test_phishing_api import auth

KEYS = {
    "virustotal_api_key": "vt-secret-key",
    "abuseipdb_api_key": "abuse-secret-key",
    "otx_api_key": "otx-secret-key",
    "urlhaus_auth_key": "urlhaus-secret-key",
}


def _json(data, status=200):
    return httpx.Response(status, json=data)


def default_responders():
    def vt(req):
        path = req.url.path
        if "/ip_addresses/" in path:
            stats = {"malicious": 5, "suspicious": 1, "harmless": 50, "undetected": 10}
        elif "/domains/" in path:
            return httpx.Response(404, json={"error": {"code": "NotFoundError"}})
        else:
            stats = {"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 10}
        return _json({"data": {"attributes": {"last_analysis_stats": stats}}})

    def abuse(req):
        return _json(
            {
                "data": {
                    "abuseConfidenceScore": 90,
                    "totalReports": 12,
                    "countryCode": "NL",
                    "isp": "ExampleNet",
                    "usageType": "Hosting",
                }
            }
        )

    def urlhaus(req):
        if req.url.path == "/v1/url/":
            return _json(
                {
                    "query_status": "ok",
                    "url_status": "online",
                    "threat": "malware_download",
                    "tags": ["emotet"],
                }
            )
        return _json({"query_status": "no_results"})

    def otx(req):
        return _json({"pulse_info": {"count": 2}})

    return {
        "www.virustotal.com": vt,
        "api.abuseipdb.com": abuse,
        "urlhaus-api.abuse.ch": urlhaus,
        "otx.alienvault.com": otx,
    }


@pytest.fixture()
def intel(monkeypatch):
    """Configure all four providers and route their HTTP calls to in-memory fakes."""
    settings = get_settings()
    for k, v in KEYS.items():
        monkeypatch.setattr(settings, k, v)
    state = {"calls": [], "responders": default_responders()}

    def handler(request: httpx.Request) -> httpx.Response:
        state["calls"].append(request)
        return state["responders"][request.url.host](request)

    monkeypatch.setattr(
        aggregator, "make_client", lambda: httpx.Client(transport=httpx.MockTransport(handler))
    )
    return state


@pytest.fixture()
def no_keys(monkeypatch):
    for k in KEYS:
        monkeypatch.setattr(get_settings(), k, None)


# ---------- indicator validation ----------
@pytest.mark.parametrize(
    "value,itype",
    [
        ("10.0.0.5", "ip"),
        ("127.0.0.1", "ip"),
        ("192.168.1.1", "ip"),
        ("::1", "ip"),
        ("localhost", "domain"),
        ("printer.local", "domain"),
        ("intranet", "domain"),
        ("ftp://example.com/x", "url"),
        ("http://10.0.0.1/admin", "url"),
        ("http://", "url"),
    ],
)
def test_internal_or_invalid_indicators_are_rejected(value, itype):
    with pytest.raises(IndicatorError):
        normalize(value, itype)


def test_valid_indicators_are_normalised():
    assert normalize("8.8.8.8", "ip") == "8.8.8.8"
    assert normalize("Example.COM.", "domain") == "example.com"
    assert normalize("https://example.com/a?b=1#frag", "url") == "https://example.com/a?b=1"


def test_virustotal_url_id_is_unpadded_urlsafe_base64():
    assert vt_url_id("http://example.com/") == "aHR0cDovL2V4YW1wbGUuY29tLw"


# ---------- providers / lookup endpoint ----------
def test_provider_status_never_exposes_keys(client, analyst, intel):  # noqa: F811
    body = client.get("/api/threat-intel/providers", headers=analyst).text
    assert all(secret not in body for secret in KEYS.values())
    assert '"configured":true' in body.replace(" ", "")


def test_lookup_requires_analyst(client, intel):
    assert client.get("/api/threat-intel/lookup?indicator=8.8.8.8&type=ip").status_code == 401
    plain = auth(client, "plain@example.com")
    r = client.get("/api/threat-intel/lookup?indicator=8.8.8.8&type=ip", headers=plain)
    assert r.status_code == 403


def test_ip_lookup_aggregates_providers_and_sends_credentials_in_headers(
    client, analyst, intel
):  # noqa: F811
    r = client.get("/api/threat-intel/lookup?indicator=8.8.8.8&type=ip", headers=analyst)
    assert r.status_code == 200, r.text
    body = r.json()
    by = {x["provider"]: x for x in body["results"]}
    assert set(by) == {"virustotal", "abuseipdb", "urlhaus", "otx"}
    assert (
        by["virustotal"]["verdict"] == "malicious" and by["virustotal"]["detail"]["malicious"] == 5
    )
    assert by["abuseipdb"]["detail"]["abuse_confidence_score"] == 90
    assert by["urlhaus"]["status"] == "not_found" and by["otx"]["verdict"] == "suspicious"
    assert body["verdict"] == "malicious" and "not a guarantee" in body["note"]
    sent = {c.url.host: c for c in intel["calls"]}
    assert sent["www.virustotal.com"].headers["x-apikey"] == "vt-secret-key"
    assert sent["api.abuseipdb.com"].headers["key"] == "abuse-secret-key"
    assert sent["urlhaus-api.abuse.ch"].headers["auth-key"] == "urlhaus-secret-key"
    assert sent["otx.alienvault.com"].headers["x-otx-api-key"] == "otx-secret-key"
    assert all(secret not in str(c.url) for c in intel["calls"] for secret in KEYS.values())


def test_results_are_cached(client, analyst, intel, session_factory):  # noqa: F811
    url = "/api/threat-intel/lookup?indicator=8.8.8.8&type=ip"
    first = client.get(url, headers=analyst).json()
    n = len(intel["calls"])
    second = client.get(url, headers=analyst).json()
    assert len(intel["calls"]) == n  # served from cache, no new outbound calls
    assert all(x["cached"] for x in second["results"]) and not any(
        x["cached"] for x in first["results"]
    )
    with session_factory() as db:
        assert db.query(ThreatIntelCache).count() == 4


def test_private_ip_is_rejected_without_any_outbound_request(client, analyst, intel):  # noqa: F811
    r = client.get("/api/threat-intel/lookup?indicator=10.1.2.3&type=ip", headers=analyst)
    assert r.status_code == 422 and intel["calls"] == []


def test_503_when_no_provider_configured(client, analyst, no_keys):  # noqa: F811
    r = client.get("/api/threat-intel/lookup?indicator=8.8.8.8&type=ip", headers=analyst)
    assert r.status_code == 503


def test_provider_failures_are_contained_and_leak_nothing(client, analyst, intel):  # noqa: F811
    def boom(req):
        raise httpx.ConnectError("connection refused")

    intel["responders"]["www.virustotal.com"] = boom
    intel["responders"]["api.abuseipdb.com"] = lambda req: httpx.Response(429)
    intel["responders"]["urlhaus-api.abuse.ch"] = lambda req: httpx.Response(401)
    intel["responders"]["otx.alienvault.com"] = lambda req: httpx.Response(500)
    r = client.get("/api/threat-intel/lookup?indicator=8.8.8.8&type=ip", headers=analyst)
    assert r.status_code == 200
    by = {x["provider"]: x for x in r.json()["results"]}
    assert by["virustotal"]["detail"]["error"] == "Provider unreachable"
    assert by["abuseipdb"]["status"] == "rate_limited"
    assert "Authentication failed" in by["urlhaus"]["detail"]["error"]
    assert by["otx"]["status"] == "error"
    assert r.json()["verdict"] == "unknown"
    assert all(secret not in r.text for secret in KEYS.values())


def test_lookup_is_audited_without_storing_the_raw_indicator(
    client, analyst, intel, session_factory
):  # noqa: F811
    client.get("/api/threat-intel/lookup?indicator=8.8.8.8&type=ip", headers=analyst)
    with session_factory() as db:
        row = db.scalar(select(AuditLog).where(AuditLog.action == "threat_intel.lookup"))
    assert row.details["type"] == "ip" and "8.8.8.8" not in str(row.details)


# ---------- security-event enrichment ----------
def test_event_source_ip_enrichment(client, analyst, intel, ingest):  # noqa: F811
    with_ip = ingest(source_ip="8.8.4.4")
    no_ip = ingest(title="no ip")
    r = client.get(f"/api/security-events/{with_ip['id']}/intel", headers=analyst)
    assert r.status_code == 200 and r.json()["indicator"] == "8.8.4.4"
    assert (
        client.get(f"/api/security-events/{no_ip['id']}/intel", headers=analyst).status_code == 400
    )
    private = ingest(source_ip="10.0.0.9", title="internal")
    assert (
        client.get(f"/api/security-events/{private['id']}/intel", headers=analyst).status_code
        == 422
    )


# ---------- phishing integration ----------
CLEAN_LOOKING = {"body_text": "Please review your documents here: https://bad.example.net/pay"}


def test_phishing_threat_intel_is_opt_in(client, intel):
    h = auth(client)
    r = client.post("/api/phishing/analyze", json=CLEAN_LOOKING, headers=h)
    assert r.status_code == 200 and r.json()["intel"] is None and intel["calls"] == []
    assert r.json()["classification"] == "low_risk"


def test_confirmed_malicious_link_is_a_strong_signal(client, intel):
    # OTX reports no pulses here, so URLhaus's listing is the ONLY indicator on the message.
    intel["responders"]["otx.alienvault.com"] = lambda req: _json({"pulse_info": {"count": 0}})
    h = auth(client)
    r = client.post(
        "/api/phishing/analyze", json={**CLEAN_LOOKING, "check_threat_intel": True}, headers=h
    )
    body = r.json()
    ti = next(i for i in body["indicators"] if i["code"] == "TI_MALICIOUS_INDICATOR")
    assert ti["category"] == "threat_intelligence" and ti["severity"] == "high"
    assert any(e.startswith("urlhaus: malicious — hxxps://bad") for e in ti["evidence"])
    assert [i["code"] for i in body["indicators"]] == ["TI_MALICIOUS_INDICATOR"]  # single indicator
    assert body["classification"] == "likely_phishing"
    assert body["intel"]["providers"] == ["otx", "urlhaus", "virustotal"]
    assert body["intel"]["indicators_checked"] >= 2 and body["intel"]["unavailable"] == 0
    # only the public link/host is ever sent out
    assert all(c.url.host != "bad.example.net" for c in intel["calls"])


def test_phishing_skips_private_links_and_bounds_lookups(client, intel):
    h = auth(client)
    links = " ".join(f"https://site{i}.example.net/p" for i in range(10))
    body = {"body_text": f"internal http://10.0.0.5/x and {links}", "check_threat_intel": True}
    r = client.post("/api/phishing/analyze", json=body, headers=h).json()
    assert r["intel"]["indicators_checked"] <= 6
    assert not any(
        "10.0.0.5" in str(c.url) or "10.0.0.5" in (c.content or b"").decode()
        for c in intel["calls"]
    )


def test_phishing_without_configured_providers_still_works(client, no_keys):
    h = auth(client)
    r = client.post(
        "/api/phishing/analyze", json={**CLEAN_LOOKING, "check_threat_intel": True}, headers=h
    )
    assert r.status_code == 200
    assert r.json()["intel"]["providers"] == [] and "not checked" in r.json()["intel"]["note"]


def test_phishing_survives_provider_outage(client, intel):
    for host in list(intel["responders"]):
        intel["responders"][host] = lambda req: httpx.Response(503)
    h = auth(client)
    r = client.post(
        "/api/phishing/analyze", json={**CLEAN_LOOKING, "check_threat_intel": True}, headers=h
    )
    assert r.status_code == 200 and r.json()["intel"]["unavailable"] > 0
    assert r.json()["classification"] == "low_risk"
