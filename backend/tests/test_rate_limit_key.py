import hashlib

from starlette.requests import Request

from app.core.limiter import rate_limit_key


def make_request(headers: list[tuple[bytes, bytes]], client: tuple[str, int] = ("127.0.0.1", 1)):
    return Request({"type": "http", "headers": headers, "client": client})


def test_telemetry_rate_limit_key_hashes_api_secret():
    secret = "ascent_ep_sensitive-key"
    request = make_request([(b"x-endpoint-key", secret.encode())])

    key = rate_limit_key(request)

    assert key == f"x-endpoint-key:{hashlib.sha256(secret.encode()).hexdigest()}"
    assert secret not in key


def test_forwarded_client_address_is_used_for_proxied_anonymous_requests():
    request = make_request(
        [(b"x-forwarded-for", b"203.0.113.8, 10.0.0.4")], client=("172.20.0.3", 1)
    )

    assert rate_limit_key(request) == "203.0.113.8"


def test_authenticated_rate_limit_key_is_separate_from_proxy_address():
    request = make_request(
        [(b"authorization", b"Bearer user-token"), (b"x-forwarded-for", b"203.0.113.8")]
    )

    assert rate_limit_key(request) == f"bearer:{hashlib.sha256(b'user-token').hexdigest()}"
