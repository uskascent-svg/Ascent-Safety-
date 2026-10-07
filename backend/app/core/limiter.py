import hashlib

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address


def rate_limit_key(request: Request) -> str:
    """Give proxied users and telemetry sources independent rate-limit buckets.

    The ingress proxy must replace, not append to, X-Forwarded-For with the actual client address.
    API credential values are hashed before they become limiter keys.
    """
    for header in ("x-endpoint-key", "x-sensor-key", "x-ingest-key"):
        credential = request.headers.get(header)
        if credential:
            digest = hashlib.sha256(credential.encode()).hexdigest()
            return f"{header}:{digest}"

    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        digest = hashlib.sha256(authorization[7:].encode()).hexdigest()
        return f"bearer:{digest}"

    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",", maxsplit=1)[0].strip()
    return get_remote_address(request)


limiter = Limiter(key_func=rate_limit_key)
