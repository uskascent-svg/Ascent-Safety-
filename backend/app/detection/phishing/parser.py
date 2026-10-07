"""Email parsing. Nothing here executes, opens or saves attachment content or visits any URL."""

import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr

from bs4 import BeautifulSoup

MAX_TEXT_CHARS = 200_000
_AUTH_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.I
)


@dataclass
class Attachment:
    filename: str | None
    content_type: str
    size: int


@dataclass
class ParsedEmail:
    sender_raw: str | None = None
    display_name: str | None = None
    sender_address: str | None = None
    sender_domain: str | None = None
    reply_to_domain: str | None = None
    subject: str = ""
    text: str = ""
    html: str | None = None
    # SPF/DKIM/DMARC results *as stated in the message's Authentication-Results header*.
    auth: dict[str, str] = field(default_factory=dict)
    attachments: list[Attachment] = field(default_factory=list)


def _domain(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].strip(" <>").lower() or None


def html_to_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    return soup.get_text(" ", strip=True)


def _body(msg: EmailMessage, kind: str) -> str | None:
    try:
        part = msg.get_body(preferencelist=(kind,))
    except Exception:  # malformed MIME structure
        return None
    if part is None:
        return None
    try:
        return part.get_content()
    except Exception:  # unknown/invalid charset: decode leniently
        payload = part.get_payload(decode=True)
        return payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else None


def _set_sender(parsed: ParsedEmail, raw_from: str | None) -> None:
    parsed.sender_raw = raw_from or None
    name, addr = parseaddr(raw_from or "")
    parsed.display_name = name or None
    parsed.sender_address = addr.lower() or None
    parsed.sender_domain = _domain(addr)


def parse_raw(raw: str) -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(raw.encode("utf-8", errors="replace"))
    parsed = ParsedEmail(subject=str(msg.get("Subject") or "").strip())
    _set_sender(parsed, str(msg.get("From") or ""))
    parsed.reply_to_domain = _domain(parseaddr(str(msg.get("Reply-To") or ""))[1])

    for header in msg.get_all("Authentication-Results") or []:
        for mech, result in _AUTH_RE.findall(str(header)):
            parsed.auth.setdefault(mech.lower(), result.lower())

    plain, html = _body(msg, "plain"), _body(msg, "html")
    parsed.html = html[:MAX_TEXT_CHARS] if html else None
    parsed.text = (plain or (html_to_text(html) if html else ""))[:MAX_TEXT_CHARS]

    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True)
        parsed.attachments.append(
            Attachment(
                filename=part.get_filename(),
                content_type=part.get_content_type(),
                size=len(payload) if isinstance(payload, bytes) else 0,
            )
        )
    return parsed


def parse_fields(
    sender: str | None, subject: str | None, body_text: str | None, body_html: str | None
) -> ParsedEmail:
    parsed = ParsedEmail(subject=(subject or "").strip())
    _set_sender(parsed, sender)
    parsed.html = body_html[:MAX_TEXT_CHARS] if body_html else None
    text = body_text or (html_to_text(body_html) if body_html else "")
    parsed.text = text[:MAX_TEXT_CHARS]
    return parsed
