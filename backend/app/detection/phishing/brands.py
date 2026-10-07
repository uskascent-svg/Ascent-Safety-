"""Detection configuration (not telemetry): well-known brands and their legitimate domains."""

BRAND_DOMAINS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com", "paypal.me"}),
    "microsoft": frozenset(
        {"microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"}
    ),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "google": frozenset({"google.com", "gmail.com", "youtube.com"}),
    "amazon": frozenset({"amazon.com", "amazon.co.uk", "amazon.de", "amazonaws.com"}),
    "netflix": frozenset({"netflix.com"}),
    "facebook": frozenset({"facebook.com", "fb.com", "meta.com"}),
    "instagram": frozenset({"instagram.com"}),
    "linkedin": frozenset({"linkedin.com"}),
    "dropbox": frozenset({"dropbox.com"}),
    "docusign": frozenset({"docusign.com", "docusign.net"}),
    "dhl": frozenset({"dhl.com"}),
    "fedex": frozenset({"fedex.com"}),
    "wellsfargo": frozenset({"wellsfargo.com"}),
    "bankofamerica": frozenset({"bankofamerica.com"}),
}

URL_SHORTENERS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
    }
)

# Heuristic only: TLDs frequently abused for throwaway domains. Low weight on its own.
SUSPICIOUS_TLDS = frozenset({"tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "zip", "work"})

# Two-label public suffixes handled by the lightweight registered-domain helper.
SECOND_LEVEL_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "co.nz",
        "co.jp",
        "co.in",
        "com.br",
        "com.cn",
        "co.za",
        "com.mx",
    }
)

DANGEROUS_EXTENSIONS = frozenset(
    {"exe", "scr", "js", "vbs", "bat", "cmd", "ps1", "jar", "msi", "lnk", "hta", "com", "pif"}
)
MACRO_EXTENSIONS = frozenset({"docm", "xlsm", "pptm"})
ARCHIVE_EXTENSIONS = frozenset({"zip", "rar", "7z", "iso", "img"})
