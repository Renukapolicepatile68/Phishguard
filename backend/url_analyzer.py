import ipaddress
import re
from urllib.parse import urlparse


SUSPICIOUS_WORDS = (
    "login",
    "verify",
    "account",
    "password",
    "secure",
    "update",
    "banking",
    "wallet",
    "signin",
    "confirm",
)


def analyze_url(value):
    url = str(value).strip()
    if not url:
        raise ValueError("Please enter a URL.")
    if len(url) > 2048:
        raise ValueError("URL must be 2048 characters or fewer.")
    if any(ord(character) < 32 or ord(character) == 127 for character in url):
        raise ValueError("The URL contains invalid control characters.")
    has_web_scheme = bool(re.match(r"^https?://", url, re.IGNORECASE))
    explicit_scheme = re.match(r"^([a-z][a-z0-9+.-]*):", url, re.IGNORECASE)
    if explicit_scheme and not has_web_scheme:
        remainder = url[explicit_scheme.end():]
        if "://" in remainder or not remainder[:1].isdigit():
            raise ValueError("Only HTTP and HTTPS URLs can be analyzed.")
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        parsed.port
    except ValueError as error:
        raise ValueError("Please enter a valid HTTP or HTTPS URL.") from error
    if parsed.scheme.lower() not in ("http", "https") or not hostname:
        raise ValueError("Please enter a valid HTTP or HTTPS URL.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing embedded credentials cannot be analyzed.")

    hostname = hostname.lower().rstrip(".")
    score = 0
    signals = []
    try:
        ipaddress.ip_address(hostname)
        score += 25
        signals.append("The host is an IP address rather than a domain name.")
        is_ip = True
    except ValueError:
        is_ip = False
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise ValueError("Please enter a valid domain name.") from error
        labels = ascii_hostname.split(".")
        if len(ascii_hostname) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("Please enter a valid domain name.")
        hostname = ascii_hostname

    if parsed.scheme.lower() == "http":
        score += 15
        signals.append("The URL uses unencrypted HTTP.")
    if "@" in parsed.netloc:
        score += 20
        signals.append("The URL contains an @ symbol in its network location.")
    if len(url) > 75:
        score += 10
        signals.append("The URL is unusually long.")
    subdomains = 0 if is_ip else max(0, len(hostname.split(".")) - 2)
    if subdomains >= 2:
        score += 10
        signals.append("The domain has multiple subdomains.")
    if "-" in hostname:
        score += 5
        signals.append("The hostname contains hyphens.")
    found = [word for word in SUSPICIOUS_WORDS if word in url.lower()]
    if found:
        score += min(25, len(found) * 5)
        signals.append("Potentially deceptive URL terms: " + ", ".join(found) + ".")

    score = min(score, 100)
    if score >= 60:
        classification = "malicious"
    elif score >= 30:
        classification = "phishing"
    else:
        classification = "safe"
    if not signals:
        signals.append("No configured URL-pattern warnings were found; this is not a guarantee of safety.")

    return {
        "url": url,
        "result": classification,
        "risk_score": score,
        "signals": signals,
        "features": {
            "url_length": len(url),
            "subdomains": subdomains,
            "https": parsed.scheme.lower() == "https",
            "ip_host": is_ip,
            "suspicious_terms": found,
        },
        "protocol": parsed.scheme.upper(),
    }
