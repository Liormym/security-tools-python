from flask import Flask, request, jsonify, render_template
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Indicator:
    category: str
    severity: str
    description: str
    evidence: str

@dataclass
class ScanResult:
    indicators: list = field(default_factory=list)
    score: int = 0

    def add(self, indicator):
        self.indicators.append(indicator)
        weights = {"HIGH": 10, "MEDIUM": 5, "LOW": 2}
        self.score += weights.get(indicator.severity, 0)

    @property
    def verdict(self):
        if self.score >= 20:
            return "PHISHING"
        if self.score >= 8:
            return "SUSPICIOUS"
        return "LIKELY SAFE"

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

URGENT_PATTERNS = re.compile(
    r"\b(urgent|urgently|immediately|action required|act now|verify now"
    r"|limited time|expires? (soon|today|in \d+)|your account (will be|has been) (suspended|locked|deactivated)"
    r"|confirm (your|account)|click (here|below|now)|update (your|billing|payment)"
    r"|unusual (activity|sign.?in)|unauthorized access|security alert"
    r"|you (have|'ve) won|congratulations|prize|reward|bonus)\b",
    re.IGNORECASE,
)

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".online", ".site", ".tk", ".ml", ".ga",
    ".cf", ".gq", ".pw", ".work", ".click", ".link", ".download",
}

BRAND_SPOOF_PATTERNS = re.compile(
    r"\b(paypal|amazon|apple|microsoft|google|facebook|netflix|bank|wells.?fargo"
    r"|chase|citibank|irs|fedex|ups|dhl|instagram|twitter|linkedin)\b",
    re.IGNORECASE,
)

URL_REGEX = re.compile(r"https?://[^\s\"'<>()]+", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"[\w.\-+]+@[\w.\-]+\.[a-zA-Z]{2,}")
FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "mail.com", "protonmail.com", "yandex.com",
}

# ---------------------------------------------------------------------------
# Analysers
# ---------------------------------------------------------------------------

def analyse_urls(text, result):
    urls = URL_REGEX.findall(text)
    for url in urls:
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
        except Exception:
            continue

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
            result.add(Indicator("Suspicious URL", "HIGH",
                "URL uses a raw IP address instead of a domain name", url))
            continue

        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                result.add(Indicator("Suspicious URL", "HIGH",
                    f"URL uses a suspicious TLD ({tld})", url))
                break

        brand_match = BRAND_SPOOF_PATTERNS.search(hostname)
        if brand_match:
            parts = hostname.split(".")
            registered = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
            if brand_match.group().lower() not in registered.lower():
                result.add(Indicator("Brand Spoofing in URL", "HIGH",
                    f"URL contains brand name '{brand_match.group()}' but actual domain is '{registered}'", url))

        if len(url) > 200:
            result.add(Indicator("Suspicious URL", "LOW",
                "Unusually long URL (possible obfuscation)", url[:120] + "…"))

        shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}
        if hostname in shorteners:
            result.add(Indicator("Suspicious URL", "MEDIUM",
                "URL uses a link shortener that hides the real destination", url))

    html_link_re = re.compile(r'href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>', re.IGNORECASE)
    for href, display in html_link_re.findall(text):
        if re.match(r"https?://", display.strip()) and display.strip() != href:
            result.add(Indicator("Misleading Hyperlink", "HIGH",
                "Displayed URL does not match the actual href",
                f"Displayed: {display.strip()!r} → Actual: {href!r}"))


def analyse_sender(text, result):
    header_section = text.split("\n\n")[0]
    from_match = re.search(r"^From:.*$", header_section, re.IGNORECASE | re.MULTILINE)
    reply_match = re.search(r"^Reply-To:.*$", header_section, re.IGNORECASE | re.MULTILINE)

    def check_address(line, field_name):
        addrs = EMAIL_REGEX.findall(line)
        for addr in addrs:
            _, domain = addr.rsplit("@", 1)
            if domain.lower() in FREE_EMAIL_DOMAINS:
                result.add(Indicator("Suspicious Sender", "MEDIUM",
                    f"{field_name} uses a free email service ({domain}), unusual for official organisations", addr))
            brand_match = BRAND_SPOOF_PATTERNS.search(domain)
            if brand_match:
                brand = brand_match.group().lower()
                registered = domain.split(".")[0].lower()
                if brand != registered:
                    result.add(Indicator("Spoofed Sender Domain", "HIGH",
                        f"{field_name} domain '{domain}' mimics '{brand}' but is not the official domain", addr))
        return addrs

    from_addrs = check_address(from_match.group(), "From") if from_match else []
    reply_addrs = check_address(reply_match.group(), "Reply-To") if reply_match else []

    if from_addrs and reply_addrs and from_addrs[0] != reply_addrs[0]:
        from_domain = from_addrs[0].split("@")[1]
        reply_domain = reply_addrs[0].split("@")[1]
        if from_domain != reply_domain:
            result.add(Indicator("Header Mismatch", "HIGH",
                "From and Reply-To addresses belong to different domains",
                f"From: {from_addrs[0]} | Reply-To: {reply_addrs[0]}"))


def analyse_urgency(text, result):
    matches = URGENT_PATTERNS.findall(text)
    unique = list(dict.fromkeys(m if isinstance(m, str) else m[0] for m in matches))
    if not unique:
        return
    severity = "HIGH" if len(unique) >= 3 else "MEDIUM"
    result.add(Indicator("Urgent Language", severity,
        f"Email contains {len(unique)} urgency/pressure phrase(s) commonly used in phishing",
        ", ".join(f'"{w}"' for w in unique[:6])))


def analyse_attachments(text, result):
    hits = re.findall(r"\b\w+\.(exe|bat|cmd|vbs|js|jar|ps1|zip|rar|7z|iso|doc[mx]?|xls[xm]?|pdf)\b", text, re.IGNORECASE)
    if hits:
        result.add(Indicator("Suspicious Attachment", "MEDIUM",
            "Email references file types that can carry malware",
            ", ".join(set(hits))))

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    text = data.get("text", "")
    if not text.strip():
        return jsonify({"error": "No email content provided"}), 400

    result = ScanResult()
    analyse_sender(text, result)
    analyse_urls(text, result)
    analyse_urgency(text, result)
    analyse_attachments(text, result)

    return jsonify({
        "verdict": result.verdict,
        "score": result.score,
        "indicators": [
            {
                "category": ind.category,
                "severity": ind.severity,
                "description": ind.description,
                "evidence": ind.evidence,
            }
            for ind in result.indicators
        ],
    })

if __name__ == "__main__":
    app.run(debug=False, port=5000)