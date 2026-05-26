import json
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from pathlib import Path
import re

import feedparser
from bs4 import BeautifulSoup

FEEDS = [
    {
        "name": "CISA Advisories",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "default_severity": "High",
    },
    {
        "name": "CISA Alerts",
        "url": "https://www.cisa.gov/news.xml",
        "default_severity": "Info",
    },
    {
        "name": "Microsoft Security Blog",
        "url": "https://www.microsoft.com/en-us/security/blog/feed/",
        "default_severity": "Info",
    },
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "default_severity": "Medium",
    },
]

KEYWORDS_CRITICAL = [
    "actively exploited", "zero-day", "zero day", "ransomware",
    "critical", "mass exploitation", "emergency"
]

KEYWORDS_HIGH = [
    "microsoft", "entra", "identity", "phishing", "credential",
    "password spray", "mfa", "exchange", "sharepoint", "vulnerability",
    "exploit", "breach"
]

def clean_html(value: str) -> str:
    value = value or ""
    soup = BeautifulSoup(value, "html.parser")
    text = soup.get_text(" ", strip=True)
    text = unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

def truncate(value: str, limit: int = 190) -> str:
    value = clean_html(value)
    if len(value) <= limit:
        return value
    return value[: limit - 3].rsplit(" ", 1)[0] + "..."

def parse_date(entry):
    for key in ("published", "updated", "created"):
        if entry.get(key):
            try:
                dt = parsedate_to_datetime(entry[key])
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception:
                pass
    return datetime.now(timezone.utc)

def classify(title: str, summary: str, default: str) -> str:
    text = f"{title} {summary}".lower()
    if any(k in text for k in KEYWORDS_CRITICAL):
        return "Critical"
    if any(k in text for k in KEYWORDS_HIGH):
        return "High"
    return default

def main():
    items = []
    seen_links = set()

    for feed in FEEDS:
        parsed = feedparser.parse(feed["url"])
        for entry in parsed.entries[:10]:
            link = entry.get("link", "").strip()
            title = clean_html(entry.get("title", "")).strip()

            if not link or not title or link in seen_links:
                continue

            summary = truncate(entry.get("summary", "") or entry.get("description", ""))
            dt = parse_date(entry)
            severity = classify(title, summary, feed["default_severity"])

            items.append({
                "title": title,
                "source": feed["name"],
                "severity": severity,
                "summary": summary or "Read the full advisory for details.",
                "date": dt.strftime("%Y-%m-%d"),
                "sortDate": dt.isoformat(),
                "link": link,
            })

            seen_links.add(link)

    items.sort(key=lambda x: x["sortDate"], reverse=True)

    output = {
        "lastUpdated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "items": [
            {k: v for k, v in item.items() if k != "sortDate"}
            for item in items[:6]
        ],
    }

    Path("threats.json").write_text(json.dumps(output, indent=2), encoding="utf-8")

if __name__ == "__main__":
    main()
