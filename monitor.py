"""
Social Media & Threat Intelligence Monitor - Jamnagar & Coastal Gujarat
Platforms: YouTube API v3, Google Social (X, FB, Insta), Reddit RSS, Telegram
Timestamps: Indian Standard Time (IST)
"""

import email.utils
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

# 1. Target Locations & Critical Infrastructure Units
KEYWORDS = [
    "CISF Jamnagar",
    "Reliance Jamnagar",
    "Sikka Thermal",
    "GSECL Sikka",
    "Vadinar Port",
    "Nayara Energy Vadinar",
    "Moti Khavdi",
    "Gulf of Kutch",
    "Okha Coastal",
    "જામનગર સિક્કા",  # Jamnagar Sikka (Gujarati)
]

# 2. Strict Filter: Incident, Threat, Disaster, and Security Triggers (English + Gujarati)
INCIDENT_FILTER = (
    'fire OR blast OR explosion OR accident OR drone OR strike OR protest OR agitation OR '
    'curfew OR "law and order" OR trespass OR breach OR leak OR casualty OR "oil spill" OR '
    'narcotics OR seized OR deployment OR alert OR mockdrill OR '
    'પોલીસ OR આગ OR અકસ્માત OR વિરોધ OR હડતાળ OR ડ્રોન OR સુરક્ષા OR બ્લાસ્ટ'
)

# Incident trigger list for local parsing (YouTube/Telegram)
INCIDENT_KEYWORDS_LIST = [
    "fire", "blast", "explosion", "accident", "drone", "strike", "protest", 
    "agitation", "curfew", "law and order", "trespass", "breach", "leak", 
    "casualty", "oil spill", "narcotics", "seized", "deployment", "alert", 
    "drill", "cisf", "police", "coast guard", "navy", "security",
    "આગ", "અકસ્માત", "વિરોધ", "હડતાળ", "ડ્રોન", "સુરક્ષા", "બ્લાસ્ટ", "ઝડપાયા"
]

SOCIAL_DOMAINS = "site:x.com OR site:twitter.com OR site:facebook.com OR site:instagram.com OR site:t.me"

STATE_FILE = "state.json"
NTFY_TOPIC = os.environ.get("NTFY_TOPIC")
NTFY_URL = f"https://ntfy.sh/{NTFY_TOPIC}" if NTFY_TOPIC else None
YOUTUBE_API_KEY = os.environ.get("YOUTUBE_API_KEY")

IST = timezone(timedelta(hours=5, minutes=30))
SECONDS_BETWEEN_NOTIFICATIONS = 3
MAX_PAYLOAD_BYTES = 3500
MAX_POST_AGE_HOURS = 36


def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not read {STATE_FILE} ({e}). Rebuilding cache.", flush=True)
    return {"seen_links": []}


def save_state(seen_links_list):
    trimmed = seen_links_list[-4000:]
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump({"seen_links": trimmed}, f, indent=2)


def fetch_youtube_api(keyword):
    """Fetches YouTube videos via Data API v3 and evaluates threat keywords."""
    if not YOUTUBE_API_KEY:
        return []

    published_after = (datetime.now(timezone.utc) - timedelta(hours=MAX_POST_AGE_HOURS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    params = {
        "part": "snippet",
        "q": keyword,
        "type": "video",
        "order": "date",
        "publishedAfter": published_after,
        "maxResults": 10,
        "key": YOUTUBE_API_KEY,
    }

    url = f"https://www.googleapis.com/youtube/v3/search?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"User-Agent": "SecurityIntelBot/1.0"})

    items = []
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        for item in data.get("items", []):
            video_id = item["id"].get("videoId")
            snippet = item.get("snippet", {})
            title = snippet.get("title", "").strip()
            desc = snippet.get("description", "").lower()
            text_body = f"{title.lower()} {desc}"

            if any(term in text_body for term in INCIDENT_KEYWORDS_LIST):
                if video_id and title:
                    link = f"https://www.youtube.com/watch?v={video_id}"
                    items.append((f"[YouTube] {title}", link, video_id))
    except Exception as e:
        print(f"YouTube API notice for '{keyword}': {e}", flush=True)

    return items


def fetch_google_social(keyword):
    """Monitors public X, Facebook, Instagram, and Telegram links matching target filters."""
    query = f'"{keyword}" ({INCIDENT_FILTER}) ({SOCIAL_DOMAINS})'
    encoded = urllib.parse.quote(query)
    url = f"https://news.google.com/rss/search?q={encoded}&hl=en-IN&gl=IN&ceid=IN:en"

    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    items = []
    now = datetime.now(timezone.utc)
    max_age = timedelta(hours=MAX_POST_AGE_HOURS)

    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = resp.read()

        root = ET.fromstring(data)
        for item in root.findall(".//item"):
            title = item.findtext("title", "").strip()
            link = item.findtext("link", "").strip()
            guid = item.findtext("guid", link).strip()
            pub_date_str = item.findtext("pubDate", "").strip()

            if pub_date_str:
                try:
                    pub_dt = email.utils.parsedate_to_datetime(pub_date_str)
                    if now - pub_dt > max_age:
                        continue
                except Exception:
                    pass

            if title and link:
                platform = "Social"
                if "facebook.com" in link:
                    platform = "Facebook"
                elif "instagram.com" in link:
                    platform = "Instagram"
                elif "x.com" in link or "twitter.com" in link:
                    platform = "X"
                elif "t.me" in link:
                    platform = "Telegram"

                items.append((f"[{platform}] {title}", link, guid))
    except Exception as e:
        print(f"Google Social RSS notice for '{keyword}': {e}", flush=True)

    return items


def fetch_reddit(keyword):
    """Pulls Reddit submissions filtered by keyword and incident terms."""
    query = f'"{keyword}" ({INCIDENT_FILTER})'
    encoded = urllib.parse.quote(query)
    url = f"https://www.reddit.com/search.rss?q={encoded}&sort=new"

    req = urllib.request.Request(url, headers={"User-Agent": "SecurityIntelBot/1.0"})
    items = []
    now = datetime.now(timezone.utc)
    max_age = timedelta(hours=MAX_POST_AGE_HOURS)

    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = resp.read()

        root = ET.fromstring(data)
        atom_ns = "http://www.w3.org/2005/Atom"
        for entry in root.findall(f"{{{atom_ns}}}entry"):
            title = entry.findtext(f"{{{atom_ns}}}title", "").strip()
            link_elem = entry.find(f"{{{atom_ns}}}link")
            link = link_elem.attrib.get("href", "").strip() if link_elem is not None else ""
            pub_str = entry.findtext(f"{{{atom_ns}}}updated", "").strip()

            if pub_str:
                try:
                    pub_dt = datetime.fromisoformat(pub_str)
                    if now - pub_dt > max_age:
                        continue
                except Exception:
                    pass

            if title and link:
                items.append((f"[Reddit] {title}", link, link))
    except Exception as e:
        print(f"Reddit notice for '{keyword}': {e}", flush=True)

    return items


def send_notification(title, message, priority="default", tags="", retries=2):
    if not NTFY_URL:
        print(f"[Alert Console]: {title}\n{message}\n", flush=True)
        return

    headers = {"Title": title, "Priority": priority}
    if tags:
        headers["Tags"] = tags

    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(
                NTFY_URL,
                data=message.encode("utf-8"),
                headers=headers,
                method="POST"
            )
            urllib.request.urlopen(req, timeout=15)
            return
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries:
                time.sleep(4 * attempt)
                continue
            print(f"Notification error: {e}", flush=True)
            return
        except Exception as e:
            print(f"Notification dispatch failed: {e}", flush=True)
            return


def send_digest(kw, items):
    formatted = [f"{i+1}. {title}\n{link}" for i, (title, link) in enumerate(items)]
    chunks = []
    curr_chunk = []
    curr_len = 0

    for entry in formatted:
        b_len = len(entry.encode("utf-8")) + 2
        if curr_chunk and (curr_len + b_len > MAX_PAYLOAD_BYTES):
            chunks.append(curr_chunk)
            curr_chunk = [entry]
            curr_len = b_len
        else:
            curr_chunk.append(entry)
            curr_len += b_len

    if curr_chunk:
        chunks.append(curr_chunk)

    total = len(chunks)
    for idx, chunk in enumerate(chunks, 1):
        part = f" (Part {idx}/{total})" if total > 1 else ""
        title = f"🚨 Incident Alert: {kw} ({len(items)} items){part}"
        body = "\n\n".join(chunk)
        send_notification(title, body, priority="urgent", tags="rotating_light,warning")
        print(f"Pushed alert for '{kw}'{part}: {len(chunk)} link(s)", flush=True)
        time.sleep(SECONDS_BETWEEN_NOTIFICATIONS)


def main():
    state = load_state()
    seen_links_list = state.get("seen_links", [])
    seen_set = set(seen_links_list)
    quiet_keywords = []

    try:
        for kw in KEYWORDS:
            matched_posts = []

            # 1. Official YouTube Data API v3
            matched_posts.extend(fetch_youtube_api(kw))

            # 2. Indexed Facebook, Instagram, X, Telegram
            matched_posts.extend(fetch_google_social(kw))

            # 3. Reddit Search RSS
            matched_posts.extend(fetch_reddit(kw))

            new_items = []
            for title, link, guid in matched_posts:
                item_id = guid if guid else link
                if item_id not in seen_set:
                    new_items.append((title, link))
                    seen_set.add(item_id)
                    seen_links_list.append(item_id)

            if new_items:
                send_digest(kw, new_items)
            else:
                quiet_keywords.append(kw)

        if quiet_keywords:
            now_ist = datetime.now(IST).strftime("%d %b %Y, %I:%M %p IST")
            quiet_summary = "\n".join([f"• {k}" for k in quiet_keywords])
            send_notification(
                f"Security Patrol: No Incidents ({len(quiet_keywords)} monitored targets)",
                f"Scan completed at {now_ist}.\nQuiet sectors:\n{quiet_summary}",
                priority="min",
                tags="shield"
            )
            print(f"Routine scan clear for {len(quiet_keywords)} sectors.", flush=True)

    finally:
        save_state(seen_links_list)


if __name__ == "__main__":
    main()
