"""
Critical Infrastructure & Security Incident Monitor - Jamnagar/Coastal Gujarat
Monitors Google News RSS with boolean threat filtering in English & Gujarati.
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

# Structured queries pairing key assets/areas with security & incident triggers
TARGET_FEEDS = [
    {
        "label": "Jamnagar Critical Assets & Security",
        "query": '(Jamnagar OR Sikka OR Vadinar OR Moti Khavdi) AND (CISF OR police OR fire OR blast OR explosion OR protest OR strike OR security OR drone OR trespass OR breach OR leak OR casualty)',
        "lang": "en-IN",
        "gl": "IN",
        "ceid": "IN:en"
    },
    {
        "label": "Jamnagar Energy & Power (RIL / GSECL / STPS)",
        "query": '("Reliance Jamnagar" OR "RIL refinery" OR "Sikka Thermal" OR "GSECL Sikka" OR "Vadinar port" OR "Nayara Energy") AND (accident OR strike OR fire OR shutdown OR blast OR dispute OR agitation)',
        "lang": "en-IN",
        "gl": "IN",
        "ceid": "IN:en"
    },
    {
        "label": "Coastal & Gulf of Kutch Maritime Security",
        "query": '("Gulf of Kutch" OR "Kutch coastal" OR Okha OR Bedi OR Rozi OR "Marine National Park Jamnagar") AND (coastguard OR "Coast Guard" OR navy OR infiltration OR narcotics OR boat OR contraband OR oil spill OR seized)',
        "lang": "en-IN",
        "gl": "IN",
        "ceid": "IN:en"
    },
    {
        "label": "Local Vernacular Incident Monitor (Gujarati)",
        "query": '(જામનગર OR સિક્કા OR વાડીનાર OR ખાવડી) AND (પોલીસ OR આગ OR અકસ્માત OR વિરોધ OR હડતાળ OR ડ્રોન OR સુરક્ષા OR બ્લાસ્ટ OR ઝડપાયા)',
        "lang": "gu-IN",
        "gl": "IN",
        "ceid": "IN:gu"
    },
    {
        "label": "General CISF & Industrial Defense Intelligence",
        "query": 'CISF AND (Gujarat OR Jamnagar OR security OR "terror threat" OR alert OR mock drill OR deployment)',
        "lang": "en-IN",
        "gl": "IN",
        "ceid": "IN:en"
    }
]

STATE_FILE = "state.json"
NTFY_TOPIC = os.environ.get("NTFY_TOPIC")
NTFY_URL = f"https://ntfy.sh/{NTFY_TOPIC}" if NTFY_TOPIC else None

SECONDS_BETWEEN_NOTIFICATIONS = 3
MAX_PAYLOAD_BYTES = 3500
MAX_ARTICLE_AGE_HOURS = 36  # Tighter window for faster incident detection


def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load {STATE_FILE} ({e}). Initializing empty state.")
    return {"seen_links": []}


def save_state(seen_links_list):
    trimmed = seen_links_list[-4000:]
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump({"seen_links": trimmed}, f, indent=2)


def fetch_news(feed_config):
    query_encoded = urllib.parse.quote(feed_config["query"])
    url = f"https://news.google.com/rss/search?q={query_encoded}&hl={feed_config['lang']}&gl={feed_config['gl']}&ceid={feed_config['ceid']}"
    
    req = urllib.request.Request(
        url, 
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    )
    
    with urllib.request.urlopen(req, timeout=12) as resp:
        data = resp.read()
        
    root = ET.fromstring(data)
    items = []
    now = datetime.now(timezone.utc)
    max_age = timedelta(hours=MAX_ARTICLE_AGE_HOURS)
    
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
            items.append((title, link, guid))
            
    return items


def send_notification(title, message, priority="default", tags=""):
    if not NTFY_URL:
        print(f"[No NTFY Configured] {title}\n{message}")
        return
        
    headers = {
        "Title": title.encode("utf-8").decode("latin-1", "replace"),
        "Priority": priority,
    }
    if tags:
        headers["Tags"] = tags
        
    try:
        req = urllib.request.Request(
            NTFY_URL,
            data=message.encode("utf-8"),
            headers=headers,
            method="POST"
        )
        urllib.request.urlopen(req, timeout=15)
    except Exception as e:
        print(f"Failed to send push alert '{title}': {e}")


def send_feed_digest(label, items):
    formatted_items = [f"{i+1}. {title}\n{link}" for i, (title, link) in enumerate(items)]
    
    chunks = []
    current_chunk = []
    current_length = 0
    
    for item_str in formatted_items:
        item_bytes = len(item_str.encode("utf-8")) + 2
        if current_chunk and (current_length + item_bytes > MAX_PAYLOAD_BYTES):
            chunks.append(current_chunk)
            current_chunk = [item_str]
            current_length = item_bytes
        else:
            current_chunk.append(item_str)
            current_length += item_bytes
            
    if current_chunk:
        chunks.append(current_chunk)
        
    total_chunks = len(chunks)
    for idx, chunk in enumerate(chunks, 1):
        suffix = f" (Part {idx}/{total_chunks})" if total_chunks > 1 else ""
        title = f"🚨 {label} ({len(items)} alerts){suffix}"
        message = "\n\n".join(chunk)
        
        send_notification(title, message, priority="urgent", tags="warning,rotating_light")
        print(f"Sent alert for '{label}'{suffix}: {len(chunk)} items.")
        time.sleep(SECONDS_BETWEEN_NOTIFICATIONS)


def main():
    state = load_state()
    seen_links_list = state.get("seen_links", [])
    seen_set = set(seen_links_list)
    
    quiet_feeds = []
    failed_feeds = []
    
    try:
        results = {}
        with ThreadPoolExecutor(max_workers=len(TARGET_FEEDS)) as executor:
            future_to_feed = {executor.submit(fetch_news, feed): feed for feed in TARGET_FEEDS}
            for future in as_completed(future_to_feed):
                feed = future_to_feed[future]
                label = feed["label"]
                try:
                    results[label] = future.result()
                except Exception as e:
                    print(f"Error fetching feed '{label}': {e}")
                    results[label] = []
                    failed_feeds.append(label)
                    
        for feed in TARGET_FEEDS:
            label = feed["label"]
            articles = results.get(label, [])
            new_items = []
            
            for title, link, guid in articles:
                item_id = guid if guid else link
                if item_id not in seen_set:
                    new_items.append((title, link))
                    seen_set.add(item_id)
                    seen_links_list.append(item_id)
                    
            if new_items:
                send_feed_digest(label, new_items)
            else:
                quiet_feeds.append(label)
                
        if quiet_feeds and len(quiet_feeds) == len(TARGET_FEEDS):
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            print(f"Status check at {now}: All feeds operational, 0 new incident triggers.")
            
    finally:
        save_state(seen_links_list)
        
    if failed_feeds and len(failed_feeds) == len(TARGET_FEEDS):
        print("CRITICAL: All RSS feeds failed. Terminating with non-zero exit.")
        sys.exit(1)


if __name__ == "__main__":
    main()
