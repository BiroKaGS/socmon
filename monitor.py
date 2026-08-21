"""
Keyword Monitor
---------------
Checks Google News RSS for a set of keywords.

Features:
- Filters out any article older than 48 hours using RSS pubDate parsing.
- Keywords WITH new articles get individual high-priority notifications with ALL links.
- Automatically splits long messages into chunks (Part 1/2, etc.) so no links are truncated.
- Keywords WITHOUT new articles are combined into a single low-priority summary notification at the end.
- Preserves up to 3,000 seen article identifiers in state.json to eliminate duplicate notifications.
- Exits non-zero if EVERY keyword fails to fetch (e.g. RSS endpoint down/blocked), so the
  GitHub Actions run is marked failed, the heartbeat step is skipped, and the watchdog
  workflow can catch the outage instead of silently reporting success.

Requires only the Python standard library.
Expects the NTFY_TOPIC environment variable.
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

KEYWORDS = [
    "CISF",
    "SIKKA",
    "JAMNAGAR",
    "RIL",
    "STPS",
    "KUTCH",
    "GEB",
    "GSECL",
]

STATE_FILE = "state.json"
NTFY_TOPIC = os.environ.get("NTFY_TOPIC")
NTFY_URL = f"https://ntfy.sh/{NTFY_TOPIC}" if NTFY_TOPIC else None

SECONDS_BETWEEN_NOTIFICATIONS = 3  # Rate limit buffer for ntfy.sh
MAX_PAYLOAD_BYTES = 3500  # Safe limit per ntfy message (~4096 max)
MAX_ARTICLE_AGE_HOURS = 48  # Discard articles older than 48 hours


def load_state():
    """Loads state.json, preserving stored list order."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load {STATE_FILE} ({e}). Starting fresh.")
    return {"seen_links": []}


def save_state(seen_links_list):
    """Saves up to 3,000 recent items while preserving strict insertion order."""
    trimmed = seen_links_list[-3000:]
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump({"seen_links": trimmed}, f, indent=2)


def fetch_news(keyword):
    """Fetches RSS results for a keyword, ignoring articles older than MAX_ARTICLE_AGE_HOURS."""
    query = urllib.parse.quote(keyword)
    url = f"https://news.google.com/rss/search?q={query}&hl=en-IN&gl=IN&ceid=IN:en"

    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

    with urllib.request.urlopen(req, timeout=10) as resp:
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

        # Filter out old articles based on RSS pubDate
        if pub_date_str:
            try:
                pub_dt = email.utils.parsedate_to_datetime(pub_date_str)
                if now - pub_dt > max_age:
                    continue  # Skip old article
            except Exception:
                pass  # Fallback: keep article if timestamp parsing fails

        if title and link:
            items.append((title, link, guid))

    return items


def send_notification(title, message, priority="default", tags="", retries=2):
    """Sends a push notification via ntfy.sh with retry logic for 429 rate limits."""
    if not NTFY_URL:
        print(
            f"NTFY_TOPIC not set. Skipping notification:\n[{title}]\n{message}"
        )
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
                method="POST",
            )
            urllib.request.urlopen(req, timeout=15)
            return
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries:
                wait = 5 * attempt
                print(
                    f"Rate limited (429), waiting {wait}s before retry..."
                )
                time.sleep(wait)
                continue
            print(f"Failed to send notification '{title}': {e}")
            return
        except Exception as e:
            print(f"Failed to send notification '{title}': {e}")
            return


def send_keyword_digest(kw, items):
    """Formats and sends ALL items for a keyword, splitting into chunks if necessary."""
    formatted_items = [
        f"{i+1}. {title}\n{link}" for i, (title, link) in enumerate(items)
    ]

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
        part_suffix = (
            f" (Part {idx}/{total_chunks})" if total_chunks > 1 else ""
        )
        title = f"{kw} ({len(items)} new){part_suffix}"
        message = "\n\n".join(chunk)

        send_notification(
            title,
            message,
            priority="high",
            tags="bell",
        )
        print(f"Sent digest for '{kw}'{part_suffix}: {len(chunk)} item(s)")
        time.sleep(SECONDS_BETWEEN_NOTIFICATIONS)


def main():
    state = load_state()
    seen_links_list = state.get("seen_links", [])
    seen_set = set(seen_links_list)

    quiet_keywords = []
    failed_keywords = []

    try:
        # Fetch all keywords in parallel instead of one-by-one. Sequential fetches meant
        # a totally healthy "no updates" run still paid the sum of 7 network round-trips;
        # running them concurrently means total fetch time is roughly the slowest single
        # request instead of the sum of all of them.
        results = {}
        with ThreadPoolExecutor(max_workers=len(KEYWORDS)) as executor:
            future_to_kw = {executor.submit(fetch_news, kw): kw for kw in KEYWORDS}
            for future in as_completed(future_to_kw):
                kw = future_to_kw[future]
                try:
                    results[kw] = future.result()
                except Exception as e:
                    print(f"Error fetching RSS for '{kw}': {e}")
                    results[kw] = []
                    failed_keywords.append(kw)

        # Process results (and send notifications) in the original keyword order,
        # sequentially — notification sending still has a deliberate rate-limit sleep,
        # so it stays outside the parallel section.
        for kw in KEYWORDS:
            articles = results.get(kw, [])
            new_items = []
            for title, link, guid in articles:
                item_id = guid if guid else link
                if item_id not in seen_set:
                    new_items.append((title, link))
                    seen_set.add(item_id)
                    seen_links_list.append(item_id)

            if new_items:
                send_keyword_digest(kw, new_items)
            else:
                quiet_keywords.append(kw)

        # Group all keywords with zero new updates into a single heartbeat message
        if quiet_keywords:
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            quiet_list = "\n".join([f"- {kw}" for kw in quiet_keywords])
            send_notification(
                f"No new updates ({len(quiet_keywords)} keywords)",
                f"Checked at {now}.\nNo new articles since last run for:\n{quiet_list}",
                priority="min",
                tags="white_check_mark",
            )
            print(
                f"Sent summary heartbeat for {len(quiet_keywords)} quiet keyword(s)."
            )

    finally:
        save_state(seen_links_list)

    # If every single keyword failed to fetch, this run didn't actually check anything
    # useful (e.g. Google News RSS is down/blocked/rate-limiting us). Fail loudly so the
    # GitHub Actions step is marked failed, the heartbeat step is skipped, and the
    # watchdog workflow can alert on it instead of silently reporting a healthy run.
    if failed_keywords and len(failed_keywords) == len(KEYWORDS):
        print(
            f"FATAL: all {len(KEYWORDS)} keyword fetches failed this run: "
            f"{', '.join(failed_keywords)}"
        )
        sys.exit(1)
    elif failed_keywords:
        print(
            f"Warning: {len(failed_keywords)} of {len(KEYWORDS)} keyword fetches "
            f"failed this run: {', '.join(failed_keywords)}"
        )


if __name__ == "__main__":
    main()
