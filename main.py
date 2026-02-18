import requests
import re
import time
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Arizona is MST (UTC-7) year-round
AZ_TZ = timezone(timedelta(hours=-7))

VERSION = "2026.02.17.CORE_CLEAN_ULTIMATE"

CORE_SOURCES = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    "https://badmojr.github.io/1Hosts/Lite/adblock.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.txt",
    "https://big.oisd.nl",
    "https://nsfw.oisd.nl",
    "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adguard/dns-rebind-protection.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
]

SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"

# Domains matching these keywords are counted but NOT removed —
# we include NSFW sources on purpose. Toggle APPLY_NSFW_FILTER to True
# if you want to actively drop them.
NSFW_REGEX = re.compile(
    r"(?i)(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|"
    r"hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|"
    r"horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|"
    r"xnxx|xvideo|xxvideo|camgirl|nude|naked)"
)
APPLY_NSFW_FILTER = False  # set True to actively drop keyword-matched domains

OUTPUT_FILE = "blocklist.txt"
YOUTUBE_RULE = (
    "/^(www\\.|m\\.|youtubei\\.|youtube\\.)?(youtube(-nocookie)?\\.com|"
    "googleapis\\.com)$/$dnsrewrite=restrictmoderate.youtube.com"
)

MAX_RETRIES = 3
RETRY_DELAY = 3


# ---------------------------------------------------------------------------
# Fetch helpers
# ---------------------------------------------------------------------------

def fetch(url, retries=MAX_RETRIES):
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(
                url,
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=(5, 30),
            )
            r.raise_for_status()
            return r.text.splitlines()
        except Exception as e:
            if attempt < retries:
                print(f"  [!] Attempt {attempt}/{retries} failed for {url}: {e} — retrying in {RETRY_DELAY}s")
                time.sleep(RETRY_DELAY)
            else:
                print(f"  [!] All {retries} attempts failed for {url}: {e}")
                return []


def fetch_all_parallel(urls, max_workers=6):
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(fetch, url): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            results[url] = future.result()
    return results


# ---------------------------------------------------------------------------
# TLD helpers
# ---------------------------------------------------------------------------

def parse_tld_patterns(lines):
    """
    Parse Hagezi spam TLD list into plain TLD strings.
    Handles: ||*.xyz^  ||*.co.uk^  *.accountant
    Returns list sorted longest-first so multi-part TLDs match before single-part.
    """
    patterns = set()
    for line in lines:
        clean = line.split("!")[0].split("#")[0].strip().lower()
        if not clean:
            continue
        clean = clean.replace("||", "").replace("^", "")
        if clean.startswith("*."):
            clean = clean[2:]
        clean = clean.lstrip(".")
        if clean:
            patterns.add(clean)
    return sorted(patterns, key=len, reverse=True)


def get_matching_tld(host, patterns_sorted):
    """Return the matching spam TLD if host ends with one, else None."""
    for p in patterns_sorted:
        if host == p or host.endswith("." + p):
            return p
    return None


# ---------------------------------------------------------------------------
# Rule parsing
# ---------------------------------------------------------------------------

def parse_rules(lines):
    """Extract valid DNS-compatible block rules. Returns list of (rule, host) tuples."""
    rules = []
    for line in lines:
        clean = line.split("!")[0].split("#")[0].strip()
        if not clean.startswith("||") or "$" in clean:
            continue
        if "^" not in clean:
            clean += "^"
        host = clean.replace("||", "").split("^")[0].lower().strip(".")
        if host:
            rules.append((clean, host))
    return rules


# ---------------------------------------------------------------------------
# Subdomain deduplication
# ---------------------------------------------------------------------------

def prune_subdomains(rules_set):
    """
    Remove rules whose host is a subdomain of another blocked host.
    e.g. if ||example.com^ is blocked, ||sub.example.com^ is redundant.
    Returns (pruned_set, removed_count).
    """
    host_to_rule = {}
    for rule in rules_set:
        host = rule.replace("||", "").split("^")[0].lower().strip(".")
        host_to_rule[host] = rule

    all_hosts = set(host_to_rule.keys())
    pruned = set()
    removed = 0

    for host, rule in host_to_rule.items():
        parts = host.split(".")
        is_redundant = any(
            ".".join(parts[i:]) in all_hosts
            for i in range(1, len(parts))
        )
        if is_redundant:
            removed += 1
        else:
            pruned.add(rule)

    return pruned, removed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    start_time = time.time()
    print(f"[*] DNS Blocklist Generator {VERSION}")
    print(f"    NSFW keyword filter: {'ACTIVE (dropping matches)' if APPLY_NSFW_FILTER else 'OBSERVE ONLY (counting matches, not dropping)'}")

    # Spam TLD list
    print("\n[*] Fetching Hagezi Spam TLDs...")
    spam_tld_raw = fetch(SPAM_TLD_URL)
    spam_patterns = parse_tld_patterns(spam_tld_raw)
    print(f"    -> {len(spam_patterns)} TLD patterns loaded")
    print(f"    -> Sample patterns: {spam_patterns[:8]}")

    # Fetch all sources in parallel
    print(f"\n[*] Fetching {len(CORE_SOURCES)} sources in parallel...")
    fetched = fetch_all_parallel(CORE_SOURCES)

    # Process rules
    print("\n[*] Processing rules...\n")
    col = f"    {'Source':<42} {'Lines':>8}  {'Added':>8}  {'Drop(TLD)':>10}  {'Drop(KW)':>10}"
    print(col)
    print("    " + "-" * (len(col) - 4))

    raw_rules = set()
    total_dropped_tld = 0
    total_dropped_kw = 0

    for url in CORE_SOURCES:
        lines = fetched.get(url, [])
        source_name = url.split("/")[-1] or url.split("/")[-2]
        before = len(raw_rules)
        dropped_tld = 0
        dropped_kw = 0

        for rule, host in parse_rules(lines):
            # Check spam TLD
            if get_matching_tld(host, spam_patterns):
                dropped_tld += 1
                continue

            # Check NSFW keyword
            if NSFW_REGEX.search(host):
                dropped_kw += 1
                if APPLY_NSFW_FILTER:
                    continue  # actively drop if filter is on

            raw_rules.add(rule)

        added = len(raw_rules) - before
        total_dropped_tld += dropped_tld
        total_dropped_kw += dropped_kw
        print(
            f"    {source_name:<42} {len(lines):>8,}  {added:>8,}  {dropped_tld:>10,}  {dropped_kw:>10,}"
        )

    print(f"\n    {'TOTAL':<42} {'':>8}  {len(raw_rules):>8,}  {total_dropped_tld:>10,}  {total_dropped_kw:>10,}")
    print(f"\n[*] Raw rules after filters: {len(raw_rules):,}")

    # Subdomain deduplication
    print("\n[*] Pruning redundant subdomain rules...")
    final_rules, removed_subdomains = prune_subdomains(raw_rules)
    print(f"    -> Removed {removed_subdomains:,} redundant subdomain rules")
    print(f"    -> Final rule count: {len(final_rules):,}")

    # Write output
    elapsed = time.time() - start_time
    now = datetime.now(AZ_TZ).strftime("%Y-%m-%d %H:%M:%S MST")
    nsfw_filter_note = (
        f"! NSFW keyword filter: ACTIVE — {total_dropped_kw:,} domains dropped\n"
        if APPLY_NSFW_FILTER
        else f"! NSFW keyword filter: OBSERVE ONLY — {total_dropped_kw:,} keyword-matched domains were NOT dropped\n"
    )

    print(f"\n[*] Writing {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(
            f"! Clean DNS Blocklist\n"
            f"! Version: {VERSION}\n"
            f"! Generated: {now}\n"
            f"! Build time: {elapsed:.1f}s\n"
            f"! Rules: {len(final_rules):,}\n"
            f"! Dropped (spam TLD filter): {total_dropped_tld:,}\n"
            f"! Dropped (subdomain dedup): {removed_subdomains:,}\n"
            + nsfw_filter_note + "\n"
        )
        f.write("! --- DNS-COMPATIBLE CORE BLOCK RULES ---\n")
        f.write("\n".join(sorted(final_rules)))
        f.write("\n\n")
        f.write("! --- HAGEZI SPAM TLDs (RAW) ---\n")
        f.write("\n".join(spam_tld_raw))
        f.write("\n\n")
        f.write("! --- CUSTOM ENFORCEMENT & SAFESEARCH ---\n")
        f.write(YOUTUBE_RULE + "\n\n")
        f.write(f"! NSFW Regex pattern: {NSFW_REGEX.pattern}\n")

    print(f"\n[+] SUCCESS — {len(final_rules):,} rules written to {OUTPUT_FILE}")
    print(f"    Spam TLD filter dropped:    {total_dropped_tld:,}")
    print(f"    Keyword matches (NSFW):     {total_dropped_kw:,}  ({'dropped' if APPLY_NSFW_FILTER else 'observed only — set APPLY_NSFW_FILTER=True to drop'})")
    print(f"    Subdomain dedup dropped:    {removed_subdomains:,}")
    print(f"    Build time:                 {elapsed:.1f}s")


if __name__ == "__main__":
    main()
