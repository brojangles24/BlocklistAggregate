import requests
import re
import time
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# Arizona is MST (UTC-7) year-round
AZ_TZ = timezone(timedelta(hours=-7))

VERSION = "2026.02.22.ULTRA_FAST_NO_PRUNE"

CORE_SOURCES = [
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
    "https://badmojr.github.io/1Hosts/Lite/adblock.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.txt",
    #"https://big.oisd.nl",
    #"https://nsfw.oisd.nl",
    "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adguard/dns-rebind-protection.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
    #"https://raw.githubusercontent.com/laylavish/uBlockOrigin-HUGE-AI-Blocklist/refs/heads/main/noai_hosts.txt",
]

SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"

NSFW_REGEX = re.compile(
    r"(?i)(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|"
    r"hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|"
    r"horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|"
    r"xnxx|xvideo|xxvideo|camgirl|nude|naked)"
)

YOUTUBE_RULE = (
    "/^(www\\.|m\\.|youtubei\\.|youtube\\.)?(youtube(-nocookie)?\\.com|"
    "googleapis\\.com)$/$dnsrewrite=restrictmoderate.youtube.com"
)
APPLY_NSFW_FILTER = True

OUTPUT_FILE = "blocklist.txt"

MAX_RETRIES = 3
RETRY_DELAY = 3

# ---------------------------------------------------------------------------
# Fetch helpers
# ---------------------------------------------------------------------------

def fetch(url, retries=MAX_RETRIES):
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=(5, 30))
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
# TLD helpers (Optimized to O(1) lookups)
# ---------------------------------------------------------------------------

def parse_tld_patterns(lines):
    tld_patterns = set()
    denyallow_map = {}

    for line in lines:
        clean = line.split("!")[0].split("#")[0].strip().lower()
        if not clean:
            continue

        denyallow_hosts = set()
        if "$" in clean:
            rule_part, _, modifiers = clean.partition("$")
            for mod in modifiers.split(","):
                if mod.startswith("denyallow="):
                    denyallow_hosts = set(mod[len("denyallow="):].split("|"))
        else:
            rule_part = clean

        rule_part = rule_part.replace("||", "").replace("^", "")
        if rule_part.startswith("*."):
            rule_part = rule_part[2:]
        rule_part = rule_part.lstrip(".")

        if not rule_part:
            continue

        tld_patterns.add(rule_part)
        if denyallow_hosts:
            denyallow_map[rule_part] = denyallow_hosts

    return tld_patterns, denyallow_map

def get_matching_tld(host, spam_set, denyallow_map):
    parts = host.split('.')
    # Check suffixes from longest (whole domain) to shortest (TLD)
    for i in range(len(parts)):
        candidate = ".".join(parts[i:])
        if candidate in spam_set:
            if candidate in denyallow_map and host in denyallow_map[candidate]:
                return None # Whitelisted exception
            return candidate
    return None

# ---------------------------------------------------------------------------
# Rule parsing (Optimized with Generators)
# ---------------------------------------------------------------------------

def parse_rules(lines):
    for line in lines:
        clean = line.split("!")[0].split("#")[0].strip()
        if not clean:
            continue

        # Regex rules
        if clean.startswith("/") and clean.endswith("/"):
            yield ('regex', clean)
            continue

        # Hosts format (0.0.0.0 or 127.0.0.1)
        if clean.startswith("0.0.0.0 ") or clean.startswith("127.0.0.1 "):
            parts = clean.split()
            if len(parts) >= 2:
                host = parts[1].lower().strip(".")
                if host:
                    yield ('domain', f"||{host}^", host)
            continue

        # Plain domain format
        if not clean.startswith("||") and " " not in clean and "*" not in clean and "/" not in clean:
            host = clean.lower().strip(".")
            if host:
                yield ('domain', f"||{host}^", host)
            continue

        # Standard AdGuard DNS rules
        if not clean.startswith("||") or "$" in clean:
            continue
        if "^" not in clean:
            clean += "^"
        host = clean.replace("||", "").split("^")[0].lower().strip(".")
        if host:
            yield ('domain', clean, host)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    start_time = time.time()
    print(f"[*] DNS Blocklist Generator {VERSION}")
    print(f"    NSFW keyword filter: {'ACTIVE (dropping matches)' if APPLY_NSFW_FILTER else 'OBSERVE ONLY (counting, not dropping)'}")

    print("\n[*] Fetching Hagezi Spam TLDs...")
    spam_tld_raw = fetch(SPAM_TLD_URL)
    spam_patterns_set, denyallow_map = parse_tld_patterns(spam_tld_raw)
    
    print(f"\n[*] Fetching {len(CORE_SOURCES)} sources in parallel...")
    fetched = fetch_all_parallel(CORE_SOURCES)

    print("\n[*] Processing rules...\n")
    header = f"    {'Source':<42} {'Lines':>8}  {'Added':>8}  {'Drop(TLD)':>10}  {'Drop(KW)':>10}"
    print(header)
    print("    " + "-" * (len(header) - 4))

    raw_domain_rules = {} # Dictionary inherently deduplicates exact host matches
    all_regex_rules = set()
    total_dropped_tld = 0
    total_dropped_kw = 0

    for url in CORE_SOURCES:
        lines = fetched.get(url, [])
        source_name = url.split("/")[-1] or url.split("/")[-2]
        before = len(raw_domain_rules)
        dropped_tld = 0
        dropped_kw = 0

        for rule_type, *data in parse_rules(lines):
            if rule_type == 'regex':
                all_regex_rules.add(data[0])
                continue # FIX APPLIED HERE
            elif rule_type == 'domain':
                rule, host = data

            if get_matching_tld(host, spam_patterns_set, denyallow_map):
                dropped_tld += 1
                continue

            if NSFW_REGEX.search(host):
                dropped_kw += 1
                if APPLY_NSFW_FILTER:
                    continue

            raw_domain_rules[host] = rule

        added = len(raw_domain_rules) - before
        total_dropped_tld += dropped_tld
        total_dropped_kw += dropped_kw
        print(f"    {source_name:<42} {len(lines):>8,}  {added:>8,}  {dropped_tld:>10,}  {dropped_kw:>10,}")

    print(f"\n[*] Raw domains after filters: {len(raw_domain_rules):,}")

    print("\n[*] Formatting final rules...")
    final_rules = sorted(raw_domain_rules.values())

    elapsed = time.time() - start_time
    now = datetime.now(AZ_TZ).strftime("%Y-%m-%d %H:%M:%S MST")
    nsfw_note = (
        f"! NSFW keyword filter: ACTIVE — {total_dropped_kw:,} domains dropped\n"
        if APPLY_NSFW_FILTER
        else f"! NSFW keyword filter: OBSERVE ONLY — {total_dropped_kw:,} keyword-matched domains kept\n"
    )

    print(f"\n[*] Writing {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(
            f"! Title: Jorgensen DNS Blocklist\n"
            f"! Version: {VERSION}\n"
            f"! Generated: {now}\n"
            f"! Build time: {elapsed:.1f}s\n"
            f"! Rules: {len(final_rules):,}\n"
            f"! Regex rules: {len(all_regex_rules)}\n"
            f"! Dropped (spam TLD filter): {total_dropped_tld:,}\n"
            f"! Dropped (subdomain dedup): DISABLED\n"
            + nsfw_note + "\n"
        )
        f.write("! --- REGEX RULES (DNS REBIND PROTECTION + OTHER) ---\n")
        f.write("\n".join(sorted(all_regex_rules)) + "\n\n")
        f.write("! --- DNS-COMPATIBLE CORE BLOCK RULES ---\n")
        f.write("\n".join(final_rules) + "\n\n")
        f.write("! --- HAGEZI SPAM TLDs (RAW) ---\n")
        f.write("\n".join(spam_tld_raw) + "\n\n")
        f.write("! --- CUSTOM ENFORCEMENT & SAFESEARCH ---\n")
        #f.write(YOUTUBE_RULE + "\n\n")
        f.write(f"! --- NSFW REGEX RULE ---\n")
        f.write(f"/{NSFW_REGEX.pattern}/\n")

    print(f"\n[+] SUCCESS — {len(final_rules):,} domain rules written to {OUTPUT_FILE} in {elapsed:.1f}s")

if __name__ == "__main__":
    main()
