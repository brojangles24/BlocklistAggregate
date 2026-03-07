import requests
import re
import time
import argparse
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# Arizona is MST (UTC-7) year-round
AZ_TZ = timezone(timedelta(hours=-7))

VERSION = "2026.03.04.OPTIMIZED"

DEFAULT_SOURCES = [
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt", # Threat Intel Full ~ 600k
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt", # Threat Intel Medium ~ 300k
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt", # Threat Intel Mini ~ 150k
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.txt", # Hagezi Ultimate ~ 300k
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt", # Hagezi Pro++ ~ 250k
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt", # Hagezi Pro ~ 200k
    "https://badmojr.github.io/1Hosts/Lite/adblock.txt", # 1Hosts Lite ~ 95k
    #"https://big.oisd.nl", # OISD Full ~ 300k
    #"https://nsfw.oisd.nl", # OISD NSFW Full ~ 300k
    "https://nsfw-small.oisd.nl", #OISD NSFW Small ~ 25k
    "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adguard/dns-rebind-protection.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
    #"https://raw.githubusercontent.com/laylavish/uBlockOrigin-HUGE-AI-Blocklist/refs/heads/main/noai_hosts.txt",
]

SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"

YOUTUBE_RULE = (
    "/^(www\\.|m\\.|youtubei\\.|youtube\\.)?(youtube(-nocookie)?\\.com|"
    "googleapis\\.com)$/$dnsrewrite=restrictmoderate.youtube.com"
)

NSFW_REGEX = re.compile(
    r"(?i)(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|"
    r"hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|"
    r"horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|"
    r"xnxx|xvideo|xxvideo|camgirl|nude|naked)"
)

APPLY_NSFW_FILTER = True
MAX_RETRIES = 3
RETRY_DELAY = 3

# ---------------------------------------------------------------------------
# Fetch helpers (Optimized with Connection Pooling & Streaming)
# ---------------------------------------------------------------------------

def fetch_stream(url, session, retries=MAX_RETRIES):
    for attempt in range(1, retries + 1):
        try:
            r = session.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=(5, 30), stream=True)
            r.raise_for_status()
            # iter_lines prevents loading a massive single string into memory
            return [line for line in r.iter_lines(decode_unicode=True) if line]
        except Exception as e:
            if attempt < retries:
                print(f"  [!] Attempt {attempt}/{retries} failed for {url}: {e} — retrying in {RETRY_DELAY}s")
                time.sleep(RETRY_DELAY)
            else:
                print(f"  [!] All {retries} attempts failed for {url}: {e}")
                return []

def fetch_all_parallel(urls, max_workers=6):
    results = {}
    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {executor.submit(fetch_stream, url, session): url for url in urls}
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
    for i in range(len(parts)):
        candidate = ".".join(parts[i:])
        if candidate in spam_set:
            if candidate in denyallow_map and host in denyallow_map[candidate]:
                return None 
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

        if clean.startswith("/") and clean.endswith("/"):
            yield ('regex', clean)
            continue

        if clean.startswith("0.0.0.0 ") or clean.startswith("127.0.0.1 "):
            parts = clean.split()
            if len(parts) >= 2:
                host = parts[1].lower().strip(".")
                if host:
                    yield ('domain', f"||{host}^", host)
            continue

        if not clean.startswith("||") and " " not in clean and "*" not in clean and "/" not in clean:
            host = clean.lower().strip(".")
            if host:
                yield ('domain', f"||{host}^", host)
            continue

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
    parser = argparse.ArgumentParser(description="DNS Blocklist Generator")
    parser.add_argument("-o", "--output", default="blocklist.txt", help="Output filename")
    args = parser.parse_args()

    start_time = time.time()
    print(f"[*] DNS Blocklist Generator {VERSION}")
    print(f"    NSFW filter: {'ACTIVE' if APPLY_NSFW_FILTER else 'OBSERVE ONLY'}")

    print("\n[*] Fetching Hagezi Spam TLDs...")
    with requests.Session() as session:
        spam_tld_raw = fetch_stream(SPAM_TLD_URL, session)
    spam_patterns_set, denyallow_map = parse_tld_patterns(spam_tld_raw)
    
    print(f"\n[*] Fetching {len(DEFAULT_SOURCES)} sources in parallel...")
    fetched = fetch_all_parallel(DEFAULT_SOURCES)

    print("\n[*] Processing rules...\n")
    header = f"    {'Source':<42} {'Lines':>8}  {'Added':>8}  {'Drop(TLD)':>10}  {'Drop(KW)':>10}"
    print(header)
    print("    " + "-" * (len(header) - 4))

    raw_domain_rules = {} 
    all_regex_rules = set()
    total_dropped_tld = 0
    total_dropped_kw = 0

    for url in DEFAULT_SOURCES:
        lines = fetched.get(url, [])
        source_name = url.split("/")[-1] or url.split("/")[-2]
        before = len(raw_domain_rules)
        dropped_tld = 0
        dropped_kw = 0

        for rule_type, *data in parse_rules(lines):
            if rule_type == 'regex':
                all_regex_rules.add(data[0])
                continue
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

    print(f"\n[*] Writing {args.output} (Memory-efficient write)...")
    final_rules = sorted(raw_domain_rules.values())

    elapsed = time.time() - start_time
    now = datetime.now(AZ_TZ).strftime("%Y-%m-%d %I:%M:%S %p MST")
    
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(
            f"! Title: Jorgensen DNS Blocklist\n"
            f"! Version: {VERSION}\n"
            f"! Generated: {now}\n"
            f"! Build time: {elapsed:.1f}s\n"
            f"! Rules: {len(final_rules):,}\n"
            f"! Regex rules: {len(all_regex_rules)}\n"
            f"! Dropped (spam TLD filter): {total_dropped_tld:,}\n"
            f"! Dropped (NSFW filter): {total_dropped_kw:,}\n\n"
        )
        
        f.write("! --- REGEX RULES (DNS REBIND PROTECTION + OTHER) ---\n")
        for rule in sorted(all_regex_rules):
            f.write(f"{rule}\n")
            
        f.write("\n! --- DNS-COMPATIBLE CORE BLOCK RULES ---\n")
        for rule in final_rules:
            f.write(f"{rule}\n")
            
        f.write("\n! --- HAGEZI SPAM TLDs (RAW) ---\n")
        for rule in spam_tld_raw:
            f.write(f"{rule}\n")
            
        f.write("\n! --- CUSTOM ENFORCEMENT & SAFESEARCH ---\n")
        f.write(YOUTUBE_RULE + "\n\n")
        f.write(f"! --- NSFW REGEX RULE ---\n")
        f.write(f"/{NSFW_REGEX.pattern}/\n")

    print(f"\n[+] SUCCESS — {len(final_rules):,} domain rules written to {args.output} in {elapsed:.1f}s")

if __name__ == "__main__":
    main()
