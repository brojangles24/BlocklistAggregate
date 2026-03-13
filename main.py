import requests
import re
import time
import argparse
import io
import zipfile
import gzip
import sys
import gc
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- CONFIGURATION ---
AZ_TZ = timezone(timedelta(hours=-7))
VERSION = "2026.03.13.GA_ULTIMATE"

# Dynamic Logic Sources (Parsed but not suffix-filtered)
REBIND_URL = "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adguard/dns-rebind-protection.txt"
ADGUARD_SAFESEARCH_URLS = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/engines_safe_search.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/youtube_safe_search.txt"
]

DEFAULT_SOURCES = [
    # --- HAGEZI THREAT INTEL ---
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt",

    # --- HAGEZI MAIN LISTS ---
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.mini.txt",

    # --- 1HOSTS ---
    #"https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Xtra/adblock.txt",
    "https://badmojr.github.io/1Hosts/Lite/adblock.txt",

    # --- OISD ---
    #"https://big.oisd.nl",
    #"https://nsfw.oisd.nl",
    "https://small.oisd.nl",
    "https://nsfw-small.oisd.nl",

    # --- SPECIALTY ---
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
    #"https://raw.githubusercontent.com/laylavish/uBlockOrigin-HUGE-AI-Blocklist/refs/heads/main/noai_hosts.txt",
]

SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"

TOP_LISTS = [
    ("https://tranco-list.eu/top-1m.csv.zip", 1, False, "zip"),
    ("http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip", 1, False, "zip"),
    #("https://www.domcop.com/files/top/top10milliondomains.csv.zip", 1, True, "zip"),
    ("https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz", 0, True, "gzip"),
    ("https://downloads.majestic.com/majestic_million.csv", 2, True, "raw"),
]

NSFW_PATTERN = (
    r"(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|"
    r"hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|"
    r"horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|"
    r"xnxx|xvideo|xxvideo|camgirl|nude|naked)"
)
NSFW_REGEX = re.compile(f"(?i){NSFW_PATTERN}")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def has_suffix_match(host, lookup_set):
    """Accurate suffix matching for TLDs and Subdomains."""
    if host in lookup_set: return True
    parts = host.split('.')
    for i in range(len(parts) - 1, 0, -1):
        # Creates '.top', then '.domain.top' etc to check against set
        suffix = "." + ".".join(parts[i:])
        if suffix in lookup_set:
            return True
    return False

def fetch_top_list(url, col_idx, skip_header, compression):
    domains = set()
    try:
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=60)
        r.raise_for_status()
        if compression == "zip":
            with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                filename = z.namelist()[0]
                with io.TextIOWrapper(z.open(filename), encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f):
                        if skip_header and i == 0: continue
                        parts = line.split(',')
                        if len(parts) > col_idx:
                            dom = parts[col_idx].strip().lower().strip('"')
                            if dom and not dom.startswith("http") and dom not in ("domain", "origin", "rank"):
                                domains.add(dom)
        elif compression == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(r.content)) as gz:
                with io.TextIOWrapper(gz, encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f):
                        if skip_header and i == 0: continue
                        parts = line.split(',')
                        if len(parts) > col_idx:
                            dom = parts[col_idx].strip().lower().strip('"')
                            if dom and dom not in ("domain", "origin", "rank"): domains.add(dom)
        else:
            for i, line in enumerate(r.text.splitlines()):
                if skip_header and i == 0: continue
                parts = line.split(',')
                if len(parts) > col_idx:
                    dom = parts[col_idx].strip().lower().strip('"')
                    if dom and dom not in ("domain", "origin", "rank"): domains.add(dom)
        print(f"[+] Loaded {len(domains)} from {url.split('/')[-1]}")
    except Exception as e:
        print(f"[!] Fetch failed for {url}: {e}")
    return domains

# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", default="blocklist.txt")
    args = parser.parse_args()

    active_sources = [s for s in DEFAULT_SOURCES if not s.startswith("#")]
    final_domains = []
    seen_domains = set()
    dropped_stats = {"irrelevant": 0, "kw": 0, "tld": 0, "dupes": 0}

    print(f"[*] Starting GitHub Actions Filter...")

    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=4) as executor:
            # 1. Fetch Top Lists
            top_futures = [executor.submit(fetch_top_list, url, idx, skip, comp) for url, idx, skip, comp in TOP_LISTS]
            master_allowlist = set()
            for future in as_completed(top_futures):
                master_allowlist.update(future.result())
            
            # Threshold Check
            if len(master_allowlist) < 3000000:
                print(f"[FATAL] Master Allowlist too small ({len(master_allowlist)}). Aborting.")
                sys.exit(1)
            
            print(f"[*] Master Allowlist: {len(master_allowlist)} unique domains.")
            gc.collect()

            # 2. Fetch Logic (SafeSearch/Rebind)
            dynamic_logic = []
            rebind_req = session.get(REBIND_URL, timeout=30)
            dynamic_logic.append("\n! --- HAGEZI DYNAMIC REBIND PROTECTION ---")
            dynamic_logic.extend([l for l in rebind_req.text.splitlines() if l.strip() and not l.startswith(('!', '#'))])
            
            dynamic_logic.append("\n! --- ADGUARD DYNAMIC SAFESEARCH ---")
            for url in ADGUARD_SAFESEARCH_URLS:
                r = session.get(url, timeout=30)
                dynamic_logic.extend([l for l in r.text.splitlines() if l.strip() and not l.startswith(('!', '#'))])

            # 3. Fetch Spam TLDs
            spam_req = session.get(SPAM_TLD_URL, timeout=30)
            spam_tld_raw = spam_req.text.splitlines()
            spam_patterns = set()
            for line in spam_tld_raw:
                clean = line.split("!")[0].split("#")[0].strip().lower()
                if clean:
                    p = clean.replace("||", "").replace("^", "").lstrip("*")
                    if not p.startswith("."): p = "." + p
                    spam_patterns.add(p)

            # 4. Processing Domain Blocklists
            print("[*] Filtering domain sources...")
            future_to_url = {executor.submit(lambda u: session.get(u, timeout=30).text.splitlines(), url): url for url in active_sources}
            
            for future in as_completed(future_to_url):
                for line in future.result():
                    clean = line.strip()
                    if not clean or clean.startswith(('!', '#', '[', ' ')): continue

                    host = None
                    if clean.startswith(("0.0.0.0 ", "127.0.0.1 ")):
                        parts = clean.split(None, 1)
                        if len(parts) == 2: host = parts[1].lower().strip(".")
                    elif clean.startswith("||") and "^" in clean:
                        host = clean[2:clean.find("^")].lower().strip(".")
                    elif "/" not in clean and "*" not in clean and " " not in clean:
                        host = clean.lower().strip(".")

                    if not host or host in seen_domains:
                        if host: dropped_stats["dupes"] += 1
                        continue

                    if host.startswith("www."): host = host[4:]

                    # --- FILTER CHAIN ---
                    if not has_suffix_match(host, master_allowlist):
                        dropped_stats["irrelevant"] += 1
                        continue
                    if has_suffix_match(host, spam_patterns):
                        dropped_stats["tld"] += 1
                        continue
                    if NSFW_REGEX.search(host):
                        dropped_stats["kw"] += 1
                        continue

                    seen_domains.add(host)
                    final_domains.append(host)

    print("[*] Sorting and writing...")
    final_domains.sort()
    now = datetime.now(AZ_TZ).strftime("%Y-%m-%d %I:%M:%S %p MST")
    
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(f"! Jorgensen High-Signal Blocklist | Version: {VERSION}\n")
        f.write(f"! Generated: {now}\n")
        f.write(f"! STATS -> Final: {len(final_domains)} | TLD: {dropped_stats['tld']} | NSFW: {dropped_stats['kw']} | Irrelevant: {dropped_stats['irrelevant']}\n\n")
        
        for dom in final_domains:
            f.write(f"||{dom}^\n")
        
        f.write("\n! --- HAGEZI SPAM TLDS ---\n")
        for line in spam_tld_raw: f.write(f"{line}\n")
        
        f.write("\n! --- NSFW REGEX BLOCK ---\n")
        f.write(f"/{NSFW_PATTERN}/\n")

        for rule in dynamic_logic:
            f.write(f"{rule}\n")
        
    print(f"\n[+] FINISHED. Final count: {len(final_domains)} domains.")
    if len(final_domains) > 530000:
        print(f"[!] WARNING: List is too large for iOS stability ({len(final_domains)} rules).")

if __name__ == "__main__":
    main()
