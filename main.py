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
VERSION = "2026.03.13.MAX_SIGNAL"

# Dynamic Logic Sources (Fetched raw, appended to footer)
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
   # "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
   # "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
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

# Included all Top Lists, including Domcop
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

def process_line(line, col_idx, domains):
    parts = line.split(',')
    if len(parts) > col_idx:
        dom = parts[col_idx].strip().lower().strip('"')
        if not dom.startswith("http"):
            if dom and dom not in ("domain", "origin", "rank"):
                domains.add(dom)
        else:
            dom = dom.replace("https://", "").replace("http://", "").split('/')[0]
            if dom: domains.add(dom)

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
                        process_line(line, col_idx, domains)
        elif compression == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(r.content)) as gz:
                with io.TextIOWrapper(gz, encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f):
                        if skip_header and i == 0: continue
                        process_line(line, col_idx, domains)
        else:
            lines = r.text.splitlines()
            for i, line in enumerate(lines):
                if skip_header and i == 0: continue
                process_line(line, col_idx, domains)
        print(f"[+] Loaded {len(domains)} from {url.split('/')[-1]}")
    except Exception as e:
        print(f"[!] Fetch failed for {url}: {e}")
    return domains

def fetch_stream(url, session):
    try:
        r = session.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=(5, 30))
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print(f"[!] Fetch failed: {url} - {e}")
        return []

def has_suffix_match(host, lookup_set):
    if host in lookup_set: return True
    idx = host.find('.')
    while idx != -1:
        if host[idx+1:] in lookup_set: return True
        idx = host.find('.', idx + 1)
    return False

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
    
    dropped_irrelevant = 0
    dropped_kw = 0
    dropped_tld = 0
    dropped_dupes = 0

    print(f"[*] Starting build with {len(active_sources)} sources and Domcop (10M)...")

    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=4) as executor:
            top_futures = [executor.submit(fetch_top_list, url, idx, skip, comp) for url, idx, skip, comp in TOP_LISTS]
            future_spam = executor.submit(fetch_stream, SPAM_TLD_URL, session)
            future_to_url = {executor.submit(fetch_stream, url, session): url for url in active_sources}

            # 1. Master Allowlist
            master_allowlist = set()
            for future in as_completed(top_futures):
                master_allowlist.update(future.result())
            
            # Threshold raised for Domcop inclusion
            if len(master_allowlist) < 3000000:
                print(f"[FATAL] Master Allowlist too small ({len(master_allowlist)}). Check Domcop.")
                sys.exit(1)
            
            print(f"[*] Master Allowlist created with {len(master_allowlist)} unique domains.")

            # 2. Fetch Dynamic Logic (SafeSearch & Rebind)
            dynamic_logic = []
            
            rebind_lines = fetch_stream(REBIND_URL, session)
            dynamic_logic.append("\n! --- HAGEZI DYNAMIC REBIND PROTECTION ---")
            dynamic_logic.extend([l for l in rebind_lines if l.strip() and not l.startswith(('!', '#'))])
            
            dynamic_logic.append("\n! --- ADGUARD DYNAMIC SAFESEARCH REWRITES ---")
            for url in ADGUARD_SAFESEARCH_URLS:
                ss_lines = fetch_stream(url, session)
                dynamic_logic.extend([l for l in ss_lines if l.strip() and not l.startswith(('!', '#'))])

            # 3. Process Blocklists
            spam_tld_raw = future_spam.result()
            spam_patterns_set = set()
            for line in spam_tld_raw:
                clean = line.split("!")[0].split("#")[0].strip().lower()
                if clean:
                    spam_patterns_set.add(clean.replace("||", "").replace("^", "").lstrip("*").lstrip("."))

            print("[*] Filtering domain sources...")
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
                        if host: dropped_dupes += 1
                        continue

                    if host.startswith("www."): host = host[4:]

                    if not has_suffix_match(host, master_allowlist):
                        dropped_irrelevant += 1
                        continue
                    
                    if has_suffix_match(host, spam_patterns_set):
                        dropped_tld += 1
                        continue

                    if NSFW_REGEX.search(host):
                        dropped_kw += 1
                        continue

                    seen_domains.add(host)
                    final_domains.append(host)

    print("[*] Sorting...")
    final_domains.sort()
    now = datetime.now(AZ_TZ).strftime("%Y-%m-%d %I:%M:%S %p MST")
    
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(f"! Jorgensen High-Signal Blocklist | Version: {VERSION}\n")
        f.write(f"! Generated: {now}\n")
        f.write(f"! Stats -> Kept: {len(final_domains)} | Irrelevant: {dropped_irrelevant} | Dupes: {dropped_dupes}\n\n")
        
        # Write Blocklist
        for dom in final_domains:
            f.write(f"||{dom}^\n")
        
        # Write Spam TLDs
        f.write("\n! --- HAGEZI SPAM TLDS ---\n")
        for line in spam_tld_raw: f.write(f"{line}\n")
        
        # Write NSFW Regex
        f.write("\n! --- NSFW REGEX BLOCK ---\n")
        f.write(f"/{NSFW_PATTERN}/\n")

        # Write Logic (Rebind + SafeSearch) at the bottom
        for rule in dynamic_logic:
            f.write(f"{rule}\n")
        
    print(f"\n[+] Success. Kept {len(final_domains)} domains. Logic rules appended.")

if __name__ == "__main__":
    main()
