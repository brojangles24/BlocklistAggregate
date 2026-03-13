import requests
import re
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
VERSION = "2026.03.13.MAINTAINED_STATUS"

# Dynamic Logic Sources
REBIND_URL = "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adguard/dns-rebind-protection.txt"
ADGUARD_SAFESEARCH_URLS = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/engines_safe_search.txt",
    #"https://adguardteam.github.io/HostlistsRegistry/assets/youtube_safe_search.txt"
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
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_big.txt",
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_small.txt",
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw_small.txt",

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

NSFW_PATTERN = r"(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo|camgirl|nude|naked)"
NSFW_REGEX = re.compile(f"(?i){NSFW_PATTERN}")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def has_suffix_match(host, lookup_set):
    if host in lookup_set: return True
    parts = host.split('.')
    for i in range(len(parts) - 1):
        parent = ".".join(parts[i+1:])
        if parent in lookup_set:
            return True
    return False

def fetch_top_list(url, col_idx, skip_header, compression):
    domains = set()
    try:
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=90)
        r.raise_for_status()
        content = r.content
        if compression == "zip":
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                with io.TextIOWrapper(z.open(z.namelist()[0]), encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f):
                        if skip_header and i == 0: continue
                        parts = line.split(',')
                        if len(parts) > col_idx:
                            dom = parts[col_idx].strip().lower().strip('"')
                            if dom and "." in dom: domains.add(dom)
        elif compression == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(content)) as gz:
                with io.TextIOWrapper(gz, encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f):
                        if skip_header and i == 0: continue
                        parts = line.split(',')
                        if len(parts) > col_idx:
                            dom = parts[col_idx].strip().lower().strip('"')
                            if dom and "." in dom: domains.add(dom)
        else:
            for i, line in enumerate(r.text.splitlines()):
                if skip_header and i == 0: continue
                parts = line.split(',')
                if len(parts) > col_idx:
                    dom = parts[col_idx].strip().lower().strip('"')
                    if dom and "." in dom: domains.add(dom)
        print(f"[+] Loaded {len(domains)} from {url.split('/')[-1]}")
    except Exception as e:
        print(f"[!] Top list failed: {url} - {e}")
    return domains

def fetch_source_lines(url):
    try:
        # stream=True prevents loading massive files fully into RAM
        r = requests.get(url, stream=True, timeout=60)
        r.raise_for_status()
        lines = []
        for line in r.iter_lines(decode_unicode=True):
            if line:
                clean = line.strip()
                if clean and not clean.startswith(('!', '#', '[', ' ')):
                    lines.append(clean)
        return lines
    except Exception as e:
        print(f"[!] Failed to fetch {url}: {e}")
        return []

# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", default="blocklist.txt")
    args = parser.parse_args()

    active_sources = [s for s in DEFAULT_SOURCES if not s.startswith(("#", "//"))]
    active_top_lists = [t for t in TOP_LISTS if isinstance(t, tuple)]

    final_domains = set()  # Using a set to merge seen/final and save memory
    stats = {"irrelevant": 0, "kw": 0, "tld": 0, "dupes": 0}

    with ThreadPoolExecutor(max_workers=4) as executor:
        # 1. Fetch Allowlist
        top_futures = [executor.submit(fetch_top_list, *t) for t in active_top_lists]
        master_allowlist = set()
        for future in as_completed(top_futures):
            master_allowlist.update(future.result())
        gc.collect()

        # Safety Threshold for GitHub Actions
        if len(master_allowlist) < 1000000:
            sys.exit(f"[!] CRITICAL: Master allowlist too small ({len(master_allowlist)}). Aborting to prevent blank blocklist.")

        # 2. Fetch Spam TLDs
        try:
            spam_req = requests.get(SPAM_TLD_URL, timeout=30)
            spam_req.raise_for_status()
            raw_spam_text = spam_req.text  # Keep exact raw text for output

            # Extract pure TLDs into a set for exact matching
            spam_tlds = set()
            for line in raw_spam_text.splitlines():
                clean_line = line.strip()
                if clean_line and not clean_line.startswith(('!', '#')):
                    # Strip adguard modifiers to get raw tld
                    tld = clean_line.split('^')[0].split('$')[0].replace('||', '').strip()
                    if tld:
                        spam_tlds.add(tld)
        except Exception as e:
            print(f"[!] Failed to fetch Spam TLDs: {e}")
            raw_spam_text = ""
            spam_tlds = set()

        # 3. Fetch Blocklist Sources
        print(f"[*] Filtering {len(active_sources)} active sources...")
        future_to_url = {executor.submit(fetch_source_lines, url): url for url in active_sources}
        
        for future in as_completed(future_to_url):
            for clean in future.result():
                host = None
                if clean.startswith(("0.0.0.0 ", "127.0.0.1 ")):
                    parts = clean.split(None, 1)
                    if len(parts) == 2: host = parts[1].lower().strip(".")
                elif clean.startswith("||") and "^" in clean:
                    host = clean[2:clean.find("^")].lower().strip(".")
                elif "/" not in clean and "*" not in clean and " " not in clean:
                    host = clean.lower().strip(".")

                if not host or host in final_domains:
                    if host: stats["dupes"] += 1
                    continue

                if host.startswith("www."): host = host[4:]

                # --- THE BALANCED FILTER CHAIN ---
                # 1. Exact TLD check
                if host.split('.')[-1] in spam_tlds:
                    stats["tld"] += 1
                    continue

                # 2. NSFW Keyword check
                if NSFW_REGEX.search(host):
                    stats["kw"] += 1
                    continue

                # 3. Irrelevant check (Allowlist)
                if not has_suffix_match(host, master_allowlist):
                    stats["irrelevant"] += 1
                    continue

                final_domains.add(host)

    # 4. Fetch Dynamic Logic (SafeSearch/Rebind)
    print("[*] Fetching dynamic footers...")
    try:
        rebind_text = requests.get(REBIND_URL, timeout=30).text
    except Exception:
        rebind_text = ""

    ss_rules = []
    for url in ADGUARD_SAFESEARCH_URLS:
        try:
            ss_rules.extend([l for l in requests.get(url, timeout=30).text.splitlines() if l.strip() and not l.startswith(('!', '#'))])
        except Exception:
            pass

    # 5. Write Output
    now = datetime.now(AZ_TZ).strftime("%Y-%m-%d %I:%M:%S %p MST")
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(f"! Jorgensen High-Signal Blocklist | Version: {VERSION}\n")
        f.write(f"! Generated: {now}\n")
        f.write(f"! Stats: Kept {len(final_domains)} | Irrelevant {stats['irrelevant']} | TLD {stats['tld']} | NSFW {stats['kw']}\n\n")
        
        for dom in sorted(final_domains): 
            f.write(f"||{dom}^\n")
        
        f.write("\n! --- DYNAMIC REBIND PROTECTION ---\n")
        if rebind_text: f.write(rebind_text)
        
        f.write("\n! --- DYNAMIC SAFESEARCH ---\n")
        for rule in ss_rules: f.write(f"{rule}\n")
        
        f.write("\n! --- NSFW REGEX BLOCK ---\n")
        f.write(f"/{NSFW_PATTERN}/\n")

        f.write("\n! --- SPAM TLDs ---\n")
        if raw_spam_text: f.write(raw_spam_text + "\n")

    print(f"[+] Final count: {len(final_domains)} domains.")

if __name__ == "__main__":
    main()
