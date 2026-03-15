import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
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
VERSION = "2026.03.14.MAINTAINED_STATUS"

# ---------------------------------------------------------------------------
# MAIN LIST SELECTION
# ---------------------------------------------------------------------------
MAIN_SOURCES = [
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
    "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Xtra/adblock.txt",
    #"https://badmojr.github.io/1Hosts/Lite/adblock.txt",
    "https://badmojr.gitlab.io/addons_1hosts/kidSaf/adblock.txt",

    # --- OISD ---
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_big.txt",
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_small.txt",
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw_small.txt",

    # --- SPECIALTY ---
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
]

# ---------------------------------------------------------------------------
# MOBILE LIST SELECTION
# ---------------------------------------------------------------------------
MOBILE_SOURCES = [
    # Pick lighter versions for mobile performance
    # --- HAGEZI THREAT INTEL ---
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt",

    # --- HAGEZI MAIN LISTS ---
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.mini.txt",

    # --- 1HOSTS ---
    #"https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Xtra/adblock.txt",
    "https://badmojr.github.io/1Hosts/Lite/adblock.txt",
    #"https://badmojr.gitlab.io/addons_1hosts/kidSaf/adblock.txt",

    # --- OISD ---
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_big.txt",
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_small.txt",
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw_small.txt",

    # --- SPECIALTY ---
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
]

# Shared Core Resources
SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"
REBIND_URL = "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adguard/dns-rebind-protection.txt"
ADGUARD_SAFESEARCH_URLS = ["https://adguardteam.github.io/HostlistsRegistry/assets/engines_safe_search.txt"]

TOP_LISTS = [
    ("https://tranco-list.eu/top-1m.csv.zip", 1, False, "zip"),
    ("http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip", 1, False, "zip"),
    ("https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz", 0, True, "gzip"),
    ("https://downloads.majestic.com/majestic_million.csv", 2, True, "raw"),
]

NSFW_PATTERN = r"(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo|camgirl|nude|naked)"
NSFW_REGEX = re.compile(f"(?i){NSFW_PATTERN}")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_retry_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session

def has_suffix_match(host, lookup_set):
    if host in lookup_set: return True
    parts = host.split('.')
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in lookup_set: return True
    return False

def _parse_csv_lines(iterable, col_idx, skip_header):
    domains = set()
    for i, line in enumerate(iterable):
        if skip_header and i == 0: continue
        parts = line.split(',')
        if len(parts) > col_idx:
            dom = parts[col_idx].strip().lower().strip('"')
            if dom and "." in dom: domains.add(dom)
    return domains

def fetch_top_list(url, col_idx, skip_header, compression):
    try:
        session = get_retry_session()
        r = session.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=90)
        r.raise_for_status()
        if compression == "zip":
            with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                with io.TextIOWrapper(z.open(z.namelist()[0]), encoding='utf-8', errors='ignore') as f:
                    return _parse_csv_lines(f, col_idx, skip_header)
        elif compression == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(r.content)) as gz:
                with io.TextIOWrapper(gz, encoding='utf-8', errors='ignore') as f:
                    return _parse_csv_lines(f, col_idx, skip_header)
        else:
            return _parse_csv_lines(r.text.splitlines(), col_idx, skip_header)
    except Exception as e:
        print(f"[-] Failed to fetch top list {url}: {e}")
        return set()

def fetch_source_lines(url):
    try:
        session = get_retry_session()
        r = session.get(url, stream=True, timeout=60)
        r.raise_for_status()
        return [l.strip() for l in r.iter_lines(decode_unicode=True) if l and not l.strip().startswith(('!', '#', '[', ' '))]
    except Exception as e:
        print(f"[-] Failed to fetch source {url}: {e}")
        return []

def parse_tld_patterns(lines):
    tld_patterns, denyallow_map = set(), {}
    for line in lines:
        clean = line.split("!")[0].split("#")[0].strip().lower()
        if not clean: continue
        denyallow_hosts = set()
        if "$" in clean:
            rule_part, _, modifiers = clean.partition("$")
            for mod in modifiers.split(","):
                if mod.startswith("denyallow="):
                    denyallow_hosts = set(mod[len("denyallow="):].split("|"))
        else: rule_part = clean
        
        rule_part = rule_part.replace("||", "").replace("^", "").replace("*", "").lstrip(".")
        if rule_part:
            tld_patterns.add(rule_part)
            if denyallow_hosts: denyallow_map[rule_part] = denyallow_hosts
    return tld_patterns, denyallow_map

def get_matching_tld(host, spam_set, denyallow_map):
    parts = host.split('.')
    for i in range(len(parts)):
        candidate = ".".join(parts[i:])
        if candidate in spam_set:
            if candidate in denyallow_map and host in denyallow_map[candidate]: return None
            return candidate
    return None

def extract_host(clean):
    if "*" in clean or "/" in clean:
        return None
    if clean.startswith(("0.0.0.0 ", "127.0.0.1 ")):
        parts = clean.split(None, 1)
        return parts[1].lower().strip(".") if len(parts) == 2 else None
    elif clean.startswith("||") and "^" in clean:
        return clean[2:clean.find("^")].lower().strip(".")
    elif " " not in clean:
        return clean.lower().strip(".")
    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", default="blocklist.txt")
    parser.add_argument("-m", "--mobile", default="mobile-blocklist.txt")
    args = parser.parse_args()

    active_main = [s for s in MAIN_SOURCES if s and not s.startswith(("#", "//"))]
    active_mobile = [s for s in MOBILE_SOURCES if s and not s.startswith(("#", "//"))]
    all_unique_urls = list(set(active_main + active_mobile))

    with ThreadPoolExecutor(max_workers=4) as executor:
        print("[*] Loading master logic (Allowlists/TLDs)...")
        top_futures = [executor.submit(fetch_top_list, *t) for t in TOP_LISTS]
        
        session = get_retry_session()
        try:
            spam_req = session.get(SPAM_TLD_URL, timeout=30)
            spam_req.raise_for_status()
            spam_patterns_set, denyallow_map = parse_tld_patterns(spam_req.text.splitlines())
        except Exception as e:
            print(f"[-] Failed to fetch SPAM TLDs: {e}")
            spam_patterns_set, denyallow_map = set(), {}

        print(f"[*] Downloading {len(all_unique_urls)} source files...")
        source_data = {}
        fetch_futures = {executor.submit(fetch_source_lines, url): url for url in all_unique_urls}
        
        master_allowlist = set()
        for future in as_completed(top_futures):
            master_allowlist.update(future.result())

        for future in as_completed(fetch_futures):
            source_data[fetch_futures[future]] = future.result()

    def build_dataset(urls, s_set, d_map, a_list):
        found = set()
        stats = {"irrelevant": 0, "kw": 0, "tld": 0, "duplicate": 0}
        for url in urls:
            for line in source_data.get(url, []):
                host = extract_host(line)
                if not host: continue
                if host.startswith("www."): host = host[4:]
                
                # Check duplicates first
                if host in found:
                    stats["duplicate"] += 1
                    continue
                
                # Check TLD matching
                if get_matching_tld(host, s_set, d_map):
                    stats["tld"] += 1
                    continue
                if NSFW_REGEX.search(host):
                    stats["kw"] += 1
                    continue
                if not has_suffix_match(host, a_list):
                    stats["irrelevant"] += 1
                    continue
                
                found.add(host)
        return found, stats

    print("[*] Generating Main List...")
    main_set, main_stats = build_dataset(active_main, spam_patterns_set, denyallow_map, master_allowlist)
    print("[*] Generating Mobile List...")
    mobile_set, mobile_stats = build_dataset(active_mobile, spam_patterns_set, denyallow_map, master_allowlist)

    # Free memory before final processing and file writing
    del source_data
    gc.collect()

    print("[*] Fetching Dynamic Footers...")
    try:
        rebind_text = session.get(REBIND_URL, timeout=30).text if REBIND_URL else ""
    except Exception as e:
        print(f"[-] Failed to fetch Rebind rules: {e}")
        rebind_text = ""
        
    ss_rules = []
    for url in ADGUARD_SAFESEARCH_URLS:
        try:
            r = session.get(url, timeout=30)
            r.raise_for_status()
            ss_rules.extend([l for l in r.text.splitlines() if l.strip() and not l.startswith(('!', '#'))])
        except Exception as e:
            print(f"[-] Failed to fetch SafeSearch rules from {url}: {e}")

    now = datetime.now(AZ_TZ).strftime("%Y-%m-%d %I:%M:%S %p MST")
    
    # Write both lists
    for filename, dataset, s, label in [(args.output, main_set, main_stats, "MAIN"), (args.mobile, mobile_set, mobile_stats, "MOBILE")]:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"! Jorgensen {label} List | Version: {VERSION}\n")
            f.write(f"! Generated: {now}\n")
            f.write(f"! Stats: Kept {len(dataset)} | Duplicates {s['duplicate']} | Irrelevant {s['irrelevant']} | TLD {s['tld']} | NSFW {s['kw']}\n\n")
            
            for dom in sorted(dataset): f.write(f"||{dom}^\n")
            
            f.write("\n! --- DYNAMIC REBIND PROTECTION ---\n" + rebind_text)
            f.write("\n! --- DYNAMIC SAFESEARCH ---\n")
            for rule in ss_rules: f.write(f"{rule}\n")
            f.write("\n! --- NSFW REGEX ---\n/" + NSFW_PATTERN + "/\n")
            
            if 'spam_req' in locals() and hasattr(spam_req, 'text'):
                f.write("\n! --- SPAM TLDs ---\n" + spam_req.text)

    print(f"[+] Complete. Main: {len(main_set)} | Mobile: {len(mobile_set)}")

if __name__ == "__main__":
    main()
