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
VERSION = "2026.03.14.FLAT_TOGGLE"

# ---------------------------------------------------------------------------
# MAIN LIST SELECTION
# Comment/Uncomment any URL below to enable or disable it for the MAIN list.
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
# Comment/Uncomment any URL below to enable or disable it for the MOBILE list.
# ---------------------------------------------------------------------------
MOBILE_SOURCES = [
    # Pick lighter versions for mobile performance
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.txt",
    "https://badmojr.github.io/1Hosts/Lite/adblock.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_small.txt",
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw_small.txt",
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

def fetch_top_list(url, col_idx, skip_header, compression):
    domains = set()
    try:
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=90)
        r.raise_for_status()
        if compression == "zip":
            with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                with io.TextIOWrapper(z.open(z.namelist()[0]), encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f):
                        if skip_header and i == 0: continue
                        parts = line.split(',')
                        if len(parts) > col_idx:
                            dom = parts[col_idx].strip().lower().strip('"')
                            if dom and "." in dom: domains.add(dom)
        elif compression == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(r.content)) as gz:
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
    except: pass
    return domains

def fetch_source_lines(url):
    try:
        r = requests.get(url, stream=True, timeout=60)
        r.raise_for_status()
        return [l.strip() for l in r.iter_lines(decode_unicode=True) if l and not l.strip().startswith(('!', '#', '[', ' '))]
    except: return []

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
        rule_part = rule_part.replace("||", "").replace("^", "").lstrip(".")
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

def has_suffix_match(host, lookup_set):
    if host in lookup_set: return True
    parts = host.split('.')
    for i in range(len(parts) - 1):
        parent = ".".join(parts[i+1:])
        if parent in lookup_set: return True
    return False

def extract_host(clean):
    if clean.startswith(("0.0.0.0 ", "127.0.0.1 ")):
        parts = clean.split(None, 1)
        return parts[1].lower().strip(".") if len(parts) == 2 else None
    elif clean.startswith("||") and "^" in clean:
        return clean[2:clean.find("^")].lower().strip(".")
    elif "/" not in clean and "*" not in clean and " " not in clean:
        return clean.lower().strip(".")
    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", default="blocklist.txt")
    parser.add_argument("-m", "--mobile", default="mobile-blocklist.txt")
    args = parser.parse_args()

    # Get only active (uncommented) URLs
    active_main = [s for s in MAIN_SOURCES if s and not s.startswith(("#", "//"))]
    active_mobile = [s for s in MOBILE_SOURCES if s and not s.startswith(("#", "//"))]
    all_unique_urls = list(set(active_main + active_mobile))

    with ThreadPoolExecutor(max_workers=4) as executor:
        print("[*] Loading master logic (Allowlists/TLDs)...")
        top_futures = [executor.submit(fetch_top_list, *t) for t in TOP_LISTS]
        
        spam_req = requests.get(SPAM_TLD_URL, timeout=30)
        spam_patterns_set, denyallow_map = parse_tld_patterns(spam_req.text.splitlines())

        print(f"[*] Downloading {len(all_unique_urls)} source files...")
        source_data = {}
        fetch_futures = {executor.submit(fetch_source_lines, url): url for url in all_unique_urls}
        
        master_allowlist = set()
        for future in as_completed(top_futures):
            master_allowlist.update(future.result())

        for future in as_completed(fetch_futures):
            source_data[fetch_futures[future]] = future.result()

    def build_dataset(urls):
        found = set()
        for url in urls:
            for line in source_data.get(url, []):
                host = extract_host(line)
                if not host: continue
                if host.startswith("www."): host = host[4:]
                if get_matching_tld(host, spam_patterns_set, denyallow_map): continue
                if NSFW_REGEX.search(host): continue
                if not has_suffix_match(host, master_allowlist): continue
                found.add(host)
        return found

    print("[*] Generating Main List...")
    main_set = build_dataset(active_main)
    print("[*] Generating Mobile List...")
    mobile_set = build_dataset(active_mobile)

    # Dynamic Footer Logic
    print("[*] Fetching Dynamic Footers...")
    rebind_text = requests.get(REBIND_URL, timeout=30).text if REBIND_URL else ""
    ss_rules = []
    for url in ADGUARD_SAFESEARCH_URLS:
        r = requests.get(url, timeout=30)
        ss_rules.extend([l for l in r.text.splitlines() if l.strip() and not l.startswith(('!', '#'))])

    now = datetime.now(AZ_TZ).strftime("%Y-%m-%d %I:%M:%S %p MST")
    
    # Write Files
    for filename, dataset, is_mobile in [(args.output, main_set, False), (args.mobile, mobile_set, True)]:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"! Jorgensen {'MOBILE' if is_mobile else 'MAIN'} List | Version: {VERSION}\n")
            f.write(f"! Generated: {now} | Count: {len(dataset)}\n\n")
            for dom in sorted(dataset): f.write(f"||{dom}^\n")
            
            # Append Dynamic Logic to BOTH lists (standard practice for high-signal)
            f.write("\n! --- DYNAMIC REBIND PROTECTION ---\n" + rebind_text)
            f.write("\n! --- DYNAMIC SAFESEARCH ---\n")
            for rule in ss_rules: f.write(f"{rule}\n")
            f.write("\n! --- NSFW REGEX ---\n/" + NSFW_PATTERN + "/\n")
            f.write("\n! --- SPAM TLDs ---\n" + spam_req.text)

    print(f"[+] Complete. Main: {len(main_set)} | Mobile: {len(mobile_set)}")

if __name__ == "__main__":
    main()
