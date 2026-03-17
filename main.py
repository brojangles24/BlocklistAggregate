#!/usr/bin/env python3
from __future__ import annotations
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse
import re
import argparse
import io
import zipfile
import gzip
import sys
import gc
import os
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- CONFIGURATION ---
AZ_TZ = timezone(timedelta(hours=-7))
VERSION = "2026.03.16.HOSTER_TRACKED"
DEBUG_SAMPLES = os.getenv("DEBUG_SAMPLES", "0") == "1"

# ---------------------------------------------------------------------------
# MAIN LIST SELECTION
# ---------------------------------------------------------------------------
MAIN_SOURCES = [
    # --- HAGEZI THREAT INTEL & HOSTER ---
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/hoster.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt",

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
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_big.txt",
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_small.txt",
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw_small.txt",

    # --- SPECIALTY ---
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
    #"https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
   # "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Tracking",
]

# ---------------------------------------------------------------------------
# MOBILE LIST SELECTION
# ---------------------------------------------------------------------------
MOBILE_SOURCES = [
    # Pick lighter versions for mobile performance
    # --- HAGEZI THREAT INTEL & HOSTER ---
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/hoster.txt",

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
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_small.txt",
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw_small.txt",

    # --- SPECIALTY ---
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
    #"https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
    #"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Tracking",
]

# Shared Core Resources
SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"
REBIND_URL = "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adguard/dns-rebind-protection.txt"
ADGUARD_SAFESEARCH_URLS = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/engines_safe_search.txt",
    #"https://adguardteam.github.io/HostlistsRegistry/assets/youtube_safe_search.txt",
]

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

def has_suffix_match(host: str, lookup_set: set[str]) -> bool:
    if host in lookup_set:
        return True
    idx = host.find('.')
    while idx != -1:
        if host[idx+1:] in lookup_set:
            return True
        idx = host.find('.', idx + 1)
    return False

def optimize_domains(domains: set[str]) -> list[str]:
    """Reverse domains to use prefix matching for subdomain pruning."""
    reversed_sorted = sorted(d[::-1] for d in domains)
    optimized: list[str] = []
    last_kept: str | None = None
    for rev in reversed_sorted:
        if last_kept and rev.startswith(last_kept + "."):
            continue
        optimized.append(rev)
        last_kept = rev
    return [d[::-1] for d in optimized]

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

# More permissive extractor to handle hosts, adblock, dnsmasq, bind, and plain URLs
DOMAIN_RE = re.compile(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}")

def extract_host(clean):
    clean = clean.split("!")[0].split("#")[0].strip()
    if not clean: return None

    # hosts file: 0.0.0.0 domain or 127.0.0.1 domain
    m = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([^\s#]+)', clean)
    if m: return m.group(1).lower().strip('.')

    # dnsmasq / address=/domain/ or server=/domain/ip
    m = re.search(r'address=/([^/]+)/|server=/([^/]+)/', clean)
    if m:
        dom = m.group(1) or m.group(2)
        return dom.lower().strip('.') if dom else None

    # adblock style ||domain^ or domain^
    m = re.search(r'^\|\|([^/\^]+)\^', clean)
    if m: return m.group(1).lower().strip('.')
    m = re.search(r'^([^/\^]+)\^', clean)
    if m: return m.group(1).lower().strip('.')

    # plain domain or bare URL
    m = DOMAIN_RE.search(clean)
    if m: return m.group(0).lower().strip('.')

    return None

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

def friendly_label_for_url(url: str) -> str:
    p = urlparse(url)
    filename = p.path.rstrip('/').split('/')[-1] or p.path
    return f"{p.netloc}/{filename}"

def build_dataset(urls, s_set, d_map, a_list, w_list, source_data):
    found = set()
    stats = {"irrelevant": 0, "kw": 0, "tld": 0, "duplicate": 0, "whitelisted": 0, "pruned": 0, "pruned_by_hoster": 0}
    source_stats = {}
    hoster_active = set()

    # Ensure hoster.txt is processed FIRST so we can use its domains to prune others
    urls_sorted = sorted(urls, key=lambda u: 0 if "hoster.txt" in u else 1)

    # initialize source_stats for all urls so they appear even if 0
    for u in urls_sorted:
        source_stats[u] = 0

    for url in urls_sorted:
        is_hoster = "hoster.txt" in url
        added_from_source = 0

        for line in source_data.get(url, []):
            host = extract_host(line)
            if not host: continue
            if host.startswith("www."): host = host[4:]

            if host in found:
                stats["duplicate"] += 1
                continue

            # Priority 1: Whitelist
            if has_suffix_match(host, w_list):
                stats["whitelisted"] += 1
                continue

            # Priority 2: SPAM TLDs
            if get_matching_tld(host, s_set, d_map):
                stats["tld"] += 1
                continue

            # Priority 3: NSFW Keywords
            if NSFW_REGEX.search(host):
                stats["kw"] += 1
                continue

            # Priority 4: Relevance
            if not has_suffix_match(host, a_list):
                stats["irrelevant"] += 1
                continue

            # Priority 5: Hoster Pruning
            if not is_hoster and has_suffix_match(host, hoster_active):
                stats["pruned_by_hoster"] += 1
                continue

            found.add(host)
            added_from_source += 1

            if is_hoster:
                hoster_active.add(host)

        source_stats[url] = added_from_source
        print(f"[*] Source contribution: {friendly_label_for_url(url)} -> {added_from_source}")

    initial_count = len(found)
    optimized = optimize_domains(found)
    stats["pruned"] = initial_count - len(optimized)

    return optimized, stats, source_stats

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", default="blocklist.txt")
    parser.add_argument("-m", "--mobile", default="mobile-blocklist.txt")
    parser.add_argument("-w", "--whitelist", default="whitelist.txt")
    args = parser.parse_args()

    # active lists derived from the literal lists above (preserve commented lines in source code)
    active_main = [s for s in MAIN_SOURCES if s and not s.strip().startswith(("#", "//"))]
    active_mobile = [s for s in MOBILE_SOURCES if s and not s.strip().startswith(("#", "//"))]
    all_unique_urls = list(dict.fromkeys(active_main + active_mobile))

    with ThreadPoolExecutor(max_workers=6) as executor:
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

        try:
            with open(args.whitelist, 'r') as wf:
                manual_whitelist = set(line.strip().lower() for line in wf if line.strip() and not line.strip().startswith(('#', '!')))
                print(f"[*] Loaded {len(manual_whitelist)} domains from {args.whitelist}")
        except FileNotFoundError:
            manual_whitelist = set()
            print(f"[*] Manual whitelist '{args.whitelist}' not found. Skipping.")

        for future in as_completed(fetch_futures):
            url = fetch_futures[future]
            lines = future.result()
            source_data[url] = lines
            if DEBUG_SAMPLES:
                safe_name = urlparse(url).netloc + "_" + urlparse(url).path.replace("/", "_").strip("_")
                try:
                    with open(f"debug_{safe_name}.sample", "w", encoding="utf-8") as dbg:
                        dbg.write("\n".join(lines[:200]))
                except Exception as e:
                    print(f"[-] Failed to write debug sample for {url}: {e}")
            print(f"[*] Fetched {len(lines)} lines from {url}")

    print("[*] Generating Main List...")
    main_set, main_stats, main_src_stats = build_dataset(active_main, spam_patterns_set, denyallow_map, master_allowlist, manual_whitelist, source_data)
    print("[*] Generating Mobile List...")
    mobile_set, mobile_stats, mobile_src_stats = build_dataset(active_mobile, spam_patterns_set, denyallow_map, master_allowlist, manual_whitelist, source_data)

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

    # Write source contributions preserving the exact formatting and commented status from the lists above
    def write_source_contributions_preserve(f, literal_list, src_stats):
        f.write("!\n! --- Source Contributions (Pre-Pruning) ---\n")
        for entry in literal_list:
            # preserve the exact string as a comment in the output and append contribution
            if entry.strip().startswith("#"):
                # extract URL portion for lookup (if any)
                url = entry.lstrip("# ").strip()
                count = src_stats.get(url, 0) if url else 0
                f.write(f"! {entry} -> {count}\n")
            else:
                url = entry.strip()
                count = src_stats.get(url, 0)
                f.write(f"! {entry} -> {count}\n")
        f.write("!\n\n")

    for filename, dataset, s, src_stats, literal_list, label in [
        (args.output, main_set, main_stats, main_src_stats, MAIN_SOURCES, "MAIN"),
        (args.mobile, mobile_set, mobile_stats, mobile_src_stats, MOBILE_SOURCES, "MOBILE"),
    ]:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"! Jorgensen {label} List | Version: {VERSION}\n")
            f.write(f"! Generated: {now}\n")
            f.write(f"! Stats: Kept {len(dataset)} | Badware-Pruned {s['pruned_by_hoster']} | General-Pruned {s['pruned']} | Whitelisted {s['whitelisted']} | Irrelevant {s['irrelevant']} | Duplicates {s['duplicate']} | TLD {s['tld']} | NSFW {s['kw']}\n")

            # Preserve original formatting and commented status in the contributions block
            write_source_contributions_preserve(f, literal_list, src_stats)

            for dom in sorted(dataset):
                f.write(f"||{dom}^\n")

            f.write("\n! --- DYNAMIC REBIND PROTECTION ---\n" + rebind_text)
            f.write("\n! --- DYNAMIC SAFESEARCH ---\n")
            for rule in ss_rules:
                f.write(f"{rule}\n")
            f.write("\n! --- NSFW REGEX ---\n/" + NSFW_PATTERN + "/\n")

            if 'spam_req' in locals() and hasattr(spam_req, 'text'):
                f.write("\n! --- SPAM TLDs ---\n" + spam_req.text)

    print(f"[+] Complete. Main: {len(main_set)} | Mobile: {len(mobile_set)}")
    print("\nMain Source Breakdown (Pre-Pruning):")
    for entry in MAIN_SOURCES:
        commented = entry.strip().startswith("#")
        url = entry.lstrip("# ").strip()
        if not url:
            print(f"  - {entry}")
            continue
        print(f"  - {entry} -> {main_src_stats.get(url, 0)}")
    print(f"  > Domains annihilated by Hoster magnet: {main_stats['pruned_by_hoster']}")

if __name__ == "__main__":
    main()
