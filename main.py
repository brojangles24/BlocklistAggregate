#!/usr/bin/env python3
from __future__ import annotations
import httpx
import asyncio
import re
import argparse
import io
import zipfile
import gzip
import gc
import os
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
from typing import Iterable

# --- CONFIGURATION ---
AZ_TZ = timezone(timedelta(hours=-7))
VERSION = "2026.07.05.OMNI_PRO_TRIE"
DEBUG_SAMPLES = os.getenv("DEBUG_SAMPLES", "0") == "1"

# FILTER TOGGLES
ENABLE_LITE_RELEVANCE = True
ENABLE_LITE_TLD = False
ENABLE_LITE_KW = False

ENABLE_MAIN_RELEVANCE = True
ENABLE_MAIN_TLD = False
ENABLE_MAIN_KW = True

ENABLE_MOBILE_RELEVANCE = True
ENABLE_MOBILE_TLD = False
ENABLE_MOBILE_KW = True

ENABLE_ULTIMATE_RELEVANCE = True
ENABLE_ULTIMATE_TLD = False
ENABLE_ULTIMATE_KW = True

# APPEND TOGGLES
ENABLE_LITE_REBIND = True
ENABLE_LITE_SAFESEARCH = True
ENABLE_LITE_NSFW_REGEX = False
ENABLE_LITE_SPAM_TLDS = False

ENABLE_MAIN_REBIND = True
ENABLE_MAIN_SAFESEARCH = True
ENABLE_MAIN_NSFW_REGEX = True
ENABLE_MAIN_SPAM_TLDS = False

ENABLE_MOBILE_REBIND = True
ENABLE_MOBILE_SAFESEARCH = True
ENABLE_MOBILE_NSFW_REGEX = True
ENABLE_MOBILE_SPAM_TLDS = False

ENABLE_ULTIMATE_REBIND = True
ENABLE_ULTIMATE_SAFESEARCH = True
ENABLE_ULTIMATE_NSFW_REGEX = True
ENABLE_ULTIMATE_SPAM_TLDS = False

# --- REGEX COMPILATION ---
NSFW_PATTERN = r"(blowjob|threesome|gangbang|deepthroat|bukkake|tits|fuck|onlyfans|porn|xxx|sex)"
NSFW_REGEX = re.compile(f"(?i){NSFW_PATTERN}")
DOMAIN_RE = re.compile(r"(?i)(?:[a-z0-9-]+\.)+[a-z]{2,}")
ADBLOCK_EXACT_RE = re.compile(r'^\|\|([^\/\^]+)\^')
ADBLOCK_BASIC_RE = re.compile(r'^([^\/\^]+)\^')

# ---------------------------------------------------------------------------
# MAIN LIST SELECTION
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# LITE SOURCES
# ---------------------------------------------------------------------------
LITE_SOURCES = [
    # --- Adult & NSFW Content ---
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",

    # --- Enforcement & Behavioral ---
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt",
    #"https://filters.adtidy.org/dns/filter_52.txt", # Encrypted DNS/VPN/TOR/Proxy Bypass
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt",

    # --- Malware & Security ---
    #"https://filters.adtidy.org/dns/filter_55.txt", # HaGeZi Badware Hoster

    # --- General Protection Tiers ---
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt", # HaGeZi Normal
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt", #TIF Mini
    "https://raw.githubusercontent.com/DNSBunker/CTI/refs/heads/main/adblock.txt", #Cyber THreat Intel
]

# ---------------------------------------------------------------------------
# MAIN SOURCES (Core Ruleset)
# ---------------------------------------------------------------------------
MAIN_SOURCES = [
    # --- Adult & NSFW Content ---
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",
    #"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    #"https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt",

    # --- Enforcement & Behavioral ---
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh-vpn-proxy-bypass.txt", # Encrypted DNS/VPN/TOR/Proxy Bypass
    #"https://codeberg.org/lumiworx/HPT-AI-Blocklist/raw/branch/main/HPT-Full-AI-List",

    # --- Malware & Security (Inactive) ---
    #"https://filters.adtidy.org/dns/filter_50.txt", # uBlock₀ Badware
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/hoster.txt", # HaGeZi Badware Hoster
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt", # TIF Full
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt", #TIF Mini
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt", # TIF Medium
    #"https://raw.githubusercontent.com/DNSBunker/CTI/refs/heads/main/adblock.txt", #Cyber THreat Intel

    # --- General Protection Tiers (Inactive) ---
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt", # HaGeZi Normal
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt", # HaGeZi Pro
    #"https://filters.adtidy.org/dns/filter_51.txt", # HaGeZi Pro++
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/dyndns.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/gambling.mini.txt", #HaGeZi Gambling Mini
]


# ---------------------------------------------------------------------------
# ULTIMATE SOURCES (Jorgensen Omni Extended)
# ---------------------------------------------------------------------------
ULTIMATE_SOURCES = [
    # --- Core Security & Threat Intelligence ---
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/dyndns.txt", # HaGeZi DynDNS Blocklist
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt", # TIF Medium
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt", #TIF Mini
    "https://filters.adtidy.org/dns/filter_50.txt", # uBlock₀ Badware
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/hoster.txt", # HaGeZi Badware Hoster
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt", # TIF Full
    "https://raw.githubusercontent.com/DNSBunker/CTI/refs/heads/main/adblock.txt", #Cyber THreat Intel
    
    # --- Bypass & Network Enforcement ---
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh-vpn-proxy-bypass.txt", # Encrypted DNS/VPN/TOR/Proxy Bypass
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt", # HaGeZi Anti-Piracy
    #"https://codeberg.org/lumiworx/HPT-AI-Blocklist/raw/branch/main/HPT-Full-AI-List",

    # --- Content, Social & Search Control ---
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt",
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",
    #"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
    #"https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/gambling.mini.txt", #HaGeZi Gambling Mini

    # --- Comprehensive Protection Tiers ---
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt", # HaGeZi Pro
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt", # HaGeZi Normal
    #"https://filters.adtidy.org/dns/filter_51.txt", # HaGeZi Pro++
]

MOBILE_SOURCES = list(MAIN_SOURCES)

# Shared Core Resources
SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"
REBIND_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adguard/dns-rebind-protection.txt"

ADGUARD_SAFESEARCH_URLS = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/engines_safe_search.txt",
    #"https://adguardteam.github.io/HostlistsRegistry/assets/youtube_safe_search.txt",
]

TOP_LISTS = [
    ("https://tranco-list.eu/top-1m.csv.zip", 1, False, "zip"),
    ("http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip", 1, False, "zip"),
    ("https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz", 0, True, "gzip"),
    ("https://downloads.majestic.com/majestic_million.csv", 2, True, "raw"),
    ("https://www.domcop.com/files/top/top10milliondomains.csv.zip", 1, True, "zip"),
    ("https://builtwith.com/dl/builtwith-top1m.zip", 0, False, "zip"),
]

# ---------------------------------------------------------------------------
# Trie Data Structures & Core Optimizers
# ---------------------------------------------------------------------------
class DomainTrieNode:
    __slots__ = ('children', 'is_blocked')
    def __init__(self):
        self.children: dict[str, DomainTrieNode] = {}
        self.is_blocked: bool = False

def optimize_domains(domains: Iterable[str]) -> list[str]:
    root = DomainTrieNode()
    for domain in domains:
        parts = domain.lower().split('.')
        current = root
        for part in reversed(parts):
            if part not in current.children:
                current.children[part] = DomainTrieNode()
            current = current.children[part]
            if current.is_blocked:
                break
        current.is_blocked = True

    results: list[str] = []
    def walk_tree(node: DomainTrieNode, path_segments: list[str]):
        if node.is_blocked:
            results.append(".".join(reversed(path_segments)))
            return
        for segment, child_node in node.children.items():
            path_segments.append(segment)
            walk_tree(child_node, path_segments)
            path_segments.pop()

    walk_tree(root, [])
    return results

def has_suffix_match(host: str, lookup_set: set[str]) -> bool:
    if host in lookup_set:
        return True
    idx = host.find('.')
    while idx != -1:
        if host[idx+1:] in lookup_set:
            return True
        idx = host.find('.', idx + 1)
    return False

def get_matching_tld(host: str, spam_set: set[str], denyallow_map: dict[str, set[str]]) -> str | None:
    if host in spam_set:
        if host in denyallow_map and host in denyallow_map[host]:
            return None
        return host
    idx = host.find('.')
    while idx != -1:
        candidate = host[idx+1:]
        if candidate in spam_set:
            if candidate in denyallow_map and host in denyallow_map[candidate]:
                return None
            return candidate
        idx = host.find('.', idx + 1)
    return None

def _parse_csv_lines(iterable: Iterable[str], col_idx: int, skip_header: bool) -> set[str]:
    domains = set()
    add_dom = domains.add
    for i, line in enumerate(iterable):
        if skip_header and i == 0:
            continue
        parts = line.split(',', col_idx + 1)
        if len(parts) > col_idx:
            dom = parts[col_idx].strip().lower().strip('"')
            if dom and "." in dom:
                add_dom(dom)
    return domains

def extract_host(clean: str) -> str | None:
    if '!' in clean: clean = clean.split('!', 1)[0]
    if '#' in clean: clean = clean.split('#', 1)[0]
    clean = clean.strip()
    if not clean: return None
    if clean.startswith("||"):
        if "$" in clean:
            clean = clean.split("$", 1)[0]
        if clean.endswith("^"):
            body = clean[2:-1]
            if "/" not in body and "^" not in body:
                return body.lower().strip('.')
        m = ADBLOCK_EXACT_RE.search(clean)
        if m: return m.group(1).lower().strip('.')
        clean = clean[2:]
    m = ADBLOCK_BASIC_RE.search(clean)
    if m: return m.group(1).lower().strip('.')
    if clean.startswith(("0.0.0.0", "127.0.0.1")):
        parts = clean.split(None, 1)
        if len(parts) > 1:
            out = parts[1].strip('.')
            if '.' in out and ' ' not in out:
                return out.lower()
    if clean.startswith(("address=/", "server=/")):
        parts = clean.split('/')
        if len(parts) > 1:
            return parts[1].lower().strip('.')
    if '.' in clean and ' ' not in clean and '/' not in clean and '\\' not in clean:
        return clean.lower().strip('.')
    m = DOMAIN_RE.search(clean)
    if m: return m.group(0).lower().strip('.')
    return None

# ---------------------------------------------------------------------------
# Async Network Engine
# ---------------------------------------------------------------------------
async def fetch_with_retry(client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response:
    total_retries = 3
    backoff_factor = 1.0
    for attempt in range(total_retries):
        try:
            response = await client.get(url, **kwargs)
            if response.status_code in [500, 502, 503, 504]:
                raise httpx.HTTPStatusError(f"Status {response.status_code}", request=response.request, response=response)
            response.raise_for_status()
            return response
        except (httpx.HTTPError, httpx.HTTPStatusError) as e:
            if attempt == total_retries - 1:
                raise e
            await asyncio.sleep(backoff_factor * (2 ** attempt))
    raise httpx.HTTPError("Failed after maximum retries.")

async def fetch_top_list(url: str, col_idx: int, skip_header: bool, compression: str, client: httpx.AsyncClient) -> set[str]:
    try:
        r = await fetch_with_retry(client, url, headers={"User-Agent": "Mozilla/5.0"}, timeout=90.0)
        def process_sync():
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
        return await asyncio.to_thread(process_sync)
    except Exception as e:
        print(f"[-] Error processing top list {url}: {e}")
        return set()

async def fetch_source_domains(url: str, client: httpx.AsyncClient) -> tuple[str, set[str]]:
    try:
        domains = set()
        add_dom = domains.add
        async with client.stream("GET", url, headers={"User-Agent": "Mozilla/5.0"}, timeout=60.0) as r:
            r.raise_for_status()
            async for line in r.aiter_lines():
                if not line: continue
                clean_line = line.strip()
                if not clean_line or clean_line.startswith(('!', '#', '[', ' ')): continue
                host = extract_host(clean_line)
                if host:
                    if host.startswith("www."):
                        host = host[4:]
                    add_dom(host)
        return url, domains
    except Exception as e:
        print(f"[-] Network error fetching source {url}: {e}")
        return url, set()

# ---------------------------------------------------------------------------
# Data Synthesis Engine
# ---------------------------------------------------------------------------
def build_dataset(urls: list[str], s_set: set[str], d_map: dict[str, set[str]], a_list: set[str], w_list: set[str], source_data: dict[str, set[str]], disable_relevance: bool = False, disable_tld: bool = False, disable_kw: bool = False) -> tuple[list[str], dict[str, int], dict[str, int], dict[str, int], dict[str, int]]:
    found = set()
    stats = {"irrelevant": 0, "kw": 0, "tld": 0, "duplicate": 0, "whitelisted": 0, "pruned": 0, "pruned_by_hoster": 0}
    source_stats = {}
    kw_counts = {}
    tld_counts = {}
    hoster_active = set()
    
    urls_sorted = sorted(urls, key=lambda u: 0 if "hoster.txt" in u or "filter_55.txt" in u or "filter_50.txt" in u else 1)
    
    for u in urls_sorted:
        source_stats[u] = 0
        
    for url in urls_sorted:
        is_hoster = "hoster.txt" in url or "filter_55.txt" in url or "filter_50.txt" in url
        added_from_source = 0
        for host in source_data.get(url, set()):
            if host in found:
                stats["duplicate"] += 1
                continue
            if has_suffix_match(host, w_list):
                stats["whitelisted"] += 1
                continue
            
            if not disable_tld:
                matched_tld = get_matching_tld(host, s_set, d_map)
                if matched_tld:
                    stats["tld"] += 1
                    tld_counts[matched_tld] = tld_counts.get(matched_tld, 0) + 1
                    continue
            
            if not disable_kw:
                m = NSFW_REGEX.search(host)
                if m:
                    matched_kw = m.group(1).lower()
                    stats["kw"] += 1
                    kw_counts[matched_kw] = kw_counts.get(matched_kw, 0) + 1
                    continue
                    
            if not disable_relevance and not has_suffix_match(host, a_list):
                stats["irrelevant"] += 1
                continue
            if not is_hoster and has_suffix_match(host, hoster_active):
                stats["pruned_by_hoster"] += 1
                continue
                
            found.add(host)
            added_from_source += 1
            if is_hoster: hoster_active.add(host)
            
        source_stats[url] = added_from_source
        
    initial_count = len(found)
    optimized = optimize_domains(found)
    stats["pruned"] = initial_count - len(optimized)
    
    return optimized, stats, source_stats, kw_counts, tld_counts

def parse_tld_patterns(lines: list[str]) -> tuple[set[str], dict[str, set[str]]]:
    tld_patterns, denyallow_map = set(), {}
    for line in lines:
        clean = line.split("!")[0].split("#")[0].strip()
        if not clean: continue
        clean = clean.lower()
        denyallow_hosts = set()
        
        if "$" in clean:
            rule_part, _, modifiers = clean.partition("$")
            for mod in modifiers.split(","):
                if mod.startswith("denyallow="):
                    denyallow_hosts = set(mod[len("denyallow="):].split("|"))
        else:
            rule_part = clean
            
        rule_part = rule_part.replace("||", "").replace("^", "").replace("*", "").lstrip(".")
        if rule_part:
            tld_patterns.add(rule_part)
            if denyallow_hosts:
                denyallow_map[rule_part] = denyallow_hosts
                
    return tld_patterns, denyallow_map

def write_output_file(filename: str, dataset: list[str], stats: dict[str, int], src_stats: dict[str, int], kw_counts: dict[str, int], tld_counts: dict[str, int], literal_list: list[str], label: str, rebind_text: str, ss_rules: list[str], spam_text: str | None, include_rebind: bool, include_safesearch: bool, include_regex: bool, include_spam: bool) -> None:
    now = datetime.now(AZ_TZ).strftime("%Y-%m-%d %I:%M:%S %p MST")
    total_kept = len(dataset)
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"! Jorgensen {label} List | Version: {VERSION}\n")
        f.write(f"! Generated: {now}\n")
        f.write(f"! Stats: Kept {total_kept} | Badware-Pruned {stats['pruned_by_hoster']} | General-Pruned {stats['pruned']} | Whitelisted {stats['whitelisted']} | Irrelevant {stats['irrelevant']} | Duplicates {stats['duplicate']} | TLD {stats['tld']} | Regex-Offloaded {stats['kw']}\n")
        
        if kw_counts:
            f.write("!\n! --- Keyword Blocks ---\n")
            for kw, count in sorted(kw_counts.items(), key=lambda x: x[1], reverse=True):
                f.write(f"! {kw}: {count}\n")
                
        if tld_counts:
            f.write("!\n! --- Top 10 TLD Blocks ---\n")
            for tld, count in sorted(tld_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                f.write(f"! {tld}: {count}\n")
                
        f.write("!\n! --- Source Contributions (Pre-Pruning) ---\n")
        for entry in literal_list:
            url = entry.lstrip("# ").strip() if entry.strip().startswith("#") else entry.strip()
            count = src_stats.get(url, 0)
            pct = (count / total_kept * 100) if total_kept > 0 else 0.0
            f.write(f"! {entry} -> {count} ({pct:.2f}%)\n")
        f.write("!\n\n")
        
        f.writelines(f"||{dom}^\n" for dom in sorted(dataset))
        
        if include_rebind:
            f.write("\n! --- DYNAMIC REBIND PROTECTION ---\n")
            if rebind_text:
                f.write(rebind_text.strip() + "\n")
            else:
                f.write("! [No Rebind Data Fetched or Empty Response]\n")
                
        if include_safesearch:
            f.write("\n! --- DYNAMIC SAFESEARCH ---\n")
            if ss_rules:
                f.writelines(f"{rule}\n" for rule in ss_rules)
            else:
                f.write("! [No SafeSearch Rules Fetched or Empty Response]\n")
                
        if include_regex:
            f.write(f"\n! --- NSFW REGEX ---\n/{NSFW_PATTERN}/\n")
            
        if include_spam:
            f.write("\n! --- SPAM TLDs ---\n")
            if spam_text:
                f.write(spam_text.strip() + "\n")
            else:
                f.write("! [No Spam TLD Data Fetched or Empty Response]\n")

# ---------------------------------------------------------------------------
# Pipeline Orchestrator
# ---------------------------------------------------------------------------
async def run_pipeline() -> None:
    args_parser = argparse.ArgumentParser()
    args_parser.add_argument("-l", "--lite", default="lite-blocklist.txt")
    args_parser.add_argument("-o", "--output", default="blocklist.txt")
    args_parser.add_argument("-m", "--mobile", default="mobile-blocklist.txt")
    args_parser.add_argument("-u", "--ultimate", default="omni-blocklist.txt")
    args_parser.add_argument("-w", "--whitelist", default="whitelist.txt")
    args = args_parser.parse_args()
    
    active_lite = [s for s in LITE_SOURCES if s and not s.strip().startswith(("#", "//"))]
    active_main = [s for s in MAIN_SOURCES if s and not s.strip().startswith(("#", "//"))]
    active_mobile = [s for s in MOBILE_SOURCES if s and not s.strip().startswith(("#", "//"))]
    active_ultimate = [s for s in ULTIMATE_SOURCES if s and not s.strip().startswith(("#", "//"))]
    all_unique_urls = list(dict.fromkeys(active_lite + active_main + active_mobile + active_ultimate))
    
    limits = httpx.Limits(max_keepalive_connections=20, max_connections=40)
    async with httpx.AsyncClient(limits=limits, follow_redirects=True) as client:
        print("[*] Allocating asynchronous pipelines...")
        master_allowlist = set()
        top_tasks = []
        if ENABLE_LITE_RELEVANCE or ENABLE_MAIN_RELEVANCE or ENABLE_MOBILE_RELEVANCE or ENABLE_ULTIMATE_RELEVANCE:
            top_tasks = [asyncio.create_task(fetch_top_list(url, col, skip, comp, client)) for url, col, skip, comp in TOP_LISTS]
            
        rebind_task = asyncio.create_task(client.get(REBIND_URL, timeout=30.0)) if REBIND_URL else None
        spam_task = asyncio.create_task(client.get(SPAM_TLD_URL, timeout=30.0)) if SPAM_TLD_URL else None
        ss_tasks = {asyncio.create_task(client.get(url, timeout=30.0)): url for url in ADGUARD_SAFESEARCH_URLS}
        
        print(f"[*] Downloading and parsing {len(all_unique_urls)} source files concurrently...")
        fetch_tasks = [asyncio.create_task(fetch_source_domains(url, client)) for url in all_unique_urls]
        
        if top_tasks:
            top_results = await asyncio.gather(*top_tasks)
            for res in top_results:
                master_allowlist.update(res)
                
        try:
            with open(args.whitelist, 'r') as wf:
                manual_whitelist = set(line.strip().lower() for line in wf if line.strip() and not line.strip().startswith(('#', '!')))
            print(f"[*] Loaded {len(manual_whitelist)} domains from {args.whitelist}")
        except FileNotFoundError:
            manual_whitelist = set()
            print(f"[*] Manual whitelist '{args.whitelist}' not found. Skipping local disk read.")
            
        source_data = {}
        for task in asyncio.as_completed(fetch_tasks):
            url, hosts = await task
            source_data[url] = hosts
            
            if DEBUG_SAMPLES:
                p = urlparse(url)
                safe_name = f"{p.netloc}*{p.path.replace('/', '*').strip('*')}"
                try:
                    with open(f"debug_{safe_name}.sample", "w", encoding="utf-8") as dbg:
                        dbg.write("\n".join(list(hosts)[0:200]))
                except OSError as e:
                    print(f"[-] Debug write fault for {url}: {e}")
                    
        print("[*] Compiling global blocklist for Spam TLD cross-reference...")
        all_blocked_domains = set().union(*source_data.values())
                    
        spam_patterns_set, denyallow_map, spam_text = set(), {}, None
        if spam_task:
            try:
                spam_res = await spam_task
                spam_res.raise_for_status()
                
                filtered_spam_lines = []
                for line in spam_res.text.splitlines():
                    if not line.strip() or line.startswith(('!', '#', '[')):
                        filtered_spam_lines.append(line)
                        continue
                        
                    if NSFW_REGEX.search(line):
                        continue
                        
                    if line.startswith("@@"):
                        clean_exc = line[2:].strip()
                        domain = extract_host(clean_exc)
                        if domain and has_suffix_match(domain, all_blocked_domains):
                            continue
                            
                    if "$denyallow=" in line or ",denyallow=" in line:
                        rule_part, sep, modifiers = line.partition("$")
                        if sep:
                            mod_list = modifiers.split(",")
                            new_mod_list = []
                            for mod in mod_list:
                                if mod.startswith("denyallow="):
                                    allowed_hosts = mod[len("denyallow="):].split("|")
                                    valid_hosts = [h for h in allowed_hosts if not has_suffix_match(h, all_blocked_domains)]
                                    if valid_hosts:
                                        new_mod_list.append("denyallow=" + "|".join(valid_hosts))
                                else:
                                    new_mod_list.append(mod)
                            
                            if new_mod_list:
                                line = f"{rule_part}${','.join(new_mod_list)}"
                            else:
                                line = rule_part
                                
                    filtered_spam_lines.append(line)
                
                spam_text = "\n".join(filtered_spam_lines)
                spam_patterns_set, denyallow_map = parse_tld_patterns(filtered_spam_lines)
                
            except Exception as e:
                print(f"[-] Failed to map custom Spam TLD footprints: {e}")
                
        rebind_text = ""
        if rebind_task:
            try:
                rebind_res = await rebind_task
                rebind_res.raise_for_status()
                rebind_text = rebind_res.text
            except Exception as e:
                print(f"[-] Failed to query secure rebinding configurations: {e}")
                
        ss_rules = []
        for task, url in ss_tasks.items():
            try:
                r = await task
                r.raise_for_status()
                ss_rules.extend([l for l in r.text.splitlines() if l.strip() and not l.startswith(('!', '#'))])
            except Exception as e:
                print(f"[-] SafeSearch sync validation failed for {url}: {e}")

        print("\n[*] Generating Lite List...")
        lite_set, lite_stats, lite_src_stats, lite_kw, lite_tld = build_dataset(
            active_lite, spam_patterns_set, denyallow_map, master_allowlist, manual_whitelist, source_data,
            disable_relevance=not ENABLE_LITE_RELEVANCE, disable_tld=not ENABLE_LITE_TLD, disable_kw=not ENABLE_LITE_KW
        )
        for url, count in lite_src_stats.items():
            pct = (count / len(lite_set) * 100) if len(lite_set) > 0 else 0
            print(f" -> {urlparse(url).netloc}/{urlparse(url).path.split('/')[-1]}: {count} ({pct:.2f}%)")
                
        print("\n[*] Generating Main List...")
        main_set, main_stats, main_src_stats, main_kw, main_tld = build_dataset(
            active_main, spam_patterns_set, denyallow_map, master_allowlist, manual_whitelist, source_data,
            disable_relevance=not ENABLE_MAIN_RELEVANCE, disable_tld=not ENABLE_MAIN_TLD, disable_kw=not ENABLE_MAIN_KW
        )
        for url, count in main_src_stats.items():
            pct = (count / len(main_set) * 100) if len(main_set) > 0 else 0
            print(f" -> {urlparse(url).netloc}/{urlparse(url).path.split('/')[-1]}: {count} ({pct:.2f}%)")
            
        print("\n[*] Generating Mobile List...")
        mobile_set, mobile_stats, mobile_src_stats, mob_kw, mob_tld = build_dataset(
            active_mobile, spam_patterns_set, denyallow_map, master_allowlist, manual_whitelist, source_data,
            disable_relevance=not ENABLE_MOBILE_RELEVANCE, disable_tld=not ENABLE_MOBILE_TLD, disable_kw=not ENABLE_MOBILE_KW
        )
        for url, count in mobile_src_stats.items():
            pct = (count / len(mobile_set) * 100) if len(mobile_set) > 0 else 0
            print(f" -> {urlparse(url).netloc}/{urlparse(url).path.split('/')[-1]}: {count} ({pct:.2f}%)")
        
        print("\n[*] Generating Omni List...")
        ultimate_set, ultimate_stats, ultimate_src_stats, ult_kw, ult_tld = build_dataset(
            active_ultimate, spam_patterns_set, denyallow_map, master_allowlist, manual_whitelist, source_data,
            disable_relevance=not ENABLE_ULTIMATE_RELEVANCE, disable_tld=not ENABLE_ULTIMATE_TLD, disable_kw=not ENABLE_ULTIMATE_KW
        )
        for url, count in ultimate_src_stats.items():
            pct = (count / len(ultimate_set) * 100) if len(ultimate_set) > 0 else 0
            print(f" -> {urlparse(url).netloc}/{urlparse(url).path.split('/')[-1]}: {count} ({pct:.2f}%)")
            
        del source_data
        gc.collect()

        write_output_file(
            args.lite, lite_set, lite_stats, lite_src_stats, lite_kw, lite_tld, LITE_SOURCES, "LITE", rebind_text, ss_rules, spam_text,
            ENABLE_LITE_REBIND, ENABLE_LITE_SAFESEARCH, ENABLE_LITE_NSFW_REGEX, ENABLE_LITE_SPAM_TLDS
        )
        write_output_file(
            args.output, main_set, main_stats, main_src_stats, main_kw, main_tld, MAIN_SOURCES, "MAIN", rebind_text, ss_rules, spam_text,
            ENABLE_MAIN_REBIND, ENABLE_MAIN_SAFESEARCH, ENABLE_MAIN_NSFW_REGEX, ENABLE_MAIN_SPAM_TLDS
        )
        write_output_file(
            args.mobile, mobile_set, mobile_stats, mobile_src_stats, mob_kw, mob_tld, MOBILE_SOURCES, "MOBILE", rebind_text, ss_rules, spam_text,
            ENABLE_MOBILE_REBIND, ENABLE_MOBILE_SAFESEARCH, ENABLE_MOBILE_NSFW_REGEX, ENABLE_MOBILE_SPAM_TLDS
        )
        write_output_file(
            args.ultimate, ultimate_set, ultimate_stats, ultimate_src_stats, ult_kw, ult_tld, ULTIMATE_SOURCES, "OMNI", rebind_text, ss_rules, spam_text,
            ENABLE_ULTIMATE_REBIND, ENABLE_ULTIMATE_SAFESEARCH, ENABLE_ULTIMATE_NSFW_REGEX, ENABLE_ULTIMATE_SPAM_TLDS
        )
        print(f"\n[+] Complete. Lite: {len(lite_set)} | Main: {len(main_set)} | Mobile: {len(mobile_set)} | Omni: {len(ultimate_set)}")

def main() -> None:
    asyncio.run(run_pipeline())

if __name__ == "__main__":
    main()
