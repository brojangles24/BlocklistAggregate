#!/usr/bin/env python3
import httpx, asyncio, re, argparse, zipfile, gzip, os, io
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
from typing import Iterable

# --- CONFIGURATION ---
AZ_TZ = timezone(timedelta(hours=-7))
VERSION = "2026.07.16.OMNI_PRO_TRIE"

# FILTER TOGGLES
ENABLE_RELEVANCE = {"main": False, "mobile": True, "ultimate": False}
ENABLE_TLD = {"main": True, "mobile": True, "ultimate": True}
ENABLE_KW = {"main": True, "mobile": True, "ultimate": True}
ENABLE_REBIND = ENABLE_SAFESEARCH = ENABLE_NSFW = ENABLE_SPAM = True

# --- REGEX ---
NSFW_REGEX = re.compile(r"(?i)(blowjob|threesome|gangbang|deepthroat|bukkake|tits|fuck|onlyfans|porn|xxx|sex)")
DOMAIN_RE = re.compile(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}")
ADBLOCK_EXACT_RE = re.compile(r'^\|\|([^/\^]+)\^')
ADBLOCK_BASIC_RE = re.compile(r'^([^/\^]+)\^')

# ---------------------------------------------------------------------------
# MAIN LIST SELECTION
# ---------------------------------------------------------------------------
MAIN_SOURCES = [
    # Core Safety & Content Filtering
    "https://filters.adtidy.org/dns/filter_55.txt", # HaGeZi Badware Hoster
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt",
]

# ---------------------------------------------------------------------------
# ULTIMATE LIST SELECTION (Jorgensen Omni)
# ---------------------------------------------------------------------------
ULTIMATE_SOURCES = [
    # --- HaGeZi Umbrella Engines ---
    "https://filters.adtidy.org/dns/filter_54.txt", # HaGeZi DynDNS
    "https://filters.adtidy.org/dns/filter_50.txt", # uBlock₀ Badware risks
    "https://filters.adtidy.org/dns/filter_55.txt", # HaGeZi Badware Hoster Blocklist
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.medium-onlydomains.txt", # Threat Intelligence Medium
    "https://filters.adtidy.org/dns/filter_51.txt", # HaGeZi Pro++ Blocklist
    "https://filters.adtidy.org/dns/filter_46.txt", # HaGeZi Anti-Piracy
    "https://filters.adtidy.org/dns/filter_52.txt", # Encrypted DNS/VPN/TOR/Proxy Bypass

    # --- Core Content Tiers ---
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",

    # --- Specialized ---
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt",
]

MOBILE_SOURCES = list(MAIN_SOURCES)

# Shared Resources
SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"
REBIND_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adguard/dns-rebind-protection.txt"
ADGUARD_SAFESEARCH_URLS = ["https://adguardteam.github.io/HostlistsRegistry/assets/engines_safe_search.txt"]

TOP_LISTS = [
    ("https://tranco-list.eu/top-1m.csv.zip", 1, False, "zip"),
    ("http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip", 1, False, "zip"),
    ("https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz", 0, True, "gzip"),
    ("https://downloads.majestic.com/majestic_million.csv", 2, True, "raw"),
    ("https://www.domcop.com/files/top/top10milliondomains.csv.zip", 1, True, "zip"),
    ("https://builtwith.com/dl/builtwith-top1m.zip", 0, False, "zip"),
]

# ---------------------------------------------------------------------------
# Trie & Helpers
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
            current = current.children.setdefault(part, DomainTrieNode())
            if current.is_blocked: break
        current.is_blocked = True
    results: list[str] = []
    def walk(node: DomainTrieNode, path: list[str]):
        if node.is_blocked:
            results.append('.'.join(reversed(path)))
            return
        for seg, child in node.children.items():
            path.append(seg)
            walk(child, path)
            path.pop()
    walk(root, [])
    return results

def has_suffix_match(host: str, lookup: set[str]) -> bool:
    if host in lookup: return True
    idx = host.find('.')
    while idx != -1:
        if host[idx+1:] in lookup: return True
        idx = host.find('.', idx + 1)
    return False

def get_matching_tld(host: str, spam_set: set[str], deny_map: dict) -> str | None:
    if host in spam_set and not (host in deny_map and host in deny_map.get(host, set())): return host
    idx = host.find('.')
    while idx != -1:
        cand = host[idx+1:]
        if cand in spam_set and not (cand in deny_map and host in deny_map.get(cand, set())): return cand
        idx = host.find('.', idx + 1)
    return None

def extract_host(line: str) -> str | None:
    if not line or line.startswith(('#', '!', '[', ' ')): return None
    clean = line.split('!', 1)[0].split('#', 1)[0].strip()
    if not clean: return None
    if clean.startswith("||"):
        clean = clean.split('$', 1)[0].rstrip('^')
        if clean.startswith("||"): clean = clean[2:]
    m = ADBLOCK_EXACT_RE.search(clean) or ADBLOCK_BASIC_RE.search(clean)
    if m: return m.group(1).lower().strip('.')
    if clean.startswith(("0.0.0.0", "127.0.0.1")):
        parts = clean.split(None, 1)
        if len(parts) > 1 and '.' in parts[1]: return parts[1].strip('.').lower()
    if clean.startswith(("address=/", "server=/")):
        parts = clean.split('/')
        if len(parts) > 1: return parts[1].lower().strip('.')
    if '.' in clean and ' ' not in clean and '/' not in clean: return clean.lower().strip('.')
    m = DOMAIN_RE.search(clean)
    return m.group(0).lower().strip('.') if m else None

def _parse_csv(iterable: Iterable[str], col: int, skip_header: bool) -> set[str]:
    domains = set()
    for i, line in enumerate(iterable):
        if skip_header and i == 0: continue
        parts = line.split(',', col + 1)
        if len(parts) > col:
            dom = parts[col].strip().lower().strip('"')
            if dom and '.' in dom: domains.add(dom)
    return domains

# ---------------------------------------------------------------------------
# Async Fetch
# ---------------------------------------------------------------------------
async def fetch_with_retry(client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response:
    for attempt in range(3):
        try:
            r = await client.get(url, **kwargs)
            r.raise_for_status()
            return r
        except httpx.HTTPError:
            if attempt == 2: raise
            await asyncio.sleep(1 * (2 ** attempt))

async def fetch_top_list(url: str, col: int, skip: bool, comp: str, client: httpx.AsyncClient) -> set[str]:
    try:
        r = await fetch_with_retry(client, url, headers={"User-Agent": "Mozilla/5.0"}, timeout=90)
        data = r.content
        def proc():
            if comp == "zip":
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    with z.open(z.namelist()[0]) as f:
                        return _parse_csv(io.TextIOWrapper(f, encoding='utf-8', errors='ignore'), col, skip)
            elif comp == "gzip":
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                    return _parse_csv(io.TextIOWrapper(gz, encoding='utf-8', errors='ignore'), col, skip)
            else:
                return _parse_csv(data.decode('utf-8', errors='ignore').splitlines(), col, skip)
        return await asyncio.to_thread(proc)
    except Exception as e:
        print(f"[-] Top list error {url}: {e}")
        return set()

async def fetch_source(url: str, client: httpx.AsyncClient) -> tuple[str, set[str]]:
    try:
        domains = set()
        async with client.stream("GET", url, headers={"User-Agent": "Mozilla/5.0"}, timeout=60) as r:
            r.raise_for_status()
            async for line in r.aiter_lines():
                if host := extract_host(line):
                    domains.add(host[4:] if host.startswith("www.") else host)
        return url, domains
    except Exception as e:
        print(f"[-] Fetch error {url}: {e}")
        return url, set()

def parse_tld_patterns(lines: list[str]) -> tuple[set[str], dict[str, set[str]]]:
    tlds, deny = set(), {}
    for line in lines:
        clean = line.split('!', 1)[0].split('#', 1)[0].strip().lower()
        if not clean: continue
        rule = clean.split('$', 1)[0].replace("||", "").replace("^", "").lstrip(".")
        if rule: tlds.add(rule)
    return tlds, deny

# ---------------------------------------------------------------------------
# Build & Output
# ---------------------------------------------------------------------------
def build_dataset(urls: list[str], spam_set: set, deny_map: dict, allow_list: set, white_list: set, source_data: dict,
                  disable_rel: bool, disable_tld: bool, disable_kw: bool):
    found = set()
    stats = {"irrel": 0, "kw": 0, "tld": 0, "dup": 0, "white": 0, "pruned": 0}
    src_stats = {u: 0 for u in urls}
    kw_c, tld_c = {}, {}
    for url in sorted(urls, key=lambda u: 0 if any(x in u for x in ("filter_55", "filter_50")) else 1):
        for host in source_data.get(url, set()):
            if host in found: stats["dup"] += 1; continue
            if has_suffix_match(host, white_list): stats["white"] += 1; continue
            if not disable_tld and (mt := get_matching_tld(host, spam_set, deny_map)):
                stats["tld"] += 1; tld_c[mt] = tld_c.get(mt, 0) + 1; continue
            if not disable_kw and (m := NSFW_REGEX.search(host)):
                kw = m.group(1).lower()
                stats["kw"] += 1; kw_c[kw] = kw_c.get(kw, 0) + 1; continue
            if not disable_rel and not has_suffix_match(host, allow_list):
                stats["irrel"] += 1; continue
            found.add(host)
            src_stats[url] += 1
    initial = len(found)
    opt = optimize_domains(found)
    stats["pruned"] = initial - len(opt)
    return opt, stats, src_stats, kw_c, tld_c

def write_file(filename: str, dataset: list[str], stats: dict, src_stats: dict, kw_c: dict, tld_c: dict,
               sources: list, label: str, rebind_t: str, ss_r: list, spam_t: str | None):
    now = datetime.now(AZ_TZ).strftime("%Y-%m-%d %I:%M:%S %p MST")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"! Jorgensen {label} List | {VERSION}\n! Generated: {now}\n")
        f.write(f"! Kept: {len(dataset)} | Pruned: {stats['pruned']} | Dup: {stats['dup']} | White: {stats['white']}\n")
        if kw_c:
            f.write("!\n! --- KW Blocks ---\n")
            for k, v in sorted(kw_c.items(), key=lambda x: x[1], reverse=True): f.write(f"! {k}: {v}\n")
        if tld_c:
            f.write("!\n! --- Top TLDs ---\n")
            for k, v in sorted(tld_c.items(), key=lambda x: x[1], reverse=True)[:10]: f.write(f"! {k}: {v}\n")
        f.write("!\n! --- Sources ---\n")
        for u in sources:
            c = src_stats.get(u, 0)
            p = (c / len(dataset) * 100) if dataset else 0
            f.write(f"! {u} -> {c} ({p:.1f}%)\n")
        f.write("!\n")
        f.writelines(f"||{d}^\n" for d in sorted(dataset))
        if ENABLE_REBIND and rebind_t: f.write(f"\n! --- REBIND ---\n{rebind_t}\n")
        if ENABLE_SAFESEARCH and ss_r: f.write("\n! --- SAFESEARCH ---\n" + "\n".join(ss_r) + "\n")
        if ENABLE_NSFW: f.write(f"\n! --- NSFW ---\n/{NSFW_REGEX.pattern[4:-1]}/\n")
        if ENABLE_SPAM and spam_t: f.write(f"\n! --- SPAM TLD ---\n{spam_t}\n")

# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
async def run_pipeline():
    p = argparse.ArgumentParser()
    p.add_argument("-o", default="blocklist.txt")
    p.add_argument("-m", default="mobile-blocklist.txt")
    p.add_argument("-u", default="omni-blocklist.txt")
    p.add_argument("-w", "--whitelist", default="whitelist.txt")
    args = p.parse_args()

    limits = httpx.Limits(max_keepalive_connections=20, max_connections=40)
    async with httpx.AsyncClient(limits=limits, follow_redirects=True) as client:
        allow = set()
        if any(ENABLE_RELEVANCE.values()):
            tops = await asyncio.gather(*[fetch_top_list(u, c, s, comp, client) for u, c, s, comp in TOP_LISTS])
            for t in tops: allow.update(t)

        try:
            with open(args.whitelist) as f:
                white = {line.strip().lower() for line in f if line.strip() and not line.strip().startswith(('#', '!'))}
        except FileNotFoundError:
            white = set()

        urls = list(dict.fromkeys(MAIN_SOURCES + MOBILE_SOURCES + ULTIMATE_SOURCES))
        source_data = dict(await asyncio.gather(*[fetch_source(u, client) for u in urls]))

        spam_set, deny_map, spam_text = set(), {}, None
        try:
            r = await fetch_with_retry(client, SPAM_TLD_URL, timeout=30)
            spam_set, deny_map = parse_tld_patterns(r.text.splitlines())
            spam_text = r.text
        except Exception as e: print(f"[-] Spam TLD: {e}")

        rebind_text = ""
        try:
            r = await fetch_with_retry(client, REBIND_URL, timeout=30)
            rebind_text = r.text
        except Exception as e: print(f"[-] Rebind: {e}")

        ss_rules = []
        for url in ADGUARD_SAFESEARCH_URLS:
            try:
                r = await fetch_with_retry(client, url, timeout=30)
                ss_rules.extend([l for l in r.text.splitlines() if l.strip() and not l.startswith(('#', '!'))])
            except Exception: pass

        for name, sources, outf, rel, tld, kw in [
            ("Main", MAIN_SOURCES, args.o, not ENABLE_RELEVANCE["main"], not ENABLE_TLD["main"], not ENABLE_KW["main"]),
            ("Mobile", MOBILE_SOURCES, args.m, not ENABLE_RELEVANCE["mobile"], not ENABLE_TLD["mobile"], not ENABLE_KW["mobile"]),
            ("Omni", ULTIMATE_SOURCES, args.u, not ENABLE_RELEVANCE["ultimate"], not ENABLE_TLD["ultimate"], not ENABLE_KW["ultimate"])
        ]:
            print(f"[*] Building {name}...")
            ds, st, sst, kwc, tldc = build_dataset(sources, spam_set, deny_map, allow, white, source_data, rel, tld, kw)
            write_file(outf, ds, st, sst, kwc, tldc, sources, name.upper(), rebind_text, ss_rules, spam_text)
            print(f" -> {name}: {len(ds)} domains")

        print("\n[+] Done.")

if __name__ == "__main__":
    asyncio.run(run_pipeline())
