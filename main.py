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
import gc
import os
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

# --- CONFIGURATION ---
AZ_TZ = timezone(timedelta(hours=-7))
VERSION = "2026.03.16.HOSTER_TRACKED"
DEBUG_SAMPLES = os.getenv("DEBUG_SAMPLES", "0") == "1"

# FILTER TOGGLES
ENABLE_MAIN_RELEVANCE = False
ENABLE_MAIN_TLD = False
ENABLE_MAIN_KW = True

ENABLE_MOBILE_RELEVANCE = True
ENABLE_MOBILE_TLD = False
ENABLE_MOBILE_KW = True

ENABLE_ULTIMATE_RELEVANCE = False
ENABLE_ULTIMATE_TLD = True
ENABLE_ULTIMATE_KW = True

# APPEND TOGGLES
ENABLE_MAIN_REBIND = False
ENABLE_MAIN_SAFESEARCH = False
ENABLE_MAIN_NSFW_REGEX = False
ENABLE_MAIN_SPAM_TLDS = False

ENABLE_MOBILE_REBIND = False
ENABLE_MOBILE_SAFESEARCH = False
ENABLE_MOBILE_NSFW_REGEX = False
ENABLE_MOBILE_SPAM_TLDS = False

ENABLE_ULTIMATE_REBIND = True
ENABLE_ULTIMATE_SAFESEARCH = True
ENABLE_ULTIMATE_NSFW_REGEX = True
ENABLE_ULTIMATE_SPAM_TLDS = True

# --- REGEX COMPILATION ---
NSFW_PATTERN = r"(blowjob|threesome|gangbang|deepthroat|bukkake|tits|fuck|onlyfans|porn|xxx|sex)"
NSFW_REGEX = re.compile(f"(?i){NSFW_PATTERN}")
DOMAIN_RE = re.compile(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}")
IP_HOST_RE = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([^\s#]+)')
DNSMASQ_RE = re.compile(r'(?:address|server)=/([^/]+)/')
ADBLOCK_EXACT_RE = re.compile(r'^\|\|([^/\^]+)\^')
ADBLOCK_BASIC_RE = re.compile(r'^([^/\^]+)\^')

# ---------------------------------------------------------------------------
# MAIN LIST SELECTION
# ---------------------------------------------------------------------------
MAIN_SOURCES = [
    # --- HAGEZI THREAT INTEL & HOSTER ---
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/hoster.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt",

    # --- HAGEZI MAIN LISTS ---
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.mini.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.mini.txt",

    # --- 1HOSTS ---
    #"https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Xtra/adblock.txt",
    #"https://badmojr.github.io/1Hosts/Lite/adblock.txt",
    #"https://badmojr.gitlab.io/addons_1hosts/kidSaf/adblock.txt",

    # --- OISD ---
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_big.txt",
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_small.txt",
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw_small.txt",

    # --- Steven Black ---
    #"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",

    # --- The Blocklist Project ---
    #"https://blocklistproject.github.io/Lists/abuse.txt",
    #"https://blocklistproject.github.io/Lists/ads.txt",
    #"https://blocklistproject.github.io/Lists/crypto.txt",
    #"https://blocklistproject.github.io/Lists/drugs.txt",
    #"https://blocklistproject.github.io/Lists/fraud.txt",
    #"https://blocklistproject.github.io/Lists/gambling.txt",
    #"https://blocklistproject.github.io/Lists/malware.txt",
    #"https://blocklistproject.github.io/Lists/phishing.txt",
    #"https://blocklistproject.github.io/Lists/piracy.txt",
    #"https://blocklistproject.github.io/Lists/porn.txt",
    #"https://blocklistproject.github.io/Lists/ransomware.txt",
    #"https://blocklistproject.github.io/Lists/redirect.txt",
    #"https://blocklistproject.github.io/Lists/scam.txt",
    #"https://blocklistproject.github.io/Lists/smart-tv.txt",
    #"https://blocklistproject.github.io/Lists/tiktok.txt",
    #"https://blocklistproject.github.io/Lists/torrent.txt",
    #"https://blocklistproject.github.io/Lists/tracking.txt",
    #"https://blocklistproject.github.io/Lists/youtube.txt",

    # --- ShadowWhisperer ---
    #"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/Lists/Adult",
    #"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Tracking",

    # --- PETER LOWE ---
    #"https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=1&mimetype=plaintext",

    # --- TELEMETRY & IOT ---
    #"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt",
    #"https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",

    # --- SECURITY / MALWARE ---
    #"https://urlhaus.abuse.ch/downloads/hostfile/",
    
    # --- SPECIALTY ---
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/dyndns.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/gambling.mini.txt",
    #"https://filters.adtidy.org/dns/filter_52.txt", #Adguard DoH, VPN, Tor, Bypass optimized blocklist
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt",
    #"https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
]

# ---------------------------------------------------------------------------
# MOBILE LIST SELECTION
# ---------------------------------------------------------------------------
MOBILE_SOURCES = [
    # --- HAGEZI THREAT INTEL & HOSTER ---
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/hoster.txt",

    # --- HAGEZI MAIN LISTS ---
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.mini.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.mini.txt",

    # --- 1HOSTS ---
    #"https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Xtra/adblock.txt",
    #"https://badmojr.github.io/1Hosts/Lite/adblock.txt",
    #"https://badmojr.gitlab.io/addons_1hosts/kidSaf/adblock.txt",

    # --- OISD ---
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_big.txt",
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_small.txt",
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw_small.txt",

    # --- Steven Black ---
    #"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",

    # --- The Blocklist Project ---
    #"https://blocklistproject.github.io/Lists/abuse.txt",
    #"https://blocklistproject.github.io/Lists/ads.txt",
    #"https://blocklistproject.github.io/Lists/crypto.txt",
    #"https://blocklistproject.github.io/Lists/drugs.txt",
    #"https://blocklistproject.github.io/Lists/fraud.txt",
    #"https://blocklistproject.github.io/Lists/gambling.txt",
    #"https://blocklistproject.github.io/Lists/malware.txt",
    #"https://blocklistproject.github.io/Lists/phishing.txt",
    #"https://blocklistproject.github.io/Lists/piracy.txt",
    #"https://blocklistproject.github.io/Lists/porn.txt",
    #"https://blocklistproject.github.io/Lists/ransomware.txt",
    #"https://blocklistproject.github.io/Lists/redirect.txt",
    #"https://blocklistproject.github.io/Lists/scam.txt",
    #"https://blocklistproject.github.io/Lists/smart-tv.txt",
    #"https://blocklistproject.github.io/Lists/tiktok.txt",
    #"https://blocklistproject.github.io/Lists/torrent.txt",
    #"https://blocklistproject.github.io/Lists/tracking.txt",
    #"https://blocklistproject.github.io/Lists/youtube.txt",

    # --- ShadowWhisperer ---
    #"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/Lists/Adult",
    #"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Tracking",

    # --- PETER LOWE ---
    #"https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=1&mimetype=plaintext",

    # --- TELEMETRY & IOT ---
    #"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt",
    #"https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",

    # --- SECURITY / MALWARE ---
    #"https://urlhaus.abuse.ch/downloads/hostfile/",
    
    # --- SPECIALTY ---
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
    #"https://filters.adtidy.org/dns/filter_52.txt", #Adguard DoH, VPN, Tor, Bypass optimized blocklist
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt", 
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/dyndns.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/gambling.mini.txt",
    #"https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
]

# ---------------------------------------------------------------------------
# ULTIMATE LIST SELECTION (Jorgensen Omni)
# ---------------------------------------------------------------------------
ULTIMATE_SOURCES = [
    # --- HAGEZI THREAT INTEL & HOSTER ---
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/hoster.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt",

    # --- HAGEZI MAIN LISTS ---
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.mini.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.mini.txt",

    # --- 1HOSTS ---
    #"https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Xtra/adblock.txt",
    #"https://badmojr.github.io/1Hosts/Lite/adblock.txt",
    #"https://badmojr.gitlab.io/addons_1hosts/kidSaf/adblock.txt",

    # --- OISD ---
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_big.txt",
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_small.txt",
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw_small.txt",

    # --- Steven Black ---
    #"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",

    # --- The Blocklist Project ---
    "https://blocklistproject.github.io/Lists/abuse.txt",
    #"https://blocklistproject.github.io/Lists/ads.txt",
    "https://blocklistproject.github.io/Lists/crypto.txt",
    "https://blocklistproject.github.io/Lists/drugs.txt",
    "https://blocklistproject.github.io/Lists/fraud.txt",
    #"https://blocklistproject.github.io/Lists/gambling.txt",
    "https://blocklistproject.github.io/Lists/malware.txt",
    "https://blocklistproject.github.io/Lists/phishing.txt",
    "https://blocklistproject.github.io/Lists/piracy.txt",
    #"https://blocklistproject.github.io/Lists/porn.txt",
    "https://blocklistproject.github.io/Lists/ransomware.txt",
    #"https://blocklistproject.github.io/Lists/redirect.txt",
    "https://blocklistproject.github.io/Lists/scam.txt",
    #"https://blocklistproject.github.io/Lists/smart-tv.txt",
    #"https://blocklistproject.github.io/Lists/tiktok.txt",
    #"https://blocklistproject.github.io/Lists/torrent.txt",
    #"https://blocklistproject.github.io/Lists/tracking.txt",
    #"https://blocklistproject.github.io/Lists/youtube.txt",
    
    # --- CUSTOM_RAW_ADULT ---
    #"https://raw.githubusercontent.com/mullvad/dns-blocklists/main/output/relay/relay_adult.txt",
    #"https://raw.githubusercontent.com/4skinSkywalker/Anti-Porn-HOSTS-File/master/HOSTS.txt",
    #"https://raw.githubusercontent.com/ameshkov/easylist/master/easylist_adult/adult_adservers.txt",
    #"https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/pornography-hosts",

    # --- ShadowWhisperer ---
    #"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/Lists/Adult",
    #"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Tracking",

    # --- PETER LOWE ---
    #"https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=1&mimetype=plaintext",

    # --- TELEMETRY & IOT ---
    #"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt",
    #"https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",

    # --- SECURITY / MALWARE ---
    #"https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuardHome.txt",
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt",
    "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt",
    "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Malware",
    "https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/hosts",
    "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts",
    "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt",
    "https://codeberg.org/xRuffKez/tif/raw/branch/main/adblock.txt",
    "https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/primary_active/hosts.txt",
    
    # --- SPECIALTY ---
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/dyndns.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/gambling.mini.txt",
    "https://filters.adtidy.org/dns/filter_52.txt", #Adguard DoH, VPN, Tor, Bypass optimized blocklist
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt",
    #"https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
    #"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Dating",
]

# Shared Core Resources
SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"
REBIND_URL = "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adguard/dns-rebind-protection.txt"
ADGUARD_SAFESEARCH_URLS = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/engines_safe_search.txt",
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
# Helpers
# ---------------------------------------------------------------------------

def get_retry_session() -> requests.Session:
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(pool_connections=15, pool_maxsize=15, max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
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
    reversed_sorted = sorted(d[::-1] for d in domains)
    optimized: list[str] = []
    last_kept: str | None = None
    for rev in reversed_sorted:
        if last_kept and rev.startswith(last_kept + "."):
            continue
        optimized.append(rev)
        last_kept = rev
    return [d[::-1] for d in optimized]

def _parse_csv_lines(iterable: Iterable[str], col_idx: int, skip_header: bool) -> set[str]:
    domains = set()
    for i, line in enumerate(iterable):
        if skip_header and i == 0: continue
        parts = line.split(',')
        if len(parts) > col_idx:
            dom = parts[col_idx].strip().lower().strip('"')
            if dom and "." in dom: domains.add(dom)
    return domains

def fetch_top_list(url: str, col_idx: int, skip_header: bool, compression: str, session: requests.Session) -> set[str]:
    try:
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
    except requests.exceptions.RequestException as e:
        print(f"[-] Network error fetching top list {url}: {e}")
    except (zipfile.BadZipFile, OSError) as e:
        print(f"[-] Processing error for top list {url}: {e}")
    return set()

def extract_host(clean: str) -> str | None:
    clean = clean.split("!")[0].split("#")[0].strip()
    if not clean: return None

    # Fast-path for standard hosts format (bypasses regex processing overhead)
    if clean.startswith(("0.0.0.0 ", "127.0.0.1 ", "0.0.0.0\t", "127.0.0.1\t")):
        parts = clean.split()
        if len(parts) > 1:
            return parts[1].lower().strip('.')

    # Fast-path for clean exact Adblock rules ||domain.com^
    if clean.startswith("||") and clean.endswith("^") and "/" not in clean and "^" not in clean[2:-1]:
        return clean[2:-1].lower().strip('.')

    # Fallback to general regex extractions
    m = IP_HOST_RE.match(clean)
    if m: return m.group(1).lower().strip('.')

    m = DNSMASQ_RE.search(clean)
    if m: return m.group(1).lower().strip('.')

    m = ADBLOCK_EXACT_RE.search(clean)
    if m: return m.group(1).lower().strip('.')
    
    m = ADBLOCK_BASIC_RE.search(clean)
    if m: return m.group(1).lower().strip('.')

    m = DOMAIN_RE.search(clean)
    if m: return m.group(0).lower().strip('.')

    return None

def fetch_source_domains(url: str, session: requests.Session) -> list[str]:
    try:
        r = session.get(url, stream=True, timeout=60, headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
        domains = []
        for line in r.iter_lines(decode_unicode=True):
            if not line: continue
            clean_line = line.strip()
            if not clean_line or clean_line.startswith(('!', '#', '[', ' ')): continue
            
            host = extract_host(clean_line)
            if host:
                if host.startswith("www."): 
                    host = host[4:]
                domains.append(host)
        return domains
    except requests.exceptions.RequestException as e:
        print(f"[-] Network error fetching source {url}: {e}")
        return []

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
        else: rule_part = clean

        rule_part = rule_part.replace("||", "").replace("^", "").replace("*", "").lstrip(".")
        if rule_part:
            tld_patterns.add(rule_part)
            if denyallow_hosts: denyallow_map[rule_part] = denyallow_hosts
    return tld_patterns, denyallow_map

def get_matching_tld(host: str, spam_set: set[str], denyallow_map: dict[str, set[str]]) -> str | None:
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

def build_dataset(urls: list[str], s_set: set[str], d_map: dict[str, set[str]], a_list: set[str], w_list: set[str], source_data: dict[str, list[str]], disable_relevance: bool = False, disable_tld: bool = False, disable_kw: bool = False) -> tuple[list[str], dict[str, int], dict[str, int]]:
    found = set()
    stats = {"irrelevant": 0, "kw": 0, "tld": 0, "duplicate": 0, "whitelisted": 0, "pruned": 0, "pruned_by_hoster": 0}
    source_stats = {}
    hoster_active = set()

    urls_sorted = sorted(urls, key=lambda u: 0 if "hoster.txt" in u else 1)

    for u in urls_sorted:
        source_stats[u] = 0

    for url in urls_sorted:
        is_hoster = "hoster.txt" in url
        added_from_source = 0

        for host in source_data.get(url, []):
            if host in found:
                stats["duplicate"] += 1
                continue

            if has_suffix_match(host, w_list):
                stats["whitelisted"] += 1
                continue

            if not disable_tld and get_matching_tld(host, s_set, d_map):
                stats["tld"] += 1
                continue

            if not disable_kw and NSFW_REGEX.search(host):
                stats["kw"] += 1
                continue

            if not disable_relevance and not has_suffix_match(host, a_list):
                stats["irrelevant"] += 1
                continue

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

def write_output_file(filename: str, dataset: list[str], stats: dict[str, int], src_stats: dict[str, int], literal_list: list[str], label: str, rebind_text: str, ss_rules: list[str], spam_text: str | None, include_rebind: bool, include_safesearch: bool, include_regex: bool, include_spam: bool) -> None:
    now = datetime.now(AZ_TZ).strftime("%Y-%m-%d %I:%M:%S %p MST")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"! Jorgensen {label} List | Version: {VERSION}\n")
        f.write(f"! Generated: {now}\n")
        f.write(f"! Stats: Kept {len(dataset)} | Badware-Pruned {stats['pruned_by_hoster']} | General-Pruned {stats['pruned']} | Whitelisted {stats['whitelisted']} | Irrelevant {stats['irrelevant']} | Duplicates {stats['duplicate']} | TLD {stats['tld']} | NSFW {stats['kw']}\n")

        f.write("!\n! --- Source Contributions (Pre-Pruning) ---\n")
        for entry in literal_list:
            if entry.strip().startswith("#"):
                url = entry.lstrip("# ").strip()
                count = src_stats.get(url, 0) if url else 0
                f.write(f"! {entry} -> {count}\n")
            else:
                url = entry.strip()
                count = src_stats.get(url, 0)
                f.write(f"! {entry} -> {count}\n")
        f.write("!\n\n")

        f.writelines(f"||{dom}^\n" for dom in sorted(dataset))

        if include_rebind and rebind_text:
            f.write("\n! --- DYNAMIC REBIND PROTECTION ---\n" + rebind_text)
        
        if include_safesearch and ss_rules:
            f.write("\n! --- DYNAMIC SAFESEARCH ---\n")
            f.writelines(f"{rule}\n" for rule in ss_rules)
            
        if include_regex:
            f.write(f"\n! --- NSFW REGEX ---\n/{NSFW_PATTERN}/\n")

        if include_spam and spam_text:
            f.write("\n! --- SPAM TLDs ---\n" + spam_text)

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", default="blocklist.txt")
    parser.add_argument("-m", "--mobile", default="mobile-blocklist.txt")
    parser.add_argument("-u", "--ultimate", default="omni-blocklist.txt")
    parser.add_argument("-w", "--whitelist", default="whitelist.txt")
    args = parser.parse_args()

    active_main = [s for s in MAIN_SOURCES if s and not s.strip().startswith(("#", "//"))]
    active_mobile = [s for s in MOBILE_SOURCES if s and not s.strip().startswith(("#", "//"))]
    active_ultimate = [s for s in ULTIMATE_SOURCES if s and not s.strip().startswith(("#", "//"))]
    
    all_unique_urls = list(dict.fromkeys(active_main + active_mobile + active_ultimate))
    
    session = get_retry_session()

    with ThreadPoolExecutor(max_workers=8) as executor:
        print("[*] Loading master logic and scheduling background downloads...")
        master_allowlist = set()
        
        if ENABLE_MAIN_RELEVANCE or ENABLE_MOBILE_RELEVANCE or ENABLE_ULTIMATE_RELEVANCE:
            top_futures = [executor.submit(fetch_top_list, url, col, skip, comp, session) for url, col, skip, comp in TOP_LISTS]
        else:
            top_futures = []

        # Background async downloads for footers
        rebind_future = executor.submit(lambda: session.get(REBIND_URL, timeout=30).text if REBIND_URL else "")
        ss_futures = {executor.submit(session.get, url, timeout=30): url for url in ADGUARD_SAFESEARCH_URLS}

        print(f"[*] Downloading and parsing {len(all_unique_urls)} source files concurrently...")
        source_data = {}
        fetch_futures = {executor.submit(fetch_source_domains, url, session): url for url in all_unique_urls}

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
            hosts = future.result()
            source_data[url] = hosts
            if DEBUG_SAMPLES:
                safe_name = urlparse(url).netloc + "_" + urlparse(url).path.replace("/", "_").strip("_")
                try:
                    with open(f"debug_{safe_name}.sample", "w", encoding="utf-8") as dbg:
                        dbg.write("\n".join(hosts[:200]))
                except OSError as e:
                    print(f"[-] Failed to write debug sample for {url}: {e}")
            print(f"[*] Fetched and parsed {len(hosts)} clean domains from {url}")

        try:
            spam_req = session.get(SPAM_TLD_URL, timeout=30)
            spam_req.raise_for_status()
            spam_patterns_set, denyallow_map = parse_tld_patterns(spam_req.text.splitlines())
            spam_text = spam_req.text
        except requests.exceptions.RequestException as e:
            print(f"[-] Failed to fetch SPAM TLDs: {e}")
            spam_patterns_set, denyallow_map, spam_text = set(), {}, None

        try:
            rebind_text = rebind_future.result() if REBIND_URL else ""
        except Exception as e:
            print(f"[-] Failed to fetch Rebind rules: {e}")
            rebind_text = ""

        ss_rules = []
        for future, url in ss_futures.items():
            try:
                r = future.result()
                r.raise_for_status()
                ss_rules.extend([l for l in r.text.splitlines() if l.strip() and not l.startswith(('!', '#'))])
            except Exception as e:
                print(f"[-] Failed to fetch SafeSearch rules from {url}: {e}")

    print("[*] Generating Main List...")
    main_set, main_stats, main_src_stats = build_dataset(
        active_main, spam_patterns_set, denyallow_map, master_allowlist, manual_whitelist, source_data, 
        disable_relevance=not ENABLE_MAIN_RELEVANCE,
        disable_tld=not ENABLE_MAIN_TLD,
        disable_kw=not ENABLE_MAIN_KW
    )
    print("[*] Generating Mobile List...")
    mobile_set, mobile_stats, mobile_src_stats = build_dataset(
        active_mobile, spam_patterns_set, denyallow_map, master_allowlist, manual_whitelist, source_data, 
        disable_relevance=not ENABLE_MOBILE_RELEVANCE,
        disable_tld=not ENABLE_MOBILE_TLD,
        disable_kw=not ENABLE_MOBILE_KW
    )
    print("[*] Generating Omni List...")
    ultimate_set, ultimate_stats, ultimate_src_stats = build_dataset(
        active_ultimate, spam_patterns_set, denyallow_map, master_allowlist, manual_whitelist, source_data, 
        disable_relevance=not ENABLE_ULTIMATE_RELEVANCE,
        disable_tld=not ENABLE_ULTIMATE_TLD,
        disable_kw=not ENABLE_ULTIMATE_KW
    )

    del source_data
    gc.collect()

    write_output_file(
        args.output, main_set, main_stats, main_src_stats, MAIN_SOURCES, "MAIN", rebind_text, ss_rules, spam_text,
        ENABLE_MAIN_REBIND, ENABLE_MAIN_SAFESEARCH, ENABLE_MAIN_NSFW_REGEX, ENABLE_MAIN_SPAM_TLDS
    )
    write_output_file(
        args.mobile, mobile_set, mobile_stats, mobile_src_stats, MOBILE_SOURCES, "MOBILE", rebind_text, ss_rules, spam_text,
        ENABLE_MOBILE_REBIND, ENABLE_MOBILE_SAFESEARCH, ENABLE_MOBILE_NSFW_REGEX, ENABLE_MOBILE_SPAM_TLDS
    )
    write_output_file(
        args.ultimate, ultimate_set, ultimate_stats, ultimate_src_stats, ULTIMATE_SOURCES, "OMNI", rebind_text, ss_rules, spam_text,
        ENABLE_ULTIMATE_REBIND, ENABLE_ULTIMATE_SAFESEARCH, ENABLE_ULTIMATE_NSFW_REGEX, ENABLE_ULTIMATE_SPAM_TLDS
    )

    print(f"[+] Complete. Main: {len(main_set)} | Mobile: {len(mobile_set)} | Omni: {len(ultimate_set)}")

if __name__ == "__main__":
    main()
