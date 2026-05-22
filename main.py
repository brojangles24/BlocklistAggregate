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
import math
from collections import Counter
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
from typing import Iterable

# --- CONFIGURATION ---
AZ_TZ = timezone(timedelta(hours=-7))
VERSION = "2026.05.22.OMNI_TLD_DEDUPLICATED"
DEBUG_SAMPLES = os.getenv("DEBUG_SAMPLES", "0") == "1"

# FILTER TOGGLES
ENABLE_MAIN_RELEVANCE = False
ENABLE_MAIN_TLD = True
ENABLE_MAIN_KW = False          # Offloaded to Control D Upstream
ENABLE_MAIN_HEURISTICS = True   # Mathematical DGA Engine

ENABLE_MOBILE_RELEVANCE = True
ENABLE_MOBILE_TLD = True
ENABLE_MOBILE_KW = False         # Offloaded to Control D Upstream
ENABLE_MOBILE_HEURISTICS = True  # Mathematical DGA Engine

ENABLE_ULTIMATE_RELEVANCE = False
ENABLE_ULTIMATE_TLD = True
ENABLE_ULTIMATE_KW = False        # Offloaded to Control D Upstream
ENABLE_ULTIMATE_HEURISTICS = True # Mathematical DGA Engine

# APPEND TOGGLES
ENABLE_MAIN_REBIND = True
ENABLE_MAIN_SAFESEARCH = True
ENABLE_MAIN_NSFW_REGEX = True
ENABLE_MAIN_SPAM_TLDS = True

ENABLE_MOBILE_REBIND = True
ENABLE_MOBILE_SAFESEARCH = True
ENABLE_MOBILE_NSFW_REGEX = True
ENABLE_MOBILE_SPAM_TLDS = True

ENABLE_ULTIMATE_REBIND = True
ENABLE_ULTIMATE_SAFESEARCH = True
ENABLE_ULTIMATE_NSFW_REGEX = True
ENABLE_ULTIMATE_SPAM_TLDS = True

# --- ALGORITHMIC INFRASTRUCTURE ---
class SuffixTrie:
    """High-performance structural trie replacing slow linear suffix matching loops."""
    def __init__(self):
        self.root = {}

    def insert(self, domain: str) -> None:
        if not domain: return
        parts = domain.strip().lower().split('.')[::-1]
        node = self.root
        for part in parts:
            if '$' in node: return  # Parent domain already handles ancestry path
            node = node.setdefault(part, {})
        node['$'] = True

    def contains_suffix(self, domain: str) -> bool:
        if not domain: return False
        parts = domain.strip().lower().split('.')[::-1]
        node = self.root
        for part in parts:
            if '$' in node: return True
            if part not in node: return False
            node = node[part]
        return '$' in node

# --- HEURISTIC MATCHERS & REGEX ---
NSFW_PATTERN = r"(blowjob|threesome|gangbang|deepthroat|bukkake|tits|fuck|onlyfans|porn|xxx|sex)"
NSFW_REGEX = re.compile(f"(?i){NSFW_PATTERN}")

# Precise structural DGA patterns (Style 1: 1-char sub + 56-char hex | Style 2: 10-char hex + 10-char hex)
DGA_PATTERN = r"^(?:[a-z]\.[0-9a-f]{56}|[0-9a-f]{10}\.[0-9a-f]{10})\.[a-z]{2,}$"
DGA_REGEX = re.compile(f"(?i){DGA_PATTERN}")

CONSONANT_PATTERN = re.compile(r'[bcdfghjklmnpqrstvwxyz]', re.I)
DOMAIN_RE = re.compile(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}")
IP_HOST_RE = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([^\s#]+)')
DNSMASQ_RE = re.compile(r'(?:address|server)=/([^/]+)/')
ADBLOCK_EXACT_RE = re.compile(r'^\|\|([^/\^]+)\^')
ADBLOCK_BASIC_RE = re.compile(r'^([^/\^]+)\^')

def calculate_shannon_entropy(label: str) -> float:
    """Computes mathematical Shannon Entropy to evaluate character randomness."""
    if not label: return 0.0
    probabilities = [count / len(label) for count in Counter(label).values()]
    return -sum(p * math.log2(p) for p in probabilities)

def is_dga_heuristic(domain: str) -> bool:
    """Evaluates labels dynamically for entropy anomalies and high consonant density."""
    if DGA_REGEX.search(domain):
        return True
    
    parts = domain.split('.')[:-1]
    for part in parts:
        if len(part) < 12: continue
        
        entropy = calculate_shannon_entropy(part)
        consonants = len(CONSONANT_PATTERN.findall(part))
        consonant_ratio = consonants / len(part)
        
        # Flag structural alphanumeric entropy chaos (e.g., zero-day dynamic tracking mutations)
        if entropy > 4.15 and len(part) > 16:
            return True
        # Flag extreme consonant clustering density
        if consonant_ratio > 0.83:
            return True
    return False

# ---------------------------------------------------------------------------
# OPTIMIZED SOURCE ARCHITECTURE (Control D Cleaned)
# ---------------------------------------------------------------------------
MAIN_SOURCES = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/dyndns.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/hoster.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt", 

    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt",
    "https://filters.adtidy.org/dns/filter_52.txt",
]

MOBILE_SOURCES = list(MAIN_SOURCES)

ULTIMATE_SOURCES = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/dyndns.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/hoster.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh-vpn-proxy-bypass.txt",

    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt",
    "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts",
    "https://codeberg.org/xRuffKez/tif/raw/branch/main/adblock.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt",
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

# --- Isolated IoT Rules Preset ---
RAW_IOT_RULES = [
    "||*", "@@||10.10.10.1^", "@@||arl.assets.apl-alexa.com^", "@@||api.amazonalexa.com^", 
    "@@||time.nist.gov^", "@@||pool.ntp.org^", "@@||api.tplinkra.com^", "@@||tplinkcloud.com^", 
    "@@||us-east-1.prod.sip-edge.amc.amazon.dev^", "@@||tp-link.com^", "@@||mega-us-pr.eufy.com^", 
    "@@||use1-api.tplinkra.com^", "@@||ntp-g7g.amazon.com^", "@@||arcus-uswest.amazon.com^", 
    "@@||api.amazon.com^", "@@||thumbnails-photos.amazon.com^", "@@||cdn2.voiceapps.com^", 
    "@@||audio-ak.spotifycdn.com^", "@@||msh.amazon.com^", "@@||audio-fa.scdn.co^", 
    "@@||mtalk.google.com^", "@@||www.tesla.com^", "@@||assistant-api.prd.usw2.vn.cloud.tesla.com^", 
    "@@||hermes-api.prd.na.vn.cloud.tesla.com^", "@@||hermes-stream-api.prd.na.vn.cloud.tesla.com^", 
    "@@||connman.vn.tesla.services^", "@@||maps-prd.go.tesla.services^", "@@||api.edge-gateway.siriusxm.com^", 
    "@@||device-api.prd.na.vn.cloud.tesla.com^", "@@||connectivitycheck.gstatic.com^", "@@||ipv4only.arpa^", 
    "@@||m1-us.feit-iot.com^", "@@||a3-us.feit-iot.com^", "@@||api-prd.ap.tesla.services^", 
    "@@||hermes-prd.ap.tesla.services^", "@@||softwareupdates.amazon.com^", "@@||alexa.amazon.com^", 
    "@@||todo-ta-g7g.amazon.com^", "@@||use1-device-tapo-care.i.tplinknbu.com^", "@@||vehicle-files.teslamotors.com^", 
    "@@||stun.tplinkcloud.com^", "@@||security.iot.i.tplinknbu.com^", "@@||a.root-servers.net^", 
    "@@||dcape-na.amazon.com^", "@@||ffs-provisioner-config.amazon-dss.com^", "@@||alexa.na.gateway.devices.a2z.com^", 
    "@@||discovery.meethue.com^", "@@||edge-aiot-ohi-prod.s3.dualstack.us-east-2.amazonaws.com^", 
    "@@||x3-prod.obs.tesla.com^", "@@||prd-bhapi-us.prd.rings.solutions^", "@@||avs-alexa-14-na.amazon.com^", 
    "@@||api.mp.tesla.services^", "@@||use1-cvm-api.i.tplinknbu.com^", "@@||tesla-hermes-snapshot-motors.s3.us-west-2.amazonaws.com^", 
    "@@||ec2-98-81-116-179.prd.rings.solutions^", "@@||d1s31zyz7dcc2d.cloudfront.prod.ota-cloudfront.net^", 
    "gateway-ink.amazon.com^", "@@||ec2-44-198-180-225.prd.rings.solutions^", "@@||dp-gw-na.amazon.com^", 
    "@@||daws.tesla.services^", "@@||davs-puffinconfig.s3.us-east-2.amazonaws.com^", "@@||use1-cipc.tplinkra.com^", 
    "@@||www.gstatic.com^", "@@||acsechocaptiveportal.com^", "@@||mmechocaptiveportal.com^", 
    "@@||android.clients.google.com^", "@@||clientservices.googleapis.com^", "@@||clients4.google.com^", 
    "@@||mas-ext.amazon.com^", "@@||dss-na.amazon.com^", "@@||arl.assets-v2.apl-alexa.com^", 
    "@@||clients3.google.com^", "@@||aiot-mqtt-us.anker.com^", "@@||tile.googleapis.com^", 
    "@@||prod.cdn.ams.alexa-personality.amazon.dev^", "@@||prod.apl-music-multimodal.com^", 
    "@@||alexa-hybrid-clear-policy-prod-na.s3.amazonaws.com^", "@@||clients2.google.com^", 
    "@@||places.googleapis.com^", "@@||use1-device-cloudgateway.iot.i.tplinknbu.com^", "@@||m3-us.iotbing.com^", 
    "@@||a3-us.iotbing.com^", "@@||det-ta-g7g.amazon.com^", "@@||aps1-openapi.i.tplinknbu.com^", 
    "@@||api.radiotime.com^", "@@||mt0.google.com^", "@@||akamai-apigateway-ownershipsvc.tesla.com^", 
    "@@||mlis.amazon.com^", "@@||s3.amazonaws.com^", "@@||apresolve.spotify.com^", 
    "@@||fireoscaptiveportal.com^", "@@||device-messaging-na.amazon.com^", "@@||www.apple.com^", 
    "@@||assistant-api.prd.na.vn.cloud.tesla.com^", "@@||www.microsoft.com^", "@@||maps.googleapis.com^", 
    "@@||mas-sdk.amazon.com^", "@@||example.com^", "@@||ap-gue1.spotify.com^", 
    "@@||ap-gew4.spotify.com^", "@@||ap.spotify.com^", "@@||connect.myqdevice.com^", 
    "@@||d70fh7jkmjrfk.cloudfront.net^", "@@||connect-ca.myqdevice.com^", "@@||d2ouawjonid8rv.cloudfront.net^", 
    "@@||m.media-amazon.com^", "@@||https.web.diagnostic.networking.aws.dev^", "@@||web.diagnostic.networking.aws.dev^", 
    "@@||eufylife.com^", "@@||networking.aws.dev^", "@@||RINgs.solUTioNs^", 
    "@@||ringS.sOluTIoNs^", "@@||RINgs.SOLUTiOns^", "@@||d2zprwa9w8uwyf.cloudfront.net^", 
    "@@||car-partner-01.lemonade.com^", "@@||d2wvvf45320aru.cloudfront.net^", "@@||telemetry-prd.vn.tesla.services^"
]

# ---------------------------------------------------------------------------
# Pure Performance Optimization Code
# ---------------------------------------------------------------------------
def get_matching_tld(host: str, spam_set: set[str], denyallow_map: dict[str, set[str]]) -> str | None:
    if host in spam_set:
        if host in denyallow_map and host in denyallow_map[host]: return None
        return host
    idx = host.find('.')
    while idx != -1:
        candidate = host[idx+1:]
        if candidate in spam_set:
            if candidate in denyallow_map and host in denyallow_map[candidate]: return None
            return candidate
        idx = host.find('.', idx + 1)
    return None

def optimize_domains(domains: set[str]) -> list[str]:
    reversed_sorted = sorted(d[::-1] for d in domains)
    optimized: list[str] = []
    last_kept: str | None = None
    for rev in reversed_sorted:
        if last_kept and rev.startswith(last_kept + "."): continue
        optimized.append(rev)
        last_kept = rev
    return [d[::-1] for d in optimized]

def _parse_csv_lines(iterable: Iterable[str], col_idx: int, skip_header: bool) -> set[str]:
    domains = set()
    add_dom = domains.add
    for i, line in enumerate(iterable):
        if skip_header and i == 0: continue
        parts = line.split(',', col_idx + 1)
        if len(parts) > col_idx:
            dom = parts[col_idx].strip().lower().strip('"')
            if dom and "." in dom: add_dom(dom)
    return domains

def extract_host(clean: str) -> str | None:
    if '!' in clean: clean = clean.split('!', 1)[0]
    if '#' in clean: clean = clean.split('#', 1)[0]
    clean = clean.strip()
    if not clean: return None

    if clean.startswith("||"):
        if "$" in clean: clean = clean.split("$", 1)[0]
        if clean.endswith("^"):
            body = clean[2:-1]
            if "/" not in body and "^" not in body: return body.lower().strip('.')
        m = ADBLOCK_EXACT_RE.search(clean) or ADBLOCK_BASIC_RE.search(clean)
        if m: return m.group(1).lower().strip('.')

    if clean.startswith(("0.0.0.0", "127.0.0.1")):
        parts = clean.split(None, 1)
        if len(parts) > 1:
            out = parts[1].strip('.')
            if '.' in out and ' ' not in out: return out.lower()

    if clean.startswith(("address=/", "server=/")):
        parts = clean.split('/')
        if len(parts) > 1: return parts[1].lower().strip('.')

    if '.' in clean and ' ' not in clean and '/' not in clean and '\\' not in clean:
        return clean.lower().strip('.')

    m = DOMAIN_RE.search(clean)
    if m: return m.group(0).lower().strip('.')
    return None

# ---------------------------------------------------------------------------
# Network Data Acquisition Layer
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
            if attempt == total_retries - 1: raise e
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
                    if host.startswith("www."): host = host[4:]
                    add_dom(host)
        return url, domains
    except Exception as e:
        print(f"[-] Network error fetching source {url}: {e}")
        return url, set()

# ---------------------------------------------------------------------------
# Algorithmic Data Processing & Trie Pruning
# ---------------------------------------------------------------------------
def build_dataset(urls: list[str], s_set: set[str], d_map: dict[str, set[str]], allow_trie: SuffixTrie, white_trie: SuffixTrie, source_data: dict[str, set[str]], disable_relevance: bool = False, disable_tld: bool = False, disable_kw: bool = False, disable_heuristics: bool = False) -> tuple[list[str], dict[str, int], dict[str, int]]:
    found = set()
    stats = {"irrelevant": 0, "kw": 0, "tld": 0, "duplicate": 0, "whitelisted": 0, "pruned": 0, "pruned_by_hoster": 0, "heuristics": 0, "punycode_purged": 0}
    source_stats = {}
    hoster_active = SuffixTrie()

    urls_sorted = sorted(urls, key=lambda u: 0 if "hoster.txt" in u else 1)
    for u in urls_sorted: source_stats[u] = 0

    for url in urls_sorted:
        is_hoster = "hoster.txt" in url
        added_from_source = 0

        for host in source_data.get(url, set()):
            if host in found:
                stats["duplicate"] += 1
                continue
            if "xn--" in host:
                stats["punycode_purged"] += 1
                continue
            if white_trie.contains_suffix(host):
                stats["whitelisted"] += 1
                continue
            if not disable_tld and get_matching_tld(host, s_set, d_map):
                stats["tld"] += 1
                continue
            if not disable_kw and NSFW_REGEX.search(host):
                stats["kw"] += 1
                continue
            if not disable_heuristics and is_dga_heuristic(host):
                stats["heuristics"] += 1
                continue
            if not disable_relevance and not allow_trie.contains_suffix(host):
                stats["irrelevant"] += 1
                continue
            if not is_hoster and hoster_active.contains_suffix(host):
                stats["pruned_by_hoster"] += 1
                continue

            found.add(host)
            added_from_source += 1
            if is_hoster: hoster_active.insert(host)

        source_stats[url] = added_from_source
        p = urlparse(url)
        filename = p.path.rstrip('/').split('/')[-1] or p.path
        print(f"[*] Source contribution: {p.netloc}/{filename} -> {added_from_source}")

    initial_count = len(found)
    optimized = optimize_domains(found)
    stats["pruned"] = initial_count - len(optimized)
    return optimized, stats, source_stats

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

def write_output_file(filename: str, dataset: list[str], stats: dict[str, int], src_stats: dict[str, int], literal_list: list[str], label: str, rebind_text: str, ss_rules: list[str], spam_text: str | None, include_rebind: bool, include_safesearch: bool, include_regex: bool, include_spam: bool, include_heuristics: bool, client_suffix: str = "", iot_rules: list[str] | None = None) -> None:
    now = datetime.now(AZ_TZ).strftime("%Y-%m-%d %I:%M:%S %p MST")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"! Jorgensen {label} List | Version: {VERSION}\n")
        f.write(f"! Generated: {now}\n")
        f.write(f"! Stats: Kept {len(dataset)} | Badware-Pruned {stats['pruned_by_hoster']} | General-Pruned {stats['pruned']} | Whitelisted {stats['whitelisted']} | Irrelevant {stats['irrelevant']} | Duplicates {stats['duplicate']} | TLD {stats['tld']} | NSFW {stats['kw']} | Heuristic DGA Counter {stats['heuristics']} | Individual Punycode Intercepts {stats['punycode_purged']}\n")

        f.write("!\n! --- Source Contributions (Pre-Pruning) ---\n")
        for entry in literal_list:
            url = entry.lstrip("# ").strip() if entry.strip().startswith("#") else entry.strip()
            count = src_stats.get(url, 0)
            f.write(f"! {entry} -> {count}\n")
        f.write("!\n\n")

        # Output the structural core list records
        f.writelines(f"||{dom}^{client_suffix}\n" for dom in sorted(dataset))

        if include_rebind and rebind_text:
            f.write("\n! --- DYNAMIC REBIND PROTECTION ---\n")
            for line in rebind_text.splitlines():
                if line.strip() and not line.strip().startswith(('!', '#')):
                    f.write(f"{line.strip()}{client_suffix}\n")
                elif line.strip():
                    f.write(f"{line}\n")

        if include_safesearch and ss_rules:
            f.write("\n! --- DYNAMIC SAFESEARCH ---\n")
            for rule in ss_rules:
                if rule.strip() and not rule.strip().startswith(('!', '#')):
                    f.write(f"{rule.strip()}{client_suffix}\n")
                elif rule.strip():
                    f.write(f"{rule}\n")

        # Embedded AdGuard-native engine formatting parameters
        if include_regex:
            f.write("\n! --- NSFW REGEX INTERCEPTIONS ---\n")
            f.write(f"||/{NSFW_PATTERN}/^{client_suffix}\n")
            
        if include_heuristics:
            f.write("\n! --- COMPILATION EMBEDDED STRUCTURAL DGA REGEX ---\n")
            f.write(f"||/{DGA_PATTERN}/^{client_suffix}\n")

        # Consolidated Global Punycode Interceptor Rule
        f.write("\n! --- GLOBAL PUNYCODE PURGE INTERCEPTOR ---\n")
        f.write(f"||xn--*^{client_suffix}\n")

        if include_spam and spam_text:
            f.write("\n! --- SPAM TLD FOOTPRINTS ---\n")
            for line in spam_text.splitlines():
                # Optimizing: Skip individual xn-- TLD rule records since global rule handles them
                if "xn--" in line: 
                    continue
                if line.strip() and not line.strip().startswith(('!', '#')):
                    f.write(f"{line.strip()}{client_suffix}\n")
                elif line.strip():
                    f.write(f"{line}\n")

        if iot_rules:
            f.write("\n! --- IOT ISOLATED SUBNET INTERCEPTIONS ---\n")
            f.writelines(f"{rule}\n" for rule in iot_rules)

# ---------------------------------------------------------------------------
# Pipeline Structural Core Execution Loop
# ---------------------------------------------------------------------------
async def run_pipeline() -> None:
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

    limits = httpx.Limits(max_keepalive_connections=20, max_connections=40)
    async with httpx.AsyncClient(limits=limits, follow_redirects=True) as client:
        print("[*] Allocating asynchronous pipelines and system structures...")
        allow_trie = SuffixTrie()
        white_trie = SuffixTrie()

        top_tasks = []
        if ENABLE_MAIN_RELEVANCE or ENABLE_MOBILE_RELEVANCE or ENABLE_ULTIMATE_RELEVANCE:
            top_tasks = [asyncio.create_task(fetch_top_list(url, col, skip, comp, client)) for url, col, skip, comp in TOP_LISTS]

        rebind_task = asyncio.create_task(client.get(REBIND_URL, timeout=30.0)) if REBIND_URL else None
        spam_task = asyncio.create_task(client.get(SPAM_TLD_URL, timeout=30.0)) if SPAM_TLD_URL else None
        ss_tasks = {asyncio.create_task(client.get(url, timeout=30.0)): url for url in ADGUARD_SAFESEARCH_URLS}

        print(f"[*] Downloading and parsing {len(all_unique_urls)} source profiles concurrently...")
        fetch_tasks = [asyncio.create_task(fetch_source_domains(url, client)) for url in all_unique_urls]

        if top_tasks:
            top_results = await asyncio.gather(*top_tasks)
            for res in top_results:
                for dom in res: allow_trie.insert(dom)

        try:
            with open(args.whitelist, 'r') as wf:
                for line in wf:
                    if line.strip() and not line.strip().startswith(('#', '!')):
                        white_trie.insert(line.strip().lower())
                print(f"[*] Loaded local tracking whitelists into SuffixTrie memory core.")
        except FileNotFoundError:
            print(f"[*] Manual whitelist storage not detected on local disk execution path.")

        source_data = {}
        for task in asyncio.as_completed(fetch_tasks):
            url, hosts = await task
            source_data[url] = hosts
            
            if DEBUG_SAMPLES:
                p = urlparse(url)
                safe_name = f"{p.netloc}_{p.path.replace('/', '_').strip('_')}"
                try:
                    with open(f"debug_{safe_name}.sample", "w", encoding="utf-8") as dbg:
                        dbg.write("\n".join(list(hosts)[0:200]))
                except OSError as e:
                    print(f"[-] Debug write fault for {url}: {e}")
            print(f"[*] Fetched and parsed {len(hosts)} clean domains from {url}")

        spam_patterns_set, denyallow_map, spam_text = set(), {}, None
        if spam_task:
            try:
                spam_res = await spam_task
                spam_res.raise_for_status()
                spam_patterns_set, denyallow_map = parse_tld_patterns(spam_res.text.splitlines())
                spam_text = spam_res.text
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

    print("[*] Generating Main List...")
    main_set, main_stats, main_src_stats = build_dataset(
        active_main, spam_patterns_set, denyallow_map, allow_trie, white_trie, source_data, 
        disable_relevance=not ENABLE_MAIN_RELEVANCE, disable_tld=not ENABLE_MAIN_TLD, disable_kw=not ENABLE_MAIN_KW, disable_heuristics=not ENABLE_MAIN_HEURISTICS
    )
    print("[*] Generating Mobile List...")
    mobile_set, mobile_stats, mobile_src_stats = build_dataset(
        active_mobile, spam_patterns_set, denyallow_map, allow_trie, white_trie, source_data, 
        disable_relevance=not ENABLE_MOBILE_RELEVANCE, disable_tld=not ENABLE_MOBILE_TLD, disable_kw=not ENABLE_MOBILE_KW, disable_heuristics=not ENABLE_MOBILE_HEURISTICS
    )
    print("[*] Generating Omni List...")
    ultimate_set, ultimate_stats, ultimate_src_stats = build_dataset(
        active_ultimate, spam_patterns_set, denyallow_map, allow_trie, white_trie, source_data, 
        disable_relevance=not ENABLE_ULTIMATE_RELEVANCE, disable_tld=not ENABLE_ULTIMATE_TLD, disable_kw=not ENABLE_ULTIMATE_KW, disable_heuristics=not ENABLE_ULTIMATE_HEURISTICS
    )

    del source_data
    gc.collect()

    # Client mapping and structural injection parameters for IoT infrastructure
    formatted_iot_rules = [f"{rule}$client=10.20.20.0/24" for rule in RAW_IOT_RULES]

    write_output_file(
        args.output, main_set, main_stats, main_src_stats, MAIN_SOURCES, "MAIN", rebind_text, ss_rules, spam_text,
        ENABLE_MAIN_REBIND, ENABLE_MAIN_SAFESEARCH, ENABLE_MAIN_NSFW_REGEX, ENABLE_MAIN_SPAM_TLDS, ENABLE_MAIN_HEURISTICS
    )
    write_output_file(
        args.mobile, mobile_set, mobile_stats, mobile_src_stats, MOBILE_SOURCES, "MOBILE", rebind_text, ss_rules, spam_text,
        ENABLE_MOBILE_REBIND, ENABLE_MOBILE_SAFESEARCH, ENABLE_MOBILE_NSFW_REGEX, ENABLE_MOBILE_SPAM_TLDS, ENABLE_MOBILE_HEURISTICS
    )
    write_output_file(
        args.ultimate, ultimate_set, ultimate_stats, ultimate_src_stats, ULTIMATE_SOURCES, "OMNI", rebind_text, ss_rules, spam_text,
        ENABLE_ULTIMATE_REBIND, ENABLE_ULTIMATE_SAFESEARCH, ENABLE_ULTIMATE_NSFW_REGEX, ENABLE_ULTIMATE_SPAM_TLDS, ENABLE_ULTIMATE_HEURISTICS,
        client_suffix="$client=10.10.10.0/24", iot_rules=formatted_iot_rules
    )

    print(f"[+] Operational Sync Sequence Terminated. Main: {len(main_set)} | Mobile: {len(mobile_set)} | Omni: {len(ultimate_set)}")

def main() -> None:
    asyncio.run(run_pipeline())

if __name__ == "__main__":
    main()
