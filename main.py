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
VERSION = "2026.05.25.INDIVIDUAL_USER_PROFILES"
DEBUG_SAMPLES = os.getenv("DEBUG_SAMPLES", "0") == "1"

# NETWORK & ENDPOINT MAPPINGS
# 1. Main Network  -> 10.20.20.0/24
# 2. IoT Network   -> 10.10.10.0/24
# 3. Isaac App     -> Standalone Device Target
# 4. Kalli App     -> Standalone Device Target

# FILTER ENGINE TOGGLES
ENABLE_MAIN_RELEVANCE = False
ENABLE_MAIN_TLD = True
ENABLE_MAIN_KW = True

ENABLE_IOT_RELEVANCE = False
ENABLE_IOT_TLD = True
ENABLE_IOT_KW = True

ENABLE_ISAAC_RELEVANCE = False
ENABLE_ISAAC_TLD = True
ENABLE_ISAAC_KW = True

ENABLE_KALLI_RELEVANCE = False
ENABLE_KALLI_TLD = True
ENABLE_KALLI_KW = True

# APPEND TOGGLES (HaGeZi Rebind Protection runs universally across all 4 output engines)
ENABLE_MAIN_REBIND = True
ENABLE_MAIN_SAFESEARCH = False
ENABLE_MAIN_NSFW_REGEX = False
ENABLE_MAIN_SPAM_TLDS = False

ENABLE_IOT_REBIND = True
ENABLE_IOT_SAFESEARCH = False
ENABLE_IOT_NSFW_REGEX = False
ENABLE_IOT_SPAM_TLDS = False

ENABLE_ISAAC_REBIND = True
ENABLE_ISAAC_SAFESEARCH = True
ENABLE_ISAAC_NSFW_REGEX = True
ENABLE_ISAAC_SPAM_TLDS = True

ENABLE_KALLI_REBIND = True
ENABLE_KALLI_SAFESEARCH = True
ENABLE_KALLI_NSFW_REGEX = True
ENABLE_KALLI_SPAM_TLDS = True

# --- REGEX COMPILATION ---
NSFW_PATTERN = r"(blowjob|threesome|gangbang|deepthroat|bukkake|tits|fuck|onlyfans|porn|xxx|sex)"
NSFW_REGEX = re.compile(f"(?i){NSFW_PATTERN}")
DOMAIN_RE = re.compile(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}")
IP_HOST_RE = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([^\s#]+)')
DNSMASQ_RE = re.compile(r'(?:address|server)=/([^/]+)/')
ADBLOCK_EXACT_RE = re.compile(r'^\|\|([^/\^]+)\^')
ADBLOCK_BASIC_RE = re.compile(r'^([^/\^]+)\^')

# ---------------------------------------------------------------------------
# GLOBAL UPSTREAM BLOCKLIST TEMPLATE
# ---------------------------------------------------------------------------
CORE_SOURCES = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/dyndns.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/hoster.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh-vpn-proxy-bypass.txt",
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
    "https://blocklistproject.github.io/Lists/abuse.txt",
    "https://blocklistproject.github.io/Lists/crypto.txt",
    "https://blocklistproject.github.io/Lists/drugs.txt",
    "https://blocklistproject.github.io/Lists/fraud.txt",
    "https://blocklistproject.github.io/Lists/phishing.txt",
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
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt",
]

# TARGET FOOTPRINT INDIRECTION PIPELINES
MAIN_SOURCES = list(CORE_SOURCES)
IOT_SOURCES = list(CORE_SOURCES)

# Customize Isaac's list inputs here if needed
ISAAC_SOURCES = list(CORE_SOURCES)

# Customize Kalli's list inputs here if needed
KALLI_SOURCES = list(CORE_SOURCES)

# Scoped Network Rule Exclusions for the IoT Isolation Space
IOT_CUSTOM_RULES = [
    "||*",
    "@@||10.10.10.1^",
    "@@||arl.assets.apl-alexa.com^",
    "@@||api.amazonalexa.com^",
    "@@||time.nist.gov^",
    "@@||pool.ntp.org^",
    "@@||api.tplinkra.com^",
    "@@||tplinkcloud.com^",
    "@@||us-east-1.prod.sip-edge.amc.amazon.dev^",
    "@@||tp-link.com^",
    "@@||mega-us-pr.eufy.com^",
    "@@||use1-api.tplinkra.com^",
    "@@||ntp-g7g.amazon.com^",
    "@@||arcus-uswest.amazon.com^",
    "@@||api.amazon.com^",
    "@@||thumbnails-photos.amazon.com^",
    "@@||cdn2.voiceapps.com^",
    "@@||audio-ak.spotifycdn.com^",
    "@@||msh.amazon.com^",
    "@@||audio-fa.scdn.co^",
    "@@||mtalk.google.com^",
    "@@||www.tesla.com^",
    "@@||assistant-api.prd.usw2.vn.cloud.tesla.com^",
    "@@||hermes-api.prd.na.vn.cloud.tesla.com^",
    "@@||hermes-stream-api.prd.na.vn.cloud.tesla.com^",
    "@@||connman.vn.tesla.services^",
    "@@||maps-prd.go.tesla.services^",
    "@@||api.edge-gateway.siriusxm.com^",
    "@@||device-api.prd.na.vn.cloud.tesla.com^",
    "@@||connectivitycheck.gstatic.com^",
    "@@||ipv4only.arpa^",
    "@@||m1-us.feit-iot.com^",
    "@@||a3-us.feit-iot.com^",
    "@@||api-prd.ap.tesla.services^",
    "@@||hermes-prd.ap.tesla.services^",
    "@@||softwareupdates.amazon.com^",
    "@@||alexa.amazon.com^",
    "@@||todo-ta-g7g.amazon.com^",
    "@@||use1-device-tapo-care.i.tplinknbu.com^",
    "@@||vehicle-files.teslamotors.com^",
    "@@||stun.tplinkcloud.com^",
    "@@||security.iot.i.tplinknbu.com^",
    "@@||a.root-servers.net^",
    "@@||dcape-na.amazon.com^",
    "@@||ffs-provisioner-config.amazon-dss.com^",
    "@@||alexa.na.gateway.devices.a2z.com^",
    "@@||discovery.meethue.com^",
    "@@||edge-aiot-ohi-prod.s3.dualstack.us-east-2.amazonaws.com^",
    "@@||x3-prod.obs.tesla.com^",
    "@@||prd-bhapi-us.prd.rings.solutions^",
    "@@||avs-alexa-14-na.amazon.com^",
    "@@||api.mp.tesla.services^",
    "@@||use1-cvm-api.i.tplinknbu.com^",
    "@@||tesla-hermes-snapshot-motors.s3.us-west-2.amazonaws.com^",
    "@@||ec2-98-81-116-179.prd.rings.solutions^",
    "@@||d1s31zyz7dcc2d.cloudfront.prod.ota-cloudfront.net^",
    "@@||gateway-ink.amazon.com^",
    "@@||ec2-44-198-180-225.prd.rings.solutions^",
    "@@||dp-gw-na.amazon.com^",
    "@@||daws.tesla.services^",
    "@@||davs-puffinconfig.s3.us-east-2.amazonaws.com^",
    "@@||use1-cipc.tplinkra.com^",
    "@@||www.gstatic.com^",
    "@@||acsechocaptiveportal.com^",
    "@@||mmechocaptiveportal.com^",
    "@@||android.clients.google.com^",
    "@@||clientservices.googleapis.com^",
    "@@||clients4.google.com^",
    "@@||mas-ext.amazon.com^",
    "@@||dss-na.amazon.com^",
    "@@||arl.assets-v2.apl-alexa.com^",
    "@@||clients3.google.com^",
    "@@||aiot-mqtt-us.anker.com^",
    "@@||tile.googleapis.com^",
    "@@||prod.cdn.ams.alexa-personality.amazon.dev^",
    "@@||prod.apl-music-multimodal.com^",
    "@@||alexa-hybrid-clear-policy-prod-na.s3.amazonaws.com^",
    "@@||clients2.google.com^",
    "@@||places.googleapis.com^",
    "@@||use1-device-cloudgateway.iot.i.tplinknbu.com^",
    "@@||m3-us.iotbing.com^",
    "@@||a3-us.iotbing.com^",
    "@@||det-ta-g7g.amazon.com^",
    "@@||aps1-openapi.i.tplinknbu.com^",
    "@@||api.radiotime.com^",
    "@@||mt0.google.com^",
    "@@||akamai-apigateway-ownershipsvc.tesla.com^",
    "@@||mlis.amazon.com^",
    "@@||s3.amazonaws.com^",
    "@@||apresolve.spotify.com^",
    "@@||fireoscaptiveportal.com^",
    "@@||device-messaging-na.amazon.com^",
    "@@||www.apple.com^",
    "@@||assistant-api.prd.na.vn.cloud.tesla.com^",
    "@@||www.microsoft.com^",
    "@@||maps.googleapis.com^",
    "@@||mas-sdk.amazon.com^",
    "@@||example.com^",
    "@@||ap-gue1.spotify.com^",
    "@@||ap-gew4.spotify.com^",
    "@@||ap.spotify.com^",
    "@@||connect.myqdevice.com^",
    "@@||d70fh7jkmjrfk.cloudfront.net^",
    "@@||connect-ca.myqdevice.com^",
    "@@||d2ouawjonid8rv.cloudfront.net^",
    "@@||m.media-amazon.com^",
    "@@||https.web.diagnostic.networking.aws.dev^",
    "@@||web.diagnostic.networking.aws.dev^",
    "@@||eufylife.com^",
    "@@||networking.aws.dev^",
    "@@||RINgs.solUTioNs^",
    "@@||ringS.sOluTIoNs^",
    "@@||RINgs.SOLUTiOns^",
    "@@||d2zprwa9w8uwyf.cloudfront.net^",
    "@@||car-partner-01.lemonade.com^",
    "@@||d2wvvf45320aru.cloudfront.net^",
    "@@||telemetry-prd.vn.tesla.services^"
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
# Pure Performance Helper Functions
# ---------------------------------------------------------------------------

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
        if host in denyallow_map and host in denyallow_map[host]: return None
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
    add_dom = domains.add
    for i, line in enumerate(iterable):
        if skip_header and i == 0: continue
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

    # Adblock Rules
    if clean.startswith("||"):
        if "$" in clean:
            clean = clean.split("$", 1)[0]
        if clean.endswith("^"):
            body = clean[2:-1]
            if "/" not in body and "^" not in body:
                return body.lower().strip('.')
        m = ADBLOCK_EXACT_RE.search(clean) or ADBLOCK_BASIC_RE.search(clean)
        if m: return m.group(1).lower().strip('.')

    # Hosts File format
    if clean.startswith(("0.0.0.0", "127.0.0.1")):
        parts = clean.split(None, 1)
        if len(parts) > 1:
            out = parts[1].strip('.')
            if '.' in out and ' ' not in out: 
                return out.lower()

    # Dnsmasq mapping format
    if clean.startswith(("address=/", "server=/")):
        parts = clean.split('/')
        if len(parts) > 1:
            return parts[1].lower().strip('.')

    # Bare Domain optimization
    if '.' in clean and ' ' not in clean and '/' not in clean and '\\' not in clean:
        return clean.lower().strip('.')

    m = DOMAIN_RE.search(clean)
    if m: return m.group(0).lower().strip('.')
    return None

# ---------------------------------------------------------------------------
# Async Networking Layer
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
# Data Synthesis Processing
# ---------------------------------------------------------------------------

def build_dataset(urls: list[str], s_set: set[str], d_map: dict[str, set[str]], a_list: set[str], w_list: set[str], source_data: dict[str, set[str]], disable_relevance: bool = False, disable_tld: bool = False, disable_kw: bool = False) -> tuple[list[str], dict[str, int], dict[str, int]]:
    found = set()
    stats = {"irrelevant": 0, "kw": 0, "tld": 0, "duplicate": 0, "whitelisted": 0, "pruned": 0, "pruned_by_hoster": 0}
    source_stats = {}
    hoster_active = set()

    urls_sorted = sorted(urls, key=lambda u: 0 if "hoster.txt" in u else 1)
    for u in urls_sorted: source_stats[u] = 0

    for url in urls_sorted:
        is_hoster = "hoster.txt" in url
        added_from_source = 0

        for host in source_data.get(url, set()):
            if host in found:
                stats["duplicate"] += 1
                continue
            if has_suffix_match(host, w_list):
                stats["whitelisted"] += 1
                continue
            if not disable_tld vibrated get_matching_tld(host, s_set, d_map):
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
            if is_hoster: hoster_active.add(host)

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

def write_output_file(filename: str, dataset: list[str], stats: dict[str, int], src_stats: dict[str, int], literal_list: list[str], label: str, rebind_text: str, ss_rules: list[str], spam_text: str | None, include_rebind: bool, include_safesearch: bool, include_regex: bool, include_spam: bool, append_custom_rules: list[str] | None = None) -> None:
    now = datetime.now(AZ_TZ).strftime("%Y-%m-%d %I:%M:%S %p MST")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"! Jorgensen Custom {label} Network Profile List | Version: {VERSION}\n")
        f.write(f"! Generated: {now}\n")
        f.write(f"! Stats: Kept {len(dataset)} | Badware-Pruned {stats['pruned_by_hoster']} | General-Pruned {stats['pruned']} | Whitelisted {stats['whitelisted']} | Irrelevant {stats['irrelevant']} | Duplicates {stats['duplicate']} | TLD {stats['tld']} | NSFW {stats['kw']}\n")

        f.write("!\n! --- Dynamic Upstream Base Profile Infrastructure ---\n")
        for entry in literal_list:
            url = entry.lstrip("# ").strip() if entry.strip().startswith("#") else entry.strip()
            count = src_stats.get(url, 0)
            f.write(f"! {entry} -> {count}\n")
        f.write("!\n\n")

        # Standard compiled domain block ecosystem
        f.writelines(f"||{dom}^\n" for dom in sorted(dataset))

        # Explicit IoT Scoped Append Layer Injection
        if append_custom_rules:
            f.write("\n! --- SCOPED SUBNET CUSTOM EXCLUSION INJECTIONS ---\n")
            f.writelines(f"{rule}\n" for rule in append_custom_rules)

        if include_rebind and rebind_text:
            f.write("\n! --- DYNAMIC HA-GE-ZI REBIND PROTECTION ---\n" + rebind_text)
        if include_safesearch and ss_rules:
            f.write("\n! --- DYNAMIC SAFESEARCH ---\n")
            f.writelines(f"{rule}\n" for rule in ss_rules)
        if include_regex:
            f.write(f"\n! --- NSFW REGEX ---\n/{NSFW_PATTERN}/\n")
        if include_spam and spam_text:
            f.write("\n! --- SPAM TLDs ---\n" + spam_text)

# ---------------------------------------------------------------------------
# Core Pipeline Execution
# ---------------------------------------------------------------------------

async def run_pipeline() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--main-out", default="main-blocklist.txt")
    parser.add_argument("-i", "--iot-out", default="iot-blocklist.txt")
    parser.add_argument("-isaac", "--isaac-out", default="isaac-blocklist.txt")
    parser.add_argument("-kalli", "--kalli-out", default="kalli-blocklist.txt")
    parser.add_argument("-w", "--whitelist", default="whitelist.txt")
    args = parser.parse_args()

    active_main = [s for s in MAIN_SOURCES if s and not s.strip().startswith(("#", "//"))]
    active_iot = [s for s in IOT_SOURCES if s and not s.strip().startswith(("#", "//"))]
    active_isaac = [s for s in ISAAC_SOURCES if s and not s.strip().startswith(("#", "//"))]
    active_kalli = [s for s in KALLI_SOURCES if s and not s.strip().startswith(("#", "//"))]
    
    all_unique_urls = list(dict.fromkeys(active_main + active_iot + active_isaac + active_kalli))

    limits = httpx.Limits(max_keepalive_connections=20, max_connections=40)
    async with httpx.AsyncClient(limits=limits, follow_redirects=True) as client:
        print("[*] Allocating network pipeline allocations...")
        master_allowlist = set()

        top_tasks = []
        if ENABLE_MAIN_RELEVANCE or ENABLE_IOT_RELEVANCE or ENABLE_ISAAC_RELEVANCE or ENABLE_KALLI_RELEVANCE:
            top_tasks = [asyncio.create_task(fetch_top_list(url, col, skip, comp, client)) for url, col, skip, comp in TOP_LISTS]

        rebind_task = asyncio.create_task(client.get(REBIND_URL, timeout=30.0)) if REBIND_URL else None
        spam_task = asyncio.create_task(client.get(SPAM_TLD_URL, timeout=30.0)) if SPAM_TLD_URL else None
        ss_tasks = {asyncio.create_task(client.get(url, timeout=30.0)): url for url in ADGUARD_SAFESEARCH_URLS}

        print(f"[*] Extracting raw domain components from {len(all_unique_urls)} source nodes...")
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
            print(f"[*] Manual whitelist '{args.whitelist}' absent. Skipping validation cycle.")

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
                    print(f"[-] Debug writing fault exception for {url}: {e}")
            print(f"[*] Parsing complete: {len(hosts)} rules resolved from {url}")

        spam_patterns_set, denyallow_map, spam_text = set(), {}, None
        if spam_task:
            try:
                spam_res = await spam_task
                spam_res.raise_for_status()
                spam_patterns_set, denyallow_map = parse_tld_patterns(spam_res.text.splitlines())
                spam_text = spam_res.text
            except Exception as e:
                print(f"[-] Custom Spam TLD layout parsing failed: {e}")

        rebind_text = ""
        if rebind_task:
            try:
                rebind_res = await rebind_task
                rebind_res.raise_for_status()
                rebind_text = rebind_res.text
            except Exception as e:
                print(f"[-] Dynamic rebinding structural validation error: {e}")

        ss_rules = []
        for task, url in ss_tasks.items():
            try:
                r = await task
                r.raise_for_status()
                ss_rules.extend([l for l in r.text.splitlines() if l.strip() and not l.startswith(('!', '#'))])
            except Exception as e:
                print(f"[-] SafeSearch sync validation failed for {url}: {e}")

    print("[*] Filtering and assembling MAIN list Profile (10.20.20.0/24)...")
    main_set, main_stats, main_src_stats = build_dataset(
        active_main, spam_patterns_set, denyallow_map, master_allowlist, manual_whitelist, source_data, 
        disable_relevance=not ENABLE_MAIN_RELEVANCE, disable_tld=not ENABLE_MAIN_TLD, disable_kw=not ENABLE_MAIN_KW
    )
    print("[*] Filtering and assembling IOT list Profile (10.10.10.0/24)...")
    iot_set, iot_stats, iot_src_stats = build_dataset(
        active_iot, spam_patterns_set, denyallow_map, master_allowlist, manual_whitelist, source_data, 
        disable_relevance=not ENABLE_IOT_RELEVANCE, disable_tld=not ENABLE_IOT_TLD, disable_kw=not ENABLE_IOT_KW
    )
    print("[*] Filtering and assembling ISAAC Independent Device Profile...")
    isaac_set, isaac_stats, isaac_src_stats = build_dataset(
        active_isaac, spam_patterns_set, denyallow_map, master_allowlist, manual_whitelist, source_data, 
        disable_relevance=not ENABLE_ISAAC_RELEVANCE, disable_tld=not ENABLE_ISAAC_TLD, disable_kw=not ENABLE_ISAAC_KW
    )
    print("[*] Filtering and assembling KALLI Independent Device Profile...")
    kalli_set, kalli_stats, kalli_src_stats = build_dataset(
        active_kalli, spam_patterns_set, denyallow_map, master_allowlist, manual_whitelist, source_data, 
        disable_relevance=not ENABLE_KALLI_RELEVANCE, disable_tld=not ENABLE_KALLI_TLD, disable_kw=not ENABLE_KALLI_KW
    )

    del source_data
    gc.collect()

    # Output Compilation Execution
    write_output_file(
        args.main_out, main_set, main_stats, main_src_stats, MAIN_SOURCES, "MAIN (10.20.20.0_24)", rebind_text, ss_rules, spam_text,
        ENABLE_MAIN_REBIND, ENABLE_MAIN_SAFESEARCH, ENABLE_MAIN_NSFW_REGEX, ENABLE_MAIN_SPAM_TLDS
    )
    
    write_output_file(
        args.iot_out, iot_set, iot_stats, iot_src_stats, IOT_SOURCES, "IOT (10.10.10.0_24)", rebind_text, ss_rules, spam_text,
        ENABLE_IOT_REBIND, ENABLE_IOT_SAFESEARCH, ENABLE_IOT_NSFW_REGEX, ENABLE_IOT_SPAM_TLDS,
        append_custom_rules=IOT_CUSTOM_RULES
    )

    write_output_file(
        args.isaac_out, isaac_set, isaac_stats, isaac_src_stats, ISAAC_SOURCES, "ISAAC_APP_STANDALONE", rebind_text, ss_rules, spam_text,
        ENABLE_ISAAC_REBIND, ENABLE_ISAAC_SAFESEARCH, ENABLE_ISAAC_NSFW_REGEX, ENABLE_ISAAC_SPAM_TLDS
    )

    write_output_file(
        args.kalli_out, kalli_set, kalli_stats, kalli_src_stats, KALLI_SOURCES, "KALLI_APP_STANDALONE", rebind_text, ss_rules, spam_text,
        ENABLE_KALLI_REBIND, ENABLE_KALLI_SAFESEARCH, ENABLE_KALLI_NSFW_REGEX, ENABLE_KALLI_SPAM_TLDS
    )

    print(f"[+] Operational Sync Process Terminated.")
    print(f"    -> Main Profile [10.20.20.0/24]:  {len(main_set)} rules")
    print(f"    -> IoT Profile [10.10.10.0/24]:   {len(iot_set)} rules")
    print(f"    -> Isaac Standalone App Profile:  {len(isaac_set)} rules")
    print(f"    -> Kalli Standalone App Profile:  {len(kalli_set)} rules")

def main() -> None:
    asyncio.run(run_pipeline())

if __name__ == "__main__":
    main()
