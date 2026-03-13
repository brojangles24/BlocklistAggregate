import requests
import re
import time
import argparse
import io
import zipfile
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

AZ_TZ = timezone(timedelta(hours=-7))
VERSION = "2026.03.12.10M_LIST"

DEFAULT_SOURCES = [
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.mini.txt",
    #"https://badmojr.github.io/1Hosts/Lite/adblock.txt",
    #"https://big.oisd.nl",
    #"https://nsfw.oisd.nl",
    #"https://nsfw-small.oisd.nl",
    "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adguard/dns-rebind-protection.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
    #"https://raw.githubusercontent.com/laylavish/uBlockOrigin-HUGE-AI-Blocklist/refs/heads/main/noai_hosts.txt",
]

SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"
TOP_10M_URL = "https://www.domcop.com/files/top/top10milliondomains.csv.zip"

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

def fetch_top_10m_set():
    print("[*] Downloading DomCop Top 10 Million list (this may take a minute)...")
    try:
        # Increased timeout because this is a massive file
        r = requests.get(TOP_10M_URL, timeout=60)
        r.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            # Safely grab the first file in the zip
            filename = z.namelist()[0]
            with z.open(filename) as f:
                domains = set()
                for line in f:
                    if b',' in line:
                        parts = line.split(b',')
                        if len(parts) >= 2:
                            dom = parts[1].decode('utf-8').strip().lower()
                            # Skip the header row if it exists
                            if dom and dom != "domain":
                                domains.add(dom)
                return domains
    except requests.RequestException as e:
        print(f"[!] Top 10M fetch failed: {e}. All domains will be included.")
        return None

def fetch_stream(url, session):
    try:
        r = session.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=(5, 30))
        r.raise_for_status()
        return r.text.splitlines()
    except requests.RequestException:
        return []

def parse_tld_patterns(lines):
    tld_patterns = set()
    denyallow_map = {}
    for line in lines:
        clean = line.split("!")[0].split("#")[0].strip().lower()
        if not clean: continue
        rule_part = clean.split("$")[0].replace("||", "").replace("^", "").lstrip("*").lstrip(".")
        tld_patterns.add(rule_part)
        if "denyallow=" in clean:
            denyallow_map[rule_part] = set(clean.split("denyallow=")[1].split(",")[0].split("|"))
    return tld_patterns, denyallow_map

def get_matching_tld(host, spam_set, denyallow_map):
    parts = host.split('.')
    for i in range(len(parts)):
        candidate = ".".join(parts[i:])
        if candidate in spam_set:
            if candidate in denyallow_map and host in denyallow_map[candidate]: return None 
            return candidate
    return None

# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", default="blocklist.txt")
    args = parser.parse_args()

    start_time = time.time()
    active_sources = [s for s in DEFAULT_SOURCES if not s.startswith("#")]

    final_output = []
    seen_domains = set()
    dropped_irrelevant = 0
    dropped_kw = 0
    dropped_tld = 0

    print(f"[*] Starting parallel downloads ({len(active_sources)} sources + Top 10M + Spam TLDs)...")

    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=8) as executor:
            future_top10m = executor.submit(fetch_top_10m_set)
            future_spam = executor.submit(fetch_stream, SPAM_TLD_URL, session)
            future_to_url = {executor.submit(fetch_stream, url, session): url for url in active_sources}

            top_10m_relevant = future_top10m.result()
            spam_tld_raw = future_spam.result()
            spam_patterns_set, denyallow_map = parse_tld_patterns(spam_tld_raw)

            print("[*] Processing lists as they download...")
            for future in as_completed(future_to_url):
                for line in future.result():
                    clean = line.strip()
                    
                    if not clean or clean.startswith(('!', '#', '[', ' ')):
                        final_output.append(line)
                        continue

                    host = None
                    if clean.startswith(("0.0.0.0 ", "127.0.0.1 ")):
                        parts = clean.split()
                        if len(parts) >= 2: host = parts[1].lower().strip(".")
                    elif clean.startswith("||") and "^" in clean:
                        host = clean.replace("||", "").split("^")[0].lower().strip(".")
                    elif "/" not in clean and "*" not in clean and " " not in clean:
                        host = clean.lower().strip(".")

                    if not host:
                        final_output.append(line)
                        continue

                    if host in seen_domains:
                        continue

                    if NSFW_REGEX.search(host):
                        dropped_kw += 1
                        continue

                    if get_matching_tld(host, spam_patterns_set, denyallow_map):
                        dropped_tld += 1
                        continue

                    # Bypass Top 10M check for IP/CIDR rules
                    is_ip_or_cidr = re.match(r'^[\d\.:/]+$', host)
                    if top_10m_relevant and host not in top_10m_relevant and not is_ip_or_cidr:
                        dropped_irrelevant += 1
                        continue

                    seen_domains.add(host)
                    final_output.append(line)

    now = datetime.now(AZ_TZ).strftime("%Y-%m-%d %I:%M:%S %p MST")
    
    print("[*] Writing final blocklist...")
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(f"! Jorgensen High-Signal Blocklist | Version: {VERSION}\n")
        f.write(f"! Generated: {now}\n")
        f.write(f"! Stats -> Irrelevant Dropped: {dropped_irrelevant} | Spam TLD Redundancy Dropped: {dropped_tld} | NSFW Dropped: {dropped_kw}\n\n")
        
        for line in final_output:
            f.write(f"{line}\n")
        
        f.write("\n! --- HAGEZI SPAM TLDS ---\n")
        for line in spam_tld_raw:
            f.write(f"{line}\n")

        f.write("\n! --- NSFW REGEX BLOCK ---\n")
        f.write(f"/{NSFW_PATTERN}/\n")

    print(f"\n[+] Done in {time.time() - start_time:.2f}s.")
    print(f"    Rules Kept: {len(seen_domains)}")
    print(f"    Dropped (NSFW Keywords): {dropped_kw}")
    print(f"    Dropped (Spam TLD Redundancy): {dropped_tld}")
    print(f"    Dropped (Not in Top 10M): {dropped_irrelevant}")

if __name__ == "__main__":
    main()
