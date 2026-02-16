import requests
import concurrent.futures
import re
from datetime import datetime

# --- CONFIGURATION ---
VERSION = datetime.now().strftime("%Y.%m.%d.01")
SOURCES = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    "https://badmojr.github.io/1Hosts/Lite/adblock.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
    "https://big.oisd.nl",
    "https://nsfw.oisd.nl",
    "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adguard/dns-rebind-protection.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt",
]

# Keywords to Nuke
NSFW_REGEX = re.compile(r"(?i)(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo)")

# YouTube Safety Rule
YOUTUBE_RULE = "/^(www\.|m\.|youtubei\.|youtube\.)?(youtube(-nocookie)?\.com|googleapis\.com)$/$dnsrewrite=restrictmoderate.youtube.com"

OUTPUT_FILE = "blocklist.txt"

def fetch_url(url):
    try:
        r = requests.get(url, timeout=25)
        r.raise_for_status()
        return r.text.splitlines(), url
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return [], url

def parse_lines(lines, is_spam_tld_list=False):
    blocks = set()
    allows = set()
    spam_tlds = set()

    for line in lines:
        line = line.strip().lower()
        if not line or line.startswith(('#', '!', ';')): continue
        
        # Detect Allows
        is_allow = line.startswith('@@')
        if is_allow: line = line[2:]
        
        # Clean AdGuard/Hosts syntax
        line = line.split('#')[0].split(';')[0].split('$')[0].strip()
        if line.startswith("||"): line = line[2:]
        if line.endswith("^"): line = line[:-1]
        if line.startswith("*."): line = line[2:]
        
        # Extract domain
        parts = line.split()
        domain = parts[1] if (len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::1")) else parts[0]

        # Validation
        if not domain: continue

        # Keyword Filter (Remove if matched)
        if NSFW_REGEX.search(domain):
            continue

        if is_spam_tld_list and not is_allow:
            # If it's a TLD list, treat entries as TLDs to block everything under them
            # Format: .top or top
            tld = domain.strip('.')
            spam_tlds.add(tld)
            blocks.add(f"||*.{tld}^")
        else:
            if '.' in domain and not domain.startswith('.'):
                if is_allow: allows.add(domain)
                else: blocks.add(domain)
                
    return blocks, allows, spam_tlds

def prune_blocks(block_set, allow_set, spam_tld_set):
    """
    1. Removes any domain whose TLD is in the spam list.
    2. Performs standard tree pruning.
    """
    print(f"Pruning and TLD filtering...")
    filtered_blocks = set()
    
    for d in block_set:
        # TLD Firewall: Remove domain if its TLD is in the spam list
        # (Unless it is already the wildcard rule itself)
        if not d.startswith("||*."):
            tld = d.split('.')[-1]
            if tld in spam_tld_set and d not in allow_set:
                continue
        filtered_blocks.add(d)

    # Standard Tree Pruning
    rev_blocks = sorted(['.'.join(d.split('.')[::-1]) for d in filtered_blocks])
    pruned_rev = []
    last_added = ""
    for rb in rev_blocks:
        current_domain = '.'.join(rb.split('.')[::-1])
        if last_added and rb.startswith(last_added + "."):
            if current_domain not in allow_set:
                continue
        pruned_rev.append(rb)
        last_added = rb
        
    return ['.'.join(d.split('.')[::-1]) for d in pruned_rev]

def main():
    all_blocks = set()
    all_allows = set()
    all_spam_tlds = set()
    start_time = datetime.now()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in SOURCES}
        for future in concurrent.futures.as_completed(future_to_url):
            lines, url = future.result()
            is_tld = "spam-tlds" in url
            b, a, t = parse_lines(lines, is_spam_tld_list=is_tld)
            all_blocks.update(b)
            all_allows.update(a)
            all_spam_tlds.update(t)
            print(f"  + Processed {url[:45]}...")

    raw_block_count = len(all_blocks)
    final_blocks = prune_blocks(all_blocks, all_allows, all_spam_tlds)
    
    # Combine everything
    final_list = sorted(final_blocks + [f"@@||{a}^" for a in all_allows])
    
    # Add the YouTube Rule at the end
    final_list.append(YOUTUBE_RULE)

    with open(OUTPUT_FILE, "w") as f:
        f.write("############################################################\n")
        f.write("# ISAAC'S ULTIMATE MASTER BLOCKLIST\n")
        f.write(f"# Revision: {VERSION}\n")
        f.write(f"# TLD Firewall: ACTIVE ({len(all_spam_tlds)} TLDs)\n")
        f.write(f"# Keyword Filtering: ACTIVE (NSFW Scrubbed)\n")
        f.write(f"# YouTube Restricted Mode: ENABLED\n")
        f.write(f"# Blocks: {len(final_blocks):,} | Allows: {len(all_allows):,}\n")
        f.write("############################################################\n\n")
        f.write("\n".join(final_list))

    print(f"Done! Final count: {len(final_list):,} (Pruned {raw_block_count - len(final_blocks):,} entries)")

if __name__ == "__main__":
    main()
