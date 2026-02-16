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
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
]

# Keywords to Nuke
NSFW_REGEX = re.compile(r"(?i)(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo)")

# YouTube Safety Rule
YOUTUBE_RULE = "/^(www\.|m\.|youtubei\.|youtube\.)?(youtube(-nocookie)?\.com|googleapis\.com)$/$dnsrewrite=restrictmoderate.youtube.com"

OUTPUT_FILE = "blocklist.txt"

def is_ip(val):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", val) is not None

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
        
        # 1. Detect Allows (@@)
        is_allow = line.startswith('@@')
        rule_content = line[2:] if is_allow else line
        
        # 2. Extract domain for logic, but don't lose the format
        clean_domain = rule_content.split('#')[0].split(';')[0].split('$')[0].strip()
        if clean_domain.startswith("||"): clean_domain = clean_domain[2:]
        if clean_domain.endswith("^"): clean_domain = clean_domain[:-1]
        if clean_domain.startswith("*."): clean_domain = clean_domain[2:]
        
        # Extract actual domain from hosts format if needed
        parts = clean_domain.split()
        domain = parts[1] if (len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::1")) else parts[0]

        if not domain or is_ip(domain): continue
        if NSFW_REGEX.search(domain): continue

        # 3. Handle TLD-only entries in the spam list
        if is_spam_tld_list and not is_allow and ('.' not in domain or domain.startswith('.')):
            tld = domain.strip('.')
            spam_tlds.add(tld)
            continue

        if is_allow:
            allows.add(domain)
        else:
            if '.' in domain and not domain.startswith('.'):
                blocks.add(domain)
                
    return blocks, allows, spam_tlds

def prune_and_reformat(block_set, allow_set, spam_tld_set):
    print(f"Filtering {len(block_set):,} blocks with TLD Firewall...")
    
    # 1. Filter out domains that fall under a blocked TLD (unless allowed)
    filtered = set()
    for d in block_set:
        tld = d.split('.')[-1]
        if tld in spam_tld_set:
            if d in allow_set:
                filtered.add(d)
            continue
        filtered.add(d)

    # 2. Tree Pruning
    rev_blocks = sorted(['.'.join(d.split('.')[::-1]) for d in filtered])
    pruned_rev = []
    last_added = ""
    for rb in rev_blocks:
        current_domain = '.'.join(rb.split('.')[::-1])
        if last_added and rb.startswith(last_added + "."):
            if current_domain not in allow_set:
                continue
        pruned_rev.append(rb)
        last_added = rb
    
    # 3. Final Re-Formatting: ADD THE SIGNS BACK
    final_list = [f"||{'.'.join(d.split('.')[::-1])}^" for d in pruned_rev]
    
    # 4. Add the TLD Firewalls as wildcards
    for tld in spam_tld_set:
        final_list.append(f"||*.{tld}^")
        
    # 5. Add the Allows with proper syntax
    for a in allow_set:
        final_list.append(f"@@||{a}^")
        
    return sorted(final_list)

def main():
    all_blocks = set()
    all_allows = set()
    all_spam_tlds = set()
    start_time = datetime.now()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in SOURCES}
        for future in concurrent.futures.as_completed(future_to_url):
            lines, url = future.result()
            b, a, t = parse_lines(lines, is_spam_tld_list=("spam-tlds" in url))
            all_blocks.update(b)
            all_allows.update(a)
            all_spam_tlds.update(t)

    final_rules = prune_and_reformat(all_blocks, all_allows, all_spam_tlds)
    final_rules.append(YOUTUBE_RULE) # Add the YouTube Regex

    with open(OUTPUT_FILE, "w") as f:
        f.write("############################################################\n")
        f.write("# ISAAC'S ADGUARD-SYNTAX MASTER LIST (NUCLEAR EDITION)\n")
        f.write(f"# TLD Firewall: {len(all_spam_tlds)} TLDs Blocked as ||*.tld^\n")
        f.write("############################################################\n\n")
        f.write("\n".join(final_rules))

    print(f"Finished in {datetime.now() - start_time}. Total rules: {len(final_rules):,}")

if __name__ == "__main__":
    main()
