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
        
        # 1. Detect Allows (@@) - CRITICAL: Do this BEFORE any other processing
        is_allow = line.startswith('@@')
        current_rule = line[2:] if is_allow else line
        
        # 2. Clean AdGuard/Hosts syntax/modifiers
        current_rule = current_rule.split('#')[0].split(';')[0].split('$')[0].strip()
        if current_rule.startswith("||"): current_rule = current_rule[2:]
        if current_rule.endswith("^"): current_rule = current_rule[:-1]
        if current_rule.startswith("*."): current_rule = current_rule[2:]
        
        # 3. Handle TLD-only rules in the Spam TLD list
        # Example: "top" or ".top" or "||top^"
        if is_spam_tld_list and not is_allow and ('.' not in current_rule or current_rule.startswith('.')):
            tld = current_rule.strip('.')
            spam_tlds.add(tld)
            continue

        # 4. Extract domain
        parts = current_rule.split()
        domain = parts[1] if (len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::1")) else parts[0]

        if not domain or is_ip(domain): continue
        if NSFW_REGEX.search(domain): continue

        # 5. Route to correct bucket
        if is_allow:
            allows.add(domain)
        else:
            if '.' in domain and not domain.startswith('.'):
                blocks.add(domain)
                
    return blocks, allows, spam_tlds

def prune_blocks(block_set, allow_set, spam_tld_set):
    print(f"Applying TLD Firewall and Pruning...")
    
    # 1. TLD Firewall: Remove domains if TLD is blocked, UNLESS they have an allow rule
    filtered_blocks = set()
    for d in block_set:
        tld = d.split('.')[-1]
        if tld in spam_tld_set:
            if d not in allow_set: # Only skip if NOT whitelisted
                continue
        filtered_blocks.add(d)

    # 2. Tree-based Pruning (The "Optimizer")
    rev_blocks = sorted(['.'.join(d.split('.')[::-1]) for d in filtered_blocks])
    pruned_rev = []
    last_added = ""
    for rb in rev_blocks:
        current_domain = '.'.join(rb.split('.')[::-1])
        # Only prune if it's a subdomain AND doesn't have a specific exception rule
        if last_added and rb.startswith(last_added + "."):
            if current_domain not in allow_set:
                continue
        pruned_rev.append(rb)
        last_added = rb
    
    # 3. Format back with AdGuard Signs ||...^
    final_signed_blocks = [f"||{'.'.join(d.split('.')[::-1])}^" for d in pruned_rev]
    
    # 4. Add the TLD Wildcards themselves (the firewall rules)
    for tld in spam_tld_set:
        final_signed_blocks.append(f"||*.{tld}^")
        
    return final_signed_blocks

def main():
    all_blocks = set()
    all_allows = set()
    all_spam_tlds = set()
    start_time = datetime.now()

    # Concurrent fetch
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in SOURCES}
        for future in concurrent.futures.as_completed(future_to_url):
            lines, url = future.result()
            is_tld_src = "spam-tlds" in url
            b, a, t = parse_lines(lines, is_spam_tld_list=is_tld_src)
            all_blocks.update(b)
            all_allows.update(a)
            all_spam_tlds.update(t)
            print(f"  + Scanned {url[:45]}...")

    # Prune and re-format
    final_blocks = prune_blocks(all_blocks, all_allows, all_spam_tlds)
    
    # Combine with properly formatted allows
    final_list = sorted(final_blocks)
    final_list += sorted([f"@@||{a}^" for a in all_allows])
    
    # Add YouTube rewrite
    final_list.append(YOUTUBE_RULE)

    with open(OUTPUT_FILE, "w") as f:
        f.write("############################################################\n")
        f.write("# ISAAC'S ULTIMATE EXCEPTION-AWARE MASTER LIST\n")
        f.write(f"# Revision: {VERSION} | TLD Firewall: ON | YouTube: Restricted\n")
        f.write(f"# Statistics: Blocks: {len(final_blocks):,} | Allows: {len(all_allows):,}\n")
        f.write("############################################################\n\n")
        f.write("\n".join(final_list))

    print(f"Finished in {datetime.now() - start_time}. Final rules: {len(final_list):,}")

if __name__ == "__main__":
    main()
