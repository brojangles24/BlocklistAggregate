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

def fetch_url(url):
    try:
        r = requests.get(url, timeout=25)
        r.raise_for_status()
        return r.text.splitlines(), url
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return [], url

def parse_lines(lines):
    blocks = set()
    allows = set()
    advanced_rules = set() # For $denyallow and other complex AdGuard rules

    for line in lines:
        line = line.strip().lower()
        if not line or line.startswith(('#', '!', ';')): continue
        
        # 1. PRESERVE ADVANCED SYNTAX (like $denyallow)
        # If the line contains a modifier ($), we keep it exactly as is
        if '$' in line:
            advanced_rules.add(line)
            continue

        # 2. Identify Allows (@@)
        is_allow = line.startswith('@@')
        clean_line = line[2:] if is_allow else line
        
        # 3. Clean AdGuard markers to get the domain for logic
        domain = clean_line.replace("||", "").replace("^", "").strip()
        
        # Extract domain from Hosts format (0.0.0.0 domain.com)
        parts = domain.split()
        domain = parts[1] if (len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::1")) else parts[0]

        if not domain or NSFW_REGEX.search(domain): continue

        if is_allow:
            allows.add(domain)
        else:
            if '.' in domain and not domain.startswith('.'):
                blocks.add(domain)
                
    return blocks, allows, advanced_rules

def prune_and_reformat(block_set, allow_set, advanced_rules):
    print(f"Pruning {len(block_set):,} domains...")
    
    # Tree Pruning for the simple domains
    rev_blocks = sorted(['.'.join(d.split('.')[::-1]) for d in block_set])
    pruned_rev = []
    last_added = ""
    for rb in rev_blocks:
        current_domain = '.'.join(rb.split('.')[::-1])
        if last_added and rb.startswith(last_added + "."):
            if current_domain not in allow_set: continue
        pruned_rev.append(rb)
        last_added = rb
    
    # Re-format simple blocks
    final_list = [f"||{'.'.join(d.split('.')[::-1])}^" for d in pruned_rev]
    
    # Add Advanced Rules (denallows) exactly as they were
    final_list.extend(list(advanced_rules))
    
    # Add Allows
    for a in allow_set:
        final_list.append(f"@@||{a}^")
        
    return sorted(final_list)

def main():
    all_blocks = set()
    all_allows = set()
    all_advanced = set()
    start_time = datetime.now()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in SOURCES}
        for future in concurrent.futures.as_completed(future_to_url):
            lines, url = future.result()
            b, a, adv = parse_lines(lines)
            all_blocks.update(b)
            all_allows.update(a)
            all_advanced.update(adv)
            print(f"  + Scanned {url[:45]}...")

    final_rules = prune_and_reformat(all_blocks, all_allows, all_advanced)
    final_rules.append(YOUTUBE_RULE)

    with open(OUTPUT_FILE, "w") as f:
        f.write("############################################################\n")
        f.write("# ISAAC'S ULTIMATE HAGEZI-COMPATIBLE MASTER LIST\n")
        f.write(f"# Revision: {VERSION} | Advanced Rules: {len(all_advanced)}\n")
        f.write("############################################################\n\n")
        f.write("\n".join(final_rules))

    print(f"Finished in {datetime.now() - start_time}. Total rules: {len(final_rules):,}")

if __name__ == "__main__":
    main()
