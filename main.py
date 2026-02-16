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

NSFW_REGEX = re.compile(r"(?i)(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo)")

YOUTUBE_RULE = "/^(www\.|m\.|youtubei\.|youtube\.)?(youtube(-nocookie)?\.com|googleapis\.com)$/$dnsrewrite=restrictmoderate.youtube.com"

OUTPUT_FILE = "blocklist.txt"

def fetch_url(url):
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []

def main():
    raw_rules = set()
    blocked_tlds = set()
    start_time = datetime.now()

    # 1. First Pass: Download and identify Nuclear TLD rules
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in SOURCES}
        for future in concurrent.futures.as_completed(future_to_url):
            lines = future.result()
            for line in lines:
                line = line.strip()
                if not line or line.startswith(('#', '!', ';')):
                    continue
                
                # Identify Nuclear TLD rules (e.g., ||*.top^)
                if line.startswith("||*.") and "^" in line and "$" not in line:
                    tld = line.replace("||*.", "").replace("^", "")
                    blocked_tlds.add(tld)
                
                raw_rules.add(line)

    print(f"Detected {len(blocked_tlds)} Nuclear TLD blocks. Scrubbing redundant domains...")

    # 2. Second Pass: Filter NSFW and Redundant TLD subdomains
    final_rules = set()
    for rule in raw_rules:
        # A. Nuke NSFW
        if NSFW_REGEX.search(rule):
            continue
            
        # B. Nuke redundant domains if the TLD is already blocked
        # Example: If ||*.top^ exists, we delete ||badsite.top^
        if not rule.startswith("||*.") and "^" in rule:
            # Extract naked domain to find the TLD
            clean_domain = rule.replace("||", "").split('^')[0].split('$')[0]
            tld = clean_domain.split('.')[-1]
            if tld in blocked_tlds:
                # If there's an allow rule (@@) or it's a DenyAllow, we KEEP it
                if not rule.startswith("@@") and "$denyallow" not in rule:
                    continue
        
        final_rules.add(rule)

    # 3. Final Construction
    sorted_output = sorted(list(final_rules))
    sorted_output.append(YOUTUBE_RULE)

    with open(OUTPUT_FILE, "w") as f:
        f.write("############################################################\n")
        f.write("# ISAAC'S PROACTIVE MASTER (STRICT + TLD FIREWALL)\n")
        f.write(f"# Revision: {VERSION}\n")
        f.write(f"# Nuclear TLDs: {len(blocked_tlds)} | Total Rules: {len(sorted_output):,}\n")
        f.write("############################################################\n\n")
        f.write("\n".join(sorted_output))

    print(f"Finished in {datetime.now() - start_time}.")

if __name__ == "__main__":
    main()
