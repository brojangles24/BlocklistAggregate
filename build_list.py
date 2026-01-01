import requests
import json
import os
import datetime
import math
import re
from collections import Counter, defaultdict
import pandas as pd
import tldextract
import Levenshtein
from dashboard import generate_dashboard

# --- CONFIGURATION ---
# Format: (URL, Weight, Tag)
SOURCES = [
    ("https://urlhaus.abuse.ch/downloads/hostfile/", 15, "Malware"), 
    ("https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Lite/domains.wildcards", 10, "Tracking"),
    ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt", 8, "Aggressive"),
    ("https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt", 6, "Mobile Ads"),
    ("https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_big.txt", 5, "General Ads"),
    ("https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Xtra/domains.wildcards", 2, "Gap Filler")
]

SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-onlydomains.txt"

DOMAIN_LIMIT = 300000
HISTORY_FILE = "history.json"
PREVIOUS_LIST_FILE = "blocklist.txt"
HVT_LIST = ['google', 'apple', 'microsoft', 'amazon', 'facebook', 'netflix', 'paypal', 'chase', 'wellsfargo', 'coinbase']

def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0: entropy += - p_x * math.log(p_x, 2)
    return entropy

def get_ngrams(text, n=2):
    words = re.split(r'[^a-z0-9]', text)
    words = [w for w in words if len(w) > 2]
    return ['-'.join(words[i:i+n]) for i in range(len(words)-n+1)]

def fetch_spam_tlds():
    tlds = set()
    print(f"Fetching Spam TLDs from: {SPAM_TLD_URL}")
    try:
        r = requests.get(SPAM_TLD_URL, timeout=30)
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip().lower()
                if line and not line.startswith('#'):
                    clean = line.replace('*.', '').replace('.', '')
                    if clean: tlds.add("." + clean)
            print(f"  -> Successfully loaded {len(tlds)} TLDs.")
        else:
            print("  -> Download failed. Skipping TLD optimization.")
    except:
        print("  -> Download error. Skipping TLD optimization.")
    return tuple(tlds) 

def fetch_domains(url):
    print(f"Fetching: {url}")
    domains = set()
    try:
        r = requests.get(url, timeout=60)
        for line in r.text.splitlines():
            line = line.strip().lower()
            if '#' in line: line = line.split('#')[0].strip()
            if not line or line.startswith('!'): continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ["0.0.0.0", "127.0.0.1"]: domains.add(parts[1])
            elif len(parts) == 1: domains.add(parts[0])
    except: pass
    return domains

def save_history(stats_data):
    history = []
    if os.path.exists(HISTORY_FILE):
        try: with open(HISTORY_FILE, "r") as f: history = json.load(f)
        except: pass
    history.append(stats_data)
    return history[-365:] 

def main():
    prev_domains = set()
    if os.path.exists(PREVIOUS_LIST_FILE):
        try: 
            with open(PREVIOUS_LIST_FILE) as f: 
                prev_domains = {line.split()[1] for line in f if line.startswith("0.0.0.0")}
        except: pass

    domain_data = {} 
    source_sets = defaultdict(set)
    spam_tlds = fetch_spam_tlds()
    removed_tld_count = 0 
    
    # 1. Ingest
    for url, weight, tag in SOURCES:
        domains = fetch_domains(url)
        source_sets[tag] = domains
        print(f"[{tag}] {len(domains)}")
        for d in domains:
            if d.endswith(spam_tlds): 
                removed_tld_count += 1
                continue 

            if d.startswith("www."): d = d[4:] 
            
            if d not in domain_data:
                domain_data[d] = {'score': 0, 'sources': []}
            domain_data[d]['score'] += weight
            domain_data[d]['sources'].append(tag)

    # 2. Rank & Cut
    sorted_domains = sorted(domain_data.items(), key=lambda x: (-x[1]['score'], x[0]))[:DOMAIN_LIMIT]
    final_domains = [x[0] for x in sorted_domains]
    final_set = set(final_domains)
    
    # 3. Deep Analysis
    print("Running Forensics...")
    rows = []
    bigram_counter = Counter()
    vowel_pattern = re.compile(r'[aeiou]')
    
    for d in final_domains:
        length = len(d)
        depth = d.count('.') + 1
        tld = d.split('.')[-1]
        entropy = calculate_entropy(d)
        vowel_ratio = len(vowel_pattern.findall(d)) / length if length > 0 else 0
        
        # Categorize for Dashboard Safety
        category = "Unclassified"
        if d in source_sets['Mobile Ads']: category = "Ads"
        elif d in source_sets['Tracking']: category = "Tracking"
        elif d in source_sets['General Ads']: category = "Ads"
        elif d in source_sets['Malware']: category = "Malware"
        elif d in source_sets['Aggressive']: category = "Aggressive"
        
        typo = None
        for hvt in HVT_LIST:
            if hvt in d and hvt != d.split('.')[0]:
                 if Levenshtein.distance(d.split('.')[0], hvt) == 1:
                     typo = f"{d} ({hvt})"
                     break
        bg = get_ngrams(d, 2)
        bigram_counter.update(bg)
        
        rows.append({
            'domain': d, 'length': length, 'depth': depth, 'tld': tld,
            'entropy': entropy, 'vowel_ratio': vowel_ratio, 'typosquat': typo,
            'category': category
        })

    df_main = pd.DataFrame(rows)

    # 4. Overlap Matrix
    source_names = list(source_sets.keys())
    overlap_matrix = {}
    for s1 in source_names:
        for s2 in source_names:
            set1 = source_sets[s1].intersection(final_set)
            set2 = source_sets[s2].intersection(final_set)
            if len(set1) == 0 or len(set2) == 0: overlap_matrix[(s1, s2)] = 0
            else: overlap_matrix[(s1, s2)] = round(len(set1.intersection(set2)) / len(set1.union(set2)), 2)

    # 5. Output
    churn = {"added": len(final_set - prev_domains), "removed": len(prev_domains - final_set)}
    stats = {"date": datetime.date.today().isoformat(), "total_count": len(final_domains)}
    history = save_history(stats)
    with open(HISTORY_FILE, "w") as f: json.dump(history, f)

    generate_dashboard(df_main, history, churn, removed_tld_count, overlap_matrix, bigram_counter.most_common(15), final_domains)

    with open("blocklist.txt", "w") as f:
        f.write(f"# Isaac's SOC Blocklist\n")
        for d in final_domains: f.write(f"0.0.0.0 {d}\n")
    with open("adblock.txt", "w") as f:
        f.write(f"! Isaac's SOC Blocklist\n")
        for d in final_domains: f.write(f"||{d}^\n")

if __name__ == "__main__":
    main()
