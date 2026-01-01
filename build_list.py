import requests
import json
import os
import datetime
import math
import re
from collections import Counter, defaultdict
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import tldextract
import Levenshtein

# --- CONFIGURATION ---
SOURCES = [
    ("https://urlhaus.abuse.ch/downloads/hostfile/", 15, "Malware"), 
    ("https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Lite/domains.wildcards", 10, "Tracking"),
    ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt", 8, "Aggressive"),
    ("https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt", 6, "Mobile Ads"),
    ("https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_big.txt", 5, "General Ads"),
    ("https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Xtra/domains.wildcards", 2, "Gap Filler")
]

# The Specific Hagezi Wildcard List
SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-onlydomains.txt"

# Fallback
FALLBACK_TLDS = {
    ".zip", ".mov", ".loan", ".win", ".date", ".review", ".party", ".accountant", ".trade", 
    ".download", ".gdn", ".racing", ".jetzt", ".stream", ".bid", ".men", ".bom", ".click", 
    ".cricket", ".faith", ".link", ".science", ".webcam", ".top", ".xyz", ".online", 
    ".site", ".pro", ".work", ".info", ".best", ".cam", ".cfd", ".cyou", ".icu", ".mw", ".rest",
    ".wiki", ".monster", ".quest", ".bond", ".bussiness", ".center", ".club", ".cool"
}

DOMAIN_LIMIT = 300000
HISTORY_FILE = "history.json"
PREVIOUS_LIST_FILE = "blocklist.txt"
HVT_LIST = ['google', 'apple', 'microsoft', 'amazon', 'facebook', 'netflix', 'paypal', 'chase', 'wellsfargo', 'coinbase']
APPLE_COLORS = ['#0A84FF', '#30D158', '#BF5AF2', '#FF9F0A', '#FF453A', '#64D2FF', '#FF375F', '#5E5CE6']
BG_COLOR = "#000000"
CARD_COLOR = "#1C1C1E"
TEXT_COLOR = "#F5F5F7"

def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0: 
            entropy += - p_x * math.log(p_x, 2)
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
                    # Handle "*.zip" or "zip" formats
                    clean = line.replace('*.', '').replace('.', '')
                    if clean: 
                        tlds.add("." + clean)
            print(f"  -> Successfully loaded {len(tlds)} TLDs.")
        else:
            print("  -> Download failed. Using fallback.")
            tlds = FALLBACK_TLDS
    except:
        print("  -> Download error. Using fallback.")
        tlds = FALLBACK_TLDS
    
    if not tlds: 
        tlds = FALLBACK_TLDS
    return tuple(tlds) 

def fetch_domains(url):
    print(f"Fetching: {url}")
    domains = set()
    try:
        r = requests.get(url, timeout=60)
        for line in r.text.splitlines():
            line = line.strip().lower()
            if '#' in line: 
                line = line.split('#')[0].strip()
            if not line or line.startswith('!'): 
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ["0.0.0.0", "127.0.0.1"]: 
                domains.add(parts[1])
            elif len(parts) == 1: 
                domains.add(parts[0])
    except: 
        pass
    return domains

def save_history(stats_data):
    history = []
    if os.path.exists(HISTORY_FILE):
        try: 
            with open(HISTORY_FILE, "r") as f: 
                history = json.load(f)
        except: 
            pass
    history.append(stats_data)
    return history[-365:] 

def generate_dashboard(df_main, history, churn_stats, removed_tld_count, source_overlap_matrix, top_bigrams, final_list):
    print("Generating Interactive Dashboard...")
    
    df_tld = df_main['tld'].value_counts().head(10).reset_index()
    df_tld.columns = ['TLD', 'Count']
    df_hist = pd.DataFrame(history)
    typos = df_main[df_main['typosquat'].notnull()]['typosquat'].value_counts().head(10).reset_index()
    typos.columns = ['Target', 'Count']
    df_bigrams = pd.DataFrame(top_bigrams, columns=['Phrase', 'Count']).head(10)
    df_sample = df_main.sample(min(2000, len(df_main)))
    sources = sorted(list(set([k[0] for k in source_overlap_matrix.keys()])))
    matrix_data = [[source_overlap_matrix.get((r, c), 0) for c in sources] for r in sources]

    fig = make_subplots(
        rows=4, cols=3,
        specs=[[{"type": "indicator"}, {"type": "indicator"}, {"type": "indicator"}],
               [{"type": "xy"}, {"type": "xy"}, {"type": "domain"}],
               [{"type": "xy"}, {"type": "heatmap"}, {"type": "xy"}],
               [{"type": "xy"}, {"type": "xy"}, {"type": "xy"}]],
        subplot_titles=("", "", "", "⚠️ Impersonation", "🗣️ Attack Phrases", "🌍 TLDs",
                        "🤖 Machine vs Human", "🔗 Source Matrix", "📏 Length",
                        "📈 Threat Growth", "🎯 Depth", "🔡 Vowel Ratio"),
        vertical_spacing=0.08
    )

    common_layout = dict(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color=TEXT_COLOR))

    fig.add_trace(go.Indicator(mode="number", value=len(df_main), title={"text": "Total Threats"}), row=1, col=1)
    fig.add_trace(go.Indicator(mode="number+delta", value=churn_stats['added'], delta={'reference': 0, 'relative': False}, title={"text": "New Today"}), row=1, col=2)
    fig.add_trace(go.Indicator(mode="number", value=removed_tld_count, title={"text": "TLD Savings"}), row=1, col=3)
    fig.add_trace(go.Bar(x=typos['Count'], y=typos['Target'], orientation='h', marker_color=APPLE_COLORS[4]), row=2, col=1)
    fig.add_trace(go.Bar(x=df_bigrams['Count'], y=df_bigrams['Phrase'], orientation='h', marker_color=APPLE_COLORS[3]), row=2, col=2)
    fig.add_trace(go.Pie(labels=df_tld['TLD'], values=df_tld['Count'], hole=0.6, marker=dict(colors=APPLE_COLORS)), row=2, col=3)
    fig.add_trace(go.Scatter(x=df_sample['length'], y=df_sample['entropy'], mode='markers', marker=dict(size=4, color=df_sample['entropy'], colorscale='Viridis', showscale=False)), row=3, col=1)
    fig.add_trace(go.Heatmap(z=matrix_data, x=sources, y=sources, colorscale='RdBu', showscale=False), row=3, col=2)
    fig.add_trace(go.Histogram(x=df_main['length'], nbinsx=30, marker_color=APPLE_COLORS[5]), row=3, col=3)
    if not df_hist.empty and 'date' in df_hist.columns:
        fig.add_trace(go.Scatter(x=df_hist['date'], y=df_hist['total_count'], mode='lines', line=dict(color=APPLE_COLORS[0], width=3)), row=4, col=1)
    depth_counts = df_main['depth'].value_counts().sort_index().head(8)
    fig.add_trace(go.Bar(x=depth_counts.index, y=depth_counts.values, marker_color=APPLE_COLORS[2]), row=4, col=2)
    fig.add_trace(go.Histogram(x=df_sample['vowel_ratio'], nbinsx=30, marker_color=APPLE_COLORS[6]), row=4, col=3)

    fig.update_layout(height=1600, width=1400, showlegend=False, template="plotly_dark", **common_layout)
    fig.update_yaxes(autorange="reversed", row=2, col=1)
    fig.update_yaxes(autorange="reversed", row=2, col=2)

    # Embedding full list (Heavy payload, optimized loop in JS)
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>God Mode DNS Intel</title>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <style>
            body {{ background-color: {BG_COLOR}; color: {TEXT_COLOR}; font-family: -apple-system, sans-serif; padding: 20px; }}
            .container {{ max-width: 1400px; margin: 0 auto; }}
            h1 {{ text-align: center; margin-bottom: 5px; }}
            .sub {{ text-align: center; color: #888; margin-bottom: 30px; }}
            .search-box {{ width: 100%; max-width: 600px; margin: 0 auto 30px auto; display: block; }}
            input {{ width: 100%; padding: 15px; border-radius: 12px; border: 1px solid #333; background: #1C1C1E; color: white; font-size: 16px; outline: none; }}
            input:focus {{ border-color: #0A84FF; }}
            #search-results {{ max-width: 600px; margin: 10px auto; text-align: left; color: #aaa; background: #111; padding: 10px; border-radius: 8px; min-height: 20px; }}
            .match {{ color: #FF453A; font-weight: bold; display: block; padding: 4px 0; }}
            .limit-note {{ font-size: 11px; color: #666; text-align: center; margin-top: 5px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ SOC Dashboard: GOD MODE</h1>
            <div class="sub">Deep Forensics & Correlation Analysis • {datetime.date.today()}</div>
            <div class="search-box">
                <input type="text" id="domainSearch" placeholder="🔍 Search Database (300k Records)..." onkeyup="searchDomains()">
                <div class="limit-note">Searching entire database. Showing top 10 matches.</div>
                <div id="search-results"></div>
            </div>
            {fig.to_html(full_html=False, include_plotlyjs=False)}
             <div style="background:{CARD_COLOR}; padding:20px; border-radius:12px; margin-top:20px;">
                <h3>🚨 Top 10 Detected Typosquats</h3>
                <table style="width:100%; text-align:left; color:#ddd;">
                    { "".join([f"<tr><td style='padding:5px; border-bottom:1px solid #333'>{t}</td></tr>" for t in typos['Target'].head(10)]) }
                </table>
            </div>
        </div>
        <script>
            const domains = {json.dumps(final_list)};
            
            function searchDomains() {{
                const input = document.getElementById('domainSearch');
                const filter = input.value.toLowerCase();
                const resultDiv = document.getElementById('search-results');
                
                if (filter.length < 3) {{ resultDiv.innerHTML = ""; return; }}
                
                let matches = [];
                let count = 0;
                for (let i = 0; i < domains.length; i++) {{
                    if (domains[i].includes(filter)) {{
                        matches.push(domains[i]);
                        count++;
                        if (count >= 10) break; 
                    }}
                }}

                if (matches.length > 0) {{
                    resultDiv.innerHTML = matches.map(m => "<span class='match'>• " + m + "</span>").join("");
                }} else {{
                    resultDiv.innerHTML = "Not found in database.";
                }}
            }}
        </script>
    </body>
    </html>
    """
    with open("stats.html", "w", encoding="utf-8") as f: f.write(html)

def main():
    prev_domains = set()
    if os.path.exists(PREVIOUS_LIST_FILE):
        try: 
            with open(PREVIOUS_LIST_FILE) as f: 
                prev_domains = {line.split()[1] for line in f if line.startswith("0.0.0.0")}
        except: 
            pass

    domain_data = {} 
    source_sets = defaultdict(set)
    spam_tlds = fetch_spam_tlds()
    removed_tld_count = 0  # <--- Initialize counter here
    
    # 1. Ingest
    for url, weight, tag in SOURCES:
        domains = fetch_domains(url)
        source_sets[tag] = domains
        print(f"[{tag}] {len(domains)}")
        for d in domains:
            # TLD FILTER with Immediate Counting
            if d.endswith(spam_tlds): 
                removed_tld_count += 1  # <--- Count the kill
                continue 

            if d.startswith("www."): 
                d = d[4:] 
            
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
            'entropy': entropy, 'vowel_ratio': vowel_ratio, 'typosquat': typo
        })

    df_main = pd.DataFrame(rows)

    # 4. Overlap Matrix
    source_names = list(source_sets.keys())
    overlap_matrix = {}
    for s1 in source_names:
        for s2 in source_names:
            set1 = source_sets[s1].intersection(final_set)
            set2 = source_sets[s2].intersection(final_set)
            if len(set1) == 0 or len(set2) == 0: 
                overlap_matrix[(s1, s2)] = 0
            else: 
                overlap_matrix[(s1, s2)] = round(len(set1.intersection(set2)) / len(set1.union(set2)), 2)

    # 5. Output
    churn = {"added": len(final_set - prev_domains), "removed": len(prev_domains - final_set)}
    
    # Passing the CORRECT removed_tld_count to the dashboard
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
