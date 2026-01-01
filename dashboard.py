import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# --- COLORS ---
APPLE_COLORS = ['#0A84FF', '#30D158', '#BF5AF2', '#FF9F0A', '#FF453A', '#64D2FF', '#FF375F', '#5E5CE6']
BG_COLOR = "#000000"
CARD_COLOR = "#1C1C1E"
TEXT_COLOR = "#F5F5F7"

def generate_dashboard(df_main, history, churn_stats, removed_tld_count, source_overlap_matrix, top_bigrams, final_list):
    print("Generating Interactive Dashboard...")
    
    # Data Prep
    df_tld = df_main['tld'].value_counts().head(10).reset_index()
    df_tld.columns = ['TLD', 'Count']
    df_hist = pd.DataFrame(history)
    typos = df_main[df_main['typosquat'].notnull()]['typosquat'].value_counts().head(10).reset_index()
    typos.columns = ['Target', 'Count']
    df_bigrams = pd.DataFrame(top_bigrams, columns=['Phrase', 'Count']).head(10)
    df_sample = df_main.sample(min(2000, len(df_main)))
    sources = sorted(list(set([k[0] for k in source_overlap_matrix.keys()])))
    matrix_data = [[source_overlap_matrix.get((r, c), 0) for c in sources] for r in sources]

    # Plotly Layout
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

    # Row 1: KPI
    fig.add_trace(go.Indicator(mode="number", value=len(df_main), title={"text": "Total Threats"}), row=1, col=1)
    fig.add_trace(go.Indicator(mode="number+delta", value=churn_stats['added'], delta={'reference': 0, 'relative': False}, title={"text": "New Today"}), row=1, col=2)
    fig.add_trace(go.Indicator(mode="number", value=removed_tld_count, title={"text": "TLD Savings"}), row=1, col=3)

    # Row 2: Charts
    fig.add_trace(go.Bar(x=typos['Count'], y=typos['Target'], orientation='h', marker_color=APPLE_COLORS[4]), row=2, col=1)
    fig.add_trace(go.Bar(x=df_bigrams['Count'], y=df_bigrams['Phrase'], orientation='h', marker_color=APPLE_COLORS[3]), row=2, col=2)
    fig.add_trace(go.Pie(labels=df_tld['TLD'], values=df_tld['Count'], hole=0.6, marker=dict(colors=APPLE_COLORS)), row=2, col=3)

    # Row 3: Forensics
    fig.add_trace(go.Scatter(x=df_sample['length'], y=df_sample['entropy'], mode='markers', marker=dict(size=4, color=df_sample['entropy'], colorscale='Viridis', showscale=False)), row=3, col=1)
    fig.add_trace(go.Heatmap(z=matrix_data, x=sources, y=sources, colorscale='RdBu', showscale=False), row=3, col=2)
    fig.add_trace(go.Histogram(x=df_main['length'], nbinsx=30, marker_color=APPLE_COLORS[5]), row=3, col=3)

    # Row 4: Trends
    if not df_hist.empty and 'date' in df_hist.columns:
        fig.add_trace(go.Scatter(x=df_hist['date'], y=df_hist['total_count'], mode='lines', line=dict(color=APPLE_COLORS[0], width=3)), row=4, col=1)
    
    depth_counts = df_main['depth'].value_counts().sort_index().head(8)
    fig.add_trace(go.Bar(x=depth_counts.index, y=depth_counts.values, marker_color=APPLE_COLORS[2]), row=4, col=2)
    fig.add_trace(go.Histogram(x=df_sample['vowel_ratio'], nbinsx=30, marker_color=APPLE_COLORS[6]), row=4, col=3)

    fig.update_layout(height=1600, width=1400, showlegend=False, template="plotly_dark", **common_layout)
    fig.update_yaxes(autorange="reversed", row=2, col=1)
    fig.update_yaxes(autorange="reversed", row=2, col=2)

    # HTML Template
    search_preview = final_list[:15000]
    
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
            <div class="sub">Deep Forensics & Correlation Analysis</div>
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
