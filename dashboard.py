import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# --- COLORS & THEME ---
# "Cyberpunk" Palette
COLORS = {
    'bg': '#050505',
    'card': 'rgba(28, 28, 30, 0.6)', # Translucent
    'text': '#E0E0E0',
    'subtext': '#888888',
    'accent': '#00F0FF', # Cyan
    'danger': '#FF2A6D', # Neon Red
    'success': '#05FFA1', # Neon Green
    'warning': '#FFD166',
    'chart_1': '#7000FF', # Purple
    'chart_2': '#00C2BA', # Teal
}

def generate_dashboard(df_main, history, churn_stats, removed_tld_count, source_overlap_matrix, top_bigrams, final_list):
    print("Generating Command Center Dashboard...")

    # --- DATA PREP ---
    df_tld = df_main['tld'].value_counts().head(8).reset_index()
    df_tld.columns = ['TLD', 'Count']
    
    typos = df_main[df_main['typosquat'].notnull()]['typosquat'].value_counts().head(8).reset_index()
    typos.columns = ['Target', 'Count']
    
    df_bigrams = pd.DataFrame(top_bigrams, columns=['Phrase', 'Count']).head(8)
    
    # Sampling for scatter plots to keep HTML size manageable
    df_sample = df_main.sample(min(2000, len(df_main)))

    # Source Matrix
    sources = sorted(list(set([k[0] for k in source_overlap_matrix.keys()])))
    matrix_data = [[source_overlap_matrix.get((r, c), 0) for c in sources] for r in sources]

    # --- PLOTLY CONFIG ---
    common_layout = dict(
        paper_bgcolor='rgba(0,0,0,0)', 
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(family='JetBrains Mono, monospace', color=COLORS['text']),
        margin=dict(l=10, r=10, t=30, b=10),
        xaxis=dict(showgrid=False, zeroline=False),
        yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.05)', zeroline=False)
    )

    # 1. Main Growth Chart
    fig_hist = px.area(pd.DataFrame(history), x='date', y='total_count', 
                       line_shape='spline', markers=True,
                       color_discrete_sequence=[COLORS['accent']])
    fig_hist.update_layout(**common_layout, height=300)
    fig_hist.update_traces(fillcolor='rgba(0, 240, 255, 0.1)', line=dict(width=3))

    # 2. TLD Ring
    fig_tld = px.pie(df_tld, values='Count', names='TLD', hole=0.7, 
                     color_discrete_sequence=px.colors.sequential.Plotly3)
    fig_tld.update_layout(**common_layout, height=300, showlegend=True)
    fig_tld.update_traces(textposition='inside', textinfo='label')

    # 3. Typosquat Bar
    fig_typo = px.bar(typos, x='Count', y='Target', orientation='h', 
                      color='Count', color_continuous_scale='Redor')
    fig_typo.update_layout(**common_layout, height=300, coloraxis_showscale=False)
    fig_typo.update_yaxes(autorange="reversed")

    # 4. Attack Phrases
    fig_words = px.bar(df_bigrams, x='Count', y='Phrase', orientation='h',
                       color='Count', color_continuous_scale='Viridis')
    fig_words.update_layout(**common_layout, height=300, coloraxis_showscale=False)
    fig_words.update_yaxes(autorange="reversed")

    # 5. Entropy Scatter (Botnet Detection)
    fig_entropy = px.scatter(df_sample, x='length', y='entropy', 
                             color='entropy', color_continuous_scale='Turbo',
                             size_max=8, opacity=0.7)
    fig_entropy.update_layout(**common_layout, height=350, xaxis_title="Length", yaxis_title="Entropy")
    fig_entropy.update_coloraxes(showscale=False)

    # 6. Source Heatmap
    fig_matrix = go.Figure(data=go.Heatmap(
        z=matrix_data, x=sources, y=sources,
        colorscale='Magma', showscale=False,
        text=matrix_data, texttemplate="%{text:.0%}"
    ))
    fig_matrix.update_layout(**common_layout, height=350)

    # --- HTML ASSEMBLY ---
    search_preview = final_list[:20000] # Increased searchable limit

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DNS Command Center</title>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
        <style>
            :root {{
                --bg: {COLORS['bg']};
                --card-bg: {COLORS['card']};
                --accent: {COLORS['accent']};
                --danger: {COLORS['danger']};
                --success: {COLORS['success']};
                --text: {COLORS['text']};
                --glass: blur(12px);
            }}
            
            * {{ box-sizing: border-box; }}
            
            body {{
                background-color: var(--bg);
                background-image: radial-gradient(circle at 50% 0%, #111 0%, var(--bg) 60%);
                color: var(--text);
                font-family: 'Inter', sans-serif;
                margin: 0;
                padding: 0;
                min-height: 100vh;
            }}

            /* TOP NAVIGATION */
            .navbar {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 20px 40px;
                border-bottom: 1px solid rgba(255,255,255,0.1);
                background: rgba(0,0,0,0.5);
                backdrop-filter: var(--glass);
                position: sticky;
                top: 0;
                z-index: 100;
            }}
            
            .brand {{
                font-family: 'JetBrains Mono', monospace;
                font-weight: 700;
                font-size: 20px;
                letter-spacing: -1px;
                color: #fff;
            }}
            .brand span {{ color: var(--accent); }}

            .status-badge {{
                background: rgba(5, 255, 161, 0.1);
                color: var(--success);
                border: 1px solid var(--success);
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}

            /* MAIN LAYOUT */
            .container {{
                max-width: 1600px;
                margin: 0 auto;
                padding: 40px;
            }}

            /* KPI GRID */
            .kpi-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                gap: 20px;
                margin-bottom: 40px;
            }}
            
            .kpi-card {{
                background: var(--card-bg);
                border: 1px solid rgba(255,255,255,0.05);
                border-radius: 16px;
                padding: 24px;
                backdrop-filter: var(--glass);
                transition: transform 0.2s;
            }}
            .kpi-card:hover {{ transform: translateY(-2px); border-color: var(--accent); }}
            
            .kpi-label {{ color: #888; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }}
            .kpi-value {{ font-size: 36px; font-weight: 800; font-family: 'JetBrains Mono', monospace; }}
            .kpi-delta {{ font-size: 14px; font-weight: 600; margin-left: 8px; }}
            .pos {{ color: var(--danger); }} /* More threats = "Positive" number but bad */
            .neg {{ color: var(--success); }}

            /* TABS */
            .tabs {{
                display: flex;
                gap: 20px;
                margin-bottom: 30px;
                border-bottom: 1px solid rgba(255,255,255,0.1);
                padding-bottom: 10px;
            }}
            .tab-btn {{
                background: none;
                border: none;
                color: #888;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                padding: 10px 20px;
                transition: 0.2s;
            }}
            .tab-btn.active {{ color: white; border-bottom: 2px solid var(--accent); }}
            .tab-btn:hover {{ color: white; }}

            /* CONTENT GRIDS */
            .section {{ display: none; animation: fadeIn 0.3s; }}
            .section.active {{ display: grid; }}
            
            .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}
            .grid-3 {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 24px; }}
            
            .chart-card {{
                background: var(--card-bg);
                border: 1px solid rgba(255,255,255,0.05);
                border-radius: 16px;
                padding: 24px;
                min-height: 350px;
            }}
            .chart-card h3 {{ margin: 0 0 20px 0; font-size: 16px; font-weight: 600; color: #fff; border-left: 3px solid var(--accent); padding-left: 10px; }}

            /* SEARCH ENGINE */
            .search-container {{
                background: var(--card-bg);
                padding: 30px;
                border-radius: 16px;
                border: 1px solid rgba(255,255,255,0.1);
                text-align: center;
                margin-bottom: 40px;
            }}
            .search-input {{
                width: 100%;
                max-width: 600px;
                background: rgba(0,0,0,0.3);
                border: 1px solid #333;
                color: white;
                padding: 16px 24px;
                border-radius: 12px;
                font-size: 18px;
                font-family: 'JetBrains Mono', monospace;
                outline: none;
                transition: 0.2s;
            }}
            .search-input:focus {{ border-color: var(--accent); box-shadow: 0 0 15px rgba(0, 240, 255, 0.2); }}
            
            #results {{ 
                margin-top: 20px; 
                display: grid; 
                grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); 
                gap: 10px; 
            }}
            .result-tag {{
                background: rgba(255, 42, 109, 0.1);
                color: var(--danger);
                border: 1px solid var(--danger);
                padding: 8px 12px;
                border-radius: 6px;
                font-family: 'JetBrains Mono', monospace;
                font-size: 13px;
                text-align: left;
            }}

            /* UTILS */
            .download-btn {{
                background: var(--accent);
                color: black;
                text-decoration: none;
                padding: 8px 16px;
                border-radius: 8px;
                font-weight: 700;
                font-size: 12px;
                margin-left: 10px;
                text-transform: uppercase;
            }}
            
            @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(10px); }} to {{ opacity: 1; transform: translateY(0); }} }}
            @media (max-width: 1000px) {{ .grid-2, .grid-3 {{ grid-template-columns: 1fr; }} }}
        </style>
    </head>
    <body>

        <nav class="navbar">
            <div class="brand">DNS<span>INTEL</span> // SOC</div>
            <div>
                <span class="status-badge">System Operational</span>
                <a href="blocklist.txt" class="download-btn">Download List</a>
                <a href="adblock.txt" class="download-btn">Adblock Format</a>
            </div>
        </nav>

        <div class="container">
            
            <div class="search-container">
                <input type="text" id="search" class="search-input" placeholder="Initiate Domain Scan..." onkeyup="doSearch()">
                <div id="results"></div>
            </div>

            <div class="kpi-grid">
                <div class="kpi-card">
                    <div class="kpi-label">Active Threats</div>
                    <div class="kpi-value">{len(final_list):,}<span class="kpi-delta pos">+{churn_stats['added']}</span></div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Optimization Savings</div>
                    <div class="kpi-value">{removed_tld_count:,}<span class="kpi-delta neg">TLDs</span></div>
                </div>
                 <div class="kpi-card">
                    <div class="kpi-label">Typosquats</div>
                    <div class="kpi-value">{typos['Count'].sum():,}<span class="kpi-delta pos">Detected</span></div>
                </div>
            </div>

            <div class="tabs">
                <button class="tab-btn active" onclick="openTab('overview')">Overview</button>
                <button class="tab-btn" onclick="openTab('forensics')">Deep Forensics</button>
            </div>

            <div id="overview" class="section active grid-2">
                <div class="chart-card">
                    <h3>Threat Landscape (TLDs)</h3>
                    {fig_tld.to_html(full_html=False, include_plotlyjs=False)}
                </div>
                <div class="chart-card">
                    <h3>Network Growth History</h3>
                    {fig_hist.to_html(full_html=False, include_plotlyjs=False)}
                </div>
                <div class="chart-card">
                    <h3>Top Impersonation Targets</h3>
                    {fig_typo.to_html(full_html=False, include_plotlyjs=False)}
                </div>
                 <div class="chart-card">
                    <h3>Common Attack Phrases</h3>
                    {fig_words.to_html(full_html=False, include_plotlyjs=False)}
                </div>
            </div>

            <div id="forensics" class="section grid-2">
                <div class="chart-card">
                    <h3>Botnet Detection (Entropy vs Length)</h3>
                    {fig_entropy.to_html(full_html=False, include_plotlyjs=False)}
                </div>
                <div class="chart-card">
                    <h3>Source Correlation Matrix</h3>
                    {fig_matrix.to_html(full_html=False, include_plotlyjs=False)}
                </div>
            </div>

        </div>

        <script>
            // TABS LOGIC
            function openTab(tabName) {{
                const tabs = document.getElementsByClassName('section');
                for (let i = 0; i < tabs.length; i++) {{ tabs[i].style.display = "none"; }}
                document.getElementById(tabName).style.display = "grid";
                
                const btns = document.getElementsByClassName('tab-btn');
                for (let i = 0; i < btns.length; i++) {{ btns[i].classList.remove('active'); }}
                event.currentTarget.classList.add('active');
            }}

            // SEARCH LOGIC
            const db = {json.dumps(search_preview)};
            function doSearch() {{
                const q = document.getElementById('search').value.toLowerCase();
                const res = document.getElementById('results');
                if (q.length < 3) {{ res.innerHTML = ''; return; }}
                
                let matches = [];
                for (let i = 0; i < db.length; i++) {{
                    if (db[i].includes(q)) {{ matches.push(db[i]); if (matches.length > 11) break; }}
                }}
                
                res.innerHTML = matches.map(d => `<div class="result-tag">${{d}}</div>`).join('');
            }}
        </script>
    </body>
    </html>
    """
    
    with open("stats.html", "w", encoding="utf-8") as f:
        f.write(html)
