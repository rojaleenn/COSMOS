import json
import glob
import os
import pandas as pd
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go

class COSMOSDashboard:
    def __init__(self):
        print("[DASHBOARD] COSMOS Dashboard initializing...")

    def load_data(self):
        threats_df = None
        threat_files = glob.glob("data/processed/threats_*.csv")
        if threat_files:
            latest = max(threat_files, key=os.path.getctime)
            threats_df = pd.read_csv(latest)
            threats_df = threats_df.fillna("unknown")
            print(f"[DASHBOARD] Loaded {len(threats_df)} threats")

        clusters = []
        cluster_files = glob.glob("data/processed/unknown_clusters_*.json")
        if cluster_files:
            latest = max(cluster_files, key=os.path.getctime)
            with open(latest) as f:
                clusters = json.load(f)
            print(f"[DASHBOARD] Loaded {len(clusters)} clusters")

        hypotheses = []
        hypothesis_files = glob.glob("data/processed/hypotheses_*.json")
        if hypothesis_files:
            latest = max(hypothesis_files, key=os.path.getctime)
            with open(latest) as f:
                hypotheses = json.load(f)
            print(f"[DASHBOARD] Loaded {len(hypotheses)} hypotheses")

        graph_results = None
        graph_files = glob.glob("data/processed/graph_analysis_*.json")
        if graph_files:
            latest = max(graph_files, key=os.path.getctime)
            with open(latest) as f:
                graph_results = json.load(f)
            print(f"[DASHBOARD] Loaded graph analysis")

        return threats_df, clusters, hypotheses, graph_results

    def build_threat_distribution(self, df):
        fig = px.pie(
            df, names="type",
            title="Threat Type Distribution",
            color_discrete_sequence=px.colors.sequential.Plasma_r,
            hole=0.4
        )
        fig.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            font_color="#c9d1d9", title_font_size=16
        )
        return fig.to_html(full_html=False)

    def build_malware_chart(self, df):
        top = df[df["malware_family"] != "unknown"]["malware_family"].value_counts().head(10).reset_index()
        top.columns = ["malware_family", "count"]
        fig = px.bar(
            top, x="count", y="malware_family",
            orientation="h", title="Top 10 Malware Families",
            color="count", color_continuous_scale="Plasma"
        )
        fig.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            font_color="#c9d1d9", title_font_size=16,
            yaxis={"categoryorder": "total ascending"}
        )
        return fig.to_html(full_html=False)

    def build_source_chart(self, df):
        source_counts = df["source"].value_counts().reset_index()
        source_counts.columns = ["source", "count"]
        fig = px.bar(
            source_counts, x="source", y="count",
            title="Threats by Source", color="source",
            color_discrete_sequence=["#58a6ff", "#3fb950", "#f78166", "#a371f7", "#ffa657"]
        )
        fig.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            font_color="#c9d1d9", title_font_size=16
        )
        return fig.to_html(full_html=False)

    def build_cluster_chart(self, clusters):
        if not clusters:
            return "<p>No cluster data available</p>"
        df = pd.DataFrame(clusters)
        fig = px.scatter(
            df, x="cluster_id", y="cosmos_confidence",
            size="size", color="cosmos_confidence",
            hover_data=["dominant_malware", "dominant_type", "size"],
            title="Unknown Threat Clusters — COSMOS Confidence Map",
            color_continuous_scale="Plasma", size_max=60
        )
        fig.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            font_color="#c9d1d9", title_font_size=16
        )
        return fig.to_html(full_html=False)

    def build_severity_chart(self, df):
        if "severity" not in df.columns:
            return "<p>No severity data</p>"
        severity_order = ["critical", "high", "medium", "low"]
        severity_colors = {
            "critical": "#f85149",
            "high": "#ffa657",
            "medium": "#e3b341",
            "low": "#3fb950"
        }
        counts = df["severity"].value_counts()
        labels = [s for s in severity_order if s in counts.index]
        values = [counts[s] for s in labels]
        colors = [severity_colors[s] for s in labels]
        fig = go.Figure(data=[go.Bar(
            x=labels, y=values,
            marker_color=colors,
            text=values, textposition="auto"
        )])
        fig.update_layout(
            title="Threats by Severity",
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            font_color="#c9d1d9", title_font_size=16
        )
        return fig.to_html(full_html=False)

    def build_world_map(self, df):
        country_counts = df[
            (df["country"] != "unknown") &
            (df["country"] != "global")
        ]["country"].value_counts().reset_index()
        country_counts.columns = ["country", "count"]

        if country_counts.empty:
            return "<p style='color:#8b949e;text-align:center;padding:40px'>No geographic data available yet</p>"

        fig = px.choropleth(
            country_counts,
            locations="country",
            locationmode="ISO-3",
            color="count",
            title="Global Threat Origin Map",
            color_continuous_scale="Plasma",
            labels={"count": "Threat Count"}
        )
        fig.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            font_color="#c9d1d9", title_font_size=16,
            geo=dict(
                bgcolor="#0d1117",
                showframe=False,
                showcoastlines=True,
                coastlinecolor="#30363d",
                showland=True,
                landcolor="#161b22",
                showocean=True,
                oceancolor="#0d1117",
                showcountries=True,
                countrycolor="#30363d"
            )
        )
        return fig.to_html(full_html=False)

    def build_timeline(self, df):
        df = df.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.dropna(subset=["timestamp"])

        if df.empty:
            return "<p style='color:#8b949e;text-align:center;padding:40px'>No timeline data available</p>"

        df["date"] = df["timestamp"].dt.date
        timeline = df.groupby(["date", "source"]).size().reset_index(name="count")

        fig = px.line(
            timeline, x="date", y="count",
            color="source", title="Threat Activity Timeline",
            color_discrete_sequence=["#58a6ff", "#3fb950", "#f78166", "#a371f7", "#ffa657"]
        )
        fig.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            font_color="#c9d1d9", title_font_size=16
        )
        return fig.to_html(full_html=False)

    def build_geo_clusters_section(self, graph_results):
        if not graph_results:
            return ""
        geo_clusters = graph_results.get("geographic_clusters", [])
        if not geo_clusters:
            return ""

        cards = ""
        for gc in geo_clusters[:5]:
            country_tags = " ".join([
                f"<span class='country-tag'>{c}</span>"
                for c in gc["countries"][:5]
            ])
            cards += f"""
            <div class="geo-card">
                <div class="geo-malware">{gc['malware_family']}</div>
                <div class="geo-countries">{country_tags}</div>
                <div class="geo-stats">
                    <span>{gc['threat_count']} threats</span>
                    <span>{gc['country_count']} countries</span>
                    <span>spread: {gc['global_spread_score']}</span>
                </div>
            </div>"""
        return cards

    def build_html(self, threats_df, clusters, hypotheses, graph_results):
        threat_dist = self.build_threat_distribution(threats_df)
        malware_chart = self.build_malware_chart(threats_df)
        source_chart = self.build_source_chart(threats_df)
        cluster_chart = self.build_cluster_chart(clusters)
        severity_chart = self.build_severity_chart(threats_df)
        world_map = self.build_world_map(threats_df)
        timeline = self.build_timeline(threats_df)
        geo_clusters_section = self.build_geo_clusters_section(graph_results)

        graph_nodes = graph_results["graph_metrics"]["total_nodes"] if graph_results else 0
        graph_edges = graph_results["graph_metrics"]["total_edges"] if graph_results else 0
        threat_communities = graph_results["graph_metrics"]["connected_components"] if graph_results else 0

        hypothesis_cards = ""
        for h in hypotheses:
            engine_badge = h.get("engine", "fallback").replace("_", " ").upper()
            engine_color = "#3fb950" if "groq" in h.get("engine", "") else "#58a6ff"
            hypothesis_cards += f"""
            <div class="card hypothesis-card">
                <div class="card-header">
                    <span class="cluster-badge">Cluster #{h['cluster_id']}</span>
                    <span class="confidence-badge">{h['cosmos_confidence']}% Confidence</span>
                    <span class="engine-badge" style="border-color:{engine_color};color:{engine_color}">{engine_badge}</span>
                </div>
                <pre class="hypothesis-text">{h['hypothesis']}</pre>
            </div>"""

        cluster_rows = ""
        for c in clusters[:15]:
            confidence = c['cosmos_confidence']
            confidence_color = (
                "#f85149" if confidence >= 90
                else "#ffa657" if confidence >= 70
                else "#e3b341"
            )
            cluster_rows += f"""
            <tr>
                <td>#{c['cluster_id']}</td>
                <td>{c['size']}</td>
                <td style="color:{confidence_color};font-weight:bold">{confidence}%</td>
                <td>{c['anomaly_percentage']}%</td>
                <td>{c['dominant_type']}</td>
                <td>{c['dominant_malware']}</td>
                <td>{list(c['sources'].keys())}</td>
            </tr>"""

        total_threats = len(threats_df)
        total_clusters = len(clusters)
        total_hypotheses = len(hypotheses)
        sources_count = threats_df["source"].nunique()
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        severity_counts = threats_df["severity"].value_counts().to_dict() if "severity" in threats_df.columns else {}
        critical = severity_counts.get("critical", 0)

        geo_section_html = ""
        if geo_clusters_section:
            geo_section_html = f"""
            <div class="section-title">Geographic Threat Clusters</div>
            <div class="geo-grid">{geo_clusters_section}</div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="3600">
    <title>COSMOS — Cyber Observation System</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #0d1117;
            color: #c9d1d9;
            font-family: 'Segoe UI', monospace;
            min-height: 100vh;
        }}
        header {{
            background: linear-gradient(135deg, #161b22, #1f2937);
            border-bottom: 1px solid #30363d;
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .logo {{
            font-size: 28px;
            font-weight: bold;
            background: linear-gradient(90deg, #58a6ff, #a371f7, #3fb950);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: 4px;
        }}
        .subtitle {{
            font-size: 11px;
            color: #8b949e;
            letter-spacing: 2px;
            margin-top: 4px;
        }}
        .status {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
            color: #3fb950;
        }}
        .status-dot {{
            width: 8px; height: 8px;
            background: #3fb950;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.3; }}
        }}
        nav {{
            background: #161b22;
            border-bottom: 1px solid #30363d;
            padding: 10px 40px;
            display: flex;
            gap: 16px;
        }}
        nav a {{
            text-decoration: none;
            font-size: 12px;
            letter-spacing: 2px;
            padding: 6px 18px;
            border-radius: 6px;
            font-family: monospace;
            transition: all 0.3s;
        }}
        nav a.active {{
            color: #58a6ff;
            border: 1px solid #58a6ff;
            background: #1f2937;
        }}
        nav a.inactive {{
            color: #8b949e;
            border: 1px solid #30363d;
        }}
        nav a:hover {{
            color: #58a6ff;
            border-color: #58a6ff;
        }}
        .container {{ padding: 30px 40px; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 16px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            transition: border-color 0.3s;
        }}
        .stat-card:hover {{ border-color: #58a6ff; }}
        .stat-number {{
            font-size: 36px;
            font-weight: bold;
            background: linear-gradient(90deg, #58a6ff, #a371f7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .stat-number.critical {{
            background: linear-gradient(90deg, #f85149, #ffa657);
            -webkit-background-clip: text;
        }}
        .stat-label {{
            font-size: 10px;
            color: #8b949e;
            margin-top: 6px;
            letter-spacing: 1px;
            text-transform: uppercase;
        }}
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 20px;
        }}
        .card-full {{ grid-column: 1 / -1; }}
        .section-title {{
            font-size: 16px;
            font-weight: bold;
            color: #58a6ff;
            margin-bottom: 20px;
            letter-spacing: 2px;
            text-transform: uppercase;
            border-bottom: 1px solid #30363d;
            padding-bottom: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th {{
            background: #21262d;
            padding: 12px;
            text-align: left;
            color: #58a6ff;
            font-size: 11px;
            letter-spacing: 1px;
            text-transform: uppercase;
        }}
        td {{
            padding: 12px;
            border-bottom: 1px solid #21262d;
        }}
        tr:hover td {{ background: #21262d; }}
        .hypothesis-card {{ margin-bottom: 20px; }}
        .card-header {{
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }}
        .cluster-badge {{
            background: #1f2937;
            border: 1px solid #58a6ff;
            color: #58a6ff;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
        }}
        .confidence-badge {{
            background: #1f2937;
            border: 1px solid #3fb950;
            color: #3fb950;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
        }}
        .engine-badge {{
            background: #1f2937;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 11px;
        }}
        .hypothesis-text {{
            font-family: 'Segoe UI', sans-serif;
            font-size: 13px;
            line-height: 1.8;
            color: #c9d1d9;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        .geo-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }}
        .geo-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 16px;
        }}
        .geo-malware {{
            color: #58a6ff;
            font-weight: bold;
            margin-bottom: 10px;
            font-size: 14px;
        }}
        .geo-countries {{
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-bottom: 10px;
        }}
        .country-tag {{
            background: #21262d;
            border: 1px solid #a371f7;
            color: #a371f7;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 11px;
        }}
        .geo-stats {{
            display: flex;
            gap: 10px;
            font-size: 11px;
            color: #8b949e;
        }}
        footer {{
            text-align: center;
            padding: 20px;
            color: #8b949e;
            font-size: 11px;
            border-top: 1px solid #30363d;
            margin-top: 40px;
        }}
    </style>
</head>
<body>
    <header>
        <div>
            <div class="logo">COSMOS</div>
            <div class="subtitle">Cyber Observation System for Mapping, Observing & Synthesizing Unknown Security Threats</div>
        </div>
        <div class="status">
            <div class="status-dot"></div>
            LIVE — {generated_at} — Auto-refresh: 1hr
        </div>
    </header>

    <nav>
        <a href="cosmos_dashboard.html" class="active">THREAT DASHBOARD</a>
        <a href="twin_visualization.html" class="inactive">DIGITAL TWIN LAB</a>
    </nav>

    <div class="container">

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{total_threats}</div>
                <div class="stat-label">Threats Collected</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{total_clusters}</div>
                <div class="stat-label">Unknown Clusters</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{total_hypotheses}</div>
                <div class="stat-label">AI Hypotheses</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{sources_count}</div>
                <div class="stat-label">Active Sources</div>
            </div>
            <div class="stat-card">
                <div class="stat-number critical">{critical}</div>
                <div class="stat-label">Critical Threats</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{threat_communities}</div>
                <div class="stat-label">Threat Communities</div>
            </div>
        </div>

        <div class="charts-grid">
            <div class="card">{threat_dist}</div>
            <div class="card">{source_chart}</div>
            <div class="card">{malware_chart}</div>
            <div class="card">{severity_chart}</div>
            <div class="card card-full">{world_map}</div>
            <div class="card card-full">{timeline}</div>
            <div class="card">{cluster_chart}</div>
        </div>

        {geo_section_html}

        <div class="card card-full" style="margin-bottom: 30px;">
            <div class="section-title">Unknown Threat Clusters</div>
            <table>
                <thead>
                    <tr>
                        <th>Cluster</th>
                        <th>Size</th>
                        <th>Confidence</th>
                        <th>Anomaly Rate</th>
                        <th>Type</th>
                        <th>Malware</th>
                        <th>Sources</th>
                    </tr>
                </thead>
                <tbody>{cluster_rows}</tbody>
            </table>
        </div>

        <div class="section-title">AI Hypothesis Engine — Threat Theories</div>
        {hypothesis_cards}

    </div>

    <footer>
        COSMOS — Cyber Observation System &nbsp;|&nbsp;
        Threats: {total_threats} &nbsp;|&nbsp;
        Clusters: {total_clusters} &nbsp;|&nbsp;
        Graph Nodes: {graph_nodes} &nbsp;|&nbsp;
        Edges: {graph_edges} &nbsp;|&nbsp;
        Generated: {generated_at}
    </footer>
</body>
</html>"""
        return html

    def run(self):
        threats_df, clusters, hypotheses, graph_results = self.load_data()
        if threats_df is None:
            print("[DASHBOARD] No threat data found.")
            return

        print("[DASHBOARD] Building dashboard...")
        html = self.build_html(threats_df, clusters, hypotheses, graph_results)

        output_path = "dashboard/cosmos_dashboard.html"
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"[DASHBOARD] Saved to {output_path}")
        return output_path

if __name__ == "__main__":
    dashboard = COSMOSDashboard()
    dashboard.run()