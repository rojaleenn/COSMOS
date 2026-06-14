import pandas as pd
import numpy as np
import networkx as nx
from collections import defaultdict
import json
import glob
import os
from datetime import datetime

class GraphAnalyzer:
    def __init__(self):
        self.graph = nx.Graph()
        print("[GRAPH] Graph Analyzer initialized")

    def load_latest_processed(self):
        """Load the most recent processed threat data"""
        files = glob.glob("data/processed/threats_*.csv")
        if not files:
            print("[GRAPH] No processed data found")
            return None
        latest = max(files, key=os.path.getctime)
        print(f"[GRAPH] Loading {latest}")
        df = pd.read_csv(latest)
        df = df.fillna("unknown")
        print(f"[GRAPH] Loaded {len(df)} threat records")
        return df

    def build_threat_graph(self, df):
        """Build a graph where nodes are threats and edges are relationships"""
        print("[GRAPH] Building threat relationship graph...")
        G = nx.Graph()

        # Add all threats as nodes
        for idx, row in df.iterrows():
            G.add_node(
                row["value"],
                source=row["source"],
                type=row["type"],
                malware=row["malware_family"],
                country=row["country"],
                confidence=row["confidence"],
                tags=row["tags"]
            )

        # Add edges between threats that share properties
        threats_by_malware = defaultdict(list)
        threats_by_type = defaultdict(list)
        threats_by_country = defaultdict(list)
        threats_by_tag = defaultdict(list)

        for idx, row in df.iterrows():
            if row["malware_family"] != "unknown":
                threats_by_malware[row["malware_family"]].append(row["value"])
            threats_by_type[row["type"]].append(row["value"])
            if row["country"] != "unknown":
                threats_by_country[row["country"]].append(row["value"])
            for tag in str(row["tags"]).split(","):
                tag = tag.strip()
                if tag and tag != "unknown":
                    threats_by_tag[tag].append(row["value"])

        # Connect threats sharing same malware family
        edge_count = 0
        for malware, values in threats_by_malware.items():
            for i in range(len(values)):
                for j in range(i+1, min(i+5, len(values))):
                    G.add_edge(
                        values[i], values[j],
                        relationship="same_malware",
                        weight=3.0
                    )
                    edge_count += 1

        # Connect threats sharing same country
        for country, values in threats_by_country.items():
            if country != "global":
                for i in range(len(values)):
                    for j in range(i+1, min(i+3, len(values))):
                        G.add_edge(
                            values[i], values[j],
                            relationship="same_country",
                            weight=2.0
                        )
                        edge_count += 1

        # Connect threats sharing same tags
        for tag, values in threats_by_tag.items():
            for i in range(len(values)):
                for j in range(i+1, min(i+3, len(values))):
                    G.add_edge(
                        values[i], values[j],
                        relationship="same_tag",
                        weight=1.5
                    )
                    edge_count += 1

        print(f"[GRAPH] Graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
        return G

    def calculate_graph_metrics(self, G):
        """Calculate graph-based threat metrics"""
        print("[GRAPH] Calculating graph metrics...")

        metrics = {}

        # Degree centrality — how connected each threat is
        degree_centrality = nx.degree_centrality(G)

        # Find the most connected threats
        top_connected = sorted(
            degree_centrality.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        # Find isolated nodes — potential unknown threats
        isolated = list(nx.isolates(G))

        # Find communities using connected components
        components = list(nx.connected_components(G))
        component_sizes = [len(c) for c in components]

        metrics = {
            "total_nodes": G.number_of_nodes(),
            "total_edges": G.number_of_edges(),
            "isolated_threats": len(isolated),
            "connected_components": len(components),
            "largest_component": max(component_sizes) if component_sizes else 0,
            "avg_component_size": round(np.mean(component_sizes), 2) if component_sizes else 0,
            "top_connected_threats": [
                {"value": v, "centrality": round(c, 4)}
                for v, c in top_connected
            ],
            "isolated_sample": isolated[:10]
        }

        print(f"[GRAPH] Isolated threats (potential unknowns): {len(isolated)}")
        print(f"[GRAPH] Connected components: {len(components)}")
        print(f"[GRAPH] Largest component size: {max(component_sizes) if component_sizes else 0}")

        return metrics

    def detect_geographic_clusters(self, df):
        """Detect threats appearing across multiple countries"""
        print("[GRAPH] Detecting geographic clusters...")

        geo_clusters = []

        # Group by malware family and check geographic spread
        malware_geo = df.groupby("malware_family")["country"].apply(
            lambda x: list(set(x))
        ).reset_index()
        malware_geo.columns = ["malware_family", "countries"]

        for _, row in malware_geo.iterrows():
            countries = [c for c in row["countries"] if c not in ["unknown", "global"]]
            if len(countries) >= 2:
                malware_df = df[df["malware_family"] == row["malware_family"]]
                geo_clusters.append({
                    "malware_family": row["malware_family"],
                    "countries": countries,
                    "country_count": len(countries),
                    "threat_count": len(malware_df),
                    "types": malware_df["type"].value_counts().to_dict(),
                    "sources": malware_df["source"].value_counts().to_dict(),
                    "global_spread_score": round(len(countries) * len(malware_df) / 10, 2)
                })

        geo_clusters.sort(key=lambda x: x["global_spread_score"], reverse=True)
        print(f"[GRAPH] Geographic clusters found: {len(geo_clusters)}")
        return geo_clusters

    def detect_temporal_patterns(self, df):
        """Detect threats that evolve over time"""
        print("[GRAPH] Detecting temporal patterns...")

        df = df.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.dropna(subset=["timestamp"])

        if df.empty:
            print("[GRAPH] No temporal data available")
            return []

        temporal_patterns = []

        # Group by malware family and analyse time spread
        for malware, group in df.groupby("malware_family"):
            if malware == "unknown" or len(group) < 3:
                continue

            time_range = (
                group["timestamp"].max() - group["timestamp"].min()
            ).days

            if time_range > 0:
                temporal_patterns.append({
                    "malware_family": malware,
                    "first_seen": group["timestamp"].min().isoformat(),
                    "last_seen": group["timestamp"].max().isoformat(),
                    "time_span_days": time_range,
                    "threat_count": len(group),
                    "persistence_score": round(
                        len(group) * time_range / 100, 2
                    ),
                    "sources": group["source"].value_counts().to_dict(),
                    "types": group["type"].value_counts().to_dict()
                })

        temporal_patterns.sort(
            key=lambda x: x["persistence_score"], reverse=True
        )
        print(f"[GRAPH] Temporal patterns found: {len(temporal_patterns)}")
        return temporal_patterns

    def run(self):
        """Run the full graph analysis pipeline"""
        print("\n[GRAPH] Starting graph analysis pipeline...")

        df = self.load_latest_processed()
        if df is None:
            return

        # Build threat graph
        G = self.build_threat_graph(df)

        # Calculate metrics
        metrics = self.calculate_graph_metrics(G)

        # Detect geographic clusters
        geo_clusters = self.detect_geographic_clusters(df)

        # Detect temporal patterns
        temporal_patterns = self.detect_temporal_patterns(df)

        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = {
            "timestamp": timestamp,
            "graph_metrics": metrics,
            "geographic_clusters": geo_clusters[:20],
            "temporal_patterns": temporal_patterns[:20]
        }

        output_path = f"data/processed/graph_analysis_{timestamp}.json"
        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)

        # Print report
        print("\n" + "="*55)
        print("        COSMOS — GRAPH ANALYSIS REPORT")
        print("="*55)
        print(f"  Threat Nodes          : {metrics['total_nodes']}")
        print(f"  Relationships (Edges) : {metrics['total_edges']}")
        print(f"  Isolated Threats      : {metrics['isolated_threats']}")
        print(f"  Threat Communities    : {metrics['connected_components']}")

        if geo_clusters:
            print(f"\n  ── TOP GEOGRAPHIC CLUSTERS ──")
            for c in geo_clusters[:3]:
                print(f"\n  Malware  : {c['malware_family']}")
                print(f"  Countries: {c['countries']}")
                print(f"  Threats  : {c['threat_count']}")
                print(f"  Spread   : {c['global_spread_score']}")

        if temporal_patterns:
            print(f"\n  ── TOP TEMPORAL PATTERNS ──")
            for t in temporal_patterns[:3]:
                print(f"\n  Malware      : {t['malware_family']}")
                print(f"  Active For   : {t['time_span_days']} days")
                print(f"  Threat Count : {t['threat_count']}")
                print(f"  Persistence  : {t['persistence_score']}")

        print("="*55)
        print(f"\n[GRAPH] Results saved to {output_path}")

        return output

if __name__ == "__main__":
    analyzer = GraphAnalyzer()
    analyzer.run()