import os
import sys
from datetime import datetime

def banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   ██████╗ ██████╗ ███████╗███╗   ███╗ ██████╗ ███████╗  ║
║  ██╔════╝██╔═══██╗██╔════╝████╗ ████║██╔═══██╗██╔════╝  ║
║  ██║     ██║   ██║███████╗██╔████╔██║██║   ██║███████╗  ║
║  ██║     ██║   ██║╚════██║██║╚██╔╝██║██║   ██║╚════██║  ║
║  ╚██████╗╚██████╔╝███████║██║ ╚═╝ ██║╚██████╔╝███████║  ║
║   ╚═════╝ ╚═════╝ ╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝  ║
║                                                          ║
║   Cyber Observation System for Mapping, Observing        ║
║   and Synthesizing Unknown Security Threats              ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
    """)

def step(number, title):
    print(f"\n{'='*55}")
    print(f"  STEP {number} — {title}")
    print(f"{'='*55}")

def main():
    start_time = datetime.now()
    banner()
    print(f"  Starting COSMOS pipeline at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  All systems initializing...\n")

    # Step 1 — Collect
    step(1, "CYBER TELESCOPE — Collecting Threat Data")
    from telescope.collector import CyberTelescope
    telescope = CyberTelescope()
    raw_data = telescope.collect_all()
    if not raw_data:
        print("[COSMOS] Telescope failed. Exiting.")
        sys.exit(1)

    # Step 2 — Process
    step(2, "DATA PROCESSOR — Structuring Threat Data")
    from telescope.processor import DataProcessor
    processor = DataProcessor()
    threats_df = processor.process_all()
    if threats_df is None:
        print("[COSMOS] Processor failed. Exiting.")
        sys.exit(1)

    # Step 3 — Deduplication
    step(3, "DEDUPLICATOR — Identifying New vs Recurring Threats")
    from engine.deduplicator import ThreatDeduplicator
    deduplicator = ThreatDeduplicator()
    new_threats_df, recurring_df, persistent = deduplicator.run()
    if new_threats_df is not None and not new_threats_df.empty:
        print(f"[COSMOS] {len(new_threats_df)} brand new threats discovered today")

    # Step 4 — Cluster Tracking
    step(4, "CLUSTER TRACKER — Tracking Threat Persistence")
    from engine.cluster_tracker import ClusterTracker
    tracker = ClusterTracker()
    tracking_results, long_term = tracker.run()

    # Step 5 — Detect Unknown Clusters
    step(5, "UNKNOWN UNKNOWN ENGINE — Discovering Clusters")
    from engine.detector import UnknownUnknownEngine
    engine = UnknownUnknownEngine()
    clusters = engine.run()
    if not clusters:
        print("[COSMOS] Engine found no clusters.")
        clusters = []

    # Step 6 — Graph Analysis
    step(6, "GRAPH ANALYZER — Mapping Threat Relationships")
    from engine.graph_analyzer import GraphAnalyzer
    graph_analyzer = GraphAnalyzer()
    graph_results = graph_analyzer.run()

    # Step 7 — Hypothesise
    step(7, "AI HYPOTHESIS ENGINE — Generating Threat Theories")
    from hypothesis.generator import HypothesisEngine
    hypothesis_engine = HypothesisEngine()
    hypotheses = hypothesis_engine.run()
    if not hypotheses:
        hypotheses = []

    # Step 8 — Alert System
    step(8, "ALERT SYSTEM — Sending Critical Threat Notifications")
    from engine.alert_system import COSMOSAlertSystem
    alert_system = COSMOSAlertSystem()
    critical = alert_system.run(
        total_threats=len(threats_df),
        new_threats=len(new_threats_df) if new_threats_df is not None and not new_threats_df.empty else 0
    )

    # Step 9 — Digital Twin Lab
    step(9, "DIGITAL TWIN LAB — Validating Hypotheses")
    from digital_twin.lab import DigitalTwinLab
    lab = DigitalTwinLab()
    twin_results = lab.run()
    if not twin_results:
        twin_results = []

    # Step 10 — Dashboard
    step(10, "DASHBOARD — Building Visual Interface")
    from dashboard.app import COSMOSDashboard
    dashboard = COSMOSDashboard()
    dashboard_path = dashboard.run()

    # Step 11 — Digital Twin Visualization
    step(11, "DIGITAL TWIN VISUALIZATION — Building Live Simulation")
    from dashboard.twin_viz import DigitalTwinVisualizer
    twin_viz = DigitalTwinVisualizer()
    twin_viz.run()

    # Calculate runtime
    end_time = datetime.now()
    runtime = round((end_time - start_time).total_seconds(), 1)

    # Extract stats
    total_threats = len(threats_df)
    total_clusters = len(clusters)
    total_hypotheses = len(hypotheses)
    sources_count = threats_df["source"].nunique()
    malware_families = threats_df["malware_family"].nunique()

    graph_nodes = graph_results["graph_metrics"]["total_nodes"] if graph_results else 0
    graph_edges = graph_results["graph_metrics"]["total_edges"] if graph_results else 0
    geo_clusters = len(graph_results["geographic_clusters"]) if graph_results else 0
    threat_communities = graph_results["graph_metrics"]["connected_components"] if graph_results else 0

    severity_counts = threats_df["severity"].value_counts().to_dict() if "severity" in threats_df.columns else {}
    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    medium = severity_counts.get("medium", 0)

    twin_confirmed = len([r for r in twin_results if "CONFIRMED" in r.get("verdict", "")]) if twin_results else 0
    twin_critical = len([r for r in twin_results if "CRITICAL" in r.get("verdict", "")]) if twin_results else 0

    hypothesis_engine_used = "Groq Llama 3.3 70B" if os.getenv("GROQ_API_KEY") else "Rule-based"

    print(f"""
╔══════════════════════════════════════════════════════════╗
║              COSMOS PIPELINE COMPLETE                    ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  STEP 1  — CYBER TELESCOPE                               ║
║    Threats Collected    : {str(total_threats).ljust(30)}║
║    Active Sources       : {str(sources_count).ljust(30)}║
║    Malware Families     : {str(malware_families).ljust(30)}║
║                                                          ║
║  STEP 2  — DATA PROCESSOR                                ║
║    Critical Threats     : {str(critical).ljust(30)}║
║    High Threats         : {str(high).ljust(30)}║
║    Medium Threats       : {str(medium).ljust(30)}║
║                                                          ║
║  STEP 3  — DEDUPLICATOR                                  ║
║    Brand New Threats    : {str(len(new_threats_df) if new_threats_df is not None and not new_threats_df.empty else 0).ljust(30)}║
║    Known Threat DB      : {str(len(deduplicator.seen_threats)).ljust(30)}║
║                                                          ║
║  STEP 4  — CLUSTER TRACKER                               ║
║    Long-term Threats    : {str(len(long_term)).ljust(30)}║
║                                                          ║
║  STEP 5  — UNKNOWN UNKNOWN ENGINE                        ║
║    Unknown Clusters     : {str(total_clusters).ljust(30)}║
║                                                          ║
║  STEP 6  — GRAPH ANALYZER                                ║
║    Threat Nodes         : {str(graph_nodes).ljust(30)}║
║    Relationships        : {str(graph_edges).ljust(30)}║
║    Threat Communities   : {str(threat_communities).ljust(30)}║
║    Geographic Clusters  : {str(geo_clusters).ljust(30)}║
║                                                          ║
║  STEP 7  — AI HYPOTHESIS ENGINE                          ║
║    Hypotheses Generated : {str(total_hypotheses).ljust(30)}║
║    Engine Used          : {str(hypothesis_engine_used).ljust(30)}║
║                                                          ║
║  STEP 8  — ALERT SYSTEM                                  ║
║    Critical Alerts Sent : {str(len(critical) if isinstance (critical, list) else 1 if critical else 0).ljust(30)}║
║                                                          ║
║  STEP 9  — DIGITAL TWIN LAB                              ║
║    Simulations Run      : {str(len(twin_results)).ljust(30)}║
║    Hypotheses Confirmed : {str(twin_confirmed).ljust(30)}║
║    Critical Findings    : {str(twin_critical).ljust(30)}║
║                                                          ║
║  STEP 10 — DASHBOARD                                     ║
║    Main Dashboard       : cosmos_dashboard.html          ║
║    Twin Visualization   : twin_visualization.html        ║
║    Runtime              : {str(f'{runtime}s').ljust(30)}║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
    """)

    # Auto open both dashboards
    import webbrowser
    webbrowser.open(os.path.abspath("dashboard/cosmos_dashboard.html"))
    webbrowser.open(os.path.abspath("dashboard/twin_visualization.html"))
    print("[COSMOS] Dashboards opened in browser.")
    print("[COSMOS] Pipeline complete. COSMOS is observing the cyber universe.")

if __name__ == "__main__":
    main()