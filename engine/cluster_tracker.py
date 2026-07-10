import json
import glob
import os
from datetime import datetime
import pandas as pd

class ClusterTracker:
    def __init__(self):
        self.tracker_file = "data/processed/cluster_history.json"
        self.history = self.load_history()
        print(f"[TRACKER] Cluster Tracker initialized")
        print(f"[TRACKER] Tracked cluster signatures: {len(self.history)}")

    def load_history(self):
        """Load cluster history from previous runs"""
        if os.path.exists(self.tracker_file):
            with open(self.tracker_file) as f:
                return json.load(f)
        return {}

    def save_history(self):
        """Save updated cluster history"""
        with open(self.tracker_file, "w") as f:
            json.dump(self.history, f, indent=2)

    def load_latest_clusters(self):
        """Load the most recent cluster data"""
        files = glob.glob("data/processed/unknown_clusters_*.json")
        if not files:
            print("[TRACKER] No cluster data found")
            return None
        latest = max(files, key=os.path.getctime)
        print(f"[TRACKER] Loading {latest}")
        with open(latest) as f:
            return json.load(f)

    def generate_cluster_signature(self, cluster):
        """Generate a unique signature for a cluster based on its characteristics"""
        dominant_malware = cluster.get("dominant_malware", "unknown")
        dominant_type = cluster.get("dominant_type", "unknown")
        sources = sorted(cluster.get("sources", {}).keys())
        size_bucket = cluster.get("size", 0) // 50
        signature = f"{dominant_malware}|{dominant_type}|{'_'.join(sources)}|{size_bucket}"
        return signature

    def track_clusters(self, clusters):
        """Compare current clusters with historical data"""
        today = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_clusters = []
        growing_clusters = []
        shrinking_clusters = []
        persistent_clusters = []
        disappeared_clusters = []

        current_signatures = {}

        for cluster in clusters:
            signature = self.generate_cluster_signature(cluster)
            current_signatures[signature] = cluster

            if signature in self.history:
                prev = self.history[signature]
                prev_size = prev.get("last_size", 0)
                curr_size = cluster.get("size", 0)
                seen_count = prev.get("seen_count", 0) + 1

                # Update history
                self.history[signature].update({
                    "last_seen": today,
                    "last_size": curr_size,
                    "last_confidence": cluster.get("cosmos_confidence", 0),
                    "seen_count": seen_count,
                    "size_history": prev.get("size_history", [prev_size]) + [curr_size]
                })

                if curr_size > prev_size * 1.1:
                    growing_clusters.append({
                        "signature": signature,
                        "malware": cluster.get("dominant_malware"),
                        "prev_size": prev_size,
                        "curr_size": curr_size,
                        "growth": round((curr_size - prev_size) / max(prev_size, 1) * 100, 1),
                        "seen_count": seen_count,
                        "confidence": cluster.get("cosmos_confidence")
                    })
                elif curr_size < prev_size * 0.9:
                    shrinking_clusters.append({
                        "signature": signature,
                        "malware": cluster.get("dominant_malware"),
                        "prev_size": prev_size,
                        "curr_size": curr_size,
                        "shrinkage": round((prev_size - curr_size) / max(prev_size, 1) * 100, 1),
                        "seen_count": seen_count,
                        "confidence": cluster.get("cosmos_confidence")
                    })
                else:
                    persistent_clusters.append({
                        "signature": signature,
                        "malware": cluster.get("dominant_malware"),
                        "size": curr_size,
                        "seen_count": seen_count,
                        "confidence": cluster.get("cosmos_confidence")
                    })
            else:
                # Brand new cluster never seen before
                self.history[signature] = {
                    "first_seen": today,
                    "last_seen": today,
                    "last_size": cluster.get("size", 0),
                    "last_confidence": cluster.get("cosmos_confidence", 0),
                    "dominant_malware": cluster.get("dominant_malware"),
                    "dominant_type": cluster.get("dominant_type"),
                    "sources": list(cluster.get("sources", {}).keys()),
                    "seen_count": 1,
                    "size_history": [cluster.get("size", 0)]
                }
                new_clusters.append({
                    "signature": signature,
                    "malware": cluster.get("dominant_malware"),
                    "type": cluster.get("dominant_type"),
                    "size": cluster.get("size", 0),
                    "confidence": cluster.get("cosmos_confidence")
                })

        # Check for disappeared clusters
        for signature, data in self.history.items():
            if signature not in current_signatures:
                last_seen = data.get("last_seen", "unknown")
                if last_seen != today:
                    disappeared_clusters.append({
                        "signature": signature,
                        "malware": data.get("dominant_malware"),
                        "last_seen": last_seen,
                        "last_size": data.get("last_size", 0),
                        "seen_count": data.get("seen_count", 0)
                    })

        self.save_history()

        return {
            "new_clusters": new_clusters,
            "growing_clusters": growing_clusters,
            "shrinking_clusters": shrinking_clusters,
            "persistent_clusters": persistent_clusters,
            "disappeared_clusters": disappeared_clusters
        }

    def get_long_term_threats(self):
        """Find clusters that have persisted across many runs"""
        long_term = []
        for signature, data in self.history.items():
            if data.get("seen_count", 0) >= 3:
                long_term.append({
                    "signature": signature,
                    "malware": data.get("dominant_malware"),
                    "first_seen": data.get("first_seen"),
                    "last_seen": data.get("last_seen"),
                    "seen_count": data.get("seen_count"),
                    "current_size": data.get("last_size"),
                    "confidence": data.get("last_confidence")
                })
        long_term.sort(key=lambda x: x["seen_count"], reverse=True)
        return long_term

    def run(self):
        """Run full cluster tracking analysis"""
        print("\n[TRACKER] Starting cluster persistence analysis...")

        clusters = self.load_latest_clusters()
        if not clusters:
            return

        tracking = self.track_clusters(clusters)
        long_term = self.get_long_term_threats()

        # Save tracking report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"data/processed/cluster_tracking_{timestamp}.json"
        with open(output_path, "w") as f:
            json.dump({
                "timestamp": timestamp,
                "tracking": tracking,
                "long_term_threats": long_term
            }, f, indent=2)

        # Print report
        print("\n" + "="*55)
        print("     COSMOS — CLUSTER PERSISTENCE REPORT")
        print("="*55)
        print(f"  Total Clusters This Run   : {len(clusters)}")
        print(f"  Brand New Clusters        : {len(tracking['new_clusters'])}")
        print(f"  Growing Clusters          : {len(tracking['growing_clusters'])}")
        print(f"  Shrinking Clusters        : {len(tracking['shrinking_clusters'])}")
        print(f"  Stable Clusters           : {len(tracking['persistent_clusters'])}")
        print(f"  Disappeared Clusters      : {len(tracking['disappeared_clusters'])}")
        print(f"  Total Historical Clusters : {len(self.history)}")

        if tracking["new_clusters"]:
            print(f"\n  NEW CLUSTERS (first time seen):")
            for c in tracking["new_clusters"][:5]:
                print(f"    - {c['malware']} | {c['type']} | size {c['size']} | {c['confidence']}% confidence")

        if tracking["growing_clusters"]:
            print(f"\n  GROWING CLUSTERS (expanding campaigns):")
            for c in tracking["growing_clusters"][:5]:
                print(f"    - {c['malware']} | {c['prev_size']} → {c['curr_size']} (+{c['growth']}%) | seen {c['seen_count']}x")

        if tracking["shrinking_clusters"]:
            print(f"\n  SHRINKING CLUSTERS (declining campaigns):")
            for c in tracking["shrinking_clusters"][:3]:
                print(f"    - {c['malware']} | {c['prev_size']} → {c['curr_size']} (-{c['shrinkage']}%)")

        if long_term:
            print(f"\n  LONG-TERM PERSISTENT THREATS (seen 3+ times):")
            for t in long_term[:5]:
                print(f"    - {t['malware']} | seen {t['seen_count']}x | size {t['current_size']} | since {t['first_seen'][:10]}")

        if tracking["disappeared_clusters"]:
            print(f"\n  DISAPPEARED CLUSTERS (no longer detected):")
            for c in tracking["disappeared_clusters"][:3]:
                print(f"    - {c['malware']} | last seen {c['last_seen'][:10]} | was size {c['last_size']}")

        print("="*55)
        print(f"\n[TRACKER] Report saved to {output_path}")

        return tracking, long_term

if __name__ == "__main__":
    tracker = ClusterTracker()
    tracker.run()