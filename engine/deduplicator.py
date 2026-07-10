import pandas as pd
import glob
import os
import json
from datetime import datetime

class ThreatDeduplicator:
    def __init__(self):
        self.seen_file = "data/processed/seen_threats.json"
        self.seen_threats = self.load_seen_threats()
        print(f"[DEDUP] Deduplicator initialized")
        print(f"[DEDUP] Known threats in database: {len(self.seen_threats)}")

    def load_seen_threats(self):
        """Load previously seen threat values"""
        if os.path.exists(self.seen_file):
            with open(self.seen_file) as f:
                return json.load(f)
        return {}

    def save_seen_threats(self):
        """Save updated seen threats database"""
        with open(self.seen_file, "w") as f:
            json.dump(self.seen_threats, f, indent=2)

    def load_latest_processed(self):
        """Load the most recent processed threats"""
        files = glob.glob("data/processed/threats_*.csv")
        if not files:
            print("[DEDUP] No processed data found")
            return None
        latest = max(files, key=os.path.getctime)
        print(f"[DEDUP] Loading {latest}")
        df = pd.read_csv(latest).fillna("unknown")
        return df

    def deduplicate(self, df):
        """Identify new threats vs previously seen threats"""
        print("[DEDUP] Analysing threat novelty...")

        new_threats = []
        recurring_threats = []
        first_seen_today = []

        today = datetime.now().strftime("%Y-%m-%d")

        for _, row in df.iterrows():
            value = str(row["value"])

            if value in self.seen_threats:
                # Threat seen before
                recurring_threats.append(row)
                # Update last seen date
                self.seen_threats[value]["last_seen"] = today
                self.seen_threats[value]["seen_count"] += 1
            else:
                # Brand new threat never seen before
                new_threats.append(row)
                first_seen_today.append(row)
                self.seen_threats[value] = {
                    "first_seen": today,
                    "last_seen": today,
                    "seen_count": 1,
                    "source": row["source"],
                    "type": row["type"],
                    "malware_family": row["malware_family"]
                }

        # Save updated database
        self.save_seen_threats()

        new_df = pd.DataFrame(new_threats) if new_threats else pd.DataFrame()
        recurring_df = pd.DataFrame(recurring_threats) if recurring_threats else pd.DataFrame()

        return new_df, recurring_df

    def get_persistence_report(self):
        """Find threats that have persisted across multiple days"""
        persistent = []
        for value, data in self.seen_threats.items():
            if data["seen_count"] > 1:
                persistent.append({
                    "value": value,
                    "source": data["source"],
                    "malware_family": data["malware_family"],
                    "first_seen": data["first_seen"],
                    "last_seen": data["last_seen"],
                    "seen_count": data["seen_count"]
                })

        persistent.sort(key=lambda x: x["seen_count"], reverse=True)
        return persistent

    def run(self):
        """Run full deduplication analysis"""
        print("\n[DEDUP] Starting threat deduplication analysis...")

        df = self.load_latest_processed()
        if df is None:
            return

        new_df, recurring_df = self.deduplicate(df)
        persistent = self.get_persistence_report()

        # Save new threats only
        if not new_df.empty:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"data/processed/new_threats_{timestamp}.csv"
            new_df.to_csv(output_path, index=False)

        print("\n" + "="*55)
        print("     COSMOS — THREAT DEDUPLICATION REPORT")
        print("="*55)
        print(f"  Total Threats This Run  : {len(df)}")
        print(f"  Brand New Threats       : {len(new_df)}")
        print(f"  Recurring Threats       : {len(recurring_df)}")
        print(f"  Total Known Threats     : {len(self.seen_threats)}")

        if persistent:
            print(f"\n  Top Persistent Threats (seen multiple times):")
            for t in persistent[:5]:
                print(f"    - {t['value'][:40]} | {t['malware_family']} | seen {t['seen_count']}x")

        if not new_df.empty:
            print(f"\n  Top New Threats Discovered Today:")
            for _, row in new_df.head(5).iterrows():
                print(f"    - {str(row['value'])[:40]} | {row['malware_family']} | {row['source']}")

        print("="*55)
        return new_df, recurring_df, persistent

if __name__ == "__main__":
    dedup = ThreatDeduplicator()
    dedup.run()