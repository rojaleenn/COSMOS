import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
import glob
import os
import json
from datetime import datetime

class UnknownUnknownEngine:
    def __init__(self):
        self.scaler = StandardScaler()
        print("[ENGINE] Unknown Unknown Engine initialized")

    def load_latest_processed(self):
        """Load the most recent processed threat data"""
        files = glob.glob("data/processed/threats_*.csv")
        if not files:
            print("[ENGINE] No processed data found. Run processor.py first.")
            return None
        latest = max(files, key=os.path.getctime)
        print(f"[ENGINE] Loading {latest}")
        df = pd.read_csv(latest)
        df = df.fillna("unknown")
        print(f"[ENGINE] Loaded {len(df)} threat records")
        return df

    def safe_encode(self, series):
        """Safely label encode a series"""
        return LabelEncoder().fit_transform(series.astype(str).fillna("unknown"))

    def safe_tag_count(self, x):
        """Safely count tags"""
        try:
            x = str(x).strip()
            if x in ["unknown", "", "nan", "none"]:
                return 0
            return len(x.split(","))
        except Exception:
            return 0

    def engineer_features(self, df):
        """Convert threat data into numerical features for ML"""
        print("[ENGINE] Engineering features...")
        features = pd.DataFrame()

        # Categorical encodings
        features["source_enc"] = self.safe_encode(df["source"])
        features["type_enc"] = self.safe_encode(df["type"])
        features["malware_enc"] = self.safe_encode(df["malware_family"])

        # Confidence score
        features["confidence"] = pd.to_numeric(
            df["confidence"], errors="coerce"
        ).fillna(50).clip(0, 100)

        # Value-based features
        values = df["value"].astype(str)
        features["value_length"] = values.apply(len)
        features["value_entropy"] = values.apply(self.calculate_entropy)
        features["has_ip"] = values.apply(
            lambda x: 1 if (
                any(c.isdigit() for c in x) and "." in x and "/" not in x
            ) else 0
        )
        features["has_http"] = values.apply(
            lambda x: 1 if "http" in x.lower() else 0
        )
        features["has_exe"] = values.apply(
            lambda x: 1 if any(
                ext in x.lower() for ext in [".exe", ".dll", ".ps1", ".bat"]
            ) else 0
        )
        features["has_hash"] = values.apply(
            lambda x: 1 if len(x) in [32, 40, 64] and x.isalnum() else 0
        )
        features["dot_count"] = values.apply(lambda x: x.count("."))
        features["slash_count"] = values.apply(lambda x: x.count("/"))

        # Tag features
        features["tag_count"] = df["tags"].apply(self.safe_tag_count)

        # Timestamp features
        timestamps = pd.to_datetime(df["timestamp"], errors="coerce")
        features["hour"] = timestamps.dt.hour.fillna(0).astype(int)
        features["day_of_week"] = timestamps.dt.dayofweek.fillna(0).astype(int)
        features["is_weekend"] = features["day_of_week"].apply(
            lambda x: 1 if x >= 5 else 0
        )

        # Fill any remaining NaN
        features = features.fillna(0)

        print(f"[ENGINE] Feature matrix: {features.shape[0]} samples x {features.shape[1]} features")
        return features

    def calculate_entropy(self, value):
        """Calculate Shannon entropy of a string"""
        try:
            value = str(value)
            if not value:
                return 0
            freq = pd.Series(list(value)).value_counts(normalize=True)
            entropy = -sum(freq * np.log2(freq + 1e-10))
            return round(float(entropy), 4)
        except Exception:
            return 0

    def detect_anomalies(self, features):
        """Use Isolation Forest to detect anomalous threats"""
        print("[ENGINE] Running Isolation Forest anomaly detection...")
        scaled = self.scaler.fit_transform(features)
        iso_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=200,
            max_samples="auto"
        )
        predictions = iso_forest.fit_predict(scaled)
        scores = iso_forest.score_samples(scaled)
        anomaly_mask = predictions == -1
        anomaly_count = int(anomaly_mask.sum())
        print(f"[ENGINE] Anomalies detected: {anomaly_count} / {len(predictions)} ({round(anomaly_count/len(predictions)*100, 1)}%)")
        return anomaly_mask, scores, scaled

    def cluster_threats(self, features, scaled):
        """Use DBSCAN to discover unknown threat clusters"""
        print("[ENGINE] Running PCA dimensionality reduction...")
        n_components = min(8, features.shape[1])
        pca = PCA(n_components=n_components, random_state=42)
        reduced = pca.fit_transform(scaled)
        variance_explained = round(sum(pca.explained_variance_ratio_) * 100, 1)
        print(f"[ENGINE] PCA variance explained: {variance_explained}%")

        print("[ENGINE] Running DBSCAN clustering...")
        dbscan = DBSCAN(eps=0.9, min_samples=3, metric="euclidean")
        labels = dbscan.fit_predict(reduced)

        n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
        n_noise = int(list(labels).count(-1))
        print(f"[ENGINE] Clusters discovered: {n_clusters}")
        print(f"[ENGINE] Unclustered anomalies: {n_noise}")
        return labels, reduced

    def calculate_cluster_confidence(self, anomaly_ratio, size, avg_confidence):
        """Calculate COSMOS confidence score for a cluster"""
        base = 100 - (anomaly_ratio * 40)
        size_bonus = min(size / 10, 10)
        confidence_factor = avg_confidence / 100
        score = (base + size_bonus) * confidence_factor
        return round(min(max(score, 10), 99), 1)

    def identify_unknown_clusters(self, df, cluster_labels, anomaly_mask, scores):
        """Identify and describe unknown threat clusters"""
        df = df.copy()
        df["cluster"] = cluster_labels
        df["is_anomaly"] = anomaly_mask
        df["anomaly_score"] = scores

        unknown_clusters = []

        for cluster_id in sorted(set(cluster_labels)):
            if cluster_id == -1:
                continue

            cluster_df = df[df["cluster"] == cluster_id]
            anomaly_ratio = float(cluster_df["is_anomaly"].mean())
            avg_confidence = float(pd.to_numeric(
                cluster_df["confidence"], errors="coerce"
            ).fillna(50).mean())

            sources = cluster_df["source"].value_counts().to_dict()
            types = cluster_df["type"].value_counts().to_dict()
            malware = cluster_df["malware_family"].value_counts().to_dict()
            tags = cluster_df["tags"].value_counts().head(5).to_dict()

            cosmos_confidence = self.calculate_cluster_confidence(
                anomaly_ratio, len(cluster_df), avg_confidence
            )

            unknown_clusters.append({
                "cluster_id": int(cluster_id),
                "size": int(len(cluster_df)),
                "anomaly_percentage": round(anomaly_ratio * 100, 1),
                "cosmos_confidence": cosmos_confidence,
                "sources": sources,
                "threat_types": types,
                "dominant_type": max(types, key=types.get),
                "malware_families": malware,
                "dominant_malware": max(malware, key=malware.get),
                "tags": tags,
                "avg_anomaly_score": round(float(cluster_df["anomaly_score"].mean()), 4),
                "sample_values": cluster_df["value"].head(5).tolist(),
                "discovered_at": datetime.now().isoformat(),
            })

        # Sort by confidence descending
        unknown_clusters.sort(key=lambda x: x["cosmos_confidence"], reverse=True)
        return unknown_clusters

    def print_report(self, df, anomaly_mask, unknown_clusters):
        """Print the COSMOS Unknown Unknown Engine report"""
        print("\n" + "="*55)
        print("       COSMOS — UNKNOWN UNKNOWN ENGINE REPORT")
        print("="*55)
        print(f"  Threats Analysed        : {len(df)}")
        print(f"  Anomalies Detected      : {int(anomaly_mask.sum())}")
        print(f"  Unknown Clusters Found  : {len(unknown_clusters)}")
        print(f"  Analysis Time           : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        if unknown_clusters:
            print("\n  ── TOP UNKNOWN THREAT CLUSTERS ──")
            for i, cluster in enumerate(unknown_clusters[:5], 1):
                print(f"\n  [{i}] Potential Emerging Threat Cluster #{cluster['cluster_id']}")
                print(f"      COSMOS Confidence  : {cluster['cosmos_confidence']}%")
                print(f"      Cluster Size       : {cluster['size']} threats")
                print(f"      Anomaly Rate       : {cluster['anomaly_percentage']}%")
                print(f"      Dominant Type      : {cluster['dominant_type']}")
                print(f"      Dominant Malware   : {cluster['dominant_malware']}")
                print(f"      Sources            : {list(cluster['sources'].keys())}")
                print(f"      Sample IOCs        : {cluster['sample_values'][:2]}")
        print("="*55)

    def run(self):
        """Run the full Unknown Unknown Engine pipeline"""
        print("\n[ENGINE] Starting Unknown Unknown detection pipeline...")

        df = self.load_latest_processed()
        if df is None:
            return

        features = self.engineer_features(df)
        anomaly_mask, scores, scaled = self.detect_anomalies(features)
        cluster_labels, reduced = self.cluster_threats(features, scaled)
        unknown_clusters = self.identify_unknown_clusters(
            df, cluster_labels, anomaly_mask, scores
        )

        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"data/processed/unknown_clusters_{timestamp}.json"
        with open(output_path, "w") as f:
            json.dump(unknown_clusters, f, indent=2)

        self.print_report(df, anomaly_mask, unknown_clusters)
        print(f"\n[ENGINE] Results saved to {output_path}")
        return unknown_clusters

if __name__ == "__main__":
    engine = UnknownUnknownEngine()
    engine.run()