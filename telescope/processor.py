import json
import os
import pandas as pd
from datetime import datetime
import glob
import re

class DataProcessor:
    def __init__(self):
        print("[PROCESSOR] Data Processor initialized")

    def load_latest(self):
        """Load the most recent telescope data file"""
        files = glob.glob("data/raw/telescope_*.json")
        if not files:
            print("[PROCESSOR] No data files found")
            return None
        latest = max(files, key=os.path.getctime)
        print(f"[PROCESSOR] Loading {latest}")
        with open(latest, "r") as f:
            return json.load(f)

    def safe_get_malware(self, pulse):
        """Safely extract malware family name from any format"""
        families = pulse.get("malware_families", [])
        if not families:
            return "unknown"
        first = families[0]
        if isinstance(first, dict):
            return first.get("display_name", first.get("id", "unknown"))
        if isinstance(first, str):
            return first
        return "unknown"

    def safe_get_country(self, pulse):
        """Safely extract country from any format"""
        countries = pulse.get("targeted_countries", [])
        if not countries:
            return "unknown"
        first = countries[0]
        if isinstance(first, dict):
            return first.get("name", "unknown")
        if isinstance(first, str):
            return first
        return "unknown"

    def clean_country(self, value):
        """Clean and validate country codes/names"""
        if not value or value == "unknown":
            return "unknown"
        value = str(value).strip()
        # Filter out long descriptions that are not countries
        if len(value) > 30:
            return "unknown"
        # Filter out URLs and technical descriptions
        if any(x in value.lower() for x in [
            "http", "botnet", "malware", "payload",
            "command", "control", "domain", "hash", "ip:"
        ]):
            return "unknown"
        return value

    def process_alienvault(self, pulses):
        """Extract structured data from AlienVault pulses"""
        records = []
        for pulse in pulses:
            indicators = pulse.get("indicators", [])
            malware = self.safe_get_malware(pulse)
            country = self.safe_get_country(pulse)
            tags = pulse.get("tags", [])
            tag_str = ",".join(tags) if isinstance(tags, list) else str(tags)

            if indicators:
                for indicator in indicators:
                    records.append({
                        "source": "alienvault",
                        "type": indicator.get("type", "unknown"),
                        "value": indicator.get("indicator", ""),
                        "malware_family": malware,
                        "country": self.clean_country(country),
                        "tags": tag_str,
                        "confidence": indicator.get("confidence", 50),
                        "timestamp": pulse.get("created", ""),
                        "pulse_name": pulse.get("name", "unknown"),
                    })
            else:
                records.append({
                    "source": "alienvault",
                    "type": "pulse",
                    "value": pulse.get("id", ""),
                    "malware_family": malware,
                    "country": self.clean_country(country),
                    "tags": tag_str,
                    "confidence": 50,
                    "timestamp": pulse.get("created", ""),
                    "pulse_name": pulse.get("name", "unknown"),
                })
        print(f"[PROCESSOR] Processed {len(records)} AlienVault indicators")
        return records

    def process_threatfox(self, iocs):
        """Extract structured data from ThreatFox IOCs"""
        records = []
        if not iocs:
            return records
        for ioc in iocs:
            tags = ioc.get("tags") or []
            # Use real country field not ioc_type_desc
            country = ioc.get("country", "unknown") or "unknown"
            records.append({
                "source": "threatfox",
                "type": ioc.get("ioc_type", "unknown"),
                "value": ioc.get("ioc", ""),
                "malware_family": ioc.get("malware", "unknown"),
                "country": self.clean_country(country),
                "tags": ",".join(tags) if isinstance(tags, list) else str(tags),
                "confidence": ioc.get("confidence_level", 50),
                "timestamp": ioc.get("first_seen", ""),
                "pulse_name": ioc.get("threat_type_desc", "unknown"),
            })
        print(f"[PROCESSOR] Processed {len(records)} ThreatFox IOCs")
        return records

    def process_urlhaus(self, urls):
        """Extract structured data from URLhaus"""
        records = []
        for url in urls:
            tags = url.get("tags") or []
            records.append({
                "source": "urlhaus",
                "type": "url",
                "value": url.get("url", ""),
                "malware_family": tags[0] if tags else "unknown",
                "country": self.clean_country(url.get("country", "unknown")),
                "tags": ",".join(tags) if isinstance(tags, list) else str(tags),
                "confidence": 75,
                "timestamp": url.get("date_added", ""),
                "pulse_name": url.get("urlhaus_reference", "unknown"),
            })
        print(f"[PROCESSOR] Processed {len(records)} URLhaus entries")
        return records

    def process_malwarebazaar(self, samples):
        """Extract structured data from MalwareBazaar"""
        records = []
        for sample in samples:
            tags = sample.get("tags") or []
            records.append({
                "source": "malwarebazaar",
                "type": "file_hash",
                "value": sample.get("sha256_hash", ""),
                "malware_family": sample.get("signature", "unknown") or "unknown",
                "country": self.clean_country(
                    sample.get("origin_country", "unknown")
                ),
                "tags": ",".join(tags) if isinstance(tags, list) else str(tags),
                "confidence": 90,
                "timestamp": sample.get("first_seen", ""),
                "pulse_name": sample.get("file_name", "unknown"),
            })
        print(f"[PROCESSOR] Processed {len(records)} MalwareBazaar samples")
        return records

    def process_feodo_tracker(self, servers):
        """Extract structured data from Feodo Tracker"""
        records = []
        for server in servers:
            if isinstance(server, dict):
                records.append({
                    "source": "feodo_tracker",
                    "type": "ip:port",
                    "value": f"{server.get('ip_address', '')}:{server.get('port', '')}",
                    "malware_family": server.get("malware", "unknown"),
                    "country": self.clean_country(server.get("country", "unknown")),
                    "tags": "botnet,c2,feodo",
                    "confidence": 95,
                    "timestamp": server.get("first_seen", ""),
                    "pulse_name": f"Feodo C2 - {server.get('malware', 'unknown')}",
                })
            elif isinstance(server, str):
                records.append({
                    "source": "feodo_tracker",
                    "type": "ip",
                    "value": server,
                    "malware_family": "botnet",
                    "country": "unknown",
                    "tags": "botnet,c2,feodo",
                    "confidence": 95,
                    "timestamp": "",
                    "pulse_name": "Feodo C2",
                })
        print(f"[PROCESSOR] Processed {len(records)} Feodo Tracker C2 servers")
        return records

    def process_mitre_attack(self, techniques):
        """Extract structured data from MITRE ATT&CK"""
        records = []
        for technique in techniques:
            external_refs = technique.get("external_references", [])
            technique_id = ""
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    break

            kill_chain = technique.get("kill_chain_phases", [])
            phases = ",".join([
                p.get("phase_name", "") for p in kill_chain
            ]) if kill_chain else "unknown"

            platforms = technique.get("x_mitre_platforms", [])
            platform_str = ",".join(platforms) if platforms else "unknown"

            records.append({
                "source": "mitre_attack",
                "type": "attack_technique",
                "value": technique_id,
                "malware_family": technique.get("name", "unknown"),
                "country": "global",
                "tags": phases,
                "confidence": 100,
                "timestamp": technique.get("modified", ""),
                "pulse_name": technique.get("name", "unknown"),
            })
        print(f"[PROCESSOR] Processed {len(records)} MITRE ATT&CK techniques")
        return records

    def enrich_with_metadata(self, df):
        """Add derived metadata columns for better analysis"""
        # Extract domain from URLs
        df["domain"] = df["value"].apply(self.extract_domain)

        # Classify threat severity
        df["severity"] = df["confidence"].apply(self.classify_severity)

        # Extract IP address
        df["is_ip"] = df["value"].apply(self.is_ip_address)

        # Tag count
        df["tag_count"] = df["tags"].apply(
            lambda x: len(str(x).split(",")) if str(x) not in ["unknown", "nan", ""] else 0
        )

        return df

    def extract_domain(self, value):
        """Extract domain from a URL or return the value if it's a domain"""
        try:
            value = str(value)
            if value.startswith("http"):
                match = re.search(r"https?://([^/]+)", value)
                return match.group(1) if match else value
            return value
        except Exception:
            return "unknown"

    def classify_severity(self, confidence):
        """Classify threat severity based on confidence"""
        try:
            confidence = float(confidence)
            if confidence >= 90:
                return "critical"
            elif confidence >= 70:
                return "high"
            elif confidence >= 50:
                return "medium"
            else:
                return "low"
        except Exception:
            return "unknown"

    def is_ip_address(self, value):
        """Check if value is an IP address"""
        try:
            pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            return 1 if re.match(pattern, str(value)) else 0
        except Exception:
            return 0

    def generate_summary(self, df):
        """Generate a detailed summary of processed threat data"""
        print("\n" + "="*55)
        print("       COSMOS THREAT INTELLIGENCE SUMMARY")
        print("="*55)
        print(f"  Total Threats Collected : {len(df)}")
        print(f"  Sources                 : {df['source'].nunique()}")
        print(f"  Unique Malware Families : {df['malware_family'].nunique()}")
        print(f"  Unique Threat Types     : {df['type'].nunique()}")
        print(f"  Countries Observed      : {df['country'].nunique()}")

        if "severity" in df.columns:
            print(f"\n  Severity Breakdown:")
            for sev, count in df["severity"].value_counts().items():
                print(f"    - {sev}: {count}")

        print(f"\n  Breakdown by Source:")
        for source, count in df["source"].value_counts().items():
            print(f"    - {source}: {count}")

        print(f"\n  Top 5 Malware Families:")
        for family, count in df["malware_family"].value_counts().head(5).items():
            print(f"    - {family}: {count}")

        print(f"\n  Top 5 Threat Types:")
        for ttype, count in df["type"].value_counts().head(5).items():
            print(f"    - {ttype}: {count}")

        print(f"\n  Top 5 Countries:")
        countries = df[df["country"] != "unknown"]["country"].value_counts().head(5)
        for country, count in countries.items():
            print(f"    - {country}: {count}")
        print("="*55)

    def process_all(self):
        """Process all raw data into a clean dataframe"""
        raw = self.load_latest()
        if not raw:
            return None

        all_records = []
        all_records.extend(self.process_alienvault(raw.get("alienvault", [])))
        all_records.extend(self.process_threatfox(raw.get("threatfox", [])))
        all_records.extend(self.process_urlhaus(raw.get("urlhaus", [])))
        all_records.extend(self.process_malwarebazaar(raw.get("malwarebazaar", [])))
        all_records.extend(self.process_feodo_tracker(raw.get("feodo_tracker", [])))
        all_records.extend(self.process_mitre_attack(raw.get("mitre_attack", [])))

        if not all_records:
            print("[PROCESSOR] No records to process")
            return None

        df = pd.DataFrame(all_records)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.drop_duplicates(subset=["value"])
        df = df.fillna("unknown")

        # Enrich with metadata
        df = self.enrich_with_metadata(df)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"data/processed/threats_{timestamp}.csv"
        df.to_csv(output_path, index=False)

        self.generate_summary(df)
        print(f"\n[PROCESSOR] Saved to {output_path}")
        return df

if __name__ == "__main__":
    processor = DataProcessor()
    processor.process_all()