import requests
import json
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

class CyberTelescope:
    def __init__(self):
        self.otx_key = os.getenv("OTX_API_KEY", "")
        self.abuse_key = os.getenv("ABUSE_CH_API_KEY", "")
        self.shodan_key = os.getenv("SHODAN_API_KEY", "")
        self.vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        print("[COSMOS] Cyber Telescope initialized")
        print(f"[COSMOS] AlienVault key  : {'OK' if self.otx_key else 'MISSING'}")
        print(f"[COSMOS] Abuse.ch key    : {'OK' if self.abuse_key else 'MISSING'}")
        print(f"[COSMOS] Shodan key      : {'OK' if self.shodan_key else 'MISSING (optional)'}")
        print(f"[COSMOS] VirusTotal key  : {'OK' if self.vt_key else 'MISSING (optional)'}")

    def fetch_alienvault(self):
        """Fetch threat data from AlienVault OTX"""
        print("[TELESCOPE] Fetching from AlienVault OTX...")
        try:
            url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
            headers = {"X-OTX-API-KEY": self.otx_key}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                results = data.get("results", [])
                print(f"[TELESCOPE] Got {len(results)} pulses from AlienVault")
                return results
            else:
                print(f"[TELESCOPE] AlienVault returned {response.status_code}")
                return []
        except Exception as e:
            print(f"[TELESCOPE] AlienVault error: {e}")
            return []

    def fetch_urlhaus(self):
        """Fetch malicious URLs from URLhaus"""
        print("[TELESCOPE] Fetching from URLhaus...")
        try:
            url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
            headers = {"Auth-Key": self.abuse_key}
            response = requests.post(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                urls = data.get("urls", [])
                print(f"[TELESCOPE] Got {len(urls)} malicious URLs from URLhaus")
                return urls
            else:
                print(f"[TELESCOPE] URLhaus returned {response.status_code}")
                return []
        except Exception as e:
            print(f"[TELESCOPE] URLhaus error: {e}")
            return []

    def fetch_threatfox(self):
        """Fetch IOCs from ThreatFox"""
        print("[TELESCOPE] Fetching from ThreatFox...")
        try:
            url = "https://threatfox-api.abuse.ch/api/v1/"
            headers = {"Auth-Key": self.abuse_key}
            payload = {"query": "get_iocs", "days": 1}
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            if response.status_code == 200:
                data = response.json()
                iocs = data.get("data", [])
                print(f"[TELESCOPE] Got {len(iocs)} IOCs from ThreatFox")
                return iocs
            else:
                print(f"[TELESCOPE] ThreatFox returned {response.status_code}")
                return []
        except Exception as e:
            print(f"[TELESCOPE] ThreatFox error: {e}")
            return []

    def fetch_malwarebazaar(self):
        """Fetch fresh malware samples from MalwareBazaar"""
        print("[TELESCOPE] Fetching from MalwareBazaar...")
        try:
            url = "https://mb-api.abuse.ch/api/v1/"
            headers = {"Auth-Key": self.abuse_key}
            payload = {"query": "get_recent", "selector": "time"}
            response = requests.post(
                url, headers=headers, data=payload, timeout=15
            )
            if response.status_code == 200:
                data = response.json()
                samples = data.get("data", [])
                if samples:
                    print(f"[TELESCOPE] Got {len(samples)} malware samples from MalwareBazaar")
                    return samples
                else:
                    print(f"[TELESCOPE] MalwareBazaar: {data.get('query_status', 'no data')}")
                    return []
            else:
                print(f"[TELESCOPE] MalwareBazaar returned {response.status_code}")
                return []
        except Exception as e:
            print(f"[TELESCOPE] MalwareBazaar error: {e}")
            return []

    def fetch_feodo_tracker(self):
        """Fetch botnet C2 servers from Feodo Tracker"""
        print("[TELESCOPE] Fetching from Feodo Tracker...")
        try:
            url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    servers = data
                elif isinstance(data, dict):
                    servers = data.get("blocklist", [])
                else:
                    servers = []
                print(f"[TELESCOPE] Got {len(servers)} botnet C2 servers from Feodo Tracker")
                return servers
            else:
                print(f"[TELESCOPE] Feodo Tracker returned {response.status_code}")
                return []
        except Exception as e:
            print(f"[TELESCOPE] Feodo Tracker error: {e}")
            return []

    def fetch_mitre_attack(self):
        """Fetch attack techniques from MITRE ATT&CK"""
        print("[TELESCOPE] Fetching from MITRE ATT&CK...")
        try:
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                objects = data.get("objects", [])
                techniques = [
                    obj for obj in objects
                    if obj.get("type") == "attack-pattern"
                    and not obj.get("revoked", False)
                ]
                print(f"[TELESCOPE] Got {len(techniques)} techniques from MITRE ATT&CK")
                return techniques
            else:
                print(f"[TELESCOPE] MITRE ATT&CK returned {response.status_code}")
                return []
        except Exception as e:
            print(f"[TELESCOPE] MITRE ATT&CK error: {e}")
            return []

    def fetch_shodan(self):
        """Fetch exposed device data from Shodan"""
        if not self.shodan_key:
            print("[TELESCOPE] Shodan key missing — skipping")
            return []
        print("[TELESCOPE] Fetching from Shodan...")
        try:
            url = "https://api.shodan.io/shodan/host/search"
            params = {
                "key": self.shodan_key,
                "query": "malware",
                "minify": True
            }
            response = requests.get(url, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json()
                matches = data.get("matches", [])
                print(f"[TELESCOPE] Got {len(matches)} results from Shodan")
                return matches
            else:
                print(f"[TELESCOPE] Shodan returned {response.status_code}")
                return []
        except Exception as e:
            print(f"[TELESCOPE] Shodan error: {e}")
            return []

    def fetch_virustotal(self):
        """Fetch latest malicious files from VirusTotal"""
        if not self.vt_key:
            print("[TELESCOPE] VirusTotal key missing — skipping")
            return []
        print("[TELESCOPE] Fetching from VirusTotal...")
        try:
            url = "https://www.virustotal.com/api/v3/feeds/files"
            headers = {"x-apikey": self.vt_key}
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                files = data.get("data", [])
                print(f"[TELESCOPE] Got {len(files)} files from VirusTotal")
                return files
            else:
                print(f"[TELESCOPE] VirusTotal returned {response.status_code}")
                return []
        except Exception as e:
            print(f"[TELESCOPE] VirusTotal error: {e}")
            return []

    def print_summary(self, results):
        """Print collection summary"""
        total = sum([
            len(results["alienvault"]),
            len(results["urlhaus"]),
            len(results["threatfox"]),
            len(results["malwarebazaar"]),
            len(results["feodo_tracker"]),
            len(results["mitre_attack"]),
            len(results["shodan"]),
            len(results["virustotal"]),
        ])
        print("\n" + "="*50)
        print("     COSMOS TELESCOPE COLLECTION SUMMARY")
        print("="*50)
        print(f"  AlienVault OTX   : {len(results['alienvault'])} pulses")
        print(f"  ThreatFox        : {len(results['threatfox'])} IOCs")
        print(f"  URLhaus          : {len(results['urlhaus'])} URLs")
        print(f"  MalwareBazaar    : {len(results['malwarebazaar'])} samples")
        print(f"  Feodo Tracker    : {len(results['feodo_tracker'])} C2 servers")
        print(f"  MITRE ATT&CK     : {len(results['mitre_attack'])} techniques")
        print(f"  Shodan           : {len(results['shodan'])} devices")
        print(f"  VirusTotal       : {len(results['virustotal'])} files")
        print(f"  {'─'*40}")
        print(f"  TOTAL            : {total} threat records")
        print("="*50)

    def collect_all(self):
        """Run all collectors and save data"""
        print("\n[COSMOS] Starting data collection...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        results = {
            "timestamp": timestamp,
            "alienvault": self.fetch_alienvault(),
            "urlhaus": self.fetch_urlhaus(),
            "threatfox": self.fetch_threatfox(),
            "malwarebazaar": self.fetch_malwarebazaar(),
            "feodo_tracker": self.fetch_feodo_tracker(),
            "mitre_attack": self.fetch_mitre_attack(),
            "shodan": self.fetch_shodan(),
            "virustotal": self.fetch_virustotal(),
        }

        output_path = f"data/raw/telescope_{timestamp}.json"
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)

        self.print_summary(results)
        print(f"\n[COSMOS] Data saved to {output_path}")
        print(f"[COSMOS] Collection complete")
        return results

if __name__ == "__main__":
    telescope = CyberTelescope()
    telescope.collect_all()