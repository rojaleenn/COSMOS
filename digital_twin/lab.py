import json
import glob
import os
import random
import hashlib
from datetime import datetime, timedelta
import pandas as pd

class DigitalTwinLab:
    def __init__(self):
        print("[TWIN] Digital Twin Lab initialized")
        self.enterprise_network = self.build_enterprise_network()
        self.attack_log = []

    def build_enterprise_network(self):
        """Build a simulated enterprise network"""
        network = {
            "name": "COSMOS Enterprise Simulation",
            "subnets": {
                "corporate": {
                    "range": "192.168.1.0/24",
                    "hosts": [
                        {"id": "WS001", "type": "workstation", "os": "Windows 11", "department": "Finance", "ip": "192.168.1.10"},
                        {"id": "WS002", "type": "workstation", "os": "Windows 10", "department": "HR", "ip": "192.168.1.11"},
                        {"id": "WS003", "type": "workstation", "os": "Windows 11", "department": "Engineering", "ip": "192.168.1.12"},
                        {"id": "WS004", "type": "workstation", "os": "macOS", "department": "Marketing", "ip": "192.168.1.13"},
                        {"id": "SRV001", "type": "server", "os": "Windows Server 2022", "role": "Domain Controller", "ip": "192.168.1.1"},
                        {"id": "SRV002", "type": "server", "os": "Linux", "role": "Web Server", "ip": "192.168.1.2"},
                        {"id": "SRV003", "type": "server", "os": "Linux", "role": "Database", "ip": "192.168.1.3"},
                    ]
                },
                "dmz": {
                    "range": "10.0.1.0/24",
                    "hosts": [
                        {"id": "FW001", "type": "firewall", "os": "pfSense", "role": "Perimeter Firewall", "ip": "10.0.1.1"},
                        {"id": "PROXY001", "type": "proxy", "os": "Linux", "role": "Web Proxy", "ip": "10.0.1.2"},
                        {"id": "MAIL001", "type": "server", "os": "Linux", "role": "Mail Server", "ip": "10.0.1.3"},
                    ]
                },
                "cloud": {
                    "range": "AWS/Azure",
                    "hosts": [
                        {"id": "CLOUD001", "type": "cloud_instance", "os": "Linux", "role": "App Server", "ip": "52.1.2.3"},
                        {"id": "CLOUD002", "type": "cloud_instance", "os": "Windows", "role": "Dev Server", "ip": "52.1.2.4"},
                        {"id": "CLOUD003", "type": "storage", "os": "S3/Blob", "role": "Cloud Storage", "ip": "52.1.2.5"},
                    ]
                }
            },
            "security_controls": {
                "firewall": True,
                "antivirus": True,
                "edr": True,
                "siem": True,
                "email_filter": True,
                "dns_filter": False,
                "mfa": False
            },
            "vulnerabilities": [
                {"id": "CVE-2024-001", "host": "WS001", "severity": "high", "description": "Unpatched RCE"},
                {"id": "CVE-2024-002", "host": "SRV002", "severity": "critical", "description": "SQL Injection"},
                {"id": "CVE-2024-003", "host": "MAIL001", "severity": "medium", "description": "Email spoofing"},
                {"id": "CVE-2024-004", "host": "CLOUD002", "severity": "high", "description": "Misconfigured storage"},
            ]
        }
        print(f"[TWIN] Enterprise network built:")
        print(f"[TWIN]   Corporate hosts : {len(network['subnets']['corporate']['hosts'])}")
        print(f"[TWIN]   DMZ hosts       : {len(network['subnets']['dmz']['hosts'])}")
        print(f"[TWIN]   Cloud instances : {len(network['subnets']['cloud']['hosts'])}")
        print(f"[TWIN]   Vulnerabilities : {len(network['vulnerabilities'])}")
        return network

    def simulate_attack_chain(self, cluster, hypothesis):
        """Simulate an attack chain based on a threat cluster"""
        malware = cluster["dominant_malware"]
        threat_type = cluster["dominant_type"]
        confidence = cluster["cosmos_confidence"]
        size = cluster["size"]

        print(f"\n[TWIN] Simulating attack for Cluster #{cluster['cluster_id']}")
        print(f"[TWIN] Malware: {malware} | Type: {threat_type}")

        attack_chain = []
        start_time = datetime.now()

        # Stage 1 — Initial Access
        initial_access = self.simulate_initial_access(threat_type, malware, start_time)
        attack_chain.append(initial_access)

        # Stage 2 — Execution
        if initial_access["success"]:
            execution = self.simulate_execution(malware, initial_access, start_time)
            attack_chain.append(execution)

            # Stage 3 — Persistence
            if execution["success"]:
                persistence = self.simulate_persistence(malware, execution, start_time)
                attack_chain.append(persistence)

                # Stage 4 — C2 Communication
                c2 = self.simulate_c2(malware, cluster, start_time)
                attack_chain.append(c2)

                # Stage 5 — Actions on Objectives
                if c2["success"]:
                    objectives = self.simulate_objectives(malware, start_time)
                    attack_chain.append(objectives)

        return attack_chain

    def simulate_initial_access(self, threat_type, malware, start_time):
        """Simulate initial access attempt"""
        vectors = {
            "domain": {
                "technique": "T1189 — Drive-by Compromise",
                "description": f"User visited malicious domain serving {malware} payload",
                "target": "WS001",
                "detected_by": "email_filter",
                "success_rate": 0.75
            },
            "url": {
                "technique": "T1566 — Phishing Link",
                "description": f"User clicked phishing URL delivering {malware}",
                "target": "WS002",
                "detected_by": "email_filter",
                "success_rate": 0.65
            },
            "ip:port": {
                "technique": "T1190 — Exploit Public-Facing Application",
                "description": f"Attacker exploited exposed service on {malware} C2 infrastructure",
                "target": "SRV002",
                "detected_by": "firewall",
                "success_rate": 0.45
            },
            "file_hash": {
                "technique": "T1204 — User Execution",
                "description": f"User executed malicious file matching {malware} signature",
                "target": "WS003",
                "detected_by": "antivirus",
                "success_rate": 0.55
            },
            "attack_technique": {
                "technique": "T1059 — Command and Scripting Interpreter",
                "description": f"Attacker used scripting to deploy {malware} components",
                "target": "WS001",
                "detected_by": "edr",
                "success_rate": 0.60
            }
        }

        vector = vectors.get(threat_type, vectors["domain"])
        detected = self.check_detection("email_filter")
        success = not detected and random.random() < vector["success_rate"]

        return {
            "stage": "Initial Access",
            "technique": vector["technique"],
            "description": vector["description"],
            "target_host": vector["target"],
            "timestamp": (start_time).isoformat(),
            "detected": detected,
            "detected_by": vector["detected_by"] if detected else None,
            "success": success,
            "ioc_generated": f"{malware.lower().replace('.', '_')}_dropper_{random.randint(1000,9999)}"
        }

    def simulate_execution(self, malware, previous_stage, start_time):
        """Simulate malware execution"""
        detected = self.check_detection("antivirus")
        success = not detected and random.random() < 0.70

        return {
            "stage": "Execution",
            "technique": "T1059.001 — PowerShell / T1106 — Native API",
            "description": f"{malware} executed on {previous_stage['target_host']} via memory injection",
            "target_host": previous_stage["target_host"],
            "timestamp": (start_time + timedelta(minutes=2)).isoformat(),
            "detected": detected,
            "detected_by": "antivirus" if detected else None,
            "success": success,
            "ioc_generated": f"proc_injection_{random.randint(1000,9999)}.log"
        }

    def simulate_persistence(self, malware, previous_stage, start_time):
        """Simulate persistence mechanism"""
        detected = self.check_detection("edr")
        success = not detected and random.random() < 0.65

        mechanisms = [
            "Registry Run Key modification",
            "Scheduled Task creation",
            "Service installation",
            "Startup folder persistence"
        ]

        return {
            "stage": "Persistence",
            "technique": "T1547 — Boot/Logon Autostart Execution",
            "description": f"{malware} established persistence via {random.choice(mechanisms)}",
            "target_host": previous_stage["target_host"],
            "timestamp": (start_time + timedelta(minutes=5)).isoformat(),
            "detected": detected,
            "detected_by": "edr" if detected else None,
            "success": success,
            "ioc_generated": f"persistence_key_{random.randint(1000,9999)}"
        }

    def simulate_c2(self, malware, cluster, start_time):
        """Simulate C2 communication"""
        detected = self.check_detection("firewall")
        success = not detected and random.random() < 0.80

        sample_ioc = cluster["sample_values"][0] if cluster["sample_values"] else "unknown.domain"

        return {
            "stage": "Command & Control",
            "technique": "T1071 — Application Layer Protocol",
            "description": f"{malware} established C2 channel to {sample_ioc}",
            "c2_server": sample_ioc,
            "timestamp": (start_time + timedelta(minutes=8)).isoformat(),
            "detected": detected,
            "detected_by": "firewall" if detected else None,
            "success": success,
            "ioc_generated": f"c2_beacon_{random.randint(1000,9999)}.pcap"
        }

    def simulate_objectives(self, malware, start_time):
        """Simulate attacker objectives"""
        detected = self.check_detection("siem")

        objectives_map = {
            "js.clearfake": "Browser credential theft and session hijacking",
            "win.cobalt_strike": "Lateral movement and domain privilege escalation",
            "win.vidar": "Credential and cryptocurrency wallet theft",
            "win.remus": "Data exfiltration and ransomware deployment",
            "AMOS Stealer": "macOS keychain and password theft",
        }

        objective = objectives_map.get(malware, "Data exfiltration and persistence")

        return {
            "stage": "Actions on Objectives",
            "technique": "T1041 — Exfiltration Over C2 / T1486 — Data Encrypted for Impact",
            "description": objective,
            "timestamp": (start_time + timedelta(minutes=15)).isoformat(),
            "detected": detected,
            "detected_by": "siem" if detected else None,
            "success": not detected,
            "ioc_generated": f"exfil_data_{random.randint(1000,9999)}.enc"
        }

    def check_detection(self, control):
        """Check if a security control would detect the attack"""
        controls = self.enterprise_network["security_controls"]
        detection_rates = {
            "firewall": 0.60,
            "antivirus": 0.55,
            "edr": 0.70,
            "siem": 0.65,
            "email_filter": 0.50,
            "dns_filter": 0.80,
            "mfa": 0.90
        }
        if controls.get(control, False):
            return random.random() < detection_rates.get(control, 0.5)
        return False

    def validate_hypothesis(self, cluster, hypothesis, attack_chain):
        """Validate hypothesis against simulation results"""
        successful_stages = [s for s in attack_chain if s["success"]]
        detected_stages = [s for s in attack_chain if s["detected"]]
        total_stages = len(attack_chain)

        success_rate = len(successful_stages) / total_stages if total_stages > 0 else 0
        detection_rate = len(detected_stages) / total_stages if total_stages > 0 else 0

        # Calculate validation confidence
        base_confidence = cluster["cosmos_confidence"]
        simulation_factor = success_rate * 0.3
        detection_factor = (1 - detection_rate) * 0.2
        validated_confidence = min(
            round(base_confidence * (1 + simulation_factor - detection_factor), 1),
            99.9
        )

        validation_result = {
            "cluster_id": cluster["cluster_id"],
            "malware": cluster["dominant_malware"],
            "original_confidence": cluster["cosmos_confidence"],
            "validated_confidence": validated_confidence,
            "confidence_change": round(validated_confidence - base_confidence, 1),
            "total_stages": total_stages,
            "successful_stages": len(successful_stages),
            "detected_stages": len(detected_stages),
            "success_rate": round(success_rate * 100, 1),
            "detection_rate": round(detection_rate * 100, 1),
            "attack_chain": attack_chain,
            "verdict": self.get_verdict(success_rate, detection_rate),
            "validated_at": datetime.now().isoformat()
        }

        return validation_result

    def get_verdict(self, success_rate, detection_rate):
        """Generate validation verdict"""
        if success_rate >= 0.8 and detection_rate < 0.3:
            return "CRITICAL — Hypothesis CONFIRMED. High success, low detection. Immediate action required."
        elif success_rate >= 0.6 and detection_rate < 0.5:
            return "HIGH — Hypothesis LIKELY CONFIRMED. Threat poses significant risk."
        elif success_rate >= 0.4:
            return "MEDIUM — Hypothesis PARTIALLY CONFIRMED. Further investigation recommended."
        elif detection_rate >= 0.7:
            return "LOW — Hypothesis PARTIALLY REFUTED. Current controls provide adequate protection."
        else:
            return "INCONCLUSIVE — Insufficient simulation data. Manual investigation required."

    def run(self):
        """Run the full Digital Twin Lab simulation"""
        print("\n[TWIN] Starting Digital Twin Lab simulation...")

        # Load clusters
        cluster_files = glob.glob("data/processed/unknown_clusters_*.json")
        if not cluster_files:
            print("[TWIN] No cluster data found")
            return
        with open(max(cluster_files, key=os.path.getctime)) as f:
            clusters = json.load(f)

        # Load hypotheses
        hypothesis_files = glob.glob("data/processed/hypotheses_*.json")
        hypotheses = []
        if hypothesis_files:
            with open(max(hypothesis_files, key=os.path.getctime)) as f:
                hypotheses = json.load(f)

        hypothesis_map = {h["cluster_id"]: h for h in hypotheses}

        # Run simulations for top 3 clusters
        results = []
        for cluster in clusters[:3]:
            hypothesis = hypothesis_map.get(cluster["cluster_id"], {})
            attack_chain = self.simulate_attack_chain(cluster, hypothesis)
            validation = self.validate_hypothesis(cluster, hypothesis, attack_chain)
            results.append(validation)

        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"data/processed/twin_validation_{timestamp}.json"
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)

        # Print report
        print("\n" + "="*55)
        print("     COSMOS — DIGITAL TWIN LAB REPORT")
        print("="*55)
        for r in results:
            print(f"\n  Cluster #{r['cluster_id']} — {r['malware']}")
            print(f"  Original Confidence  : {r['original_confidence']}%")
            print(f"  Validated Confidence : {r['validated_confidence']}%")
            print(f"  Confidence Change    : {'+' if r['confidence_change'] >= 0 else ''}{r['confidence_change']}%")
            print(f"  Attack Success Rate  : {r['success_rate']}%")
            print(f"  Detection Rate       : {r['detection_rate']}%")
            print(f"  Verdict              : {r['verdict']}")
            print(f"\n  Attack Chain:")
            for stage in r["attack_chain"]:
                status = "✓ SUCCESS" if stage["success"] else "✗ BLOCKED" if stage["detected"] else "✗ FAILED"
                print(f"    [{status}] {stage['stage']} — {stage['technique']}")
        print("="*55)
        print(f"\n[TWIN] Results saved to {output_path}")
        return results

if __name__ == "__main__":
    lab = DigitalTwinLab()
    lab.run()