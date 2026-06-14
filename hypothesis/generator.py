import json
import os
import glob
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

class HypothesisEngine:
    def __init__(self):
        self.groq_key = os.getenv("GROQ_API_KEY", "")
        self.anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
        print("[HYPOTHESIS] AI Hypothesis Engine initialized")
        if self.groq_key:
            print("[HYPOTHESIS] Engine mode: Groq Llama 3.3 70B (FREE)")
        elif self.anthropic_key:
            print("[HYPOTHESIS] Engine mode: Anthropic Claude")
        else:
            print("[HYPOTHESIS] Engine mode: Rule-based fallback")

    def load_latest_clusters(self):
        files = glob.glob("data/processed/unknown_clusters_*.json")
        if not files:
            print("[HYPOTHESIS] No cluster data found. Run detector.py first.")
            return None
        latest = max(files, key=os.path.getctime)
        print(f"[HYPOTHESIS] Loading {latest}")
        with open(latest, "r") as f:
            return json.load(f)

    def load_graph_results(self):
        files = glob.glob("data/processed/graph_analysis_*.json")
        if not files:
            return None
        latest = max(files, key=os.path.getctime)
        with open(latest, "r") as f:
            return json.load(f)

    def build_prompt(self, cluster, graph_results=None):
        geo_context = ""
        if graph_results:
            for geo in graph_results.get("geographic_clusters", []):
                if geo["malware_family"] == cluster["dominant_malware"]:
                    geo_context = f"Geographic spread: {geo['countries']} across {geo['country_count']} countries"
                    break

        temporal_context = ""
        if graph_results:
            for t in graph_results.get("temporal_patterns", []):
                if t["malware_family"] == cluster["dominant_malware"]:
                    temporal_context = f"Temporal pattern: active {t['time_span_days']} days, persistence score {t['persistence_score']}"
                    break

        return f"""You are COSMOS, an expert cybersecurity threat intelligence AI used by top security researchers.
Analyse this real threat cluster detected from live global threat feeds and generate a precise, technical hypothesis.
Be specific, insightful, and reference real-world attack patterns where relevant.

CLUSTER INTELLIGENCE:
- Cluster ID: #{cluster['cluster_id']}
- Size: {cluster['size']} threats
- COSMOS Confidence: {cluster['cosmos_confidence']}%
- Anomaly Rate: {cluster['anomaly_percentage']}%
- Dominant Threat Type: {cluster['dominant_type']}
- Dominant Malware Family: {cluster['dominant_malware']}
- All Malware Families: {list(cluster['malware_families'].keys())[:5]}
- Data Sources: {list(cluster['sources'].keys())}
- Sample IOCs: {cluster['sample_values'][:2]}
- Tags: {list(cluster['tags'].keys())[:3]}
{geo_context}
{temporal_context}

Generate a structured, professional threat hypothesis:

HYPOTHESIS #{cluster['cluster_id']}

THREAT SUMMARY:
[2 sentences - what this cluster represents, why it is significant]

OBSERVED BEHAVIOUR:
[3 technical bullet points about attack patterns, infrastructure, and operational security]

THREAT ACTOR PROFILE:
[2 sentences - sophistication level, likely motivation, target sectors]

ATTACK VECTOR:
[1 sentence - specific delivery mechanism and exploitation method]

KILL CHAIN ANALYSIS:
[Map to specific MITRE ATT&CK techniques relevant to this threat]

POTENTIAL IMPACT:
[2 sentences - business impact, data at risk, sectors affected]

RECOMMENDED INVESTIGATION:
1. [Specific technical action]
2. [Specific technical action]
3. [Specific technical action]

CONFIDENCE ASSESSMENT:
[1 sentence - current confidence level and what evidence would confirm this hypothesis]"""

    def generate_with_groq(self, cluster, graph_results=None):
        """Generate hypothesis using Groq Llama 3.3 70B — Free"""
        try:
            prompt = self.build_prompt(cluster, graph_results)
            headers = {
                "Authorization": f"Bearer {self.groq_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": "llama-3.3-70b-versatile",
                "messages": [
                    {
                        "role": "system",
                        "content": "You are COSMOS, an expert cybersecurity AI that generates precise, technical threat intelligence hypotheses. Always respond with structured professional analysis using the exact format requested."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "max_tokens": 1000,
                "temperature": 0.7
            }
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                text = data["choices"][0]["message"]["content"]
                print(f"[HYPOTHESIS] Groq generated {len(text)} characters")
                return text
            else:
                print(f"[HYPOTHESIS] Groq error {response.status_code}: {response.text[:200]}")
                return self.generate_fallback_hypothesis(cluster)
        except Exception as e:
            print(f"[HYPOTHESIS] Groq error: {e}")
            return self.generate_fallback_hypothesis(cluster)

    def generate_with_anthropic(self, cluster, graph_results=None):
        """Generate hypothesis using Anthropic Claude"""
        try:
            import urllib.request
            prompt = self.build_prompt(cluster, graph_results)
            headers = {
                "Content-Type": "application/json",
                "x-api-key": self.anthropic_key,
                "anthropic-version": "2023-06-01"
            }
            payload = json.dumps({
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 1000,
                "messages": [{"role": "user", "content": prompt}]
            }).encode("utf-8")
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=payload,
                headers=headers,
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["content"][0]["text"]
        except Exception as e:
            print(f"[HYPOTHESIS] Anthropic error: {e}")
            return self.generate_fallback_hypothesis(cluster)

    def generate_fallback_hypothesis(self, cluster):
        """Rule-based hypothesis when no AI API is available"""
        malware = cluster["dominant_malware"]
        threat_type = cluster["dominant_type"]
        size = cluster["size"]
        confidence = cluster["cosmos_confidence"]
        sources = list(cluster["sources"].keys())
        anomaly = cluster["anomaly_percentage"]

        type_description = (
            "network-based C2 communication" if "ip" in threat_type
            else "domain-based infrastructure abuse" if "domain" in threat_type
            else "file-based payload delivery" if "hash" in threat_type
            else "technique-based attack pattern" if "technique" in threat_type
            else "web-based attack vector"
        )

        return f"""HYPOTHESIS #{cluster['cluster_id']}

THREAT SUMMARY:
COSMOS has identified a cluster of {size} threats with consistent behavioural patterns
centred around {malware} activity with {anomaly}% anomaly rate indicating novel characteristics.
The cluster was detected across {len(sources)} intelligence source(s) suggesting active campaigning.

OBSERVED BEHAVIOUR:
• Dominant indicator type: {threat_type} — consistent with {type_description}
• Malware family: {malware} — uniform operational pattern across {len(sources)} source(s)
• Infrastructure scale of {size} indicators suggests an organised, ongoing campaign

THREAT ACTOR PROFILE:
The actor demonstrates moderate-to-high sophistication through deliberate use of {threat_type}
infrastructure with consistent {malware} tooling. Targeting profile suggests financially or
espionage-motivated operations against enterprise environments.

ATTACK VECTOR:
{threat_type.upper()}-based delivery mechanism consistent with known {malware} operational
patterns observed across {', '.join(sources)}.

KILL CHAIN ANALYSIS:
Initial Access [{threat_type}] → Execution [{malware}] → Persistence → C2 Communication → Exfiltration

POTENTIAL IMPACT:
A confirmed {malware} campaign through {threat_type} infrastructure could result in credential
theft, lateral movement, and data exfiltration across enterprise networks. The {size} active
indicators suggest broad targeting across multiple industry sectors.

RECOMMENDED INVESTIGATION:
1. Cross-reference {cluster['sample_values'][0] if cluster['sample_values'] else 'identified IOCs'} against DNS query logs and proxy access logs
2. Deploy {malware}-specific YARA rules and detection signatures in EDR platforms
3. Block identified {threat_type} indicators at perimeter firewall, DNS sinkhole, and web proxy

CONFIDENCE ASSESSMENT:
Confidence is {confidence}% based on cluster consistency across {len(sources)} source(s).
Sandbox detonation of file samples and cross-source IOC correlation would confirm this hypothesis."""

    def generate_hypothesis(self, cluster, graph_results=None):
        """Route to the best available AI engine"""
        if self.groq_key:
            return self.generate_with_groq(cluster, graph_results)
        elif self.anthropic_key:
            return self.generate_with_anthropic(cluster, graph_results)
        else:
            return self.generate_fallback_hypothesis(cluster)

    def run(self):
        """Generate hypotheses for top unknown clusters"""
        clusters = self.load_latest_clusters()
        if not clusters:
            return []

        graph_results = self.load_graph_results()
        top_n = min(3, len(clusters))
        print(f"\n[HYPOTHESIS] Generating hypotheses for top {top_n} clusters...")

        hypotheses = []
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        for cluster in clusters[:top_n]:
            print(f"\n[HYPOTHESIS] Analysing Cluster #{cluster['cluster_id']}...")
            hypothesis_text = self.generate_hypothesis(cluster, graph_results)

            hypothesis = {
                "cluster_id": cluster["cluster_id"],
                "cosmos_confidence": cluster["cosmos_confidence"],
                "dominant_malware": cluster["dominant_malware"],
                "dominant_type": cluster["dominant_type"],
                "cluster_size": cluster["size"],
                "generated_at": datetime.now().isoformat(),
                "engine": (
                    "groq_llama3.3_70b" if self.groq_key
                    else "anthropic_claude" if self.anthropic_key
                    else "rule_based_fallback"
                ),
                "hypothesis": hypothesis_text
            }
            hypotheses.append(hypothesis)

            print("\n" + "="*55)
            print(hypothesis_text)
            print("="*55)

        output_path = f"data/processed/hypotheses_{timestamp}.json"
        with open(output_path, "w") as f:
            json.dump(hypotheses, f, indent=2)

        print(f"\n[HYPOTHESIS] {len(hypotheses)} hypotheses generated")
        print(f"[HYPOTHESIS] Engine: {'Groq Llama 3.3 70B (FREE)' if self.groq_key else 'Rule-based fallback'}")
        print(f"[HYPOTHESIS] Saved to {output_path}")
        return hypotheses

if __name__ == "__main__":
    engine = HypothesisEngine()
    engine.run()