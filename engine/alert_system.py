import smtplib
import os
import json
import glob
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

class COSMOSAlertSystem:
    def __init__(self):
        self.email_from = os.getenv("COSMOS_EMAIL", "")
        self.email_password = os.getenv("COSMOS_EMAIL_PASSWORD", "")
        self.email_to = os.getenv("COSMOS_ALERT_TO", "")
        self.confidence_threshold = 95
        print(f"[ALERT] Alert System initialized")
        print(f"[ALERT] Sending from : {self.email_from}")
        print(f"[ALERT] Sending to   : {self.email_to}")
        print(f"[ALERT] Threshold    : {self.confidence_threshold}% confidence")

    def load_latest_clusters(self):
        """Load the most recent cluster data"""
        files = glob.glob("data/processed/unknown_clusters_*.json")
        if not files:
            return None
        latest = max(files, key=os.path.getctime)
        with open(latest) as f:
            return json.load(f)

    def load_latest_hypotheses(self):
        """Load the most recent hypotheses"""
        files = glob.glob("data/processed/hypotheses_*.json")
        if not files:
            return []
        latest = max(files, key=os.path.getctime)
        with open(latest) as f:
            return json.load(f)

    def load_dedup_stats(self):
        """Load deduplication stats"""
        seen_file = "data/processed/seen_threats.json"
        if os.path.exists(seen_file):
            with open(seen_file) as f:
                data = json.load(f)
                return len(data)
        return 0

    def get_critical_clusters(self, clusters):
        """Filter clusters above confidence threshold"""
        return [
            c for c in clusters
            if c.get("cosmos_confidence", 0) >= self.confidence_threshold
        ]

    def build_email_html(self, critical_clusters, hypotheses, total_threats, new_threats):
        """Build a professional HTML email"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cluster_rows = ""
        for c in critical_clusters[:10]:
            confidence = c.get("cosmos_confidence", 0)
            color = "#f85149" if confidence >= 99 else "#ffa657"
            cluster_rows += f"""
            <tr>
                <td style="padding:8px;border-bottom:1px solid #30363d">#{c['cluster_id']}</td>
                <td style="padding:8px;border-bottom:1px solid #30363d">{c['size']}</td>
                <td style="padding:8px;border-bottom:1px solid #30363d;color:{color};font-weight:bold">{confidence}%</td>
                <td style="padding:8px;border-bottom:1px solid #30363d">{c['dominant_type']}</td>
                <td style="padding:8px;border-bottom:1px solid #30363d">{c['dominant_malware']}</td>
                <td style="padding:8px;border-bottom:1px solid #30363d">{list(c['sources'].keys())}</td>
            </tr>"""

        hypothesis_cards = ""
        for h in hypotheses[:2]:
            hypothesis_cards += f"""
            <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:16px;">
                <div style="display:flex;gap:10px;margin-bottom:12px;">
                    <span style="background:#1f2937;border:1px solid #58a6ff;color:#58a6ff;padding:3px 10px;border-radius:12px;font-size:12px;">Cluster #{h['cluster_id']}</span>
                    <span style="background:#1f2937;border:1px solid #3fb950;color:#3fb950;padding:3px 10px;border-radius:12px;font-size:12px;">{h['cosmos_confidence']}% Confidence</span>
                    <span style="background:#1f2937;border:1px solid #a371f7;color:#a371f7;padding:3px 10px;border-radius:12px;font-size:12px;">GROQ LLAMA 3.3 70B</span>
                </div>
                <pre style="font-family:Arial,sans-serif;font-size:12px;color:#c9d1d9;white-space:pre-wrap;line-height:1.6;">{h['hypothesis'][:800]}...</pre>
            </div>"""

        html = f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="background:#0d1117;color:#c9d1d9;font-family:Arial,sans-serif;padding:20px;margin:0;">

    <div style="max-width:800px;margin:0 auto;">

        <div style="background:linear-gradient(135deg,#161b22,#1f2937);border:1px solid #30363d;border-radius:12px;padding:24px;margin-bottom:24px;">
            <h1 style="background:linear-gradient(90deg,#58a6ff,#a371f7,#3fb950);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-size:28px;letter-spacing:4px;margin:0;">COSMOS</h1>
            <p style="color:#8b949e;font-size:11px;letter-spacing:2px;margin:4px 0 0 0;">Cyber Observation System for Mapping, Observing & Synthesizing Unknown Security Threats</p>
            <div style="margin-top:16px;display:flex;gap:8px;align-items:center;">
                <div style="width:8px;height:8px;background:#3fb950;border-radius:50%;"></div>
                <span style="color:#3fb950;font-size:12px;">ALERT — {timestamp}</span>
            </div>
        </div>

        <div style="background:#f85149;border-radius:8px;padding:16px;margin-bottom:24px;text-align:center;">
            <h2 style="color:white;margin:0;font-size:18px;">CRITICAL THREAT ALERT</h2>
            <p style="color:white;margin:8px 0 0 0;font-size:14px;">{len(critical_clusters)} unknown threat clusters detected above {self.confidence_threshold}% confidence threshold</p>
        </div>

        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px;">
            <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center;">
                <div style="font-size:32px;font-weight:bold;color:#58a6ff;">{total_threats}</div>
                <div style="font-size:11px;color:#8b949e;margin-top:4px;letter-spacing:1px;">THREATS COLLECTED</div>
            </div>
            <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center;">
                <div style="font-size:32px;font-weight:bold;color:#f85149;">{len(critical_clusters)}</div>
                <div style="font-size:11px;color:#8b949e;margin-top:4px;letter-spacing:1px;">CRITICAL CLUSTERS</div>
            </div>
            <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center;">
                <div style="font-size:32px;font-weight:bold;color:#3fb950;">{new_threats}</div>
                <div style="font-size:11px;color:#8b949e;margin-top:4px;letter-spacing:1px;">NEW THREATS TODAY</div>
            </div>
        </div>

        <div style="background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;margin-bottom:24px;">
            <h3 style="color:#58a6ff;letter-spacing:2px;text-transform:uppercase;margin:0 0 16px 0;font-size:14px;border-bottom:1px solid #30363d;padding-bottom:10px;">Critical Unknown Clusters</h3>
            <table style="width:100%;border-collapse:collapse;font-size:13px;">
                <thead>
                    <tr style="background:#21262d;">
                        <th style="padding:10px;text-align:left;color:#58a6ff;font-size:11px;letter-spacing:1px;">CLUSTER</th>
                        <th style="padding:10px;text-align:left;color:#58a6ff;font-size:11px;letter-spacing:1px;">SIZE</th>
                        <th style="padding:10px;text-align:left;color:#58a6ff;font-size:11px;letter-spacing:1px;">CONFIDENCE</th>
                        <th style="padding:10px;text-align:left;color:#58a6ff;font-size:11px;letter-spacing:1px;">TYPE</th>
                        <th style="padding:10px;text-align:left;color:#58a6ff;font-size:11px;letter-spacing:1px;">MALWARE</th>
                        <th style="padding:10px;text-align:left;color:#58a6ff;font-size:11px;letter-spacing:1px;">SOURCES</th>
                    </tr>
                </thead>
                <tbody>{cluster_rows}</tbody>
            </table>
        </div>

        <div style="background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;margin-bottom:24px;">
            <h3 style="color:#58a6ff;letter-spacing:2px;text-transform:uppercase;margin:0 0 16px 0;font-size:14px;border-bottom:1px solid #30363d;padding-bottom:10px;">AI Hypothesis Engine — Threat Theories</h3>
            {hypothesis_cards}
        </div>

        <div style="text-align:center;padding:20px;color:#8b949e;font-size:11px;border-top:1px solid #30363d;">
            COSMOS — Cyber Observation System &nbsp;|&nbsp; Generated: {timestamp}<br>
            This is an automated alert from your COSMOS threat intelligence system.
        </div>

    </div>

</body>
</html>"""
        return html

    def send_alert(self, critical_clusters, hypotheses, total_threats, new_threats):
        """Send email alert"""
        if not self.email_from or not self.email_password or not self.email_to:
            print("[ALERT] Email credentials missing — skipping alert")
            return False

        try:
            print(f"[ALERT] Sending alert email to {self.email_to}...")

            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"COSMOS ALERT — {len(critical_clusters)} Critical Threat Clusters Detected — {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            msg["From"] = self.email_from
            msg["To"] = self.email_to

            html_content = self.build_email_html(
                critical_clusters, hypotheses, total_threats, new_threats
            )
            msg.attach(MIMEText(html_content, "html"))

            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(self.email_from, self.email_password)
                server.sendmail(self.email_from, self.email_to, msg.as_string())

            print(f"[ALERT] Alert email sent successfully to {self.email_to}")
            return True

        except Exception as e:
            print(f"[ALERT] Failed to send email: {e}")
            return False

    def run(self, total_threats=0, new_threats=0):
        """Run the alert system"""
        print("\n[ALERT] Checking for critical threats...")

        clusters = self.load_latest_clusters()
        if not clusters:
            print("[ALERT] No cluster data found")
            return

        hypotheses = self.load_latest_hypotheses()
        critical_clusters = self.get_critical_clusters(clusters)

        print(f"[ALERT] Total clusters    : {len(clusters)}")
        print(f"[ALERT] Critical clusters : {len(critical_clusters)}")

        if critical_clusters:
            self.send_alert(critical_clusters, hypotheses, total_threats, new_threats)
        else:
            print(f"[ALERT] No clusters above {self.confidence_threshold}% threshold — no alert sent")

        return critical_clusters

if __name__ == "__main__":
    alert = COSMOSAlertSystem()
    alert.run(total_threats=1772, new_threats=967)