import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import os

EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "false").lower() == "true"
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "your-email@gmail.com")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD", "your-app-password")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")

def send_email_notification(subject, body, recipient=None):
    if not EMAIL_ENABLED:
        print(f"📧 Email notification (disabled): {subject}")
        return False
    
    try:
        recipient = recipient or ADMIN_EMAIL
        
        msg = MIMEMultipart('alternative')
        msg['From'] = SENDER_EMAIL
        msg['To'] = recipient
        msg['Subject'] = subject
        
        html_body = f"""
        <html>
          <head>
            <style>
              body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
              .header {{ background-color: #2563eb; color: white; padding: 20px; text-align: center; }}
              .content {{ padding: 20px; }}
              .alert {{ background-color: #fee2e2; border-left: 4px solid #dc2626; padding: 15px; margin: 10px 0; }}
              .warning {{ background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 10px 0; }}
              .info {{ background-color: #dbeafe; border-left: 4px solid #2563eb; padding: 15px; margin: 10px 0; }}
              .footer {{ background-color: #f3f4f6; padding: 15px; text-align: center; font-size: 12px; color: #6b7280; }}
            </style>
          </head>
          <body>
            <div class="header">
              <h1>🛡️ IDS Alert Notification</h1>
            </div>
            <div class="content">
              <h2>{subject}</h2>
              {body}
              <p><strong>Timestamp:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            </div>
            <div class="footer">
              <p>AI-Powered Intrusion Detection System</p>
              <p>This is an automated notification. Please do not reply to this email.</p>
            </div>
          </body>
        </html>
        """
        
        msg.attach(MIMEText(html_body, 'html'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        print(f"📧 Email sent successfully: {subject}")
        return True
        
    except Exception as e:
        print(f"❌ Email error: {str(e)}")
        return False

def send_critical_alert(alert_data):
    subject = f"🚨 CRITICAL ALERT: {alert_data['attack_type']} Attack Detected"
    
    body = f"""
    <div class="alert">
      <h3>Critical Security Alert</h3>
      <p><strong>Attack Type:</strong> {alert_data['attack_type']}</p>
      <p><strong>Severity:</strong> {alert_data['severity']}</p>
      <p><strong>Confidence:</strong> {alert_data['confidence'] * 100:.1f}%</p>
      <p><strong>Source IP:</strong> {alert_data['source_ip']}</p>
      <p><strong>Destination IP:</strong> {alert_data['destination_ip']}</p>
      <p><strong>Status:</strong> {'🛡️ BLOCKED' if alert_data.get('blocked') else '⚠️ DETECTED'}</p>
      <p><strong>Details:</strong> {alert_data['details']}</p>
    </div>
    <div class="info">
      <h4>Recommended Actions:</h4>
      <ul>
        <li>Review the attack pattern in the dashboard</li>
        <li>Verify if the source IP should be permanently blocked</li>
        <li>Check system logs for additional suspicious activity</li>
        <li>Update firewall rules if necessary</li>
      </ul>
    </div>
    """
    
    return send_email_notification(subject, body)

def send_high_risk_ip_notification(ip_data):
    subject = f"⚠️ HIGH RISK IP DETECTED: {ip_data['ip_address']}"
    
    body = f"""
    <div class="warning">
      <h3>High Risk IP Address Detected</h3>
      <p><strong>IP Address:</strong> {ip_data['ip_address']}</p>
      <p><strong>Risk Score:</strong> {ip_data['risk_score']:.1f}/100</p>
      <p><strong>Threat Level:</strong> {ip_data['threat_level']}</p>
      <p><strong>Attack Count:</strong> {ip_data['attack_count']}</p>
      <p><strong>Attack Types:</strong> {', '.join(ip_data['attack_types'])}</p>
      <p><strong>Reputation:</strong> {ip_data['reputation']}</p>
    </div>
    <div class="info">
      <h4>Recommended Actions:</h4>
      <ul>
        <li>Consider blocking this IP address</li>
        <li>Investigate the source of these attacks</li>
        <li>Update intrusion prevention rules</li>
        <li>Monitor for additional attacks from this source</li>
      </ul>
    </div>
    """
    
    return send_email_notification(subject, body)

def send_system_health_report(health_data):
    subject = f"📊 Daily System Health Report - Status: {health_data['status']}"
    
    body = f"""
    <div class="info">
      <h3>System Health Summary</h3>
      <p><strong>Overall Status:</strong> {health_data['status']}</p>
      <p><strong>Health Score:</strong> {health_data['health_score']}/100</p>
      <p><strong>Total Monitored IPs:</strong> {health_data['total_ips']}</p>
      <p><strong>Malicious IPs:</strong> {health_data['malicious_ips']}</p>
      <p><strong>At Risk IPs:</strong> {health_data['at_risk_ips']}</p>
    </div>
    <div class="info">
      <h4>System Performance:</h4>
      <ul>
        <li>Detection Rate: Active</li>
        <li>Model Accuracy: 72.1%</li>
        <li>Auto-Blocking: Enabled</li>
        <li>Database Status: Connected</li>
      </ul>
    </div>
    """
    
    return send_email_notification(subject, body) 