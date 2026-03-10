import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.logger_config import ids_logger

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "moalfatih22@gmail.com"
SMTP_PASSWORD = "Muew8621as@@"
ALERT_EMAIL = "mohammedalfateh.ahme@final.edu.tr"

def send_email_alert(attack_type, confidence, source_ip, destination_ip, severity):
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = ALERT_EMAIL
        msg['Subject'] = f"🚨 IDS ALERT: {attack_type} Attack Detected"
        
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2 style="color: #dc2626;">Security Alert Detected</h2>
            <table style="border-collapse: collapse; width: 100%;">
                <tr style="background-color: #f3f4f6;">
                    <td style="padding: 10px; border: 1px solid #ddd;"><strong>Attack Type:</strong></td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{attack_type}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #ddd;"><strong>Confidence:</strong></td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{confidence*100:.2f}%</td>
                </tr>
                <tr style="background-color: #f3f4f6;">
                    <td style="padding: 10px; border: 1px solid #ddd;"><strong>Severity:</strong></td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{severity}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #ddd;"><strong>Source IP:</strong></td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{source_ip}</td>
                </tr>
                <tr style="background-color: #f3f4f6;">
                    <td style="padding: 10px; border: 1px solid #ddd;"><strong>Destination IP:</strong></td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{destination_ip}</td>
                </tr>
            </table>
            <p style="margin-top: 20px; color: #6b7280;">
                This is an automated alert from your AI-Powered IDS System.
            </p>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        ids_logger.info(f"Email alert sent for {attack_type} attack")
        return True
    except Exception as e:
        ids_logger.error(f"Failed to send email: {e}")
        return False