"""
SMTP Email Integration for SOAR System
Handles email notifications for security alerts and incidents
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional, Dict, Any
import logging
import os

logger = logging.getLogger(__name__)

class SMTPEmailIntegration:
    """SMTP Email integration for SOAR notifications"""

    def __init__(self):
        # Configuration from environment variables or defaults
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.username = os.getenv('SMTP_USERNAME', 'malditoaziado@gmail.com')
        self.app_password = os.getenv('SMTP_APP_PASSWORD', 'dmyn gdqi hpkz bzct')
        self.use_tls = os.getenv('SMTP_USE_TLS', 'true').lower() == 'true'
        self.from_email = os.getenv('SMTP_FROM_EMAIL', self.username)

        # Default recipients
        self.default_recipients = os.getenv('SMTP_DEFAULT_RECIPIENTS', 'malditoaziado@gmail.com').split(',')

    def _create_server_connection(self):
        """Create secure SMTP server connection"""
        context = ssl.create_default_context() if self.use_tls else None
        server = smtplib.SMTP(self.smtp_server, self.smtp_port)

        if self.use_tls:
            server.starttls(context=context)

        server.login(self.username, self.app_password)
        return server

    def send_email(self, to_emails: List[str], subject: str, body: str,
                   cc_emails: Optional[List[str]] = None,
                   attachments: Optional[List[str]] = None) -> bool:
        """Send email with optional attachments"""
        message = MIMEMultipart()
        message['From'] = self.from_email
        message['To'] = ', '.join(to_emails)
        message['Subject'] = subject

        if cc_emails:
            message['Cc'] = ', '.join(cc_emails)
            to_emails.extend(cc_emails)

        message.attach(MIMEText(body, 'html'))

        # Add attachments if provided
        if attachments:
            from email.mime.base import MIMEBase
            from email import encoders
            for attachment_path in attachments:
                if os.path.exists(attachment_path):
                    with open(attachment_path, 'rb') as file:
                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(file.read())
                        encoders.encode_base64(part)
                        part.add_header('Content-Disposition',
                                      f'attachment; filename={os.path.basename(attachment_path)}')
                        message.attach(part)

        try:
            server = self._create_server_connection()
            server.sendmail(self.from_email, to_emails, message.as_string())
            server.quit()
            logger.info(f"Email sent successfully to {to_emails}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False

    def send_soar_alert(self, alert_data: Dict[str, Any], recipients: Optional[List[str]] = None) -> bool:
        """Send formatted SOAR security alert"""
        if not recipients:
            recipients = self.default_recipients

        subject = f"🚨 SOAR Security Alert: {alert_data.get('title', 'Security Incident')}"

        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f8f9fa;">
            <div style="background-color: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h2 style="color: #dc3545; text-align: center;">🚨 Security Alert Detected</h2>

                <table style="width: 100%; border-collapse: collapse; margin-top: 20px;">
                    <tr style="background-color: #e9ecef;">
                        <td style="padding: 12px; border: 1px solid #dee2e6; font-weight: bold;">Title:</td>
                        <td style="padding: 12px; border: 1px solid #dee2e6;">{alert_data.get('title', 'N/A')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 12px; border: 1px solid #dee2e6; font-weight: bold;">Description:</td>
                        <td style="padding: 12px; border: 1px solid #dee2e6;">{alert_data.get('description', 'N/A')}</td>
                    </tr>
                    <tr style="background-color: #e9ecef;">
                        <td style="padding: 12px; border: 1px solid #dee2e6; font-weight: bold;">Severity:</td>
                        <td style="padding: 12px; border: 1px solid #dee2e6;">{alert_data.get('severity', 'N/A')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 12px; border: 1px solid #dee2e6; font-weight: bold;">Source:</td>
                        <td style="padding: 12px; border: 1px solid #dee2e6;">{alert_data.get('source', 'SOAR System')}</td>
                    </tr>
                    <tr style="background-color: #e9ecef;">
                        <td style="padding: 12px; border: 1px solid #dee2e6; font-weight: bold;">Timestamp:</td>
                        <td style="padding: 12px; border: 1px solid #dee2e6;">{alert_data.get('timestamp', 'N/A')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 12px; border: 1px solid #dee2e6; font-weight: bold;">Actions Taken:</td>
                        <td style="padding: 12px; border: 1px solid #dee2e6;">{', '.join(alert_data.get('actions', ['Alert generated']))}</td>
                    </tr>
                </table>

                <div style="text-align: center; margin-top: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 5px;">
                    <p style="margin: 0; color: #6c757d; font-size: 14px;">
                        <em>This alert was automatically generated by the SOAR security system.</em>
                    </p>
                </div>
            </div>
        </body>
        </html>
        """

        return self.send_email(
            to_emails=recipients,
            subject=subject,
            body=body
        )

    def send_test_email(self) -> bool:
        """Send test email to verify configuration"""
        return self.send_email(
            to_emails=self.default_recipients,
            subject="SOAR SMTP Test - Configuration Verification",
            body="<h1>✅ SOAR SMTP Integration Test</h1><p>This is a test email to verify SMTP configuration is working correctly.</p>"
        )

# Global instance for use throughout the system
smtp_integration = SMTPEmailIntegration()

def send_notification_email(recipients: List[str], subject: str, body: str) -> bool:
    """Convenience function for sending notification emails"""
    return smtp_integration.send_email(recipients, subject, body)

def send_alert_email(alert_data: Dict[str, Any], recipients: Optional[List[str]] = None) -> bool:
    """Convenience function for sending SOAR alerts"""
    return smtp_integration.send_soar_alert(alert_data, recipients)
