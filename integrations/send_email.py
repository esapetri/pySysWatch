import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import aiosmtplib

async def send_email(config, subject, message):
    try:
        msg = MIMEMultipart()
        msg['From'] = 'monitor@yourdomain.com'
        msg['To'] = config.get('EmailConfig', 'AdminEmail')
        msg['Subject'] = subject

        msg.attach(MIMEText(message, 'plain'))
        
        smtp_server = config.get('EmailConfig', 'SMTPServer')
        smtp_port = config.getint('EmailConfig', 'SMTPPort')
        smtp_username = config.get('EmailConfig', 'SMTPUsername')
        smtp_password = config.get('EmailConfig', 'SMTPPassword')

        async with aiosmtplib.SMTP(smtp_server, smtp_port) as server:
            await server.login(smtp_username, smtp_password)
            await server.send_message(msg)
        
        logging.info(f"Alert email sent: {subject}")
    except Exception as e:
        logging.error(f"Failed to send alert email: {str(e)}")
