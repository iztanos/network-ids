import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from typing import Optional
import requests

def send_slack_alert(webhook_url, message):
    payload = {'text': message}
    response = requests.post(webhook_url, json=payload)
    if response.status_code != 200:
        raise ValueError(
            f'Request to slack returned an error {response.status_code}, the response is:\n{response.text}'
        )



def send_email_alert(subject, body, to_email):
    # Replace 'your-email@gmail.com' and 'your-email-password' with your actual email and password
    from_email = "test-email@example.com"
    from_password = "test-email-password"

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, from_password)
    text = msg.as_string()
    server.sendmail(from_email, to_email, text)
    server.quit()
