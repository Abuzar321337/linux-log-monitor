import os
import time
import re
import smtplib
from email.mime.text import MIMEText

# Log file path
LOG_FILE = "/var/log/auth.log"  # Change if needed (e.g., /var/log/syslog)

# Email Alert Configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "yoursenderemail"
SENDER_PASSWORD = "yourgoogleapppassword"
RECEIVER_EMAIL = "yourreciveremail"

# Suspicious activity patterns
PATTERNS = {
    "Failed SSH Login": r"Failed password for",
    "Root Access": r"session opened for user root",
    "Brute Force Attack": r"Maximum authentication attempts exceeded",
}

# Function to send email alerts
def send_email_alert(subject, message):
    try:
        msg = MIMEText(message)
        msg["Subject"] = subject
        msg["From"] = SENDER_EMAIL
        msg["To"] = RECEIVER_EMAIL

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        print("[+] Alert email sent successfully!")
    except Exception as e:
        print(f"[-] Failed to send email: {e}")

# Function to monitor log file
def monitor_log():
    print("[*] Monitoring log file for suspicious activity...")

    with open(LOG_FILE, "r") as file:
        file.seek(0, os.SEEK_END)  # Start at the end of the file
        while True:
            line = file.readline()
            if not line:
                time.sleep(1)  # Wait for new log entries
                continue

            for alert, pattern in PATTERNS.items():
                if re.search(pattern, line):
                    print(f"[ALERT] {alert} detected: {line.strip()}")
                    send_email_alert(f"Security Alert: {alert}", line.strip())

if __name__ == "__main__":
    monitor_log()
