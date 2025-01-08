import pandas as pd
import re
import smtplib
from email.mime.text import MIMEText

# Define the path to the log file
log_file_path = '/var/log/ufw.log'

# Function to parse log file
def parse_logs(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

# Function to extract log details
def extract_log_details(log_line):
    regex = r'(\w{3}\s+\d+\s+\d+:\d+:\d+).*SRC=(\S+).*DST=(\S+).*SPT=(\d+).*DPT=(\d+)'
    match = re.search(regex, log_line)
    if match:
        return {
            'timestamp': match.group(1),
            'source_ip': match.group(2),
            'destination_ip': match.group(3),
            'source_port': match.group(4),
            'destination_port': match.group(5)
        }
    return None

# Read and parse the logs
logs = parse_logs(log_file_path)
log_details = [extract_log_details(log) for log in logs if extract_log_details(log)]

# Create a DataFrame
df = pd.DataFrame(log_details)

# Detect repeated failed login attempts from the same IP
failed_login_attempts = df[df['destination_port'] == '22'].groupby('source_ip').size()
suspicious_ips = failed_login_attempts[failed_login_attempts > 5].index.tolist()

# Function to send alert
def send_alert(subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = 'msonithokozile@gmail.com'
    msg['To'] = ''

    with smtplib.SMTP('smtp.example.com') as server:
        server.login('your_email@example.com', 'your_password')
        server.sendmail('your_email@example.com', 'recipient_email@example.com', msg.as_string())

# Send alert for suspicious IPs
if suspicious_ips:
    send_alert("Suspicious Activity Detected", f"Suspicious IPs: {suspicious_ips}")

# Print detected suspicious IPs
print("Suspicious IPs with repeated failed login attempts:", suspicious_ips)
