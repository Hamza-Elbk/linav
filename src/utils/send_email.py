#!/usr/bin/env python3
import sys
import smtplib
from email.message import EmailMessage

def main():
    if len(sys.argv) < 5:
        print("Usage: send_email.py <smtp_server> <smtp_port> <user> <password> <to> <subject> <body_file>")
        sys.exit(1)
    smtp_server, smtp_port, user, password, to, subject, body_file = sys.argv[1:8]
    with open(body_file, 'r') as f:
        body = f.read()
    msg = EmailMessage()
    msg['From'] = user
    msg['To'] = to
    msg['Subject'] = subject
    msg.set_content(body)
    with smtplib.SMTP_SSL(smtp_server, int(smtp_port)) as server:
        server.login(user, password)
        server.send_message(msg)

if __name__ == '__main__':
    main()