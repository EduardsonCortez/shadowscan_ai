import tkinter as tk
from tkinter import ttk
from urllib.parse import urlparse
import socket
import whois
import requests
import base64
from datetime import datetime

API_KEY = "c41bff5cd6e44a2e85018df0e15295dc0fd81184874f386674b53362b9b4f693"

scam_keywords = [
    "free","win","cashback","bonus","iphone",
    "prize","gift","claim","limited","offer"
]

def scan():

    progress.start()

    window.after(2000, analyze)


def check_virustotal(url):

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {
        "x-apikey": API_KEY
    }

    try:
        response = requests.get(vt_url, headers=headers)
        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats["malicious"]

        return malicious

    except:
        return "Unknown"


def analyze():

    progress.stop()

    url = entry.get()
    parsed = urlparse(url)
    domain = parsed.netloc

    warnings = []

    # keyword detection
    for word in scam_keywords:
        if word in url.lower():
            warnings.append(f"Keyword detected: {word}")

    # https check
    if not url.startswith("https://"):
        warnings.append("Website not using HTTPS")

    # ip lookup
    try:
        ip = socket.gethostbyname(domain)
    except:
        ip = "Unknown"

    # domain age
    try:
        w = whois.whois(domain)

        creation = w.creation_date

        if isinstance(creation,list):
            creation = creation[0]

        age = (datetime.now() - creation).days

        if age < 180:
            warnings.append("New domain (possible phishing)")

        age_info = f"{age} days"

    except:
        age_info = "Unknown"

    # VirusTotal check
    vt_result = check_virustotal(url)

    if vt_result != "Unknown" and vt_result > 0:
        warnings.append(f"VirusTotal flagged by {vt_result} engines")

    # risk score
    if len(warnings) >= 3:
        result = "HIGH RISK"
        color = "#ff4c4c"

    elif len(warnings) >= 1:
        result = "SUSPICIOUS"
        color = "#ffcc00"

    else:
        result = "SAFE"
        color = "#00ff88"

    result_label.config(text=f"RESULT: {result}", fg=color)

    report.delete("1.0", tk.END)

    report.insert(tk.END,f"Domain: {domain}\n")
    report.insert(tk.END,f"IP Address: {ip}\n")
    report.insert(tk.END,f"Domain Age: {age_info}\n")
    report.insert(tk.END,f"VirusTotal Flags: {vt_result}\n\n")

    if warnings:
        report.insert(tk.END,"Warnings:\n")
        for w in warnings:
            report.insert(tk.END,f"- {w}\n")
    else:
        report.insert(tk.END,"No suspicious indicators detected.")


window = tk.Tk()
window.title("ShadowScan AI")
window.geometry("720x540")
window.configure(bg="#0d1117")

title = tk.Label(
    window,
    text="SHADOWSCAN AI",
    font=("Consolas",24,"bold"),
    fg="#00ffcc",
    bg="#0d1117"
)
title.pack(pady=10)

subtitle = tk.Label(
    window,
    text="AI Powered Phishing Detection Tool",
    font=("Consolas",10),
    fg="#aaaaaa",
    bg="#0d1117"
)
subtitle.pack()

entry = tk.Entry(
    window,
    width=75,
    font=("Consolas",11),
    bg="#161b22",
    fg="#00ffcc",
    insertbackground="white"
)
entry.pack(pady=20)

scan_btn = tk.Button(
    window,
    text="SCAN LINK",
    font=("Consolas",12,"bold"),
    bg="#238636",
    fg="white",
    command=scan
)
scan_btn.pack()

progress = ttk.Progressbar(
    window,
    orient="horizontal",
    length=500,
    mode="indeterminate"
)
progress.pack(pady=15)

result_label = tk.Label(
    window,
    text="RESULT:",
    font=("Consolas",18,"bold"),
    fg="white",
    bg="#0d1117"
)
result_label.pack(pady=10)

report = tk.Text(
    window,
    height=16,
    width=85,
    bg="#161b22",
    fg="#00ffcc",
    font=("Consolas",10)
)
report.pack(pady=10)

window.mainloop()
