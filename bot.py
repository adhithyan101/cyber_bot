# ==========================================================
# Cyber Scam & Phishing Detection Bot
# Image-based Risk Visualization | Cloud-ready
# Author: Ebin
# ==========================================================

# ---------- Render Free-tier HTTP workaround ----------
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import os

PORT = int(os.getenv("PORT", 10000))

class DummyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Bot is running")

def keep_alive():
    server = HTTPServer(("0.0.0.0", PORT), DummyHandler)
    server.serve_forever()

threading.Thread(target=keep_alive, daemon=True).start()

# ---------- Telegram & Security Imports ----------
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    MessageHandler,
    CommandHandler,
    ContextTypes,
    filters
)

import re
import base64
import requests
import tldextract
import Levenshtein

# =========================
# ENVIRONMENT VARIABLES
# =========================
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
BOT_TOKEN = os.getenv("BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

VT_URL = "https://www.virustotal.com/api/v3/urls/"
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# =========================
# USER DATA
# =========================
user_language = {}
vt_cache = {}
sb_cache = {}
abuse_cache = {}

# =========================
# OFFICIAL DOMAINS & RULES
# =========================
OFFICIAL_DOMAINS = [
    "paytm.com", "amazon.in", "flipkart.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com",
    "gov.in", "nic.in"
]

HIGH_RISK_TLDS = [".xyz", ".top", ".click", ".tk", ".info"]

SCAM_KEYWORDS = [
    "urgent", "verify", "account blocked", "kyc",
    "suspended", "click immediately", "free", "winner"
]

# =========================
# IMAGE MAPPING
# =========================
RISK_IMAGES = [
    (10,  "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_0_10.png.png"),
    (20,  "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_11_20.png.png"),
    (30,  "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_21_30.png.png"),
    (40,  "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_31_40.png.png"),
    (50,  "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_41_50.png.png"),
    (60,  "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_51_60.png.png"),
    (70,  "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_61_70.png.png"),
    (80,  "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_71_80.png.png"),
    (90,  "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_81_90.png.png"),
    (100, "https://raw.githubusercontent.com/3bin-05/cyber_bot/main/images/risk_91_100.png.png"),
]

def get_risk_image(confidence):
    for limit, url in RISK_IMAGES:
        if confidence <= limit:
            return url
    return RISK_IMAGES[-1][1]

# =========================
# HELPER FUNCTIONS
# =========================
# (UNCHANGED — exactly your versions)
# safe_browsing_check
# abuseipdb_check
# virustotal_check
# risk_banner
# extract_links
# keyword_score
# root_domain
# similarity_score
# tld_risk

# =========================
# CORE ANALYSIS (FIXED)
# =========================
def analyze_message(text):
    risk = 0
    reasons = []

    k = keyword_score(text)
    if k:
        risk += k
        reasons.append("Scam-related keywords detected")

    for link in extract_links(text):
        domain = root_domain(link)

        # 🥇 Google Safe Browsing (ALWAYS SHOWN)
        sb_hit, sb_reason = safe_browsing_check(link)
        reasons.append(sb_reason)
        if sb_hit:
            return "DANGEROUS", 95, reasons

        sim, real = similarity_score(domain)
        if sim > 0.80:
            risk += 4
            reasons.append(f"Impersonation of {real}")

        tr = tld_risk(domain)
        if tr:
            risk += tr
            reasons.append("High-risk domain extension")

        # 🥈 AbuseIPDB (ALWAYS SHOWN)
        abuse_risk, abuse_reason = abuseipdb_check(domain)
        reasons.append(abuse_reason)
        risk += abuse_risk

        # 🥉 VirusTotal (ALWAYS SHOWN)
        vt_risk, vt_reason = virustotal_check(link)
        reasons.append(vt_reason)
        risk += vt_risk

    confidence = min(10 + risk * 12, 95)

    if confidence >= 90:
        label = "DANGEROUS"
    elif confidence >= 70:
        label = "SUSPICIOUS"
    else:
        label = "SAFE"

    return label, confidence, reasons

# =========================
# TELEGRAM HANDLERS
# =========================
# (UNCHANGED — exactly your version)

# =========================
# MAIN
# =========================
def main():
    print("🤖 Cyber Scam Bot running...")
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("lang", change_language))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.run_polling()

if __name__ == "__main__":
    main()
# ==========================================================
