# ==========================================================
# High-Confidence Scam & Phishing Detection Telegram Bot
# Author: Ebin
# ==========================================================

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
import language_tool_python
import os

# =========================
# API KEYS
# =========================

BOT_TOKEN = os.getenv("BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/urls/"

# =========================
# INIT
# =========================
tool = language_tool_python.LanguageTool("en-US")
user_language = {}

# =========================
# OFFICIAL ROOT DOMAINS
# =========================
OFFICIAL_DOMAINS = [
    "paytm.com", "amazon.in", "flipkart.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com",
    "gov.in", "nic.in"
]

HIGH_RISK_TLDS = [".xyz", ".top", ".click", ".tk", ".info"]

SCAM_KEYWORDS = [
    "urgent", "verify", "account blocked",
    "kyc", "suspended", "click immediately"
]

# =========================
# USER MESSAGES
# =========================

START_MSG = (
    "👋 *Welcome to Cyber Scam Detection Bot*\n\n"
    "🛡️ *What this bot does:*\n"
    "• Detects scam & phishing messages\n"
    "• Identifies fake or impersonated domains\n"
    "• Checks links against malware databases\n\n"
    "⚠️ *Note:* This tool provides safety guidance, not absolute decisions.\n\n"
    "🌐 Choose your preferred language:\n"
    "1️⃣ English\n"
    "2️⃣ മലയാളം"
)

CONFIDENCE_SCALE = (
    "📊 *Confidence Scale:*\n"
    "• 90–95% → Very High Risk\n"
    "• 70–89% → Suspicious\n"
    "• Below 70% → Low Risk\n\n"
    "⚠️ Always verify with official sources."
)

EN_CLASSIFICATION = {
    "DANGEROUS": "🚫 *DANGEROUS* — Do NOT click or respond.",
    "SUSPICIOUS": "⚠️ *SUSPICIOUS* — Verify manually before acting.",
    "SAFE": "✅ *LOW RISK* — No strong indicators detected."
}

ML_CLASSIFICATION = {
    "DANGEROUS": "🚫 *അപകടകരം* — ക്ലിക്ക് ചെയ്യരുത്.",
    "SUSPICIOUS": "⚠️ *സംശയാസ്പദം* — സ്ഥിരീകരിക്കുക.",
    "SAFE": "✅ *കുറഞ്ഞ അപകടസാധ്യത* — ശക്തമായ തട്ടിപ്പ് സൂചനകൾ ഇല്ല."
}

DISCLAIMER = (
    "\n\nℹ️ *Disclaimer:*\n"
    "This analysis is advisory. Attackers continuously evolve techniques.\n"
    "Always confirm directly via official apps or websites."
)

# =========================
# HELPER FUNCTIONS
# =========================

def extract_links(text):
    return re.findall(r'https?://\S+', text)


def grammar_score(text):
    matches = tool.check(text)
    return len(matches) / max(len(text.split()), 1)


def keyword_score(text):
    return sum(1 for k in SCAM_KEYWORDS if k in text.lower())


def domain_parts(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"


def similarity_score(domain):
    scores = []
    for real in OFFICIAL_DOMAINS:
        s = Levenshtein.ratio(domain, real)
        scores.append((s, real))
    return max(scores)


def tld_risk(domain):
    return 2 if any(domain.endswith(tld) for tld in HIGH_RISK_TLDS) else 0


def virustotal_check(url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(VT_URL + url_id, headers=headers, timeout=10)

        if r.status_code != 200:
            return 0, "VirusTotal scan unavailable"

        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)

        return mal * 3 + sus * 2, f"VirusTotal detections → {mal} malicious, {sus} suspicious"
    except:
        return 0, "VirusTotal check failed"


# =========================
# CORE ANALYSIS
# =========================

def analyze_links(text):
    risk = 0
    reasons = []

    for link in extract_links(text):
        domain = domain_parts(link)

        if domain in OFFICIAL_DOMAINS:
            reasons.append("Domain matches official source")
            continue

        sim, real = similarity_score(domain)
        if sim > 0.80:
            risk += 4
            reasons.append(f"Impersonation detected ({int(sim*100)}% similar to {real})")

        tld_score = tld_risk(domain)
        if tld_score:
            risk += tld_score
            reasons.append("High-risk domain extension used")

        vt_risk, vt_reason = virustotal_check(link)
        risk += vt_risk
        reasons.append(vt_reason)

    return risk, reasons


def analyze_message(text):
    risk = 0
    reasons = []

    g = grammar_score(text)
    if g > 0.1:
        risk += 1
        reasons.append("Language inconsistencies detected")

    k = keyword_score(text)
    if k:
        risk += k
        reasons.append("Scam-related keywords found")

    lr, lr_reasons = analyze_links(text)
    risk += lr
    reasons.extend(lr_reasons)

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

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_language.pop(update.effective_user.id, None)
    await update.message.reply_text(START_MSG, parse_mode="Markdown")


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text.strip()

    if user_id not in user_language:
        if text == "1":
            user_language[user_id] = "EN"
            await update.message.reply_text("Language set to English.\nSend a message to analyze.")
        elif text == "2":
            user_language[user_id] = "ML"
            await update.message.reply_text("ഭാഷ മലയാളമായി സജ്ജീകരിച്ചു.\nസന്ദേശം അയയ്ക്കുക.")
        else:
            await update.message.reply_text("Please select:\n1️⃣ English\n2️⃣ മലയാളം")
        return

    label, confidence, reasons = analyze_message(text)
    reason_text = "\n".join(f"• {r}" for r in reasons)

    if user_language[user_id] == "EN":
        reply = (
            f"🔍 *Analysis Result*\n\n"
            f"*Classification:* {EN_CLASSIFICATION[label]}\n"
            f"*Confidence:* {confidence}%\n\n"
            f"*Reasons:*\n{reason_text}\n\n"
            f"{CONFIDENCE_SCALE}"
            f"{DISCLAIMER}"
        )
    else:
        reply = (
            f"🔍 *വിശകലന ഫലം*\n\n"
            f"*വർഗ്ഗീകരണം:* {ML_CLASSIFICATION[label]}\n"
            f"*വിശ്വാസനില:* {confidence}%\n\n"
            f"*കാരണങ്ങൾ:*\n{reason_text}\n\n"
            f"{DISCLAIMER}"
        )

    await update.message.reply_text(reply, parse_mode="Markdown")


# =========================
# MAIN
# =========================

def main():
    print("🤖 Cyber Scam Bot running...")
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.run_polling()

if __name__ == "__main__":
    main()
