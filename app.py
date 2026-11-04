"""
Kavach - Phishing Domain Detector (starter version)
Run with:  streamlit run app.py
"""
import re

import pandas as pd
import plotly.express as px
import streamlit as st
import tldextract
from rapidfuzz import fuzz

# Use tldextract's built-in suffix list, so it works offline
extract = tldextract.TLDExtract(suffix_list_urls=())

# Real brands that phishers like to copy -> list of their real domains
# (a brand can own several real domains, e.g. amazon.in AND amazon.com)
BRANDS = {
    "sbi": ["sbi.co.in"], "onlinesbi": ["onlinesbi.sbi"], "hdfcbank": ["hdfcbank.com"],
    "icicibank": ["icicibank.com"], "axisbank": ["axisbank.com"], "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"], "google": ["google.com"],
    "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"], "irctc": ["irctc.co.in"], "microsoft": ["microsoft.com"],
    "apple": ["apple.com"], "facebook": ["facebook.com"], "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"], "netflix": ["netflix.com"], "paypal": ["paypal.com"],
    "incometax": ["incometax.gov.in"], "uidai": ["uidai.gov.in"],
}
# Flat set of every official domain -> instant "Safe"
LEGIT_DOMAINS = {d for domains in BRANDS.values() for d in domains}

SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "click",
                   "zip", "shop", "online", "site", "live", "icu", "info"}
SUSPICIOUS_WORDS = ["login", "verify", "secure", "update", "kyc", "account",
                    "bank", "reward", "bonus", "free", "support", "confirm"]

# Look-alike characters: 0->o, 1->l, rn->m, etc.
HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"),
              ("3", "e"), ("5", "s"), ("@", "a")]


def normalize(text: str) -> str:
    for fake, real in HOMOGLYPHS:
        text = text.replace(fake, real)
    return text


def analyze(url: str) -> dict:
    url = url.strip().lower()
    parts = extract(url)
    domain = f"{parts.domain}.{parts.suffix}" if parts.suffix else parts.domain
    name = parts.domain
    full_host = ".".join(p for p in [parts.subdomain, parts.domain, parts.suffix] if p)

    score, reasons = 0, []

    if domain in LEGIT_DOMAINS:
        return {"url": url, "domain": domain, "score": 0,
                "verdict": "Safe", "reasons": "Known official domain"}

    # 1. Look-alike brand name (typosquatting)
    clean = normalize(name.replace("-", ""))
    best_brand, best_sim = None, 0
    for brand in BRANDS:
        sim = fuzz.ratio(clean, brand)
        if brand in clean and clean != brand:
            sim = max(sim, 90)  # brand hidden inside, e.g. sbi-kyc-update
        if sim > best_sim:
            best_brand, best_sim = brand, sim
    if clean in BRANDS and name != clean:
        score += 70
        reasons.append(f"Fake letters copy '{clean}' (e.g. 0 for o, rn for m)")
    elif best_sim >= 80:
        score += 45
        reasons.append(f"Looks like '{best_brand}' ({best_sim:.0f}% similar) but is not the real site")

    # 2. Brand name sitting in the subdomain, e.g. paytm.secure-login.xyz
    #    +45 so that "brand in subdomain" + a suspicious TLD (+15) always reaches 60 = Phishing
    for brand in BRANDS:
        if brand in parts.subdomain:
            score += 45
            reasons.append(f"Brand '{brand}' used in subdomain")
            break

    # 3. Cheap / abused TLD
    if parts.suffix in SUSPICIOUS_TLDS:
        score += 15
        reasons.append(f"Suspicious ending '.{parts.suffix}'")

    # 4. Scammy words
    hits = [w for w in SUSPICIOUS_WORDS if w in full_host]
    if hits:
        score += min(10 * len(hits), 20)
        reasons.append("Contains words: " + ", ".join(hits))

    # 5. Structure tricks
    if name.count("-") >= 2:
        score += 10
        reasons.append("Many hyphens")
    if re.search(r"\d", name):
        score += 5
        reasons.append("Digits in name")
    if len(full_host) > 30:
        score += 5
        reasons.append("Very long domain")
    if re.fullmatch(r"[\d.]+", full_host):
        score += 30
        reasons.append("Raw IP address instead of a name")

    score = min(score, 100)
    verdict = "Phishing" if score >= 60 else "Suspicious" if score >= 30 else "Safe"
    return {"url": url, "domain": domain, "score": score, "verdict": verdict,
            "reasons": "; ".join(reasons) or "No red flags found"}


# ---------------- UI ----------------
st.set_page_config(page_title="Kavach", page_icon="🛡️", layout="centered")
st.title("🛡️ Kavach")
st.caption("Phishing domain detector: spots look-alike sites of banks and popular brands")

tab1, tab2 = st.tabs(["Check one link", "Check a list (CSV)"])

with tab1:
    url = st.text_input("Paste a link or domain", placeholder="e.g. sbi-kyc-update.xyz")
    if url:
        r = analyze(url)
        color = {"Safe": "green", "Suspicious": "orange", "Phishing": "red"}[r["verdict"]]
        st.markdown(f"### :{color}[{r['verdict']}]  —  risk score {r['score']}/100")
        st.progress(r["score"] / 100)
        st.write("**Why:**")
        for reason in r["reasons"].split("; "):
            st.write("•", reason)

with tab2:
    st.write("Upload a CSV with a column named **domain**.")
    file = st.file_uploader("CSV file", type="csv")
    if file:
        df = pd.read_csv(file)
        results = pd.DataFrame([analyze(str(d)) for d in df["domain"]])
        st.dataframe(results, width="stretch")
        fig = px.pie(results, names="verdict", hole=0.5, color="verdict",
                     color_discrete_map={"Safe": "#2e7d32", "Suspicious": "#f9a825",
                                         "Phishing": "#c62828"})
        st.plotly_chart(fig, width="stretch")
        st.download_button("Download results", results.to_csv(index=False),
                           "kavach_results.csv", "text/csv")