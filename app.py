"""
Kavach - Phishing Domain Detector
Rule-based score + machine-learning probability, averaged into one verdict.

Run with:  streamlit run app.py
Train the ML model first (once) with:  python train.py
"""
import json
import re
from pathlib import Path

import joblib
import pandas as pd
import plotly.express as px
import streamlit as st

# Brand list, scam words, look-alike logic and ML features are shared with train.py
from features import (BRANDS, LEGIT_DOMAINS, SUSPICIOUS_TLDS, SUSPICIOUS_WORDS,
                      brand_match, extract_features, parse)

HERE = Path(__file__).parent


def verdict_for(score: float) -> str:
    return "Phishing" if score >= 60 else "Suspicious" if score >= 30 else "Safe"


def analyze(url: str) -> dict:
    """Rule-based risk score (0-100) with the reasons behind it."""
    url = url.strip().lower()
    parts, full_host = parse(url)
    domain = f"{parts.domain}.{parts.suffix}" if parts.suffix else parts.domain
    name = parts.domain

    score, reasons = 0, []

    if domain in LEGIT_DOMAINS:
        return {"url": url, "domain": domain, "score": 0,
                "verdict": "Safe", "reasons": "Known official domain"}

    # 1. Look-alike brand name (typosquatting)
    clean, best_brand, best_sim, is_homoglyph = brand_match(name)
    if is_homoglyph:
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
    return {"url": url, "domain": domain, "score": score, "verdict": verdict_for(score),
            "reasons": "; ".join(reasons) or "No red flags found"}


def load_model():
    """Load model.joblib (made by train.py). Returns None if it does not exist yet."""
    path = HERE / "model.joblib"
    return joblib.load(path) if path.exists() else None


ML_TRUST = 0.70  # the ML model only gets a say when it is at least this sure


def full_analysis(url: str, bundle) -> dict:
    """Rule score + ML probability -> final score.

    If ML probability >= 70%:  final = max(rule score, average of rule score and ML x 100)
    Otherwise:                 final = rule score
    "decided_by" says whether the ML model actually raised the score.
    """
    r = analyze(url)
    r["rule_score"] = r["score"]
    r["ml_probability"] = None  # percent, 0-100
    r["decided_by"] = "Rules"

    # Official domains stay Safe; no ML needed. Without a model we keep the rule score only.
    if bundle is None or r["domain"] in LEGIT_DOMAINS:
        return r

    model = bundle["model"]
    row = pd.DataFrame([extract_features(url)], columns=bundle["features"])
    p = model.predict_proba(row)[0][list(model.classes_).index(1)]
    r["ml_probability"] = round(p * 100, 1)
    if p >= ML_TRUST:
        blended = round((r["rule_score"] + r["ml_probability"]) / 2)
        if blended > r["rule_score"]:
            r["score"] = blended
            r["decided_by"] = "Rules + ML"
        r["verdict"] = verdict_for(r["score"])
    if p >= 0.5:
        note = f"ML model: {r['ml_probability']:.0f}% chance of phishing"
        r["reasons"] = note if r["reasons"] == "No red flags found" else r["reasons"] + "; " + note
    return r


# ---------------- UI ----------------
st.set_page_config(page_title="Kavach", page_icon="🛡️", layout="centered")
st.title("🛡️ Kavach")
st.caption("Phishing domain detector: spots look-alike sites of banks and popular brands")


@st.cache_resource
def get_model():
    return load_model()


bundle = get_model()
if bundle is None:
    st.warning("ML model not found, so only the rule-based score is shown. "
               "Run `python train.py` once to create model.joblib.")

tab1, tab2 = st.tabs(["Check one link", "Check a list (CSV)"])

with tab1:
    url = st.text_input("Paste a link or domain", placeholder="e.g. sbi-kyc-update.xyz")
    if url:
        r = full_analysis(url, bundle)
        color = {"Safe": "green", "Suspicious": "orange", "Phishing": "red"}[r["verdict"]]
        st.markdown(f"### :{color}[{r['verdict']}]  —  risk score {r['score']}/100")
        st.progress(r["score"] / 100)
        c1, c2, c3 = st.columns(3)
        c1.metric("Rule-based score", f"{r['rule_score']}/100")
        c2.metric("ML probability of phishing",
                  "n/a" if r["ml_probability"] is None else f"{r['ml_probability']:.0f}%")
        c3.metric("Verdict decided by", r["decided_by"])
        st.write("**Why:**")
        for reason in r["reasons"].split("; "):
            st.write("•", reason)

with tab2:
    st.write("Upload a CSV with a column named **domain**.")
    file = st.file_uploader("CSV file", type="csv")
    if file:
        df = pd.read_csv(file)
        results = pd.DataFrame([full_analysis(str(d), bundle) for d in df["domain"]])
        cols = ["url", "domain", "verdict", "score", "rule_score", "ml_probability",
                "decided_by", "reasons"]
        results = results[cols]
        st.dataframe(results, width="stretch")
        fig = px.pie(results, names="verdict", hole=0.5, color="verdict",
                     color_discrete_map={"Safe": "#2e7d32", "Suspicious": "#f9a825",
                                         "Phishing": "#c62828"})
        st.plotly_chart(fig, width="stretch")
        st.download_button("Download results", results.to_csv(index=False),
                           "kavach_results.csv", "text/csv")

# ---------------- Model performance ----------------
with st.expander("Model performance"):
    metrics_file = HERE / "metrics.json"
    importance_file = HERE / "feature_importance.csv"
    if metrics_file.exists() and importance_file.exists():
        m = json.loads(metrics_file.read_text(encoding="utf-8"))
        a, b, c, d = st.columns(4)
        a.metric("Test accuracy", f"{m['accuracy']:.1%}")
        b.metric("Precision", f"{m['precision']:.1%}")
        c.metric("Recall", f"{m['recall']:.1%}")
        d.metric("F1", f"{m['f1']:.1%}")
        st.caption(f"RandomForest trained on {m['n_train']:,} domains and tested on "
                   f"{m['n_test']:,} unseen ones (Tranco top sites vs Phishing.Database).")
        imp = pd.read_csv(importance_file).sort_values("importance")
        fig = px.bar(imp, x="importance", y="feature", orientation="h",
                     title="Top 10 features the model relies on")
        fig.update_layout(yaxis_title=None, xaxis_title="Importance")
        st.plotly_chart(fig, width="stretch")
    else:
        st.info("No model stats yet. Run `python train.py` to create them.")
