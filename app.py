"""
Kavach - Phishing Domain Detector
Rule-based score + machine-learning probability, averaged into one verdict.

Run with:  streamlit run app.py
Train the ML model first (once) with:  python train.py
"""
import html
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


def lookalike_target(url: str):
    """If the link imitates a known brand, return that brand's real domain, else None.
    Display helper only: it does not change any score."""
    parts, _ = parse(url)
    domain = f"{parts.domain}.{parts.suffix}" if parts.suffix else parts.domain
    if domain in LEGIT_DOMAINS:
        return None
    clean, best_brand, best_sim, is_homoglyph = brand_match(parts.domain)
    if is_homoglyph:
        brand = clean
    elif best_sim >= 80:
        brand = best_brand
    else:
        brand = next((b for b in BRANDS if b in parts.subdomain), None)
    return BRANDS[brand][0] if brand else None


def explain(r: dict, target) -> str:
    """One plain-English sentence about how the rules and the ML model contributed."""
    rule, ml, by = r["rule_score"], r["ml_probability"], r["decided_by"]
    if r["domain"] in LEGIT_DOMAINS:
        return "This is a known official domain, so it is Safe and no further checks were needed."
    if target:
        trick = "Rules found a look-alike trick"
    elif rule >= 30:
        trick = "Rules found warning signs"
    else:
        trick = "Rules found little or nothing suspicious"
    if ml is None:
        return f"{trick}. The ML model is not available, so only the rules were used."
    if by == "Rules + ML":
        return f"{trick}, and the ML model was {ml:.0f}% sure it is phishing, so it raised the final score."
    if ml >= ML_TRUST * 100:
        return (f"{trick}. The ML model agrees ({ml:.0f}% sure), "
                "but the rules already scored higher, so the rules decided.")
    return f"{trick}; the ML model was only {ml:.0f}% sure, so it didn't add extra risk."


# ---------------- UI ----------------
COLORS = {"Phishing": "#EF4444", "Suspicious": "#F59E0B", "Safe": "#22C55E"}
ICONS = {"Phishing": "🚨", "Suspicious": "⚠️", "Safe": "✅"}
EXAMPLES = ["paytrn.com", "sbi-kyc-update-now.top", "amazon.security-check.icu",
            "flipkart-sale.in", "google.com"]
# Human-readable names for the model's features (used in the importance chart)
FEATURE_LABELS = {
    "length": "Domain length", "hyphens": "Number of hyphens", "digits": "Number of digits",
    "dots": "Number of dots", "subdomain_count": "Number of subdomains",
    "vowel_ratio": "Share of vowels", "entropy": "Randomness of characters",
    "suspicious_tld": "Risky ending (.xyz, .top...)", "scam_words": "Scam words (login, kyc...)",
    "brand_similarity": "Similarity to a known brand", "brand_in_subdomain": "Brand name in subdomain",
    "homoglyph_match": "Fake-letter trick (0 for o...)",
}
NO_TOOLBAR = {"displayModeBar": False}  # hide the Plotly toolbar on every chart

st.set_page_config(page_title="Kavach", page_icon="🛡️", layout="centered")

st.markdown("""<style>
.block-container {max-width: 880px; padding-top: 2.2rem;}
.k-card {border: 1px solid; border-radius: 16px; padding: 22px 26px; margin: 14px 0 16px 0;}
.k-verdict {font-size: 2.3rem; font-weight: 800; line-height: 1.1;}
.k-score {font-size: 1.05rem; margin-top: 6px; opacity: .92;}
.k-bar {height: 12px; background: rgba(255,255,255,.10); border-radius: 999px; margin-top: 14px; overflow: hidden;}
.k-bar > div {height: 100%; border-radius: 999px;}
.k-chip {display: inline-block; padding: 6px 13px; margin: 0 8px 8px 0; border-radius: 999px;
         background: #111827; border: 1px solid #243041; font-size: .85rem;}
.k-hint {border: 1px solid #22C55E; background: #22C55E14; border-radius: 12px; padding: 11px 16px; margin: 4px 0 12px 0;}
.k-explain {border-left: 3px solid #22C55E; padding: 4px 0 4px 14px; margin: 10px 0 18px 0; opacity: .92;}
.k-step {background: #111827; border: 1px solid #243041; border-radius: 14px; padding: 16px 18px; height: 100%;}
.k-step h4 {margin: 0 0 6px 0;}
.k-count {border: 1px solid; border-radius: 12px; padding: 10px 14px; text-align: center; font-size: 1.05rem;}
.k-footer {text-align: center; opacity: .55; font-size: .85rem; margin-top: 44px;}
</style>""", unsafe_allow_html=True)


def style_chart(fig):
    """Match Plotly charts to the dark theme."""
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      font_color="#E5E7EB", margin=dict(l=10, r=10, t=40, b=10))
    return fig


@st.cache_resource
def get_model():
    return load_model()


def use_example(domain: str):
    """Button callback: put the example in the input box (the check runs on the rerun)."""
    st.session_state["link_input"] = domain


# ----- Header -----
st.title("🛡️ Kavach", anchor=False)
st.subheader("Spot fake bank & shopping sites before you click", anchor=False)
st.caption("Works offline · Rules + Machine Learning")

bundle = get_model()
if bundle is None:
    st.warning("ML model not found, so only the rule-based score is shown. "
               "Run `python train.py` once to create model.joblib.")

tab1, tab2, tab3 = st.tabs(["Check a link", "Check a list (CSV)", "How it works"])

# ----- Tab 1: one link -----
with tab1:
    url = st.text_input("Paste a link or domain", key="link_input",
                        placeholder="e.g. sbi-kyc-update.xyz")
    st.caption("Or try an example:")
    for col, ex in zip(st.columns(len(EXAMPLES)), EXAMPLES):
        col.button(ex, key=f"ex_{ex}", on_click=use_example, args=(ex,), width="stretch")

    if url.strip():
        r = full_analysis(url, bundle)
        color, icon = COLORS[r["verdict"]], ICONS[r["verdict"]]

        # Big coloured verdict card with a matching progress bar
        st.markdown(
            f'<div class="k-card" style="background:{color}1A;border-color:{color}">'
            f'<div class="k-verdict" style="color:{color}">{icon} {r["verdict"]}</div>'
            f'<div class="k-score">Final risk score <b>{r["score"]}/100</b> · '
            f'<code>{html.escape(r["domain"])}</code></div>'
            f'<div class="k-bar"><div style="width:{r["score"]}%;background:{color}"></div></div>'
            f'</div>', unsafe_allow_html=True)

        # "Did you mean ...?" when the link imitates a known brand
        target = lookalike_target(url)
        if target:
            st.markdown(f'<div class="k-hint">🔎 Did you mean the real site: '
                        f'<b>{html.escape(target)}</b>?</div>', unsafe_allow_html=True)

        c1, c2, c3 = st.columns(3)
        c1.metric("Rule score", f"{r['rule_score']}/100")
        c2.metric("ML probability",
                  "n/a" if r["ml_probability"] is None else f"{r['ml_probability']:.0f}%")
        c3.metric("Decided by", r["decided_by"])
        st.markdown(f'<div class="k-explain">💡 {html.escape(explain(r, target))}</div>',
                    unsafe_allow_html=True)

        st.write("**Why:**")
        good = ("Known official domain", "No red flags found")  # these get a tick, not a flag
        chips = "".join(f'<span class="k-chip">{"✅" if x in good else "🚩"} {html.escape(x)}</span>'
                        for x in r["reasons"].split("; "))
        st.markdown(f"<div>{chips}</div>", unsafe_allow_html=True)

# ----- Tab 2: CSV -----
with tab2:
    st.write("Upload a CSV with a column named **domain**.")
    file = st.file_uploader("CSV file", type="csv")
    if file:
        df = pd.read_csv(file)
        if "domain" not in df.columns:
            st.error("Could not find a column named **domain** in this CSV.")
        else:
            results = pd.DataFrame([full_analysis(str(d), bundle) for d in df["domain"]])
            cols = ["url", "domain", "verdict", "score", "rule_score", "ml_probability",
                    "decided_by", "reasons"]
            results = results[cols]

            # Summary counts
            counts = results["verdict"].value_counts()
            for col, (name, label) in zip(st.columns(3), [("Phishing", "phishing"),
                                                          ("Suspicious", "suspicious"),
                                                          ("Safe", "safe")]):
                c = COLORS[name]
                col.markdown(f'<div class="k-count" style="border-color:{c};background:{c}1A;color:{c}">'
                             f'{ICONS[name]} <b>{counts.get(name, 0)}</b> {label}</div>',
                             unsafe_allow_html=True)
            st.write("")

            def color_verdict(v):
                c = COLORS.get(v, "#E5E7EB")
                return f"background-color: {c}33; color: {c}; font-weight: 700"

            styled = (results.style.map(color_verdict, subset=["verdict"])
                      .format({"ml_probability": "{:.1f}"}, na_rep="n/a"))
            st.dataframe(styled, width="stretch", hide_index=True)

            fig = px.pie(results, names="verdict", hole=0.55, color="verdict",
                         color_discrete_map=COLORS)
            st.plotly_chart(style_chart(fig), width="stretch", config=NO_TOOLBAR)
            st.download_button("Download results", results.to_csv(index=False),
                               "kavach_results.csv", "text/csv")

# ----- Tab 3: how it works -----
with tab3:
    steps = [
        ("1 · 📏 Rules", "Checks the link for look-alike names (paytrn → paytm), fake letters, "
                         "brand names hidden in the subdomain, risky endings like .xyz, scam "
                         "words and odd structure. Result: a risk score from 0 to 100."),
        ("2 · 🤖 Machine learning", "A Random Forest trained on 20,000 popular sites and 20,000 real "
                                   "phishing hosts looks at 12 patterns in how the domain is built "
                                   "and gives the % chance that it is phishing."),
        ("3 · ⚖️ Final verdict", "If the ML model is at least 70% sure, the final score is the higher "
                                "of the rule score and the average of both; otherwise the rule score "
                                "is used. 60+ Phishing, 30-59 Suspicious, below 30 Safe. Known "
                                "official domains are always Safe."),
    ]
    for col, (title, text) in zip(st.columns(3), steps):
        col.markdown(f'<div class="k-step"><h4>{title}</h4>{text}</div>', unsafe_allow_html=True)

    st.subheader("Model performance", anchor=False)
    metrics_file = HERE / "metrics.json"
    importance_file = HERE / "feature_importance.csv"
    if metrics_file.exists() and importance_file.exists():
        m = json.loads(metrics_file.read_text(encoding="utf-8"))
        a, b, c, d = st.columns(4)
        a.metric("Test accuracy", f"{m['accuracy']:.1%}")
        b.metric("Precision", f"{m['precision']:.1%}")
        c.metric("Recall", f"{m['recall']:.1%}")
        d.metric("F1", f"{m['f1']:.1%}")
        st.caption(f"Tested on {m['n_test']:,} domains the model had never seen. The rules do the "
                   "look-alike detection; the model adds a second opinion on how a domain is built.")
        imp = pd.read_csv(importance_file)
        imp["feature"] = imp["feature"].map(lambda f: FEATURE_LABELS.get(f, f))
        imp = imp.sort_values("importance")
        fig = px.bar(imp, x="importance", y="feature", orientation="h",
                     title="What the model looks at most")
        fig.update_traces(marker_color="#22C55E")
        fig.update_layout(yaxis_title=None, xaxis_title="Importance")
        st.plotly_chart(style_chart(fig), width="stretch", config=NO_TOOLBAR)
    else:
        st.info("No model stats yet. Run `python train.py` to create them.")

# ----- Footer -----
st.markdown('<div class="k-footer">Built by Team Ctrl-C-Ctrl-V · Hackfest 2026</div>',
            unsafe_allow_html=True)
