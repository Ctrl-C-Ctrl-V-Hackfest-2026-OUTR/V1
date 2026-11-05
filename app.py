"""
Kavach - Phishing Domain Detector (the Streamlit user interface).
The detection logic itself is in detector.py.

Run with:  streamlit run app.py
Train the ML model first (once) with:  python train.py
"""
import html
import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from detector import explain, full_analysis, load_model
from outputs import EXPORTERS, FORMATS, check_many, flat_row, read_domains, speed, to_json
from page_compare import compare_html, compare_images, conclusion

HERE = Path(__file__).parent

# ---------------- UI ----------------
COLORS = {"Phishing": "#EF4444", "Suspicious": "#F59E0B", "Safe": "#22C55E"}
ICONS = {"Phishing": "🚨", "Suspicious": "⚠️", "Safe": "✅"}
EXAMPLES = ["paytrn.com", "sbi-kyc-update-now.top", "amazon.security-check.icu",
            "rediit.com", "google.com"]
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
.k-ev {background: #111827; border: 1px solid #243041; border-radius: 14px; padding: 16px 20px; margin: 4px 0 14px 0;}
.k-ev-grid {display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 12px 24px;}
.k-ev-label {font-size: .78rem; opacity: .7; margin-bottom: 2px;}
.k-ev-name {font-family: ui-monospace, Consolas, monospace; font-size: 1.2rem; overflow-wrap: anywhere;}
.k-same {color: #22C55E;}
.k-changed {color: #EF4444; font-weight: 700; background: #EF444422; border-radius: 3px;}
.k-missing {color: #9CA3AF; text-decoration: line-through;}
.k-ev-edits {margin: 12px 0 0 0; padding-left: 18px; font-size: .9rem;}
</style>""", unsafe_allow_html=True)


def style_chart(fig):
    """Match Plotly charts to the dark theme."""
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      font_color="#E5E7EB", margin=dict(l=10, r=10, t=40, b=10))
    return fig


@st.cache_resource
def get_model():
    return load_model()


def colored_name(parts: list) -> str:
    """Coloured letters for the evidence box: green = same, red = changed/extra, grey = missing."""
    return "".join(f'<span class="k-{kind}">{html.escape(text)}</span>' for text, kind in parts)


def evidence_box(ev: dict) -> str:
    """Side-by-side box: the genuine name, the suspicious name, and the exact edits."""
    edits = "".join(f"<li>{html.escape(edit)}</li>" for edit in ev["edits"])
    return (f'<div class="k-ev"><div class="k-ev-grid">'
            f'<div><div class="k-ev-label">Genuine</div>'
            f'<div class="k-ev-name">{colored_name(ev["real_parts"])}</div></div>'
            f'<div><div class="k-ev-label">Suspicious</div>'
            f'<div class="k-ev-name">{colored_name(ev["shown_parts"])}</div></div>'
            f'</div><ul class="k-ev-edits">{edits}</ul></div>')


@st.cache_data(max_entries=5, show_spinner="Checking domains...")
def check_file(data: bytes, filename: str, _bundle) -> tuple:
    """Check an uploaded file once, so pressing a download button doesn't check it all again."""
    return check_many(read_domains(data, filename), _bundle)


def show_page_comparison(domain_differs):
    """Optional section: compare a saved copy of the suspicious page with the genuine one."""
    st.caption("Upload saved copies of both pages (browser: Save page as, or a screenshot). "
               "Nothing is fetched from the internet, and the files are only read, never opened or run. "
               "This is extra evidence and does not change the risk score.")
    left, right = st.columns(2)
    with left:
        st.markdown("**Suspicious page**")
        bad_html = st.file_uploader("Saved HTML", type=["html", "htm"], key="bad_html")
        bad_image = st.file_uploader("Screenshot", type=["png", "jpg", "jpeg"], key="bad_image")
    with right:
        st.markdown("**Genuine page**")
        good_html = st.file_uploader("Saved HTML", type=["html", "htm"], key="good_html")
        good_image = st.file_uploader("Screenshot", type=["png", "jpg", "jpeg"], key="good_image")

    content = visual = None
    if bad_html and good_html:
        content = compare_html(bad_html.getvalue(), good_html.getvalue())
    if bad_image and good_image:
        try:
            visual = compare_images(bad_image.getvalue(), good_image.getvalue())
        except ValueError as err:
            st.error(str(err))
    if content is None and visual is None:
        st.info("Upload both HTML files and/or both screenshots to compare them.")
        return

    c1, c2 = st.columns(2)
    c1.metric("Content similarity", "not compared" if content is None else f"{content['content_similarity']}%")
    c2.metric("Visual similarity", "not compared" if visual is None else f"{visual['visual_similarity']}%")
    level, sentence = conclusion(content and content["content_similarity"],
                                 visual and visual["visual_similarity"], domain_differs)
    {"strong": st.error, "same_site": st.success, "none": st.info}[level](sentence)

    if content:
        names = {"title": "Title", "form_fields": "Form fields", "visible_text": "Visible text (TF-IDF cosine)",
                 "image_names": "Logo and image file names"}
        st.markdown("**Content evidence:** " + " · ".join(f"{names[k]} {v}%" for k, v in content["parts"].items()))
        if content["asks_for_password"] or content["asks_for_otp"]:
            asks = " and ".join(word for word, flag in (("a password", content["asks_for_password"]),
                                                        ("an OTP or PIN", content["asks_for_otp"])) if flag)
            st.warning(f"The suspicious page asks for {asks}.")
        for label, values in (("Same form fields", content["shared_fields"]),
                              ("Same image files", content["shared_images"])):
            if values:
                st.caption(f"{label}: " + ", ".join(values))
    if visual:
        st.markdown(f"**Visual evidence:** Perceptual hash {visual['hash_similarity']}% · "
                    f"Structural similarity {visual['structural_similarity']}%")


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
        target, ev = r["target"], r["evidence"]
        if target:
            st.markdown(f'<div class="k-hint">🔎 Did you mean the real site: '
                        f'<b>{html.escape(target)}</b>?</div>', unsafe_allow_html=True)

        # The three scores the judges look for
        c1, c2, c3 = st.columns(3)
        c1.metric(f"Closeness to {ev['nearest_genuine'] or 'any known site'}", f"{ev['closeness']}%",
                  help="How close the name is to the nearest genuine site, after fixing fake letters. "
                       "A real name copied whole inside a longer one counts as 100%.")
        c2.metric("Phishing probability (ML)",
                  "not needed" if r["ml_probability"] is None else f"{r['ml_probability']:.0f}%")
        c3.metric("Final risk score", f"{r['score']}/100")
        st.caption(f"Attack type: {ev['attack_label']} · Edit distance: {ev['edit_distance']} · "
                   f"Rule score: {r['rule_score']}/100 · Decided by: {r['decided_by']}")

        # Letter-by-letter evidence, only when the name really imitates a genuine site
        if ev["shown_parts"] and not ev["is_genuine"]:
            st.subheader("Similarity evidence", anchor=False)
            st.markdown(evidence_box(ev), unsafe_allow_html=True)

        st.markdown(f'<div class="k-explain">💡 {html.escape(explain(r, target))}</div>',
                    unsafe_allow_html=True)

        st.write("**Why:**")
        # Safe reasons get a tick, not a flag
        is_good = r["verdict"] == "Safe" and r["note"]
        chips = "".join(f'<span class="k-chip">{"✅" if is_good or x == "No red flags found" else "🚩"} '
                        f'{html.escape(x)}</span>' for x in r["reasons"].split("; "))
        st.markdown(f"<div>{chips}</div>", unsafe_allow_html=True)

        # st.code has a built-in copy button at the top right of the box
        result_json = to_json(flat_row(r)).decode("utf-8")
        with st.expander("Copy or download this result as JSON"):
            st.code(result_json, language="json")
            st.download_button("Download JSON", result_json, "kavach_result.json", "application/json",
                               on_click="ignore")

    # Is the checked link somewhere other than the genuine site? None until a link is pasted.
    link_is_elsewhere = not r["evidence"]["is_genuine"] if url.strip() else None
    with st.expander("Compare page (optional)"):
        show_page_comparison(link_is_elsewhere)

# ----- Tab 2: CSV -----
with tab2:
    st.write("Upload a CSV with a column named **domain**, or a text file with one domain per line.")
    file = st.file_uploader("CSV or text file", type=["csv", "txt"], key="batch_file")
    if file:
        try:
            rows, seconds = check_file(file.getvalue(), file.name, bundle)
        except ValueError as err:
            st.error(str(err))
        else:
            results = pd.DataFrame(rows)

            # How fast was it?
            ms, per_second = speed(len(rows), seconds)
            s1, s2, s3 = st.columns(3)
            s1.metric("Domains checked", f"{len(rows):,}")
            s2.metric("Time per domain", f"{ms:.1f} ms")
            s3.metric("Domains per second", f"{per_second:,.0f}")

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
            st.caption("closeness_percent: how close the name is to nearest_genuine. "
                       "evidence: the exact changes from the genuine name.")
            st.dataframe(styled, width="stretch", hide_index=True)

            fig = px.pie(results, names="verdict", hole=0.55, color="verdict",
                         color_discrete_map=COLORS)
            st.plotly_chart(style_chart(fig), width="stretch", config=NO_TOOLBAR)

            # on_click="ignore": downloading doesn't need to rerun the app
            for col, fmt in zip(st.columns(3), EXPORTERS):
                mime, filename = FORMATS[fmt]
                col.download_button(f"Download {fmt.upper()}", EXPORTERS[fmt](rows), filename, mime,
                                    on_click="ignore", width="stretch")

# ----- Tab 3: how it works -----
with tab3:
    steps = [
        ("1 · 📏 Rules", "Official domains, verified .bank.in banks, the top 20,000 sites and their "
                         "subdomains are Safe straight away. Everything else is checked for an @ hiding "
                         "the real address (sbi.bank.in@evil.com), fake letters (paytrn → paytm), names "
                         "one typo from a brand or top site (yutube → youtube), brand names used in the "
                         "name or subdomain, risky endings like .xyz, scam words and odd structure. "
                         "Result: a risk score from 0 to 100."),
        ("2 · 🤖 Machine learning", "A Random Forest trained on the PhiUSIIL dataset (about 135,000 real "
                                   "sites and 84,000 phishing hosts) looks at 12 patterns in how the domain is built "
                                   "and gives the % chance that it is phishing. Free-hosting sites "
                                   "never get the subdomain shortcut, because anyone can publish there: "
                                   "their subdomains always get all the checks and this model."),
        ("3 · ⚖️ Final verdict", "If the ML model is at least 70% sure, the final score is the higher "
                                "of the rule score and the average of both; otherwise the rule score "
                                "is used. So ML can only raise the risk. 60+ Phishing, 30-59 Suspicious, "
                                "below 30 Safe."),
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
