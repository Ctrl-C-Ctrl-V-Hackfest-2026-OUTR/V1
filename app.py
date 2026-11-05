"""
Kavach - Phishing Domain Detector (the Streamlit user interface).

This file only draws things. Every score comes from detector.py, sms.py and outputs.py,
and all the styling lives in style.css.

Run with:  streamlit run app.py
Train the ML model first (once) with:  python train.py
"""
import html
import json
import math
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from detector import explain, full_analysis, load_model
from evidence import ATTACK_LABELS
from outputs import (EXPORTERS, FORMATS, check_many, check_messages, flat_row, read_domains,
                     read_messages, speed, to_json)
from page_compare import compare_html, compare_images, conclusion
from sms import MESSAGE_COLUMNS, WHAT_TO_DO, check_message, flat_message_row

HERE = Path(__file__).parent

# ---------------- design tokens that Python also needs ----------------
# The same values are defined as CSS variables at the top of style.css.
COLORS = {"Phishing": "#EF4444", "Suspicious": "#F59E0B", "Safe": "#22C55E"}
MUTED = "#9CA3AF"
BRAND = "#22C55E"
# A message says "Scam" where a domain says "Phishing", but the colour and icon are the same
VERDICT_COLORS = {"Scam": "Phishing", "Suspicious": "Suspicious", "Safe": "Safe"}
ICONS = {"Phishing": "🚨", "Suspicious": "⚠️", "Safe": "✅"}
VERDICT_ICONS = {"Scam": "🚨", "Suspicious": "⚠️", "Safe": "✅"}

EXAMPLES = ["paytrn.com", "sbi-kyc-update-now.top", "amazon.security-check.icu",
            "rediit.com", "google.com"]
# Realistic examples for the message tab: a short button label -> (message, sender)
MESSAGE_EXAMPLES = {
    "Bank KYC": ("Dear Customer, your SBI account will be blocked today. "
                 "Update KYC now: sbi-kyc-update.xyz", ""),
    "Electricity": ("Your electricity connection will be disconnected tonight at 9.30 PM. "
                    "Call 98XXXXXX21 immediately.", "9876543210"),
    "Lottery": ("Congratulations! You won ₹25,00,000 in KBC lottery. Claim at bit.ly/kbc-win", ""),
    "Parcel": ("Your parcel is held at customs. Pay ₹49 fee: indiapost-delivery.top", ""),
    "Genuine OTP": ("Your OTP for login is 482913. Do not share it with anyone. -HDFC Bank", "AD-HDFCBK"),
}
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

# Simple line icons, drawn inline so there is nothing to download.
# Each entry is the inside of an <svg> with a 24x24 viewBox.
ICON_PATHS = {
    "shield": '<path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z"/>'
              '<path d="m9 12 2 2 4-4"/>',
    "link": '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/>'
            '<path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>',
    "message": '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
    "file": '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
            '<path d="M14 2v6h6"/>',
    "check": '<path d="M20 6 9 17l-5-5"/>',
    "warning": '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>'
               '<path d="M12 9v4"/><path d="M12 17h.01"/>',
    "search": '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
    "offline": '<path d="M12 2a10 10 0 1 0 10 10"/><path d="M12 6v6l4 2"/>',
    "sparkle": '<path d="M12 3v4M12 17v4M3 12h4M17 12h4"/><circle cx="12" cy="12" r="3"/>',
}


def icon(name: str, size: int = 16, color: str = "currentColor", stroke: float = 1.8) -> str:
    """One inline SVG icon. aria-hidden, because the text next to it already says what it means."""
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            f'stroke="{color}" stroke-width="{stroke}" stroke-linecap="round" '
            f'stroke-linejoin="round" aria-hidden="true">{ICON_PATHS[name]}</svg>')


st.set_page_config(page_title="Kavach", page_icon="🛡️", layout="centered",
                   initial_sidebar_state="collapsed")


# Read on every run, not cached: the file is tiny, and editing style.css then refreshing the
# browser shows the change straight away.
st.markdown(f"<style>{(HERE / 'style.css').read_text(encoding='utf-8')}</style>",
            unsafe_allow_html=True)


# ---------------- small drawing helpers ----------------

def card(body: str, title: str = "", icon_name: str = "", fade: bool = True) -> str:
    """A bordered surface card. `body` is already-escaped HTML."""
    head = (f'<div class="k-card-title">{icon(icon_name) if icon_name else ""}'
            f"{html.escape(title)}</div>") if title else ""
    return f'<div class="k-card{" k-fade" if fade else ""}">{head}{body}</div>'


def score_ring(score: int, color: str) -> str:
    """The score as a circular gauge. Drawn as an SVG ring, so it needs no chart library."""
    radius, stroke = 46, 9
    size = (radius + stroke) * 2
    middle = size / 2
    circumference = 2 * math.pi * radius
    gap = circumference * (1 - min(max(score, 0), 100) / 100)
    return (
        f'<svg class="k-ring" width="{size}" height="{size}" viewBox="0 0 {size} {size}" '
        f'role="img" aria-label="Risk score {score} out of 100">'
        f'<circle class="k-ring-track" cx="{middle}" cy="{middle}" r="{radius}" fill="none" '
        f'stroke-width="{stroke}"/>'
        f'<circle class="k-ring-value" cx="{middle}" cy="{middle}" r="{radius}" fill="none" '
        f'stroke="{color}" stroke-width="{stroke}" stroke-linecap="round" '
        f'stroke-dasharray="{circumference:.1f}" stroke-dashoffset="{gap:.1f}" '
        f'transform="rotate(-90 {middle} {middle})"/>'
        f'<text class="k-ring-text" x="50%" y="46%" text-anchor="middle" '
        f'dominant-baseline="middle" fill="{color}">{score}</text>'
        f'<text class="k-ring-unit" x="50%" y="68%" text-anchor="middle">/ 100</text>'
        f"</svg>")


def verdict_card(verdict: str, color: str, subtitle: str, score: int) -> str:
    """The big result banner: icon, word, one line of detail and the gauge."""
    return (
        f'<div class="k-verdict-card k-fade" style="background:{color}14;border-color:{color}">'
        f'<div class="k-verdict-body">'
        f'<div class="k-verdict-word" style="color:{color}">'
        f'<span aria-hidden="true">{ICONS.get(verdict, VERDICT_ICONS.get(verdict, ""))}</span>'
        f"{html.escape(verdict)}</div>"
        f'<div class="k-verdict-sub">{subtitle}</div></div>'
        f"{score_ring(score, color)}</div>")


def reason_chips(reasons: list, points: list, all_clear: bool) -> str:
    """Each reason as a chip. The dot grows with the points that reason added, and the number
    is written out too, so the information is never carried by colour or size alone."""
    chips = []
    for index, reason in enumerate(reasons):
        added = points[index] if index < len(points) else 0
        if all_clear:
            mark = f'<span style="color:{BRAND}">{icon("check", 14, BRAND)}</span>'
            amount = ""
        else:
            # 9px at 0 points up to 15px at 70; a neutral colour, because red, amber and
            # green are kept for verdicts only
            diameter = 9 + min(added, 70) / 70 * 6
            mark = (f'<span class="k-dot" style="width:{diameter:.0f}px;height:{diameter:.0f}px;'
                    f'opacity:{0.45 + min(added, 70) / 70 * 0.55:.2f}"></span>')
            amount = f'<span class="k-chip-pts">+{added}</span>' if added else ""
        chips.append(f'<span class="k-chip">{mark}{html.escape(reason)}{amount}</span>')
    return f'<div class="k-chips">{"".join(chips)}</div>'


def coloured_name(parts: list) -> str:
    """Coloured letters for the evidence card: green = same, red = changed/extra, grey = missing."""
    return "".join(f'<span class="k-{kind}">{html.escape(text)}</span>' for text, kind in parts)


def evidence_card(ev: dict) -> str:
    """Genuine and suspicious names side by side, with the exact edits underneath."""
    edits = "".join(f"<li>{html.escape(edit)}</li>" for edit in ev["edits"])
    body = (f'<div class="k-diff">'
            f'<div><div class="k-diff-label">Genuine</div>'
            f'<div class="k-diff-name">{coloured_name(ev["real_parts"])}</div></div>'
            f'<div><div class="k-diff-label">Suspicious</div>'
            f'<div class="k-diff-name">{coloured_name(ev["shown_parts"])}</div></div></div>'
            f'<ul class="k-edits">{edits}</ul>')
    return card(body, "Why Kavach thinks this", "search")


def empty_state(icon_name: str, text: str) -> str:
    return (f'<div class="k-empty">{icon(icon_name, 40, MUTED, 1.2)}'
            f"<p>{html.escape(text)}</p></div>")


def count_tile(name: str, count: int, label: str) -> str:
    colour = COLORS[name]
    return (f'<div class="k-count">'
            f'<div class="k-count-num" style="color:{colour}">{count}</div>'
            f'<div class="k-count-label"><span aria-hidden="true">{ICONS[name]}</span>'
            f"{html.escape(label)}</div></div>")


def style_chart(fig):
    """Every chart: transparent background, Inter, a muted grid and no toolbar."""
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      font=dict(family="Inter, system-ui, sans-serif", color="#E5E7EB", size=13),
                      margin=dict(l=8, r=8, t=36, b=8),
                      legend=dict(bgcolor="rgba(0,0,0,0)"))
    fig.update_xaxes(gridcolor="#1F2937", zerolinecolor="#1F2937")
    fig.update_yaxes(gridcolor="#1F2937", zerolinecolor="#1F2937")
    return fig


def step_card(number: str, title: str, text: str) -> str:
    return (f'<div class="k-step"><div class="k-step-num">{html.escape(number)}</div>'
            f"<h4>{html.escape(title)}</h4><p>{html.escape(text)}</p></div>")


def highlight_message(text: str, spans: list) -> str:
    """The message in a chat bubble, with the risky words marked.
    Every piece goes through html.escape, so pasted HTML can never run."""
    pieces, last = [], 0
    for start, end in spans:
        pieces.append(html.escape(text[last:start]))
        pieces.append(f'<span class="k-mark">{html.escape(text[start:end])}</span>')
        last = end
    pieces.append(html.escape(text[last:]))
    return f'<div class="k-bubble k-fade">{"".join(pieces)}</div>'


@st.cache_resource
def get_model():
    return load_model()


@st.cache_data(max_entries=5, show_spinner="Checking domains…")
def check_file(data: bytes, filename: str, _bundle) -> tuple:
    """Check an uploaded file once, so pressing a download button doesn't check it all again."""
    return check_many(read_domains(data, filename), _bundle)


@st.cache_data(max_entries=5, show_spinner="Checking messages…")
def check_message_file(data: bytes, filename: str, _bundle) -> tuple:
    return check_messages(read_messages(data, filename), _bundle)


def use_example(domain: str):
    """Button callback: put the example in the input box (the check runs on the rerun)."""
    st.session_state["link_input"] = domain


def use_message(key: str):
    """Button callback: put an example message (and its sender) in the boxes."""
    text, sender = MESSAGE_EXAMPLES[key]
    st.session_state["msg_input"] = text
    st.session_state["sender_input"] = sender


def show_page_comparison(domain_differs):
    """Optional section: compare a saved copy of the suspicious page with the genuine one."""
    st.caption("Upload saved copies of both pages (in your browser: Save page as, or a screenshot). "
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
    c1.metric("Content similarity",
              "not compared" if content is None else f"{content['content_similarity']}%")
    c2.metric("Visual similarity",
              "not compared" if visual is None else f"{visual['visual_similarity']}%")
    level, sentence = conclusion(content and content["content_similarity"],
                                 visual and visual["visual_similarity"], domain_differs)
    {"strong": st.error, "same_site": st.success, "none": st.info}[level](sentence)

    if content:
        names = {"title": "Title", "form_fields": "Form fields",
                 "visible_text": "Visible text (TF-IDF cosine)", "image_names": "Logo and image file names"}
        st.markdown("**Content evidence:** "
                    + " · ".join(f"{names[k]} {v}%" for k, v in content["parts"].items()))
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


# ============================== header ==============================

st.markdown(
    f'<div class="k-hero">'
    f'<div class="k-brand">{icon("shield", 44, BRAND, 1.6)}'
    f'<h1 class="k-wordmark">Kavach</h1></div>'
    f'<p class="k-tagline">Spot fake bank, shopping and government sites before you click.</p>'
    f'<div class="k-pills">'
    f'<span class="k-pill">{icon("offline", 14)}Works offline</span>'
    f'<span class="k-pill">{icon("search", 14)}Explains every verdict</span>'
    f'<span class="k-pill">{icon("sparkle", 14)}Rules + ML</span>'
    f"</div></div>", unsafe_allow_html=True)

bundle = get_model()
if bundle is None:
    st.warning("ML model not found, so only the rule-based score is shown. "
               "Run `python train.py` once to create model.joblib.")

tab_link, tab_msg, tab_list, tab_how = st.tabs(
    ["Check a link", "Check a message", "Check a list", "How it works"])

# ============================== check a link ==============================

with tab_link:
    row, button = st.columns([5, 1], vertical_alignment="bottom")
    url = row.text_input("Paste a link or domain", key="link_input",
                         placeholder="Paste a link, e.g. sbi-kyc-update.xyz")
    button.button("Check", type="primary", width="stretch")

    st.caption("Or try an example")
    for col, example in zip(st.columns(len(EXAMPLES)), EXAMPLES):
        col.button(example, key=f"ex_{example}", on_click=use_example, args=(example,),
                   width="stretch")

    if url.strip():
        with st.spinner("Checking…"):
            r = full_analysis(url, bundle)
        colour = COLORS[r["verdict"]]
        target, ev = r["target"], r["evidence"]

        st.markdown(verdict_card(r["verdict"], colour,
                                 f'<code class="k-mono">{html.escape(r["domain"])}</code>',
                                 r["score"]), unsafe_allow_html=True)

        if target:
            st.markdown(f'<div class="k-callout">{icon("search", 18)}'
                        f'<span>Did you mean the real site '
                        f'<b class="k-mono">{html.escape(target)}</b>?</span></div>',
                        unsafe_allow_html=True)

        # The three numbers a judge looks for
        c1, c2, c3 = st.columns(3)
        c1.metric("Final risk", f"{r['score']}/100",
                  help="Rules and the ML model combined. This decides the verdict: "
                       "60 or more is Phishing, 30 to 59 is Suspicious.")
        c2.metric(f"Closeness to {ev['nearest_genuine'] or 'any known site'}",
                  f"{ev['closeness']}%",
                  help="How similar the whole name is to the nearest genuine site, after fixing "
                       "fake letters. Only the real site itself gets 100%.")
        c3.metric("ML probability",
                  "not needed" if r["ml_probability"] is None else f"{r['ml_probability']:.0f}%",
                  help="The model's chance that this is phishing, judged only from how the "
                       "address is built. Skipped for sites we already know are real.")
        st.caption(f"Attack type: {ev['attack_label']} · Edit distance: {ev['edit_distance']} · "
                   f"Rule score: {r['rule_score']}/100 · Decided by: {r['decided_by']}")

        # Letter-by-letter evidence, only when the name really imitates a genuine site
        if ev["shown_parts"] and not ev["is_genuine"]:
            st.markdown(evidence_card(ev), unsafe_allow_html=True)

        st.markdown(f'<div class="k-explain">{html.escape(explain(r, target))}</div>',
                    unsafe_allow_html=True)

        all_clear = r["verdict"] == "Safe" and bool(r["note"])
        st.markdown(reason_chips(r["reasons"].split("; "), r.get("reason_points", []), all_clear),
                    unsafe_allow_html=True)

        # st.code has a built-in copy button at the top right of the box
        result_json = to_json(flat_row(r)).decode("utf-8")
        with st.expander("Copy or download this result as JSON"):
            st.code(result_json, language="json")
            st.download_button("Download JSON", result_json, "kavach_result.json",
                               "application/json", on_click="ignore")
    else:
        st.markdown(empty_state("link", "Paste a link above, or pick an example, to see the "
                                        "verdict and the evidence behind it."),
                    unsafe_allow_html=True)

    # Is the checked link somewhere other than the genuine site? None until a link is pasted.
    link_is_elsewhere = not r["evidence"]["is_genuine"] if url.strip() else None
    with st.expander("Compare page (optional)"):
        show_page_comparison(link_is_elsewhere)

# ============================== check a message ==============================

with tab_msg:
    st.caption("Paste an SMS, WhatsApp or email message. Kavach checks every link in it "
               "and the wording, all offline.")
    for col, key in zip(st.columns(len(MESSAGE_EXAMPLES)), MESSAGE_EXAMPLES):
        col.button(key, key=f"msg_{key}", on_click=use_message, args=(key,), width="stretch")

    message = st.text_area("The message", key="msg_input", height=120,
                           placeholder="Dear Customer, your account will be blocked today…")
    sender = st.text_input("Sender (optional)", key="sender_input",
                           placeholder="e.g. AD-SBIBNK or 9876543210",
                           help="An Indian company SMS comes from a registered header like "
                                "AD-SBIBNK, not a personal mobile number. This is a soft hint: "
                                "a sender is easy to fake.")

    if message.strip():
        with st.spinner("Checking…"):
            m = check_message(message, sender, bundle)
        colour = COLORS[VERDICT_COLORS[m["verdict"]]]

        st.markdown(verdict_card(m["verdict"], colour, "Message risk score", m["score"]),
                    unsafe_allow_html=True)

        c1, c2, c3 = st.columns(3)
        c1.metric("Wording score", f"{m['text_score']}/100",
                  help="How much the words themselves look like a scam.")
        c2.metric("Worst link score", f"{m['link_score']}/100",
                  help="The highest risk score of any link in the message, from the same checks "
                       "as the Check a link tab.")
        c3.metric("Links found", len(m["links"]))
        st.markdown(f'<div class="k-explain">{html.escape(m["explanation"])}</div>',
                    unsafe_allow_html=True)

        st.subheader("The message, with the risky parts marked", anchor=False)
        st.markdown(highlight_message(m["text"], m["spans"]), unsafe_allow_html=True)

        if m["links"]:
            st.subheader("Links found in this message", anchor=False)
            link_rows = [{"link": link["host"], "verdict": link["verdict"], "score": link["score"],
                          "nearest genuine": link["result"]["evidence"]["nearest_genuine"] or "",
                          "closeness %": link["result"]["evidence"]["closeness"],
                          "why": "; ".join(link["result"]["evidence"]["edits"])
                                 or link["result"]["reasons"]}
                         for link in m["links"]]
            st.dataframe(pd.DataFrame(link_rows), width="stretch", hide_index=True)
            st.caption("Each link is checked with exactly the same rules and model as the "
                       "Check a link tab.")

        st.markdown(reason_chips(m["reasons"], [], m["verdict"] == "Safe"), unsafe_allow_html=True)
        if m["sender_check"]["reason"]:
            st.caption(f"Sender: {m['sender_check']['reason']}")

        if m["verdict"] != "Safe":
            steps = "".join(f"<li>{html.escape(step)}</li>" for step in WHAT_TO_DO)
            st.markdown(f'<div class="k-todo k-fade"><div class="k-todo-title">'
                        f"{icon('warning', 17)}What to do</div><ul>{steps}</ul></div>",
                        unsafe_allow_html=True)

        result_json = to_json(flat_message_row(m), MESSAGE_COLUMNS).decode("utf-8")
        with st.expander("Copy or download this result as JSON"):
            st.code(result_json, language="json")
            st.download_button("Download JSON", result_json, "kavach_message.json",
                               "application/json", on_click="ignore")
    else:
        st.markdown(empty_state("message", "Paste a message above, or pick an example, to see "
                                           "which words and links make it risky."),
                    unsafe_allow_html=True)

    with st.expander("Check many messages from a CSV"):
        st.write("Upload a CSV with a **message** column (and an optional **sender** column), "
                 "or a text file with one message per line.")
        msg_file = st.file_uploader("CSV or text file", type=["csv", "txt"], key="msg_file")
        if msg_file:
            try:
                msg_rows, msg_seconds = check_message_file(msg_file.getvalue(), msg_file.name, bundle)
            except ValueError as err:
                st.error(str(err))
            else:
                ms, per_second = speed(len(msg_rows), msg_seconds)
                s1, s2 = st.columns(2)
                s1.metric("Messages checked", f"{len(msg_rows):,}")
                s2.metric("Time per message", f"{ms:.1f} ms")
                st.dataframe(pd.DataFrame(msg_rows)[MESSAGE_COLUMNS], width="stretch",
                             hide_index=True)
                for col, fmt in zip(st.columns(3), EXPORTERS):
                    mime, _ = FORMATS[fmt]
                    try:
                        col.download_button(f"Download {fmt.upper()}",
                                            EXPORTERS[fmt](msg_rows, MESSAGE_COLUMNS),
                                            f"kavach_messages.{fmt}", mime,
                                            on_click="ignore", width="stretch")
                    except ImportError:  # Excel export needs openpyxl
                        col.caption(f"{fmt.upper()} needs one more package. "
                                    "Run: pip install -r requirements.txt")

# ============================== check a list ==============================

with tab_list:
    st.caption("Upload a CSV with a column named **domain**, or a text file with one domain "
               "per line. Drag the file onto the box below.")
    file = st.file_uploader("CSV or text file", type=["csv", "txt"], key="batch_file")
    if not file:
        st.markdown(empty_state("file", "Nothing uploaded yet. Try sample_domains.csv from the "
                                        "project folder to see how it looks."),
                    unsafe_allow_html=True)
    else:
        try:
            rows, seconds = check_file(file.getvalue(), file.name, bundle)
        except ValueError as err:
            st.error(str(err))
        else:
            results = pd.DataFrame(rows)
            counts = results["verdict"].value_counts()

            # How many of each, and how fast
            for col, (name, label) in zip(st.columns(3), [("Phishing", "phishing"),
                                                          ("Suspicious", "suspicious"),
                                                          ("Safe", "safe")]):
                col.markdown(count_tile(name, int(counts.get(name, 0)), label),
                             unsafe_allow_html=True)
            st.write("")
            ms, per_second = speed(len(rows), seconds)
            s1, s2, s3 = st.columns(3)
            s1.metric("Domains checked", f"{len(rows):,}")
            s2.metric("Time per domain", f"{ms:.1f} ms")
            s3.metric("Domains per second", f"{per_second:,.0f}")

            fig = px.pie(results, names="verdict", hole=0.62, color="verdict",
                         color_discrete_map=COLORS)
            fig.update_traces(marker=dict(line=dict(color="#0B0F14", width=3)))
            fig.update_layout(height=280, showlegend=True)
            st.plotly_chart(style_chart(fig), width="stretch", config=NO_TOOLBAR)

            def verdict_pill(value):
                shade = COLORS.get(value, "#E5E7EB")
                return f"background-color: {shade}26; color: {shade}; font-weight: 700"

            # Float64 keeps the missing values as real blanks, so they print as "n/a" not "None"
            results["ml_probability"] = pd.array(results["ml_probability"], dtype="Float64")
            styled = (results.style.map(verdict_pill, subset=["verdict"])
                      .format({"ml_probability": "{:.1f}"}, na_rep="n/a"))
            st.dataframe(styled, width="stretch", hide_index=True)
            st.caption("closeness_percent: how close the name is to nearest_genuine. "
                       "evidence: the exact changes from the genuine name.")

            # on_click="ignore": downloading doesn't need to rerun the app
            for col, fmt in zip(st.columns(3), EXPORTERS):
                mime, filename = FORMATS[fmt]
                try:
                    col.download_button(f"Download {fmt.upper()}", EXPORTERS[fmt](rows), filename,
                                        mime, on_click="ignore", width="stretch")
                except ImportError:  # Excel export needs openpyxl
                    col.caption(f"{fmt.upper()} needs one more package. "
                                "Run: pip install -r requirements.txt")

# ============================== how it works ==============================

with tab_how:
    steps = [
        ("1", "Rules",
         "Official domains, verified .bank.in banks, the top 20,000 sites and their subdomains are "
         "Safe straight away. Everything else is checked for an @ hiding the real address "
         "(sbi.bank.in@evil.com), fake letters (paytrn → paytm), names one typo from a brand "
         "or top site (yutube → youtube), brand or top-site names used in the name or "
         "subdomain, risky endings like .xyz, scam words and odd structure. Result: a risk score "
         "from 0 to 100."),
        ("2", "Machine learning",
         "A Random Forest trained on the PhiUSIIL dataset (about 135,000 real sites and 84,000 "
         "phishing hosts) looks at 12 patterns in how the domain is built and gives the % chance "
         "that it is phishing. Free-hosting sites never get the subdomain shortcut, because anyone "
         "can publish there: their subdomains always get all the checks and this model."),
        ("3", "Final verdict",
         "If the ML model is at least 70% sure, the final score is the higher of the rule score and "
         "the average of both; otherwise the rule score is used. So ML can only raise the risk. "
         "60+ Phishing, 30-59 Suspicious, below 30 Safe."),
    ]
    for col, (number, title, text) in zip(st.columns(3), steps):
        col.markdown(step_card(number, title, text), unsafe_allow_html=True)

    st.subheader("Checking a whole message", anchor=False)
    st.write("The **Check a message** tab takes a pasted SMS, WhatsApp or email message and does "
             "two things: it pulls out every link and runs it through exactly the checks above, "
             "and it reads the wording for scam patterns. The final score is the higher of the two, "
             "plus a little when both are bad at once.")
    message_steps = [
        ("Links, however they are hidden",
         "Scammers break links so they are not clickable: hxxp://, sbi-kyc[.]xyz, \"sbi dot xyz\", "
         "or a space before the dot. Kavach undoes all of these, then scores each link. A shortened "
         "link (bit.ly) cannot be expanded offline, so it is flagged for hiding where it goes."),
        ("Scam wording",
         "Asking for an OTP or PIN (which no real bank does), urgency and threats, KYC and Aadhaar "
         "demands, prizes and lotteries, parcel and electricity stories, easy-money job offers, a "
         "mobile number to call, a UPI ID to pay, and Hinglish wording like \"band ho jayega\"."),
        ("Who it claims to be",
         "If the words name a brand (SBI, Paytm, Amazon) but the link is not that brand's real site, "
         "that is a strong signal. The sender is a softer hint: Indian companies send from a "
         "registered header like AD-SBIBNK, not a personal mobile number."),
    ]
    for col, (title, text) in zip(st.columns(3), message_steps):
        col.markdown(f'<div class="k-step"><h4>{html.escape(title)}</h4>'
                     f"<p>{html.escape(text)}</p></div>", unsafe_allow_html=True)
    st.caption("A genuine OTP message (\"Your OTP is 482913, do not share it\") stays Safe, because "
               "only a request for an OTP counts, never a message that gives you one.")

    st.subheader("The three scores", anchor=False)
    scores = [
        ("Closeness",
         "How similar the whole name is to the nearest genuine site (0-100%), from edit distance "
         "after fixing fake letters. Only the real site itself gets 100%. The evidence card shows "
         "exactly which letters changed."),
        ("ML probability",
         "The model's % chance that the domain is phishing, judged only from how the address is "
         "built. Not needed when the site is already known to be real."),
        ("Final risk", "Rules plus ML, from 0 to 100. This decides the verdict."),
    ]
    for col, (title, text) in zip(st.columns(3), scores):
        col.markdown(f'<div class="k-step"><h4>{html.escape(title)}</h4>'
                     f"<p>{html.escape(text)}</p></div>", unsafe_allow_html=True)

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
        st.markdown(f"**Data:** the PhiUSIIL phishing URL dataset, {m['n_legit']:,} real sites and "
                    f"{m['n_phishing']:,} phishing hosts. The model sees only our own 12 features "
                    "of the host name. We don't use PhiUSIIL's ready-made columns: one of them "
                    "(URLSimilarityIndex) gets 99.7% alone, which means it gives the answer away.")
        st.caption(f"Tested on {m['n_test']:,} hosts from sites the model had never seen. The rules "
                   "do the look-alike detection; the model adds a second opinion on how a domain "
                   "is built.")
        if m.get("calibration"):
            st.markdown("**Can you trust the percentage?** When the model says 80%, is it right "
                        "about 80% of the time?")
            st.dataframe(pd.DataFrame([{"Model said": row["range"], "Domains": row["count"],
                                        "Actually phishing": f"{row['actual']:.0%}"}
                                       for row in m["calibration"]]), hide_index=True)
            st.caption("Measured at PhiUSIIL's mix of 38% phishing. Real traffic has far less "
                       "phishing, so real-world precision will be lower.")
        imp = pd.read_csv(importance_file)
        imp["feature"] = imp["feature"].map(lambda f: FEATURE_LABELS.get(f, f))
        imp = imp.sort_values("importance")
        fig = px.bar(imp, x="importance", y="feature", orientation="h",
                     title="What the model looks at most")
        fig.update_traces(marker_color=BRAND)
        fig.update_layout(yaxis_title=None, xaxis_title="Importance")
        st.plotly_chart(style_chart(fig), width="stretch", config=NO_TOOLBAR)
    else:
        st.info("No model stats yet. Run `python train.py` to create them.")

    evaluation_file = HERE / "evaluation.json"
    if evaluation_file.exists():
        e = json.loads(evaluation_file.read_text(encoding="utf-8"))
        st.subheader("Tests on synthetic look-alikes", anchor=False)
        st.write(f"We generated {e['n_fakes']:,} fake domains of ten attack types, from our brand "
                 "list and the top 200 sites. Caught means Suspicious or Phishing.")
        st.dataframe(pd.DataFrame([{"Attack type": ATTACK_LABELS[row["attack_type"]],
                                    "Brands caught": f"{row['brands']['final']:.0%}",
                                    "Top 200 sites caught": f"{row['popular']['final']:.0%}"}
                                   for row in e["attacks"]]), hide_index=True)
        fa = e["false_alarms"]
        st.caption(f"False alarms on {fa['count']:,} real sites, with the popular-site shortcut "
                   f"turned off so they can't pass automatically: {fa['final']:.1%} flagged, "
                   f"{fa['phishing']:.1%} as Phishing.")

        st.subheader("Speed", anchor=False)
        s1, s2 = st.columns(2)
        s1.metric("Time per domain, as a list", f"{e['batch_ms_per_domain']:.1f} ms")
        s2.metric("Domains per second, as a list", f"{e['batch_per_second']:,.0f}")

    st.subheader("Output formats", anchor=False)
    st.write("Download results as CSV, JSON or Excel from the list tab, copy a single result as "
             "JSON, or use the command-line tool:")
    st.code("python kavach_cli.py domains.csv --format xlsx --out results.xlsx", language="bat")

# ============================== footer ==============================

st.markdown('<div class="k-footer">Built by Team Ctrl-C-Ctrl-V · Hackfest 2026 · '
            "Works fully offline</div>", unsafe_allow_html=True)
