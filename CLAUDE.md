# Kavach – Project Context

## About the project

- 36-hour hackathon, 4-person team. Track: Cybersecurity & Digital Trust.
- Problem statement **PS-08: Phishing Domain Detection**. Detect look-alike phishing domains (e.g. fake bank and UPI sites). Must work **offline**: no live WHOIS or online lookups.
- I'm the main builder. Teammates handle UI design and pitching, so keep the tech stack **simple** and the UI **clean and good-looking**.
- I'm a beginner-to-intermediate Python user on **Windows**. Explain commands briefly.

## Environment (already set up)

- Windows, Python 3, Command Prompt / PowerShell.
- A working venv exists at `C:\Users\Subham Mishra\Desktop\HACKFEST\venv` with: pandas, scikit-learn, rapidfuzz, tldextract, streamlit, plotly.
- Activate (CMD): `venv\Scripts\activate`. Run the app: `streamlit run app.py` (opens http://localhost:8501).
- If working in a new folder, create a fresh venv there and install the same packages.

## Current code: `app.py` (Streamlit, working)

Location: `app.py` in this repo (HACKFEST). Note: an unrelated old Flask `app.py` is in Downloads. Ignore it.

Rule-based risk score (0–100) per domain:

1. **Typosquatting:** rapidfuzz `fuzz.ratio` of the domain name against a `BRANDS` dict (sbi, hdfcbank, icicibank, paytm, phonepe, google, amazon, flipkart, irctc, etc. → list of real domains, e.g. amazon → amazon.in and amazon.com). Brand hidden inside the name counts as 90% similar. ≥80% similar gives +45.
2. **Homoglyphs:** normalize 0→o, 1→l, rn→m, vv→w, 3→e, 5→s. If the normalized name exactly matches a brand, +70.
3. Brand in a subdomain (e.g. `paytm.verify-account.click`): +45, so brand-in-subdomain plus a suspicious TLD always reaches 60 (Phishing).
4. Suspicious TLDs (xyz, top, tk, click, online, info…): +15.
5. Scam words (login, verify, kyc, update, reward…): +10 each, max +20.
6. ≥2 hyphens +10, digits +5, length >30 +5, raw IP +30.

- Known official domains in `LEGIT_DOMAINS` → Safe, score 0.
- Verdict: ≥60 Phishing, 30–59 Suspicious, <30 Safe. Every verdict shows the reasons.
- tldextract runs offline: `tldextract.TLDExtract(suffix_list_urls=())`.

UI (polished for the demo; dark theme set in `.streamlit/config.toml`: primary `#22C55E`, background `#0B0F14`, secondary `#111827`, text `#E5E7EB`):

- Header: shield + "Kavach", tagline "Spot fake bank & shopping sites before you click", and "Works offline · Rules + Machine Learning". Footer: "Built by Team Ctrl-C-Ctrl-V · Hackfest 2026".
- Three tabs: **Check a link**, **Check a list (CSV)**, **How it works**.
- **Check a link:**
  - Text input plus five example buttons (`paytrn.com`, `sbi-kyc-update-now.top`, `amazon.security-check.icu`, `flipkart-sale.in`, `google.com`). A button callback writes the example into `st.session_state["link_input"]`, and the check runs on the rerun.
  - Large coloured verdict card (red Phishing 🚨, amber Suspicious ⚠️, green Safe ✅) with the final score and a custom HTML progress bar in the same colour.
  - "Did you mean the real site: ...?" when the link imitates a brand (look-alike name, fake letters, or brand in the subdomain). It uses the first real domain in `BRANDS` (`lookalike_target()` in `app.py`).
  - Three metrics (Rule score, ML probability, Decided by) and a one-line plain-English explanation (`explain()` in `app.py`).
  - Reasons shown as small chips.
- **Check a list (CSV):** upload a CSV with a `domain` column (a clear error is shown if it is missing). Shows summary counts (phishing / suspicious / safe), a results table with a red/amber/green verdict column, a Plotly donut chart and a download button.
- **How it works:** 3 steps (Rules, then ML, then Final verdict), the model performance metrics, and the feature importance chart with human-readable labels (`FEATURE_LABELS` in `app.py`).
- UI rules of thumb: all user-supplied text put into HTML goes through `html.escape`; Plotly charts use `config={"displayModeBar": False}`; use `width="stretch"` (not `use_container_width`, which is deprecated in Streamlit 1.66); headings use `anchor=False`.

## Machine-learning model

Added on the `ml-model` branch. The rule-based score above is kept; the model adds a second opinion.

- `features.py`: shared logic used by both `app.py` and `train.py`. Holds `BRANDS`, `LEGIT_DOMAINS`, `SUSPICIOUS_TLDS`, `SUSPICIOUS_WORDS`, `HOMOGLYPHS`, `normalize`, `brand_match` and `extract_features`. It must not import `app.py` (importing `app.py` starts the Streamlit UI).
- 12 features per domain: length, hyphens, digits, dots, subdomain count, vowel ratio, character entropy, suspicious TLD, scam-word count, best brand similarity, brand in subdomain, homoglyph match.
- `train.py`: run `python train.py`. It downloads the data once into `data/` (gitignored), then works offline.
  - Legit: top 20,000 of the Tranco list, minus the official brand domains in `LEGIT_DOMAINS`.
  - Phishing: 20,000 random hosts from Phishing.Database, minus hosts whose registered domain is in the Tranco top 20,000 (free-hosting sites like github.io, blogspot.com, weebly.com).
  - Stratified 80/20 split, RandomForest (100 trees, max_depth=14, min_samples_leaf=2, seed 42).
  - Writes `model.joblib` (joblib compress=3), `feature_importance.csv` (top 10) and `metrics.json`.
  - If a download fails it prints manual Kaggle instructions.
- Blend rule in `full_analysis()` in `app.py`:
  - ML probability >= 70%: final score = max(rule score, (rule score + ML probability × 100) / 2).
  - ML probability < 70%: final score = rule score.
  - So ML can only raise the score, never lower it. Same verdict thresholds (60 / 30).
  - The UI shows "Decided by": `Rules` or `Rules + ML` (the latter only when ML actually raised the score).
  - Official domains skip the model. If `model.joblib` is missing, the app shows the rule score only with a warning.
- Current metrics (test set of 7,997 domains): accuracy 85.8%, precision 91.1%, recall 79.3%, F1 84.8%. Top features: length, subdomain_count, entropy, digits, dots.
- Caveat for the pitch: much of the model's signal is domain length and subdomain structure (differences between the two data sources), not look-alike detection. The rules still do the look-alike work.
- `model.joblib` (2.7 MB), `feature_importance.csv` and `metrics.json` are committed, so teammates do not need to retrain. `data/` is not committed.
- The "How it works" tab shows these metrics and a Plotly bar chart of the feature importances.

`sample_domains.csv` has 10 test domains (mix of real and fake, e.g. `paytrn.com`, `amaz0n-rewards.top`, `onlinesbi-kyc-update.xyz`).

## Next steps (planned)

1. Add more brands (more Indian banks, UPI apps, government sites).
2. Add an ML model (done on the `ml-model` branch, see the Machine-learning model section).
3. Polish the UI for the demo (done, see the UI description above).
4. Prepare a demo flow: paste a fake link → red verdict with reasons → upload a CSV → show the chart.

## How to work with me

- Keep code simple and well commented. Prefer one file until it gets too big.
- Test before saying something works.
- Give Windows commands (CMD or PowerShell), not Linux/Mac commands.
