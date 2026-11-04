# Kavach – Project Context

## About the project

- 36-hour hackathon, 4-person team. Track: Cybersecurity & Digital Trust.
- Problem statement **PS-08: Phishing Domain Detection**. Detect look-alike phishing domains (e.g. fake bank and UPI sites). Must work **offline**: no live WHOIS or online lookups.
- I'm the main builder. Teammates handle UI design and pitching, so keep the tech stack **simple** and the UI **clean and good-looking**.
- I'm a beginner-to-intermediate Python user on **Windows**. Explain commands briefly.

## Environment (already set up)

- Windows, Python 3, Command Prompt / PowerShell.
- A working venv exists at `C:\Users\Subham Mishra\kavach\venv` with: pandas, scikit-learn, rapidfuzz, tldextract, streamlit, plotly.
- Activate (CMD): `venv\Scripts\activate`. Run the app: `streamlit run app.py` (opens http://localhost:8501).
- If working in a new folder, create a fresh venv there and install the same packages.

## Current code: `app.py` (Streamlit, working)

Location: `C:\Users\Subham Mishra\kavach\app.py`. Note: an unrelated old Flask `app.py` is in Downloads. Ignore it.

Rule-based risk score (0–100) per domain:

1. **Typosquatting:** rapidfuzz `fuzz.ratio` of the domain name against a `BRANDS` dict (sbi, hdfcbank, icicibank, paytm, phonepe, google, amazon, flipkart, irctc, etc. → real domains). Brand hidden inside the name counts as 90% similar. ≥80% similar gives +45.
2. **Homoglyphs:** normalize 0→o, 1→l, rn→m, vv→w, 3→e, 5→s. If the normalized name exactly matches a brand, +70.
3. Brand in a subdomain (e.g. `paytm.verify-account.click`): +20.
4. Suspicious TLDs (xyz, top, tk, click, online, info…): +15.
5. Scam words (login, verify, kyc, update, reward…): +10 each, max +20.
6. ≥2 hyphens +10, digits +5, length >30 +5, raw IP +30.

- Known official domains in `LEGIT_DOMAINS` → Safe, score 0.
- Verdict: ≥60 Phishing, 30–59 Suspicious, <30 Safe. Every verdict shows the reasons.
- tldextract runs offline: `tldextract.TLDExtract(suffix_list_urls=())`.

UI has two tabs:

- **Check one link:** text input, coloured verdict, progress bar, reasons.
- **Check a list (CSV):** upload a CSV with a `domain` column, see a results table, a Plotly donut chart, and a download button.

`sample_domains.csv` has 10 test domains (mix of real and fake, e.g. `paytrn.com`, `amaz0n-rewards.top`, `onlinesbi-kyc-update.xyz`).

## Next steps (planned)

1. Add more brands (more Indian banks, UPI apps, government sites).
2. Add an ML model: take a labeled phishing-domain dataset (e.g. from Kaggle), extract the same features, train a scikit-learn RandomForestClassifier, save it with joblib, and show its prediction next to the rule score.
3. Polish the UI for the demo: colours, layout, a clear "why it's dangerous" explanation.
4. Prepare a demo flow: paste a fake link → red verdict with reasons → upload a CSV → show the chart.

## How to work with me

- Keep code simple and well commented. Prefer one file until it gets too big.
- Test before saying something works.
- Give Windows commands (CMD or PowerShell), not Linux/Mac commands.
