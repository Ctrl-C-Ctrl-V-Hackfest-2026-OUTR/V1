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

## Official deliverables (PS-08)

Judged on closeness/probability scores, detection speed, ease of use and flexible output formats. Key constraint: "Explain the similarity evidence and make probability or closeness scores visible."

1. Automated detection of look-alike phishing domains.
2. Offline labelled URL data (PhiUSIIL sample replaces WHOIS) and synthetic look-alike pairs.
3. Similarity analysis against genuine domains, using content/code or page images as feasible.
4. Probability or closeness scores.
5. Fast detection with usable output in flexible formats.

## Code layout

- `app.py`: Streamlit UI only. Note: an unrelated old Flask `app.py` is in Downloads. Ignore it.
- `detector.py`: `analyze()`, `full_analysis()`, `lookalike_target()`, `explain()`, `load_model()`. Must not import `app.py` or streamlit.
- `evidence.py`: `similarity_evidence()` gives nearest genuine domain, closeness, edit distance, attack type and exact edits. `align()` is the letter-by-letter alignment.
- `outputs.py`: `check_many()` scores a whole list in one model call, plus `to_csv`, `to_json`, `to_xlsx`. Exports show cells starting with `= + - @` as text, so a spreadsheet can't run them.
- `kavach_cli.py`: `python kavach_cli.py input.csv|input.txt --format csv|json|xlsx --out file`.
- `lookalikes.py`: `python lookalikes.py` writes `data/synthetic_pairs.csv` (gitignored; genuine, lookalike, attack_type).
- `evaluate.py`: `python evaluate.py` prints detection per attack type, false alarms and speed, and writes `evaluation.json` (committed; the How it works tab shows it).
- `page_compare.py`: optional saved-page comparison. Reads uploads only, fetches nothing, never changes the risk score.

## Detection rules (`detector.py`)

Rule-based risk score (0–100) per domain:

These return Safe (score 0) straight away, in this order:

- Known official domains in `LEGIT_DOMAINS`.
- Anything under `.bank.in` (`TRUSTED_ENDINGS`): only RBI-verified banks can register there.
- Registered domain in `POPULAR_SET` with no subdomain or `www`.
- Subdomains of a popular site (`accounts.spotify.com`, reason "Subdomain of popular real website <domain>"), because they belong to the same owner. Not for `FREE_HOSTING` sites (`random.weebly.com`) or when a brand is in the subdomain (`paytm.spotify.com`): those get all the checks below and ML.

Everything else gets a score. An address with `@` before the host (`before_at()`) never gets the instant Safe above:

- `@` trick: +40, reason "Uses @ to hide the real address — the browser goes to <real host>". +60 instead (so Phishing) if the part before the `@` names a brand, official domain or `.bank.in` address (`at_imitates()`, e.g. `sbi.bank.in@evil.com`). An `@` in the path doesn't count.
- If the real host is one of the trusted ones above (`user@reddit.com`, `someone@gmail.com`), only those points count and ML is skipped.

Rules 1 to 4 are one group: only the first match counts, and the group is skipped when the registered domain is popular (e.g. `paytm-login.weebly.com`).

1. **Homoglyphs:** normalize 0→o, 1→l (or i), rn→m, vv→w, 3→e, 5→s, Cyrillic look-alikes (`CYRILLIC_LETTERS`) and decoded `xn--` names. If the normalized name exactly matches a brand, +70.
2. **One typo from a brand:** exactly 1 Damerau-Levenshtein edit (`edit_distance()`) from a brand with 5+ letters: +60, so Phishing on its own. Names in `ORDINARY_WORDS` (tomato, mantra, email…) skip this rule, but usually still hit rule 3.
3. **Typosquatting:** rapidfuzz `fuzz.ratio` of the domain name against a `BRANDS` dict (→ list of real domains, e.g. amazon → amazon.in and amazon.com). A brand hidden inside counts as 90% similar. ≥80% similar gives +45. This number is internal: the UI only shows closeness, so users see one similarity figure. A brand is "hidden inside" (`brand_hidden_in()`) if it is a whole hyphen-separated word (`sbi-kyc`, `kyc-paytm`), or, also checking with hyphens removed (`ama-zon-login`, `hdfc-bank-login`): 6+ letter brands anywhere inside (`startamazonstore`), 5-letter brands at the start of a word (`paytmkyc`), 3-4 letter brands when everything else is `SUSPICIOUS_WORDS` (`sbikyc`, `kycsbi`). So `pineapple` and `lesbian` don't count.
4. **Popular sites:** +45, only Suspicious on its own, because these names cause more false alarms than curated brands. Either exactly 1 edit from (or fake letters spelling) a name in `POPULAR_NAMES` (top 2,000 sites, 5+ letters; `popular_lookalike()`), or a top-200 name on another ending or with only scam words added (`top_site_abuse()`: `reddit.xyz`, `reddit-login.com`). `COMMON_WORD_SITES` (office, cloud, forms…) skip `top_site_abuse()`.
5. Brand in a subdomain (`subdomain_brand()`, same word test as rule 3, e.g. `paytm.verify-account.click`): +45, so brand-in-subdomain plus a suspicious TLD always reaches 60 (Phishing).
6. Suspicious TLDs (xyz, top, tk, click, online, info…): +15.
7. Scam words (login, verify, kyc, update, reward…): +10 each, max +20.
8. ≥2 hyphens +10, digits +5, length >30 +5, raw IP +30.

- Verdict: ≥60 Phishing, 30–59 Suspicious, <30 Safe. Every verdict shows the reasons, and each reason quotes its evidence (`Many hyphens: 3 in '...'`, `One typo away from 'youtube': missing 'o' at position 2`).
- `popular_domains.txt` (committed, 19,998 domains in rank order) is made by `python build_popular.py` from `data/tranco.csv`. It removes domains that imitate a brand and prints what it removed. Real sites that only look like a match stay in its `KEEP` dict (mail.com, kodak.com, telegra.ph, googl.com…).
- The app ignores URL paths. `sites.google.com/view/...` is Safe because `google.com` is official, so that `FREE_HOSTING` entry has no effect.
- tldextract runs offline: `tldextract.TLDExtract(suffix_list_urls=())`.

UI (polished for the demo; dark theme set in `.streamlit/config.toml`: primary `#22C55E`, background `#0B0F14`, secondary `#111827`, text `#E5E7EB`):

- Header: shield + "Kavach", tagline "Spot fake bank & shopping sites before you click", and "Works offline · Rules + Machine Learning". Footer: "Built by Team Ctrl-C-Ctrl-V · Hackfest 2026".
- Three tabs: **Check a link**, **Check a list (CSV)**, **How it works**.
- **Check a link:**
  - Text input plus five example buttons (`paytrn.com`, `sbi-kyc-update-now.top`, `amazon.security-check.icu`, `rediit.com`, `google.com`; `rediit.com` is the amber example). A button callback writes the example into `st.session_state["link_input"]`, and the check runs on the rerun.
  - Large coloured verdict card (red Phishing 🚨, amber Suspicious ⚠️, green Safe ✅) with the final score and a custom HTML progress bar in the same colour.
  - "Did you mean the real site: ...?" when the link imitates a brand (look-alike name, fake letters, brand in the subdomain, or brand hidden before an `@`) or a popular site. For brands it uses the first real domain in `BRANDS` (`lookalike_target()` in `detector.py`).
  - Three metrics (Closeness to <genuine>, Phishing probability (ML), Final risk score), a caption with attack type, edit distance, rule score and what decided it, and a one-line plain-English explanation (`explain()` in `detector.py`).
  - "Similarity evidence" box when the name imitates a genuine site: genuine vs suspicious side by side (green = same, red = changed/extra, grey strikethrough = missing) and the exact edits.
  - Reasons shown as small chips, then an expander to copy (`st.code`) or download the result as JSON.
  - "Compare page (optional)" expander: saved HTML gives content similarity %, screenshots give visual similarity %. A close copy on a different domain shows strong phishing evidence. The 70% content and 80% visual cut-offs are judgement calls.
- **Check a list (CSV):** upload a CSV with a `domain` column or a text file with one domain per line (clear errors for bad files). Shows speed (domains, ms per domain, domains per second), summary counts (phishing / suspicious / safe), a results table with a red/amber/green verdict column, a Plotly donut chart and CSV, JSON and Excel downloads.
- **How it works:** 3 steps (Rules, then ML, then Final verdict), the three scores, model metrics with data notes and a calibration table, the feature importance chart (`FEATURE_LABELS` in `app.py`), the synthetic test table, speed and output formats.
- UI rules of thumb: all user-supplied text put into HTML goes through `html.escape`; Plotly charts use `config={"displayModeBar": False}`; use `width="stretch"` (not `use_container_width`, which is deprecated in Streamlit 1.66); headings use `anchor=False`.

## Machine-learning model

Added on the `ml-model` branch. The rule-based score above is kept; the model adds a second opinion.

- `features.py`: shared logic used by every other file. Holds `BRANDS`, `LEGIT_DOMAINS`, `TRUSTED_ENDINGS`, `FREE_HOSTING`, `ORDINARY_WORDS`, the `POPULAR_*` lists, `SUSPICIOUS_TLDS`, `SUSPICIOUS_WORDS`, `HOMOGLYPHS`, `normalize`, `brand_match`, the look-alike helpers and `extract_features`. It must not import `app.py` (importing `app.py` starts the Streamlit UI). `extract_features` ignores a leading `www.`.
- 12 features per domain: length, hyphens, digits, dots, subdomain count, vowel ratio, character entropy, suspicious TLD, scam-word count, best brand similarity, brand in subdomain, homoglyph match.
- `train.py`: run `python train.py`. It downloads PhiUSIIL once into `data/` (gitignored), then works offline.
  - PhiUSIIL labels 1 = LEGITIMATE, so it flips them to 1 = phishing and stops if known hosts (`KNOWN_HOSTS`) have the wrong label.
  - One row per host, without `www.`; drops official brand domains (their rows are redirects like google.com/url?q=...) and hosts with both labels.
  - PhiUSIIL's own columns are never used: `URLSimilarityIndex` alone gets 99.7%. Training stops if any of our features reaches 98% alone.
  - The `www` leak: all legit rows start `https://www.`, only 41% of phishing rows do. Seeing `www` makes the model flag 100% of real sites typed without it.
  - 80/20 split by registered domain (`StratifiedGroupKFold`), RandomForest (100 trees, max_depth=14, min_samples_leaf=2, seed 42).
  - Writes `model.joblib` (joblib compress=3), `feature_importance.csv` (top 10) and `metrics.json` (with calibration and a cross-check on the other data source).
  - Fallback: `python train.py --source tranco` (Tranco top 20,000 + Phishing.Database, minus hosts on Tranco domains). It also falls back if PhiUSIIL can't be downloaded.
- Blend rule in `score_link()` in `detector.py`:
  - ML probability >= 70%: final score = max(rule score, (rule score + ML probability × 100) / 2).
  - ML probability < 70%: final score = rule score.
  - So ML can only raise the score, never lower it. Same verdict thresholds (60 / 30).
  - The UI shows "Decided by": `Rules` or `Rules + ML` (the latter only when ML actually raised the score).
  - These skip the model (results from `settled()` in `detector.py`, which have a `note` that `explain()` shows): official domains, `.bank.in`, popular sites and their subdomains, and an `@` trick whose real host is one of those.
  - Subdomains of `FREE_HOSTING` sites (in `features.py`) always go to the model, because anyone can publish there (e.g. `random.weebly.com`). The model scores almost any subdomain high, so a neutral subdomain there ends up Suspicious.
  - `FREE_HOSTING` is hand-picked and incomplete (the comment above it says how), and a popular site missing from it gets instant Safe for all its subdomains. 12,233 of the 392,164 feed hosts (3.1%) are in that position, on 477 sites, led by plesk.page, amazonaws.com, tw1.ru, trycloudflare.com and appdomain.cloud.
  - If `model.joblib` is missing, the app shows the rule score only with a warning.
- Current metrics (test set of 43,805 hosts): accuracy 85.3%, precision 93.5%, recall 66.4%, F1 77.6%. Top features: subdomain_count, digits, suspicious_tld, length, dots.
- Probabilities are well calibrated on the test set, but only at PhiUSIIL's mix of 38% phishing. Real-world precision will be lower.
- Compared with the old Tranco model, the full app (rules + ML) flags more real sites (3.9% to about 5.3% when the switch was made) and catches fewer feed hosts (78.8% to 72.3%), though the old model trained on that feed. On PhiUSIIL's held-out sites, the old model gets 73.1% accuracy and the new one 85.3%.
- Caveat for the pitch: much of the model's signal is subdomain and address structure (differences between the data sources), not look-alike detection. The rules still do the look-alike work.
- Synthetic test (`python evaluate.py`): 9,501 fakes. Final false alarms 5.8% of 2,000 real sites with the popular shortcut off. One-typo fakes of 3-4 letter brands (`bsi`, `joi`) are missed on purpose. List speed 1.1 ms per domain.
- `model.joblib` (5.5 MB), `feature_importance.csv` and `metrics.json` are committed, so teammates do not need to retrain. `data/` is not committed.
- The "How it works" tab shows these metrics, a calibration table and a Plotly bar chart of the feature importances.

`sample_domains.csv` has 10 test domains (mix of real and fake, e.g. `paytrn.com`, `amaz0n-rewards.top`, `onlinesbi-kyc-update.xyz`).

## Next steps (planned)

1. Add more brands (22 added on the `lookalike-fix` branch; more Indian banks and government sites could still be added).
2. Add an ML model (done on the `ml-model` branch, see the Machine-learning model section).
3. Polish the UI for the demo (done, see the UI description above).
4. Prepare a demo flow: paste a fake link → red verdict with evidence box → upload a CSV → show speed and downloads.
5. All five PS-08 deliverables are built (`deliverables` branch). Open decision: add the biggest open hosts (amazonaws.com, plesk.page, cloudfront.net…) to `FREE_HOSTING`.

## How to work with me

- Keep code simple and well commented. Add a new file only when one is really needed.
- Test before saying something works.
- Give Windows commands (CMD or PowerShell), not Linux/Mac commands.
