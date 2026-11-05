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
- `evidence.py`: `similarity_evidence()` gives nearest genuine domain, closeness, edit distance, attack type and exact edits. `align()` is the letter-by-letter alignment. Closeness is whole-name Damerau-Levenshtein similarity after fixing fake letters, and `_result()` caps it at 99% for anything that is not the genuine site, so a fake never shows 100%. A brand copied inside a longer name scores low and is reported as `combosquat` instead, with the line "Contains the full brand name 'amazon' plus extra words...".
- `outputs.py`: `check_many()` scores a whole list in one model call, plus `to_csv`, `to_json`, `to_xlsx`. Exports show cells starting with `= + - @` as text, so a spreadsheet can't run them.
- `kavach_cli.py`: `python kavach_cli.py input.csv|input.txt --format csv|json|xlsx --out file`.
- `test_rules.py`: `python test_rules.py` runs everything in about 30 seconds and exits with code 1 on any failure. Five sections: Links (`LINK_CASES`, input and expected verdict), Evidence, Exports and command-line tool, Page comparison, and App (headless, through `streamlit.testing.v1.AppTest`). A section that raises counts as one failed check, so one missing package can't hide the rest. The file says how to add SMS messages. Must not import `app.py`.
- `lookalikes.py`: `python lookalikes.py` writes `data/synthetic_pairs.csv` (gitignored; genuine, lookalike, attack_type).
- `evaluate.py`: `python evaluate.py` prints detection per attack type, false alarms and speed, and writes `evaluation.json` (committed; the How it works tab shows it).
- `page_compare.py`: optional saved-page comparison. Reads uploads only, fetches nothing, never changes the risk score.
- `sms.py`: `check_message(text, sender, bundle)` for a pasted SMS / WhatsApp / email. Holds `find_links`, `deobfuscate`, `SIGNALS`, `check_sender`, `WHAT_TO_DO` and `MESSAGE_COLUMNS`. Must not import `app.py` or streamlit.

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

Rules 1 to 5 are one group: only the first match counts, and the group is skipped when the registered domain is popular (e.g. `paytm-login.weebly.com`).

1. **Homoglyphs:** normalize 0→o, 1→l (or i), rn→m, vv→w, 3→e, 5→s, Cyrillic look-alikes (`CYRILLIC_LETTERS`) and decoded `xn--` names. If the normalized name exactly matches a brand, +70.
2. **One typo from a brand:** exactly 1 Damerau-Levenshtein edit (`edit_distance()`) from a brand with 5+ letters: +60, so Phishing on its own. Names in `ORDINARY_WORDS` (tomato, mantra, email…) skip this rule, but usually still hit rule 3.
3. **Short brand plus only scam words:** a 3-4 letter brand with nothing but `SUSPICIOUS_WORDS` around it (`scam_words_brand()`: sbikyc, kycsbi, sbi-login): +60, so Phishing on its own. `lesbian` and `sbismith` don't match, because the rest must be scam words.
4. **Typosquatting:** rapidfuzz `fuzz.ratio` of the domain name against a `BRANDS` dict (→ list of real domains, e.g. amazon → amazon.in and amazon.com). A brand hidden inside counts as 90% similar. ≥80% similar gives +45. This number is internal: the UI only shows closeness, so users see one similarity figure. A brand is "hidden inside" (`brand_hidden_in()`) if it is a whole hyphen-separated word (`sbi-kyc`, `kyc-paytm`), or, also checking with hyphens removed (`ama-zon-login`, `hdfc-bank-login`): 6+ letter brands anywhere inside (`startamazonstore`), 5-letter brands at the start of a word (`paytmkyc`), 3-4 letter brands when everything else is `SUSPICIOUS_WORDS` (`sbikyc`, `kycsbi`). So `pineapple` and `lesbian` don't count.
5. **Popular sites:** +45, only Suspicious on its own, because these names cause more false alarms than curated brands. Either exactly 1 edit from (or fake letters spelling) a name in `POPULAR_NAMES` (top 2,000 sites, 5+ letters; `popular_lookalike()`), or a top-200 name on another ending or with only scam words added (`top_site_abuse()`: `reddit.xyz`, `reddit-login.com`). `COMMON_WORD_SITES` (office, cloud, forms…) skip `top_site_abuse()`.
6. Brand in a subdomain (`subdomain_brand()`, same word test as rule 3, e.g. `paytm.verify-account.click`): +45, so brand-in-subdomain plus a suspicious TLD always reaches 60 (Phishing).
7. Suspicious TLDs (xyz, top, tk, click, online, info…): +15.
8. Scam words (login, verify, kyc, update, reward…): +10 each, max +20.
9. ≥2 hyphens +10, digits +5, length >30 +5, raw IP +30.

- Verdict: ≥60 Phishing, 30–59 Suspicious, <30 Safe. Every verdict shows the reasons, and each reason quotes its evidence (`Many hyphens: 3 in '...'`, `One typo away from 'youtube': missing 'o' at position 2`).
- `popular_domains.txt` (committed, 19,998 domains in rank order) is made by `python build_popular.py` from `data/tranco.csv`. It removes domains that imitate a brand and prints what it removed. Real sites that only look like a match stay in its `KEEP` dict (mail.com, kodak.com, telegra.ph, googl.com…).
- The app ignores URL paths. `sites.google.com/view/...` is Safe because `google.com` is official, so that `FREE_HOSTING` entry has no effect.
- tldextract runs offline: `tldextract.TLDExtract(suffix_list_urls=())`.

## UI (redesigned on the `ui-polish` branch)

`app.py` only draws things; every number comes from `detector.py`, `sms.py` and `outputs.py`.
**All custom CSS lives in `style.css`**, read fresh on each run (not cached, so editing it and
refreshing the browser shows the change). `.streamlit/config.toml` sets the dark base theme and
`toolbarMode = "minimal"`; `style.css` hides what is left of Streamlit's chrome.

Design rules, all enforced in `style.css`:

- **Tokens:** every colour and size is a CSS variable on `:root` (`--bg #0B0F14`, `--surface #111827`, `--raised #161E2B`, `--border #1F2937`, `--text #E5E7EB`, `--muted #9CA3AF`, `--brand #22C55E`, plus `--phishing`, `--suspicious`, `--safe`). Spacing is an 8px grid (`--s1`…`--s4`), cards are 16px radius with a 1px border and a soft shadow.
- **Red, amber and green are only ever used for verdicts**, so they keep their meaning. Reason-chip dots are neutral grey, sized and labelled with the points instead.
- **A verdict is always an icon and a word**, never colour alone. Contrast measured at 6.6–7.6:1 against the surface behind, above the 4.5:1 target.
- **Inter** from Google Fonts, with a clear scale (hero 2.6rem/800, section 1.25rem/700, body 1rem, small 0.85rem muted). Scores use `font-variant-numeric: tabular-nums`.
- Content is centred at 920px. At 640px and below, columns wrap; a column holding a `.k-step` card goes full width (via `:has()`), because a paragraph in a 150px column is unreadable.

Streamlit selectors that matter in 1.66 (they are not the documented BaseWeb ones):

- Tabs are `[role="tablist"]` with `[data-testid="stTab"]` children, styled into a segmented control. The active tab's green bar is `.react-aria-SelectionIndicator`, hidden so the pill behind the label replaces it.
- Streamlit's own icons are ligatures in a symbol font, so `[data-testid="stIconMaterial"]` must keep `font-family: "Material Symbols Rounded"`. A blanket Inter rule once printed "keyboard_arrow_right" as literal words in every expander label.
- Equal-height cards in a row need `height: 100%` on the whole wrapper chain (`stVerticalBlock`, `stElementContainer`, `stMarkdown`, `stMarkdownContainer`), not just on the card: those wrappers have no height of their own, so a card's `height: 100%` has nothing to measure against.
- `st.metric` is kept (rather than hand-built tiles) and restyled as a card, because it stays testable through `AppTest` and keeps its `help` tooltip.

Layout:

- **Hero:** inline SVG shield in brand green + the "Kavach" wordmark, the tagline "Spot fake bank, shopping and government sites before you click", and three pills (Works offline · Explains every verdict · Rules + ML). A very low-opacity radial green glow sits behind it.
- **Four tabs:** **Check a link**, **Check a message**, **Check a list**, **How it works**.
- Icons are inline SVG from `ICON_PATHS` in `app.py` via `icon(name, size, colour)`. No emoji in headings; emoji stay inside verdict badges only.
- **Check a link:** one input with a primary "Check" button on the same row, then five example chips (`paytrn.com`, `sbi-kyc-update-now.top`, `amazon.security-check.icu`, `rediit.com`, `google.com`; `rediit.com` is the amber example). A callback writes into `st.session_state["link_input"]` and the check runs on the rerun.
  - Verdict card: icon + word, the domain in monospace, and the score as an SVG ring gauge (`score_ring()`, a stroke-dasharray circle, so no chart library is involved).
  - Three stat tiles: Final risk · Closeness to <genuine> · ML probability. Then a caption with attack type, edit distance, rule score and what decided it, and a one-line explanation (`explain()`).
  - "Did you mean …?" as a green outline callout with the real domain in monospace.
  - Evidence card titled "Why Kavach thinks this": genuine vs suspicious side by side (green = same, red = changed/extra, grey strikethrough = missing) and the exact edits.
  - Reason chips, each with a dot sized by the points that reason added and a `+N` label. `detector.py` returns `reason_points` alongside `reasons` purely for this; it changes no arithmetic.
  - Empty state (`empty_state()`) before any check, instead of a blank page. `st.spinner("Checking…")` while analysing.
  - "Compare page (optional)" expander: saved HTML gives content similarity %, screenshots give visual similarity %. A close copy on a different domain shows strong phishing evidence. The 70% content and 80% visual cut-offs are judgement calls.
- **Check a message:** five example buttons (`MESSAGE_EXAMPLES`), a text area and an optional sender box. Verdict card (Scam borrows the Phishing colour via `VERDICT_COLORS`), three tiles (Wording score, Worst link score, Links found), the message in a chat bubble with risky words marked (`highlight_message()`, every piece `html.escape`d), a table of the links found with each verdict and closeness, reason chips, the sender note, a calm "What to do" card when not Safe, and the result as JSON. An expander checks a CSV of messages.
- **Check a list:** drag-and-drop upload card, then three verdict count tiles and three speed tiles, a donut in the verdict colours (transparent background, height 280), a results table with coloured verdict pills, and CSV / JSON / Excel downloads in one row. An empty state before anything is uploaded.
- **How it works:** three numbered step cards (Rules → ML → Final verdict), the message section, the three scores, model metrics as stat tiles with data notes and a calibration table, the feature-importance chart, the synthetic test table, speed and output formats.
- **Footer:** "Built by Team Ctrl-C-Ctrl-V · Hackfest 2026 · Works fully offline".
- UI rules of thumb: all user-supplied text put into HTML goes through `html.escape`; Plotly charts use `config={"displayModeBar": False}` and `style_chart()` (transparent background, Inter, muted grid); use `width="stretch"` (not `use_container_width`, which is deprecated in Streamlit 1.66); headings use `anchor=False`; sentence case everywhere.

## Message checking (`sms.py`)

Verdicts are Scam / Suspicious / Safe at the same 60 / 30 thresholds. `final = max(link score, text score)`, plus 10 when the link score is ≥60 and the text score ≥30.

- **Links:** `find_links()` makes two passes. The first reads the text as written, so each link has a span and can be highlighted; the second reads `deobfuscate(text)` and picks up hidden links, which have `span=None`. `deobfuscate` handles `hxxp`, `[.]`/`(.)`/`[dot]`, " dot " and a space before the dot. The space-before-dot rule is deliberate: ordinary writing never puts a space before a full stop, so "blocked today. Update" is not glued into `today.Update`, but "sbi-kyc . xyz" is joined. Each link then goes through `full_analysis()` unchanged.
- **Shorteners** (`SHORTENERS`) cannot be expanded offline, so their link score is floored at 45 and they add +20 to the text score.
- **Wording:** `SIGNALS` is a list of {name, points, reason, patterns}. Word stems are written `disconnect\w*`, never `disconnect\b`, which would miss "disconnected" — that bug silently disabled several signals once. A signal matching 2+ of its own patterns counts for half as much again.
- **The genuine-OTP guard matters most.** Only a *request* counts ("share the OTP", "enter your UPI PIN to receive"), never a message that gives you one. Genuine bank OTPs must stay Safe, and `test_rules.py` has cases both ways.
- **Brand mismatch** uses `without_links()`, which blanks every link out of the text (after de-obfuscation) before looking for brand names. Without it, `sbi-kyc.xyz` would itself prove the message "says SBI", which is circular and double-counts the domain check.
- **Sender** (`check_sender`): `AD-SBIBNK`, optionally with a `-P`/`-S`/`-T`/`-G` category letter that operators add since May 2025. A mobile number only scores points when the message also names a brand. Soft on purpose: a sender is trivially faked.
- **Helpline numbers in `WHAT_TO_DO` were checked in November 2026:** 1930 and cybercrime.gov.in for money already lost (1930 replaced 155260 in April 2022), and forwarding spam SMS to 1909. Re-check before changing them.
- Not built: the optional TF-IDF text classifier. The rules handle the test set, and the UCI SMS Spam Collection is English marketing spam rather than Indian scams, so it would need heavy caveats.

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
  - `FREE_HOSTING` has two parts, and the comment above it says which is which: the hosts listed by hand, and 30 more chosen from the data (count the feed hosts on each Tranco top-20,000 domain, rank them, take the first 30 not already listed, skipping one company's own site with no public hosting). If the feed is ever refreshed, redo that count before changing the list. It is still incomplete, and a popular site missing from it gets instant Safe for all its subdomains.
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
5. All five PS-08 deliverables are built (`deliverables` branch).
6. SMS scam check built on the `sms-check` branch (see the Message checking section).
7. Still open: one-typo fakes of 3-4 letter brands (`bsi.co.in`) are missed on purpose; `FREE_HOSTING` is still incomplete below the top 30; the model's signal is mostly address structure, not look-alikes. Synthetic tests: 1.7 ms per domain as a list, false alarms 5.8%.

## How to work with me

- Keep code simple and well commented. Add a new file only when one is really needed.
- Test before saying something works.
- Run python test_rules.py after every change (323 checks, about 35 seconds).
- Give Windows commands (CMD or PowerShell), not Linux/Mac commands.
