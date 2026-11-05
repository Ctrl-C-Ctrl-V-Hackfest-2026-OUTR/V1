# Kavach – Project Context

## About the project

- 36-hour hackathon, 4-person team. Track: Cybersecurity & Digital Trust.
- Problem statement **PS-08: Phishing Domain Detection**. Detect look-alike phishing domains (e.g. fake bank and UPI sites). Must work **offline**: no live WHOIS or online lookups.
- I'm the main builder. Teammates handle UI design and pitching, so keep the tech stack **simple** and the UI **clean and good-looking**.
- I'm a beginner-to-intermediate Python user on **Windows**. Explain commands briefly.

## Environment (already set up)

- Windows, Python 3, Command Prompt / PowerShell.
- A working venv exists at `C:\Users\Subham Mishra\Desktop\HACKFEST\venv` with: pandas, scikit-learn, rapidfuzz, tldextract, streamlit, plotly.
- Activate (CMD): `venv\Scripts\activate`. **Run the project: `python server.py`** (opens http://127.0.0.1:8000).
- **The website is the one interface for new work.** Build new features into `frontend/index.html`, `server.py` and the Python backend. `app.py` and `style.css` (Streamlit) stay as they are, with no new features; keep the App section of `test_rules.py` passing.
- OCR is optional: `pip install -r requirements-ocr.txt`, then `python ocr.py --setup` (installed in the venv already).
- If working in a new folder, create a fresh venv there and install the same packages.

## Official deliverables (PS-08)

Judged on closeness/probability scores, detection speed, ease of use and flexible output formats. Key constraint: "Explain the similarity evidence and make probability or closeness scores visible."

1. Automated detection of look-alike phishing domains.
2. Offline labelled URL data (PhiUSIIL sample replaces WHOIS) and synthetic look-alike pairs.
3. Similarity analysis against genuine domains, using content/code or page images as feasible.
4. Probability or closeness scores.
5. Fast detection with usable output in flexible formats.

## Code layout

- `server.py`: start here. Standard-library web server for the website and its JSON API. See "Website frontend" below. Must not import `app.py` or streamlit.
- `frontend/index.html`: the Kavach website, one file with no build step (inline CSS and JS; Google Fonts only).
- `app.py`: the older Streamlit UI. No new features. Note: an unrelated old Flask `app.py` is in Downloads. Ignore it.
- `brands.json`: the watchlist, as data (see "The watchlist" below). `brands_custom.json`: brands added on the page, local and gitignored.
- `datasets.py`: `python datasets.py` downloads missing data into `data/`, writes the held-out `data/realworld_test.csv` and `data_sources.json` (committed: source, date, rows, licence). Build-time only.
- `ocr.py`: `read_image(bytes)`, `scan_image(bytes, mode, bundle)`, `scan_text(text, mode, bundle)`, `ocr_status()`. See "Screenshot scan" below. Must not import `app.py` or streamlit.
- `browser_check.py`: drives the website in Edge with Playwright (`pip install playwright`, not a requirement).
- `detector.py`: `analyze()`, `full_analysis()`, `lookalike_target()`, `explain()`, `load_model()`. Must not import `app.py` or streamlit.
- `evidence.py`: `similarity_evidence()` gives nearest genuine domain, closeness, edit distance, attack type and exact edits. `align()` is the letter-by-letter alignment. Closeness is whole-name Damerau-Levenshtein similarity after fixing fake letters, and `_result()` caps it at 99% for anything that is not the genuine site, so a fake never shows 100%. A brand copied inside a longer name scores low and is reported as `combosquat` instead, with the line "Contains the full brand name 'amazon' plus extra words...".
- `outputs.py`: `check_many()` scores a whole list in one model call, plus `to_csv`, `to_json`, `to_xlsx`. Exports show cells starting with `= + - @` as text, so a spreadsheet can't run them.
- `kavach_cli.py`: `python kavach_cli.py input.csv|input.txt --format csv|json|xlsx --out file`.
- `test_rules.py`: `python test_rules.py` runs everything in about a minute and exits with code 1 on any failure. Sections: Links (`LINK_CASES`), More links (`test_links.csv`), Messages, More messages (`test_messages.csv`), Message details, Evidence, Exports and command-line tool, Page comparison, Server (a real `server.py` on a free port, with a temporary `KAVACH_CUSTOM_BRANDS` file), OCR (says "skipped" if not installed) and App (headless). In the CSV files a note starting `known_gap` is a case we know is wrong: it is listed as a known miss, and doesn't fail the run. A section that raises counts as one failed check, so one missing package can't hide the rest. Must not import `app.py`.
- `lookalikes.py`: `python lookalikes.py` writes `data/synthetic_pairs.csv` (gitignored; genuine, lookalike, attack_type).
- `evaluate.py`: `python evaluate.py` prints the synthetic test, the real-world test and the message tests, separately, and writes `evaluation.json` (committed; the website reads it).
- `page_compare.py`: optional saved-page comparison. Reads uploads only, fetches nothing, never changes the risk score.
- `sms.py`: `check_message(text, sender, bundle)` for a pasted SMS / WhatsApp / email. Holds `find_links`, `deobfuscate`, `SIGNALS`, `check_sender`, `WHAT_TO_DO` and `MESSAGE_COLUMNS`. Must not import `app.py` or streamlit.

## Detection rules (`detector.py`)

Rule-based risk score (0–100) per domain:

These return Safe (score 0) straight away, in this order:

- Known official domains in `LEGIT_DOMAINS`.
- Anything under `.bank.in`, `.gov.in` or `.nic.in` (`TRUSTED_ENDINGS`): only RBI-verified banks or government bodies can register there. None of the 413,000 feed hosts is on `.gov.in` or `.nic.in`. They can still be hacked. `.fin.in` (RBI's ending for NBFCs) is not added yet.
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
6. Brand in a subdomain (`subdomain_brand()`, same word test as rule 3, e.g. `paytm.verify-account.click`): +45, so brand-in-subdomain plus a suspicious TLD always reaches 60 (Phishing). A protected ending used as a disguise (`sbi.gov.in.evil.com`): +60.
7. Suspicious TLDs (xyz, top, tk, click, online, info…, plus xin, bond, help, cyou, cfd, sbs, added because phishing is 6+ times as common there as among real sites): +15.
8. Scam words (login, verify, kyc, update, reward…): +10 each, max +20.
9. ≥2 hyphens +10, digits +5, length >30 +5, raw IP +30.
10. A subdomain of a `FREE_HOSTING` site: a floor of 30 (Suspicious). It is left out of the ML average (`floor_added`), so it means "unknown owner", not more risk, and never reaches Phishing alone.

All the points are in `POINTS` in `detector.py`. `signal_catalog()` builds the website's signals grid from them, so the page can't drift from the code.

- Verdict: ≥60 Phishing, 30–59 Suspicious, <30 Safe. Every verdict shows the reasons, and each reason quotes its evidence (`Many hyphens: 3 in '...'`, `One typo away from 'youtube': missing 'o' at position 2`).
- `popular_domains.txt` (committed, 19,998 domains in rank order) is made by `python build_popular.py` from `data/tranco.csv`. It removes domains that imitate a brand and prints what it removed. Real sites that only look like a match stay in its `KEEP` dict (mail.com, kodak.com, telegra.ph, googl.com…).
- The app ignores URL paths. `sites.google.com/view/...` is Safe because `google.com` is official, so that `FREE_HOSTING` entry has no effect.
- tldextract runs offline: `tldextract.TLDExtract(suffix_list_urls=())`.

## The watchlist

`features.py` loads `brands.json` plus `brands_custom.json` into `BRAND_RECORDS` and `BRANDS` (name -> real domains, aliases included). These are changed in place by `_load_brands()`, never replaced, and `on_brands_changed()` tells `evidence.py` and `sms.py` to rebuild. Each record: `key`, `name`, `category`, `domains` (first = "the real site"), `words` (how a message names it), `checked`, `proof`, and optionally:

- `aliases` (`hdfc`, `canara`, `aadhaar`) and `no_typo`: match when exact or hidden, never as a typo or "looks similar". `no_typo` = new names of 6 letters or fewer, or with 5+ real names one edit away on the Tranco top 1M.
- `weak` and `weak_aliases` (`navi`, `axis`, `lic`): also ordinary words, so they only match with nothing but scam words around them.

`normalize()` turns `rn` into `m`, so names are compared in their normalized form (`_BRAND_FORMS`), or `karnatakabank-login` would never match. Digits in a key don't work well, so `5paisa` was left out. The 42 older keys keep their original behaviour.

`add_custom_brand()` refuses anything that would turn a fake into a trusted site. Don't grow `popular_domains.txt` to widen coverage: a bigger instant-Safe list lets more compromised sites through.

## Website frontend (`frontend/index.html` + `server.py`)

The main interface. It does no detection of its own when the server is running: every verdict, score, closeness, ML probability, message check and export comes from the Python code. It replaces everything the Streamlit app offers.

- Run: `python server.py` (opens http://127.0.0.1:8000; `--port`, `--no-browser`). It listens on this computer only, checks the `Host` and `Origin` headers, and never goes online.
- API (JSON unless noted): `GET /api/health` (with `ocr`), `GET /api/stats` (everything the page shows: metrics, evaluation split into `real_world` and synthetic, `signals`, `message_signals`, `sources`, live `examples`), `GET /api/brands`, `POST /api/brands {name, domain}`, `POST /api/brands/remove {key}`, `POST /api/check {url}`, `POST /api/bulk {domains}` (up to 20,000), `POST /api/message {text, sender}`, `POST /api/messages {content, filename}` and `/api/messages/export` (a whole file), `POST /api/export {format, domains}`, `POST /api/compare` (base64 files, page_compare.py), `POST /api/image?mode=auto|sms|website` (raw image bytes, 8 MB), `POST /api/image/text {text, mode}` (corrected text from a website screenshot; a message uses `/api/message`).
- **Nothing that can go stale is hard-coded in the page.** The numbers strip, How it works examples, signals grids and the measured panel all read `/api/stats`. Real-feed and synthetic numbers are shown apart, never blended.
- The page maps results in `fromPy()`: Phishing / Suspicious / Safe become its red / amber / green; official domains and restricted endings show as "Verified official"; each reason in `reasons` (split on `; `, matched to `reason_points`) becomes a signal row with a short label from `PYLABELS`. Add a label there when adding a rule.
- Red, amber and green are for verdicts only. All user-supplied and OCR text goes through `esc()` before reaching HTML.
- Fallback: opened as a plain file, or if the server stops, a small rules-only engine in the browser takes over (its own 16 brands, cut-offs 70 / 40, no ML) and the badge says so. Screenshot scan, message files and page comparison say they need the server instead of faking a result. Brands added while the server is off stay in the browser, then move to the server when it is back.
- The page sends at most 10,000 domains to the API (1,000 per request); a longer list is scored in the browser.
- Edit `frontend/index.html` directly (refresh the browser; the server sends `Cache-Control: no-store`). Check it with `python browser_check.py`.

## Screenshot scan (`ocr.py`)

RapidOCR + onnxruntime, chosen by measuring it against EasyOCR (table in README). One Latin pass with the bundled PP-OCRv6 models, then the Devanagari model on each line, keeping its reading when it really read Hindi. The angle classifier is off: it flips Devanagari lines, and screenshots are upright. `RapidOCR` remembers call flags, so always pass `use_det`, `use_cls` and `use_rec`.

- Images stay in memory, and are never logged or written. Exact model paths mean nothing can be downloaded at check time. Type comes from the first bytes. `MAX_BYTES` 8 MB, `MAX_PIXELS` 40 million.
- `repair_text()` rejoins links that wrapping or OCR broke. Website mode looks for an address in the top 20% or bottom 14%, on a line with at most 2 words.
- Page evidence is separate and may only raise the verdict: brand claimed + secrets asked + address not that brand's and not trusted = at least 45, or 60 if the address already scored 30+. Page wording alone never decides. No address = `Unclear`, and much of an image unreadable turns Safe into `Unclear` (`POOR_READ_SHARE`).
- Odia isn't supported: no bundled model has the script. `KAVACH_NO_OCR=1` makes the server behave as if OCR isn't installed.

## Message checking (`sms.py`)

Verdicts are Scam / Suspicious / Safe at the same 60 / 30 thresholds. `final = max(link score, text score)`, plus 10 when the link score is ≥60 and the text score ≥30.

- **Links:** `find_links()` makes two passes. The first reads the text as written, so each link has a span and can be highlighted; the second reads `deobfuscate(text)` and picks up hidden links, which have `span=None`. `deobfuscate` handles `hxxp`, `[.]`/`(.)`/`[dot]`, " dot " and a space before the dot. The space-before-dot rule is deliberate: ordinary writing never puts a space before a full stop, so "blocked today. Update" is not glued into `today.Update`, but "sbi-kyc . xyz" is joined. Each link then goes through `full_analysis()` unchanged.
- **Shorteners** (`SHORTENERS`) cannot be expanded offline, so their link score is floored at 45 and they add +20 to the text score.
- **Wording:** `SIGNALS` is a list of {name, points, reason, patterns}. Word stems are written `disconnect\w*`, never `disconnect\b`, which would miss "disconnected" — that bug silently disabled several signals once. A signal matching 2+ of its own patterns counts for half as much again. Devanagari patterns are plain text without `\b` (vowel signs aren't word characters in Python), and stop at the danda (`।`) as well as a full stop.
- **The genuine-OTP guard matters most.** Only a *request* counts ("share the OTP", "enter your UPI PIN to receive"), never a message that gives you one, and `NEGATED` drops a negated match ("Never share your OTP", "किसी के साथ साझा न करें"). Genuine bank OTPs must stay Safe, and `test_rules.py` has cases both ways.
- **Brand mismatch** uses `without_links()`, which blanks every link out of the text (after de-obfuscation) before looking for brand names. Without it, `sbi-kyc.xyz` would itself prove the message "says SBI", which is circular and double-counts the domain check.
- **Sender** (`check_sender`): `AD-SBIBNK`, optionally with a `-P`/`-S`/`-T`/`-G` category letter that operators add since May 2025. A mobile number only scores points when the message also names a brand. Soft on purpose: a sender is trivially faked.
- **Helpline numbers in `WHAT_TO_DO` were checked in November 2026:** 1930 and cybercrime.gov.in for money already lost (1930 replaced 155260 in April 2022), and forwarding spam SMS to 1909. Re-check before changing them.
- Not built: the optional TF-IDF text classifier. The UCI SMS Spam Collection is English marketing spam rather than Indian scams, so it is only used as a false-alarm check on real everyday messages.
- `test_messages.csv` has three sets: `dev` (used while tuning), `holdout` (written first, printed once while tuning, so lightly contaminated) and `holdout2` (written after the rules were final, scored once). Don't tune against `holdout2`: add a new set instead.

## Machine-learning model

Added on the `ml-model` branch. The rule-based score above is kept; the model adds a second opinion.

- `features.py`: shared logic used by every other file. Holds `BRANDS`, `LEGIT_DOMAINS`, `TRUSTED_ENDINGS`, `FREE_HOSTING`, `ORDINARY_WORDS`, the `POPULAR_*` lists, `SUSPICIOUS_TLDS`, `SUSPICIOUS_WORDS`, `HOMOGLYPHS`, `normalize`, `brand_match`, the look-alike helpers and `extract_features`. It must not import `app.py` (importing `app.py` starts the Streamlit UI). `extract_features` ignores a leading `www.`.
- 12 features per domain: length, hyphens, digits, dots, subdomain count, vowel ratio, character entropy, suspicious TLD, scam-word count, best brand similarity, brand in subdomain, homoglyph match.
- `train.py`: run `python datasets.py` once, then `python train.py`. The default `mixed` source is PhiUSIIL + 60,000 Tranco top-1M sites + 120,000 Phishing.Database hosts (`load_mixed()`). `--source phiusiil` and `--source tranco` also work, and `--out folder` saves elsewhere. Every registered domain in `data/realworld_test.csv` is dropped first. OpenPhish and PhishTank are never trained on.
  - PhiUSIIL labels 1 = LEGITIMATE, so it flips them to 1 = phishing and stops if known hosts (`KNOWN_HOSTS`) have the wrong label.
  - One row per host, without `www.`; drops official brand domains (their rows are redirects like google.com/url?q=...) and hosts with both labels.
  - PhiUSIIL's own columns are never used: `URLSimilarityIndex` alone gets 99.7%. Training stops if any of our features reaches 98% alone.
  - The `www` leak: all legit rows start `https://www.`, only 41% of phishing rows do. Seeing `www` makes the model flag 100% of real sites typed without it.
  - 80/20 split by registered domain (`StratifiedGroupKFold`), RandomForest (100 trees, max_depth=14, min_samples_leaf=2, seed 42).
  - Writes `model.joblib` (joblib compress=3), `feature_importance.csv` (top 10) and `metrics.json` (with calibration).
- Blend rule in `score_link()` in `detector.py`:
  - ML probability >= 70%: final score = max(rule score, (rule score + ML probability × 100) / 2). The free-hosting floor is left out of that average.
  - ML probability < 70%: final score = rule score.
  - So ML can only raise the score, never lower it. Same verdict thresholds (60 / 30).
  - The UI shows "Decided by": `Rules` or `Rules + ML` (the latter only when ML actually raised the score).
  - These skip the model (results from `settled()` in `detector.py`, which have a `note` that `explain()` shows): official domains, `.bank.in`, `.gov.in`, `.nic.in`, popular sites and their subdomains, and an `@` trick whose real host is one of those.
  - `FREE_HOSTING` (in `features.py`) has three parts, and the comments there say how each was chosen. The newest uses older feed data only: 14+ hosts and offers public hosting. If the feed is refreshed, redo that count before changing the list. It is still incomplete (`us.cc`, `edgeone.dev`), and a popular site missing from it gets instant Safe for all its subdomains.
  - If `model.joblib` is missing, the app shows the rule score only with a warning.
- Results are in README ("How well it works"), `evaluation.json` and `metrics.json`, and the website reads those two files. Don't copy numbers into code. Three separate tests, never blended: real feeds (`real_world`), synthetic, and the ML model alone.
- On real feeds about 79% of phishing hosts are flagged but only about 17% are called Phishing: most contain no brand, so rules + ML reach Suspicious. Real-feed false alarms about 2.9%.
- Caveat for the pitch: much of the model's signal is subdomain and address structure, not look-alike detection. The rules still do the look-alike work. Probabilities are calibrated only at the test's mix; real traffic has far less phishing.
- `model.joblib` (about 8 MB), `feature_importance.csv` and `metrics.json` are committed, so teammates do not need to retrain. `data/` is not committed.

`sample_domains.csv` has 10 test domains (mix of real and fake, e.g. `paytrn.com`, `amaz0n-rewards.top`, `onlinesbi-kyc-update.xyz`).

## Known limits

1. One-typo fakes of `no_typo` and 3-4 letter names are missed on purpose.
2. Plain phishing names with no brand get Suspicious at best, or nothing: about 1 in 5 real feed hosts is missed.
3. A plain name on a risky ending reads as Suspicious when the ML model is 70%+ sure (`mybakery.xyz`). Ordinary words 80% similar to a brand read as Suspicious (`tomato.com`). Both are `known_gap` cases.
4. Real project pages on free hosting are Suspicious by design.
5. Odia screenshots aren't read. Photos of phone screens are untested: the tests use clean screenshots.
6. All scam messages in the tests are written by us. No open dataset of Indian scam SMS was found.

## How to work with me

- Keep code simple and well commented. Add a new file only when one is really needed.
- Test before saying something works.
- Run python test_rules.py after every change (865 checks, about a minute). Run python browser_check.py after changing the website.
- Give Windows commands (CMD or PowerShell), not Linux/Mac commands.
