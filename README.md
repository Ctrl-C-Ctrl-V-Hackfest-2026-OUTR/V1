# 🛡️ Kavach

**Spot fake bank and shopping sites before you click.**

Kavach is an offline phishing-domain detector built for Hackfest 2026 (Cybersecurity & Digital Trust, problem statement PS-08). Paste a link or upload a list of domains and Kavach tells you whether each one is **Safe**, **Suspicious** or **Phishing**, with a risk score from 0 to 100 and the reasons behind it. It is aimed at look-alike domains that imitate Indian banks, UPI apps and popular shopping sites, such as `paytrn.com` (pretending to be `paytm.com`) or `sbi-kyc-update-now.top`.

It works fully offline: no WHOIS, no online lookups, no API calls. Everything runs on your machine.

## Screenshot

<!-- TODO: replace with a real screenshot of the app, e.g. save it as docs/screenshot.png -->
![Kavach screenshot](docs/screenshot.png)

*Screenshot coming soon.*

## How it works

Every domain goes through two checks that are combined into one verdict, and you always see three numbers:

- **Closeness:** how similar the *whole* name is to the nearest genuine site, 0-100%, from Damerau-Levenshtein distance after fixing fake letters. Only the real site itself gets 100%. A brand copied inside a longer name scores low here (`startamazonstore.net` is 38% similar to `amazon.in`), because that is reported separately as **Combosquatting**: "Contains the full brand name 'amazon' plus extra words 'start' and 'store'". The app also shows the attack type and the exact edits, such as `'rn' replaces 'm' at position 5`, with the changed letters highlighted.
- **Phishing probability:** the ML model's % chance that it is phishing.
- **Final risk score:** rules plus ML, from 0 to 100. This decides the verdict.

### 1. Rules (risk score 0-100)

These are **Safe straight away**, with no further checks:

- Known official domains (for example `sbi.co.in`, `amazon.com`, `amazon.in`).
- Anything under `.bank.in`, because only RBI-verified Indian banks can register there (for example `sbi.bank.in`).
- The top 20,000 most popular websites (for example `reddit.com`, `www.reddit.com`). Popular domains that imitate a brand are removed from this list.
- Subdomains of those popular websites (for example `accounts.spotify.com`), because they belong to the same owner. Free-hosting sites and subdomains naming another brand don't get this (see below).

Everything else gets a risk score. Of the look-alike checks (fake letters, one typo from a brand, looks like a brand, one typo from a top site), only the strongest match counts.

| Check | Points |
|---|---|
| `@` hiding the real address (`https://user@evil.com`), where the browser goes to the part after the `@` | +40 |
| The same, when the hidden part names a brand, official domain or `.bank.in` address (`sbi.bank.in@evil.com`) | +60 |
| Fake letters that spell a brand (`0` for `o`, `rn` for `m`, `vv` for `w`, Cyrillic letters, `xn--` names, ...) | +70 |
| One typo from a brand with 5+ letters (`yutube.com`). A short list of everyday words such as `tomato` skips this check | +60 |
| A short brand (3-4 letters) with nothing but scam words around it (`sbikyc.net`, `sbilogin.net`, `kycsbi.net`) | +60 |
| Name looks like a known brand (80%+ similar; a brand hidden inside the name counts as 90%) | +45 |
| One typo from a top-2,000 site, or fake letters that spell one (`rediit.com`) | +45 |
| A top-200 site's name on another ending, or with only scam words added (`reddit.xyz`, `reddit-login.com`) | +45 |
| Brand name used in a subdomain (e.g. `paytm.verify-account.click`) | +45 |
| Risky ending (`.xyz`, `.top`, `.click`, `.icu`, `.info`, ...) | +15 |
| Scam words (`login`, `verify`, `kyc`, `update`, `reward`, ...) | +10 each, max +20 |
| 2+ hyphens / digits in the name / very long domain | +10 / +5 / +5 |
| Raw IP address instead of a name | +30 |

A typo means inserting, deleting or changing one letter, or swapping two neighbouring letters.

A brand counts as hidden inside a name or subdomain if it is a whole hyphen-separated word (`sbi-kyc-update`, `kyc-paytm`), or, with the hyphens removed (`ama-zon-login` becomes `amazonlogin`):

- **6+ letters:** anywhere inside (`startamazonstore`, `myflipkartoffer`).
- **5 letters:** at the start of a word (`paytmkyc`).
- **3-4 letters:** when everything else is scam words (`sbikyc`, `sbilogin`, `kycsbi`). This exact pattern is a classic look-alike, so it scores +60 on its own.

So `pineapple.com` does not count as `apple`, and `lesbian.com` does not count as `sbi`.

Subdomains of popular sites are Safe, with two exceptions that skip the name check but get every other check:

- **Free-hosting sites** (`random.weebly.com`, `phish.s3.amazonaws.com`), because anyone can publish there. The list is partly chosen from the data: we counted how many hosts in the phishing feed sit on each Tranco top-20,000 domain and added the top 30 that offer public hosting.
- **Another brand's name in the subdomain** (`paytm.spotify.com`).

An `@` trick never gets an instant Safe. If the browser really ends up on a trusted site (`user@reddit.com`), only the `@` points count and the model is skipped.

### 2. Machine learning

A scikit-learn **RandomForest** looks at 12 features of the domain (length, hyphens, digits, dots, number of subdomains, vowel ratio, character randomness, risky ending, scam words, similarity to a known brand, brand in subdomain, fake-letter match) and returns the probability that the domain is phishing.

It was trained on the [PhiUSIIL Phishing URL dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset): **134,784 real sites** and **84,236 phishing hosts** after removing duplicates (PhiUSIIL labels 1 = legitimate, so `train.py` flips them). Tranco + Phishing.Database remain as a fallback (`python train.py --source tranco`).

Two data problems were found and handled:

- PhiUSIIL's own columns are not used. `URLSimilarityIndex` alone gets 99.7% accuracy, so it gives the answer away, and others need the live page.
- Every legit row starts `https://www.`, but only 41% of phishing rows do. A model that sees this flags every real site typed without `www` (100% of Tranco sites in our test), so the features ignore a leading `www.`.

The model is skipped for everything that is Safe straight away, including subdomains of popular sites (`en.wikipedia.org`, `login.yahoo.com`). Subdomains of free-hosting sites always go to the model, because anyone can publish there (`random.weebly.com`).

### 3. Final verdict

- If the ML probability is **70% or higher**: final score = the higher of the rule score and the average of the rule score and the ML probability.
- Otherwise: final score = the rule score.

So the ML model can only **raise** the risk, never lower it. The app shows which one decided the verdict ("Rules" or "Rules + ML").

**60 or more = Phishing, 30 to 59 = Suspicious, below 30 = Safe.**

Examples:

| Domain | Rule score | ML probability | Final | Verdict |
|---|---|---|---|---|
| `paytrn.com` | 70 | 59% | 70 | Phishing |
| `yutube.com` | 60 | 52% | 60 | Phishing |
| `sbi.bank.in@evil.com` | 60 | 12% | 60 | Phishing |
| `hdfc-bank-login.com` | 75 | 89% | 82 | Phishing |
| `sbi-kyc-update-now.top` | 90 | 94% | 92 | Phishing |
| `amazon.security-check.icu` | 60 | 99% | 79 | Phishing |
| `rediit.com` | 45 | 18% | 45 | Suspicious |
| `sbikyc.net` | 70 | 65% | 70 | Phishing |
| `google.com` | 0 | n/a | 0 | Safe |
| `sbi.bank.in` | 0 | n/a | 0 | Safe |
| `accounts.spotify.com` | 0 | n/a | 0 | Safe |

## Model metrics

Measured on **43,805 hosts** held out from training (80/20 split that keeps all hosts of one site together, so these are sites the model never saw):

| Accuracy | Precision | Recall | F1 |
|---|---|---|---|
| 85.3% | 93.5% | 66.4% | 77.6% |

Confusion matrix: 26,176 legit correct, 781 false alarms, 5,664 phishing missed, 11,184 phishing caught. The top features are number of subdomains, digits, risky ending, length and dots.

Calibration: when the model gives a percentage, how often is it really phishing?

| Model said | Domains | Actually phishing |
|---|---|---|
| 0-10% | 1,348 | 8% |
| 10-20% | 25,885 | 16% |
| 20-30% | 2,613 | 25% |
| 30-40% | 1,363 | 34% |
| 40-50% | 631 | 42% |
| 50-60% | 352 | 53% |
| 60-70% | 434 | 61% |
| 70-80% | 813 | 73% |
| 80-90% | 1,253 | 88% |
| 90-100% | 9,113 | 99% |

On the other data source, which it did not train on, at ML 70% or more: 2.4% of real Tranco sites flagged, 65.1% of Phishing.Database hosts caught.

**Honest caveats:**

- Calibration was measured at PhiUSIIL's mix of 38% phishing. Real traffic has far less phishing, so real-world precision will be lower.
- Much of the model's signal comes from how a domain is built (subdomains, digits, length), which partly reflects differences between the data sources rather than pure look-alike detection. The rules do the look-alike work; the model adds a second opinion.

## Tests on synthetic look-alikes

`lookalikes.py` generates fake domains of ten attack types from our brand list and the top 200 sites, plus real sites as negatives. Caught means Suspicious or Phishing.

| Attack type | Brands: rules | Brands: final | Top 200: rules | Top 200: final |
|---|---|---|---|---|
| missing_letter | 100% | 100% | 88% | 89% |
| extra_letter | 100% | 100% | 84% | 85% |
| swapped_letters | 96% | 96% | 90% | 90% |
| keyboard_neighbour | 93% | 93% | 84% | 84% |
| homoglyph | 98% | 98% | 91% | 92% |
| cyrillic | 100% | 100% | 93% | 93% |
| hyphen | 100% | 100% | 90% | 91% |
| combosquat | 99% | 99% | 76% | 86% |
| tld_swap | 100% | 100% | 77% | 86% |
| subdomain_abuse | 100% | 100% | 100% | 100% |

- **False alarms:** 5.8% of 2,000 real sites flagged (0.4% as Phishing), with the popular-site shortcut turned off so they can't pass automatically.
- **Known gap:** one-typo fakes of 3-4 letter brands (`bsi.co.in`, `joi.com`) are left out on purpose, because nearly any short word is one edit from them.
- **Speed:** 1.1 ms per domain as a list (881 domains/second), 6.4 ms when checked one at a time.

To re-run these:

```bat
python lookalikes.py
python evaluate.py
```

## Run it locally

You need Python 3 and Git. These steps are for Windows (Command Prompt or PowerShell). The project was built and tested with Python 3.14.

```bat
git clone https://github.com/Ctrl-C-Ctrl-V-Hackfest-2026-OUTR/V1.git
cd V1

python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

streamlit run app.py
```

The app opens at http://localhost:8501. Use the first tab to check a single link, and copy or download the result as JSON. Use the second tab to check a whole list: upload a CSV with a column named `domain` (see `sample_domains.csv`) or a text file with one domain per line, then download the results as CSV, JSON or Excel.

### Command-line tool

Check a list without opening the app. Works with a `.csv` that has a `domain` column, or a `.txt` with one domain per line:

```bat
python kavach_cli.py sample_domains.csv
python kavach_cli.py sample_domains.csv --format json --out results.json
python kavach_cli.py domains.txt --format xlsx --out results.xlsx
```

Each export has these columns: domain, verdict, final score, ML probability, nearest genuine site, closeness %, attack type, evidence, reasons, rule score and what decided it.

### Compare a page (optional)

In the first tab, open **Compare page** and upload saved copies of the suspicious and genuine pages. Saved HTML gives a content similarity % (title, form fields, visible text with TF-IDF cosine, image file names), and screenshots give a visual similarity % (perceptual hash and structural similarity). A close copy on a different domain is shown as strong phishing evidence. Nothing is fetched from the internet, uploaded files are only read, and this doesn't change the risk score.

The trained model (`model.joblib`) is included in the repo, so you do not need to train anything. If it is missing, the app still works with the rule-based score only.

### Run the tests

```bat
python test_rules.py
```

One command runs everything, in about 30 seconds. It prints a table per section, a summary, and exits with code 1 if anything fails:

| Section | What it checks |
|---|---|
| Links | The expected verdict for each test link |
| Evidence | Nearest genuine site, closeness %, attack type, the exact edits and the reason text |
| Exports and command-line tool | CSV, JSON and Excel columns, formula-safe cells, and `kavach_cli.py` run for real |
| Page comparison | Saved HTML and screenshot similarity, on pages made up inside the test |
| App (headless) | The real `app.py` driven by Streamlit's test tool: verdict card, evidence box, downloads and error messages |

Expected verdicts are what a link *should* get, so if a test fails, look at why before changing it. A few verdicts are decided by the ML model and are marked with a comment: retraining can flip those.

**Check these by eye before a demo** (no test can see them):

- The app in a browser: colours, spacing and the dark theme.
- The red, green and grey letters in the evidence box line up as expected.
- A real CSV upload, and that the downloaded CSV, JSON and Excel files open properly.
- The page comparison with a page you really saved from a browser, rather than the made-up ones in the test.

### Retrain the model (optional)

```bat
python train.py
```

The first run downloads PhiUSIIL into `data/` (needs internet once, about 15 MB). After that it works offline. If the download fails, it tells you how to get the file by hand. It prints a leakage check, accuracy, precision, recall, F1, the confusion matrix and calibration, then rewrites `model.joblib`, `feature_importance.csv` and `metrics.json`.

## Project files

| File | What it does |
|---|---|
| `app.py` | Streamlit app: the user interface |
| `detector.py` | Detection logic: rule-based score and ML blend |
| `evidence.py` | Similarity evidence: closeness, attack type and exact edits |
| `outputs.py` | Fast list checking and CSV, JSON and Excel export |
| `kavach_cli.py` | Command-line tool |
| `page_compare.py` | Optional comparison of saved pages and screenshots |
| `features.py` | Shared brand list, trusted and free-hosting lists, scam words, look-alike logic and ML features |
| `lookalikes.py` | Generates synthetic look-alikes into `data/synthetic_pairs.csv` |
| `evaluate.py` | Tests detection per attack type, false alarms and speed; writes `evaluation.json` |
| `test_rules.py` | All the tests in one command: links, evidence, exports, page comparison and the headless app |
| `popular_domains.txt` | The top popular sites, most popular first |
| `build_popular.py` | Rebuilds `popular_domains.txt` from `data/tranco.csv` and prints what it removed |
| `train.py` | Downloads data, trains and evaluates the model |
| `model.joblib` | Trained RandomForest |
| `metrics.json`, `feature_importance.csv` | Test metrics, calibration and top features from the last training run |
| `evaluation.json` | Results of the last `evaluate.py` run |
| `sample_domains.csv` | 10 test domains, a mix of real and fake |
| `requirements.txt` | Pinned package versions |

## Team

Built by Team Ctrl-C-Ctrl-V for Hackfest 2026.
