# 🛡️ Kavach

**Spot fake bank and shopping sites before you click.**

Kavach is an offline phishing-domain detector built for Hackfest 2026 (Cybersecurity & Digital Trust, problem statement PS-08). Paste a link or upload a list of domains and Kavach tells you whether each one is **Safe**, **Suspicious** or **Phishing**, with a risk score from 0 to 100 and the reasons behind it. It is aimed at look-alike domains that imitate Indian banks, UPI apps and popular shopping sites, such as `paytrn.com` (pretending to be `paytm.com`) or `sbi-kyc-update-now.top`.

It works fully offline: no WHOIS, no online lookups, no API calls. Everything runs on your machine.

## Screenshot

<!-- TODO: replace with a real screenshot of the app, e.g. save it as docs/screenshot.png -->
![Kavach screenshot](docs/screenshot.png)

*Screenshot coming soon.*

## How it works

Every domain goes through two checks that are combined into one verdict.

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
| Fake letters that spell a brand (`0` for `o`, `rn` for `m`, `vv` for `w`, ...) | +70 |
| One typo from a brand with 5+ letters (`yutube.com`). A short list of everyday words such as `tomato` skips this check | +60 |
| Name looks like a known brand (80%+ similar; a brand hidden inside the name counts as 90%) | +45 |
| One typo from a top-2,000 site (`rediit.com`) | +45 |
| Brand name used in a subdomain (e.g. `paytm.verify-account.click`) | +45 |
| Risky ending (`.xyz`, `.top`, `.click`, `.icu`, `.info`, ...) | +15 |
| Scam words (`login`, `verify`, `kyc`, `update`, `reward`, ...) | +10 each, max +20 |
| 2+ hyphens / digits in the name / very long domain | +10 / +5 / +5 |
| Raw IP address instead of a name | +30 |

A typo means inserting, deleting or changing one letter, or swapping two neighbouring letters.

A brand counts as hidden inside a name or subdomain if it is a whole hyphen-separated word (`sbi-kyc-update`, `kyc-paytm`), or, with the hyphens removed (`ama-zon-login` becomes `amazonlogin`):

- **6+ letters:** anywhere inside (`startamazonstore`, `myflipkartoffer`).
- **5 letters:** at the start of a word (`paytmkyc`).
- **3-4 letters:** when everything else is scam words (`sbikyc`, `sbilogin`, `kycsbi`).

So `pineapple.com` does not count as `apple`, and `lesbian.com` does not count as `sbi`.

Subdomains of popular sites are Safe, with two exceptions that skip the name check but get every other check:

- **Free-hosting sites** (`random.weebly.com`, `paytm-login.weebly.com`), because anyone can publish there.
- **Another brand's name in the subdomain** (`paytm.spotify.com`).

An `@` trick never gets an instant Safe. If the browser really ends up on a trusted site (`user@reddit.com`), only the `@` points count and the model is skipped.

### 2. Machine learning

A scikit-learn **RandomForest** looks at 12 features of the domain (length, hyphens, digits, dots, number of subdomains, vowel ratio, character randomness, risky ending, scam words, similarity to a known brand, brand in subdomain, fake-letter match) and returns the probability that the domain is phishing.

It was trained on **19,966 popular sites** (Tranco top list) and **20,000 real phishing hosts** (Phishing.Database). Free-hosting sites such as `github.io` and `blogspot.com` were removed from the phishing side so the model does not just learn "has a subdomain = phishing".

The model is skipped for everything that is Safe straight away, including subdomains of popular sites (`en.wikipedia.org`, `login.yahoo.com`). Subdomains of free-hosting sites always go to the model, because anyone can publish there (`random.weebly.com`).

### 3. Final verdict

- If the ML probability is **70% or higher**: final score = the higher of the rule score and the average of the rule score and the ML probability.
- Otherwise: final score = the rule score.

So the ML model can only **raise** the risk, never lower it. The app shows which one decided the verdict ("Rules" or "Rules + ML").

**60 or more = Phishing, 30 to 59 = Suspicious, below 30 = Safe.**

Examples:

| Domain | Rule score | ML probability | Final | Verdict |
|---|---|---|---|---|
| `paytrn.com` | 70 | 17% | 70 | Phishing |
| `yutube.com` | 60 | 14% | 60 | Phishing |
| `sbi.bank.in@evil.com` | 60 | 5% | 60 | Phishing |
| `hdfc-bank-login.com` | 75 | 90% | 82 | Phishing |
| `sbi-kyc-update-now.top` | 90 | 99% | 95 | Phishing |
| `amazon.security-check.icu` | 60 | 100% | 80 | Phishing |
| `rediit.com` | 45 | 10% | 45 | Suspicious |
| `sbikyc.net` | 55 | 17% | 55 | Suspicious |
| `google.com` | 0 | n/a | 0 | Safe |
| `sbi.bank.in` | 0 | n/a | 0 | Safe |
| `accounts.spotify.com` | 0 | n/a | 0 | Safe |

## Model metrics

Measured on a held-out test set of **7,994 domains** the model never saw during training (80/20 split):

| Accuracy | Precision | Recall | F1 |
|---|---|---|---|
| 85.3% | 90.4% | 79.0% | 84.3% |

The top features are domain length, number of subdomains, character randomness, digits and dots.

**Honest caveat:** much of the model's signal comes from how a domain is built (length, subdomains), which partly reflects differences between the two data sources rather than pure look-alike detection. The rules do the look-alike work; the model adds a second opinion.

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

The app opens at http://localhost:8501. Use the first tab to check a single link. Use the CSV tab to check a whole list: upload a CSV with a column named `domain` (see `sample_domains.csv`) and download the results.

The trained model (`model.joblib`) is included in the repo, so you do not need to train anything. If it is missing, the app still works with the rule-based score only.

### Retrain the model (optional)

```bat
python train.py
```

The first run downloads the training data into `data/` (needs internet once, about 20 MB). After that it works offline. It prints accuracy, precision, recall, F1 and the confusion matrix, then rewrites `model.joblib`, `feature_importance.csv` and `metrics.json`.

## Project files

| File | What it does |
|---|---|
| `app.py` | Streamlit app: rule-based score, ML blend and the user interface |
| `features.py` | Shared brand list, trusted and free-hosting lists, scam words, look-alike logic and ML features |
| `popular_domains.txt` | The top popular sites, most popular first |
| `build_popular.py` | Rebuilds `popular_domains.txt` from `data/tranco.csv` and prints what it removed |
| `train.py` | Downloads data, trains and evaluates the model |
| `model.joblib` | Trained RandomForest |
| `metrics.json`, `feature_importance.csv` | Test metrics and top features from the last training run |
| `sample_domains.csv` | 10 test domains, a mix of real and fake |
| `requirements.txt` | Pinned package versions |

## Team

Built by Team Ctrl-C-Ctrl-V for Hackfest 2026.
