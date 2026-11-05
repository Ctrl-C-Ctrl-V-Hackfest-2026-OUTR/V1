# 🛡️ Kavach

**Spot fake bank and shopping sites before you click.**

Kavach is an offline phishing-domain and SMS-scam detector built for Hackfest 2026 (Cybersecurity & Digital Trust, problem statement PS-08). Paste a link or upload a list of domains and Kavach tells you whether each one is **Safe**, **Suspicious** or **Phishing**, with a risk score from 0 to 100 and the reasons behind it. It is aimed at look-alike domains that imitate Indian banks, UPI apps and popular shopping sites, such as `paytrn.com` (pretending to be `paytm.com`) or `sbi-kyc-update-now.top`.

You can also paste a whole SMS, WhatsApp or email message, in English, Hinglish or Hindi: Kavach pulls out every link, checks each one, reads the wording for scam patterns and gives one verdict. Or drop in a **screenshot** of a message or a website and Kavach reads it first.

**To run it: `python server.py`** (see [Run it locally](#run-it-locally)). The website at http://127.0.0.1:8000 is the main interface.

It works fully offline: no WHOIS, no online lookups, no API calls. Everything runs on your machine.

## What it delivers for PS-08

| Deliverable | Where to see it |
|---|---|
| Automated detection of look-alike phishing domains | Domain check and Bulk scan on the website, or `kavach_cli.py`. See [How it works](#how-it-works) |
| Offline labelled data and synthetic look-alike pairs | PhiUSIIL and other offline data in place of WHOIS, plus `lookalikes.py`. See [Where the data comes from](#where-the-data-comes-from) |
| Similarity analysis against genuine domains | Nearest genuine site, closeness %, attack type and exact edits for every domain. [Compare a page](#compare-a-page-optional) adds saved pages and screenshots |
| Probability or closeness scores | Closeness %, ML phishing probability and final risk score are always shown |
| Fast detection in flexible formats | 0.9 ms per domain as a list, with CSV, JSON and Excel downloads. See [Synthetic look-alikes](#synthetic-look-alikes) for how it was measured |

## How it works

Every domain goes through two checks that are combined into one verdict, and you always see three numbers:

- **Closeness:** how similar the *whole* name is to the nearest genuine site, 0-100%, from Damerau-Levenshtein distance after fixing fake letters. Only the real site itself gets 100%. A brand copied inside a longer name scores low here (`startamazonstore.net` is 38% similar to `amazon.in`), because that is reported separately as **Combosquatting**: "Contains the full brand name 'amazon' plus extra words 'start' and 'store'". The app also shows the attack type and the exact edits, such as `'rn' replaces 'm' at position 5`, with the changed letters highlighted.
- **Phishing probability:** the ML model's % chance that it is phishing.
- **Final risk score:** rules plus ML, from 0 to 100. This decides the verdict.

### 1. Rules (risk score 0-100)

These are **Safe straight away**, with no further checks:

- Known official domains of the 181 brands on the watchlist (see [The watchlist](#the-watchlist)).
- Anything under `.bank.in`, because only RBI-verified Indian banks can register there (for example `sbi.bank.in`), and under `.gov.in` and `.nic.in`, because only Indian government bodies can. Not one of the 413,000 hosts in our phishing feeds is on `.gov.in` or `.nic.in`, while 33 of 1,192 real ones used to be flagged. Such a site can still be hacked, which no check of a name can see.
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
| A protected ending used as a disguise (`sbi.gov.in.evil.com`, `hdfc.bank.in.update.top`) | +60 |
| Name looks like a known brand (80%+ similar; a brand hidden inside the name counts as 90%) | +45 |
| One typo from a top-2,000 site, or fake letters that spell one (`rediit.com`) | +45 |
| A top-200 site's name on another ending, or with only scam words added (`reddit.xyz`, `reddit-login.com`) | +45 |
| Brand name used in a subdomain (e.g. `paytm.verify-account.click`) | +45 |
| Risky ending (`.xyz`, `.top`, `.click`, `.icu`, `.info`, `.cfd`, `.sbs`, `.help`, ...) | +15 |
| Scam words (`login`, `verify`, `kyc`, `update`, `reward`, ...) | +10 each, max +20 |
| 2+ hyphens / digits in the name / very long domain | +10 / +5 / +5 |
| Raw IP address instead of a name | +30 |
| A page on a free-hosting site, where anyone can publish | at least 30 (Suspicious) |

A typo means inserting, deleting or changing one letter, or swapping two neighbouring letters.

A brand counts as hidden inside a name or subdomain if it is a whole hyphen-separated word (`sbi-kyc-update`, `kyc-paytm`), or, with the hyphens removed (`ama-zon-login` becomes `amazonlogin`):

- **6+ letters:** anywhere inside (`startamazonstore`, `myflipkartoffer`).
- **5 letters:** at the start of a word (`paytmkyc`).
- **3-4 letters:** when everything else is scam words (`sbikyc`, `sbilogin`, `kycsbi`). This exact pattern is a classic look-alike, so it scores +60 on its own.

So `pineapple.com` does not count as `apple`, and `lesbian.com` does not count as `sbi`.

Subdomains of popular sites are Safe, with two exceptions that skip the name check but get every other check:

- **Free-hosting sites** (`random.weebly.com`, `phish.s3.amazonaws.com`), because anyone can publish there, so the address says nothing about who runs the page. These always score at least 30, so a real project on `github.io` shows as Suspicious too: that is deliberate. The list is chosen from the data: we count hosts in the older phishing feeds on each domain and add those with 14+ hosts that offer public hosting. Never from the held-out test rows.
- **Another brand's name in the subdomain** (`paytm.spotify.com`).

An `@` trick never gets an instant Safe. If the browser really ends up on a trusted site (`user@reddit.com`), only the `@` points count and the model is skipped.

### 2. Machine learning

A scikit-learn **RandomForest** looks at 12 features of the domain (length, hyphens, digits, dots, number of subdomains, vowel ratio, character randomness, risky ending, scam words, similarity to a known brand, brand in subdomain, fake-letter match) and returns the probability that the domain is phishing.

It is trained on 371,903 hosts: 191,881 real and 180,022 phishing. That is the [PhiUSIIL dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset), plus 60,000 real sites from the Tranco top 1 million and 120,000 hosts from Phishing.Database. The extra real sites taught it that a small real site can have digits or a cheap ending, which halved its false alarms on real sites. Everything in the held-out test set is kept out of training, by registered domain. To go back to PhiUSIIL alone: `python train.py --source phiusiil`.

Two data problems were found and handled:

- PhiUSIIL's own columns are not used. `URLSimilarityIndex` alone gets 99.7% accuracy, so it gives the answer away, and others need the live page.
- Every legit PhiUSIIL row starts `https://www.`, but only 41% of phishing rows do. A model that sees this flags every real site typed without `www` (100% of Tranco sites in our test), so the features ignore a leading `www.`.

The model is skipped for everything that is Safe straight away, including subdomains of popular sites (`en.wikipedia.org`, `login.yahoo.com`). Subdomains of free-hosting sites always go to the model, because anyone can publish there (`random.weebly.com`).

### 3. Final verdict

- If the ML probability is **70% or higher**: final score = the higher of the rule score and the average of the rule score and the ML probability.
- Otherwise: final score = the rule score.

So the ML model can only **raise** the risk, never lower it. The page shows which one decided the verdict ("Rules" or "Rules + ML").

**60 or more = Phishing, 30 to 59 = Suspicious, below 30 = Safe.**

Examples:

| Domain | Why | Verdict |
|---|---|---|
| `paytrn.com` | `rn` is a fake `m` | Phishing |
| `yutube.com` | One typo from a brand | Phishing |
| `sbi.bank.in@evil.com` | The address before `@` is hidden | Phishing |
| `hdfc-bank-login.com` | Brand plus scam words | Phishing |
| `sbi-kyc-update-now.top` | Brand, risky ending, scam words, hyphens | Phishing |
| `sbi.gov.in.evil.com` | Protected ending used as a disguise | Phishing |
| `rediit.com` | One typo from a popular site | Suspicious |
| `random.weebly.com` | Anyone can publish here | Suspicious |
| `google.com`, `sbi.bank.in`, `mha.gov.in` | Official or restricted | Safe |
| `accounts.spotify.com` | Subdomain of a popular site | Safe |

The website's How it works section shows two examples worked out live, with the current scores.

## Checking a whole message

The **Message scan** section takes a pasted message and an optional sender. It scores two things and takes the higher, with a small bonus when both are bad:

**1. Every link in the message** goes through all the domain checks above. Scammers break links so they are not clickable, and Kavach undoes each trick before checking:

| Written as | Read as |
|---|---|
| `hxxp://evil.com` | `evil.com` |
| `sbi-kyc[.]xyz`, `sbi-kyc(.)xyz` | `sbi-kyc.xyz` |
| `sbi dot xyz` | `sbi.xyz` |
| `paytm-kyc . top` | `paytm-kyc.top` |
| `(sbi-kyc.xyz).` | `sbi-kyc.xyz` |

A space *before* the dot is the giveaway, because ordinary writing never puts one there. That is why "your account will be blocked today. Update KYC" is not read as a link to `today.Update`, and `at 9.30 PM`, `Rs 25,00,000` and `ram@gmail.com` are left alone.

A shortened link (`bit.ly`, `tinyurl.com`, `cutt.ly`, `is.gd`, `t.ly`, `rb.gy`, `shorturl.at`, `goo.gl` and others; the full list is `SHORTENERS` in `sms.py`) cannot be expanded offline, so it is flagged: **"Shortened link hides the real address"**.

**2. The wording**, in English, Hinglish and Hindi (Devanagari), with points capped so no single phrase decides the verdict:

| Signal | Points |
|---|---|
| Sends an app file to install (`wedding-card.apk`) | +60 |
| Asks you to share an OTP, PIN, CVV or password | +40 |
| Threatens arrest: "digital arrest", FIR, CBI, money laundering, "press 9 to talk" | +40 |
| Asks for a remote-control app (AnyDesk, TeamViewer) | +40 |
| Promises a prize, lottery win, cashback or refund | +30 |
| Offers work from home, daily earnings or paid tasks | +30 |
| Offers an instant loan with no checks | +30 |
| Promises guaranteed or doubled returns | +30 |
| Claims money was sent to you by mistake | +30 |
| Asks you to download and install something | +30 |
| The words name a brand but the link is not that brand's site | +30 |
| Asks you to pay a UPI ID directly | +30 |
| Threatens a traffic fine or a blocked FASTag | +25 |
| Asks you to update KYC, PAN or Aadhaar | +20 |
| Pushes you to act immediately, or threatens to block your account | +20 |
| Claims a parcel, customs or electricity problem | +20 |
| Tells you to call a personal mobile number | +20 |
| A shortened link | +20 |
| Links to a chat account (`wa.me`, `t.me`) instead of a website | +15 |
| Promises easy money, a job, a loan or returns, and gives a link to claim it | +15 |
| Sent from a mobile number while claiming to be a brand (soft hint) | +15 |

A signal that matches two or more different wordings counts for half as much again. Hinglish (`band ho jayega`, `turant`, `OTP batao`, `galti se`, `ghar baithe`) and Hindi (`खाता बंद हो जाएगा`, `ओटीपी बताएं`, `डिजिटल अरेस्ट`) are covered.

**Genuine messages stay Safe.** Only a *request* for an OTP counts, never a message that gives you one, and a negated one ("Never share your OTP", "इसे किसी के साथ साझा न करें") doesn't count either. So "Your OTP for login is 482913. Do not share it with anyone. -HDFC Bank" scores 0. The same goes for transaction alerts ("Rs 500 debited from A/c XX1234... -SBI") and delivery updates that link to `amazon.in`.

**60 or more = Scam, 30 to 59 = Suspicious, below 30 = Safe**, the same thresholds as the link checks. Anything not Safe shows a "What to do" box: don't click, never share an OTP or PIN, call **1930** or report at **cybercrime.gov.in** if money is already gone, and forward spam SMS to **1909**.

Examples:

| Message | Verdict | Score |
|---|---|---|
| `Dear Customer, your SBI account will be blocked today. Update KYC now: sbi-kyc-update.xyz` | Scam | 100 |
| `Your electricity connection will be disconnected tonight at 9.30 PM. Call 98XXXXXX21 immediately.` | Scam | 70 |
| `Your parcel is held at customs. Pay ₹49 fee: indiapost-delivery.top` | Scam | 80 |
| `Congratulations! You won ₹25,00,000 in KBC lottery. Claim at bit.ly/kbc-win` | Scam | 80 |
| `Aapka SBI account band ho jayega. Turant KYC update kare: sbi-verify.top` | Scam | 100 |
| `Pay ₹10 to confirm delivery: scammer@ybl` | Suspicious | 30 |
| `Your OTP for login is 482913. Do not share it with anyone. -HDFC Bank` | Safe | 0 |
| `Rs 500 debited from A/c XX1234 on 05-11-26 to AMAZON. Not you? Call 18001234567 -SBI` | Safe | 0 |

**Sender check.** An Indian company SMS arrives from a registered DLT header: two letters for the operator and circle, then the brand's short name, such as `AD-SBIBNK` or `VM-HDFCBK`. Since May 2025 operators also add a category letter: `-P` promotional, `-S` service, `-T` transactional, `-G` government, as in `AD-SBIBNK-S`. A personal mobile number claiming to be a bank is a red flag. This stays a **soft** signal worth few points, because a sender is easy to fake, people paste it inconsistently, and plenty of genuine messages use other formats.

## The watchlist

181 brands live in **`brands.json`**, so adding one needs no code change: brokers and trading, cooperative bank, crypto exchange, electricity and gas, global tech, government, payments and wallets, payments bank, private bank, public sector bank, shopping and delivery, small finance bank, telecom. Each official domain was checked on its live website in November 2026, and the record keeps the proof (its page title, or the redirect it follows). The check found that most Indian banks have moved to `.bank.in`, with their old addresses redirecting there, and corrected several guesses (`dhan.bank.in`, `airtelpayments.bank.in`).

A longer watchlist can mean more false alarms, so each name was counted against the real sites on the Tranco top 1 million before it got any weight:

- **Most names** match exact, hidden in a longer name, or as a typo.
- **Names of 6 letters or fewer, or with 5+ real sites one edit away** (`aubank`, `groww`, `fedex`, `uber`, marked `no_typo`) only match exact or hidden. Otherwise real banks such as `abbank.vn` would be called Phishing.
- **Names that are also ordinary words** (`navi`, `axis`, `lic`, marked `weak`) only match with nothing but scam words around them (`navi-login`, `axis-kyc`). 77 real sites contain the word `navi`.

**The instant-Safe popular list was not made bigger.** A bigger list means more compromised sites and free-hosting subdomains pass unchecked. It stays at the top 20,000, and we audited it against the new brands: the 7 domains that sit close to a brand are unrelated real sites, not fakes.

**Add a brand on the website:** the page sends it to the server, which refuses anything that would turn a fake into a trusted site (`paytrn.com`, `abc.weebly.com`), stores it in `brands_custom.json` on this computer (not committed) and starts scoring look-alikes of it straight away, in links and messages. To add one for everyone, add a record to `brands.json` and run `python test_rules.py` and `python evaluate.py`.

## Screenshot scan

Drop in, choose or paste (Ctrl+V) a screenshot on the website. It stays in memory on this computer: it is never saved or logged, and no link found in it is ever opened.

- **A message or chat:** the text goes through the same message check, with the same verdicts and what-to-do steps.
- **A website:** Kavach looks for the address where a browser's address bar sits, checks it like any other link, then reads the page for what it claims to be and what it asks for (card number, CVV, PIN, OTP, Aadhaar, PAN, net banking password).
- **Auto** guesses which of these it is and says what it guessed and why.

**Page evidence is shown separately, and may only raise the verdict.** The address score is exactly what Domain check gives. Page wording never decides alone, because plenty of honest pages mention a bank or have a password box. It raises the verdict in one case: the page claims a brand, asks for secrets, and the address is not that brand's and is not a trusted site. That means at least Suspicious (45), or Phishing (60) if the address already looked wrong. The result says when this happened. If no address can be read, the verdict is **Unclear**, not Safe.

**OCR is never presented as certain,** because its mistakes (l and 1, rn and m, O and 0) are exactly the tricks look-alike domains use. So every link shows how sure the reading was, low-confidence lines are listed, a link that could be a misreading says so ("it may really say paytm.com"), and you can correct the text and check again. Cyrillic look-alike letters are invisible in a picture, so the page suggests copying the link as text. If much of an image can't be read, a Safe verdict becomes **Unclear**.

**Why RapidOCR.** Measured on 15 phone-style screenshots rendered in a real browser, Python 3.14 on Windows:

| | RapidOCR + onnxruntime | EasyOCR | Tesseract |
|---|---|---|---|
| Wheels for Python 3.14 | Yes | Yes | No wheel: separate Windows installer |
| Install size | 285 MB, models included | about 1,007 MB + 215 MB Hindi model | Not measured |
| Web addresses read correctly | 15 of 16 | 4 of 16: it drops dots and turns digits into Hindi numerals | Not measured |
| Text accuracy, English / Hindi | 99.8% / 97.8% | 95.2% / 90.3% | Not measured |
| Time per image, on this laptop's CPU | about 0.6 s | about 6.9 s | Not measured |
| Odia | No | No | Has an Odia model, not tested |

English and Hindi work. **Odia does not:** the text comes out as garbage, though links in the image are still found, and the verdict says Unclear rather than Safe when nothing else stands out.

Install it once (the rest of Kavach works without it, and the page explains how to turn it on):

```bat
pip install -r requirements-ocr.txt
python ocr.py --setup
```

`--setup` downloads the 8 MB Hindi model once. The English models come with the package. At check time Kavach names the exact model files, so nothing can be downloaded, and the tests run the whole scan with the network blocked.

## How well it works

There are three separate tests, and they answer different questions, so they are never blended into one headline number. Everything here is also on the website, read from `evaluation.json` and `metrics.json`.

### Real phishing feeds and real sites

This is the honest one. It is made first by `datasets.py`, and training then drops every registered domain in it. The phishing hosts were submitted since 2026-07-01 or are on today's feed. Only PhishTank has dates per row, so the training snapshot from Phishing.Database can't be split by date itself: it is kept apart by site instead. A strict check, training only on data dated before the cut, gave about the same recall (78.3%).

| Group | Hosts | Flagged | Called Phishing |
|---|---|---:|---:|
| Real: .gov.in and .nic.in | 1,192 | 0.0% | 0.0% |
| Real: .in sites below the top 20,000 | 3,000 | 1.7% | 0.2% |
| Phishing: OpenPhish community feed | 259 | 84.9% | 7.7% |
| Phishing: PhishTank, submitted since 2026-07-01 | 6,098 | 78.4% | 17.0% |
| Real: sites ranked below the top 20,000 | 5,000 | 4.3% | 0.1% |

| | Recall | False alarms | Precision at this mix |
|---|---:|---:|---:|
| Flagged (Suspicious or Phishing) | 78.6% | 2.89% | 94.9% |
| Called Phishing | 16.6% | 0.11% | 99.1% |

**Read this honestly.** Most real phishing hosts don't contain a brand name, so they get **Suspicious**, not Phishing. About 1 in 5 real feed hosts is missed: mostly short, plain names with nothing to go on, which is the limit of checking a name without looking up the site. The test is 41% phishing, and real traffic has far less, so real-world precision will be lower. We also chose the training mix using this test, so it is slightly optimistic: re-download the feeds (delete `data/openphish` and `data/phishtank`, then run `python datasets.py`) and run `python evaluate.py` for a fresh reading.

### Synthetic look-alikes

`lookalikes.py` makes 15,451 fakes of ten attack types from our brands and the top 200 sites, plus real sites as negatives. Our own generator, so it only says whether we catch tricks we already know about. Fakes of `.gov.in` and `.bank.in` sites use plain `.in`, because nobody can register under those endings. Caught means Suspicious or Phishing.

| Attack type | Brands: rules | Brands: final | Top 200: rules | Top 200: final |
|---|---|---|---|---|
| missing_letter | 78% | 78% | 88% | 89% |
| extra_letter | 76% | 76% | 84% | 85% |
| swapped_letters | 79% | 79% | 90% | 91% |
| keyboard_neighbour | 72% | 72% | 84% | 84% |
| homoglyph | 91% | 91% | 91% | 93% |
| cyrillic | 96% | 96% | 93% | 94% |
| hyphen | 94% | 94% | 90% | 90% |
| combosquat | 92% | 95% | 75% | 89% |
| tld_swap | 96% | 98% | 77% | 86% |
| subdomain_abuse | 100% | 100% | 100% | 100% |

- **False alarms:** 5.8% of 2,000 real sites flagged (0.3% as Phishing), with the popular-site shortcut turned off so they can't pass automatically.
- **Known gap, on purpose:** one-typo fakes of `no_typo` and 3-4 letter names (`bsi.co.in`, `jio.com` with a letter changed) are left out, because nearly any short word is one edit from them. That is why the brand typo rows are below 100%.
- **Speed:** 0.9 ms per domain as a list, 6.3 ms when checked one at a time.

### The ML model on its own

Measured on 74,381 hosts from sites it never trained on. This test is harder than the old PhiUSIIL-only one, because it has newer feed hosts in it, so don't compare these with the old 85.3% accuracy. The real-world test above is the fair comparison.

| Accuracy | Precision | Recall | F1 |
|---|---|---|---|
| 81.1% | 92.8% | 66.0% | 77.1% |

Confusion matrix: 36,526 legit correct, 1,851 false alarms, 12,242 phishing missed, 23,762 phishing caught. Calibration: when the model gives a percentage, how often is it really phishing?

| Model said | Hosts | Actually phishing |
|---|---:|---:|
| 0-10% | 557 | 7% |
| 10-20% | 6,492 | 15% |
| 20-30% | 33,162 | 24% |
| 30-40% | 6,207 | 36% |
| 40-50% | 2,350 | 46% |
| 50-60% | 1,193 | 58% |
| 60-70% | 888 | 68% |
| 70-80% | 2,007 | 75% |
| 80-90% | 2,943 | 87% |
| 90-100% | 18,582 | 99% |

Much of the model's signal comes from how a domain is built (subdomains, digits, length), which partly reflects differences between the data sources rather than pure look-alike detection. The rules do the look-alike work; the model adds a second opinion.

### Messages

| Test | Result |
|---|---:|
| Scam messages written after the rules were final, scored once | 15 of 18 |
| Genuine messages written after the rules were final, scored once | 12 of 12 |
| Scam messages written first, seen once while tuning | 37 of 41 |
| Genuine messages written first, seen once while tuning | 36 of 36 |
| Real everyday SMS flagged by mistake (UCI, English) | 0.12% of 4,827, none as Scam |

All these scam messages are written by us and anonymised, because no good open dataset of Indian scam SMS exists, and that is a real limit: treat these as regression tests rather than a measure of how many real scams are caught.

### Where the data comes from

| Source | Date | Rows | Licence | Used for |
|---|---|---:|---|---|
| [PhiUSIIL Phishing URL dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) | 2024-03-04 | 235,795 | CC BY 4.0 | training |
| [Phishing.Database (active domains)](https://github.com/Phishing-Database/Phishing.Database) | 2026-11-04 | 392,163 | MIT | training candidate |
| [Tranco top 1 million](https://tranco-list.eu/) | 2026-11-06 | 1,000,000 | No licence of its own. Built from Cisco Umbrella, Majestic (CC BY 3.0), Farsight, CrUX (CC BY-SA 4.0) and Cloudflare Radar (CC BY-NC 4.0); cite Le Pochat et al., NDSS 2019 | real-site lists: popular sites, training negatives and the held-out legit test |
| [PhishTank online-valid (verified phishing, with dates)](https://www.phishtank.com/developer_info.php) | 2026-11-06 | 21,703 | Cisco Talos terms; free download, a few per day without a key. Terms not clear for training or redistribution | evaluation only, never committed |
| [OpenPhish community feed](https://openphish.com/) | 2026-11-06 | 265 | OpenPhish terms: personal and academic research, no redistribution or derivative works | evaluation only, never committed |
| [UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection) | 2026-11-06 | 5,574 | CC BY 4.0 | false-alarm check on real everyday messages (English and Singapore English, not Indian scams) |

Looked at and not used: URLhaus (its text feed answers 410 Gone, and it lists malware, not phishing) and Kaggle phishing URL sets (mostly older copies of the same feeds, with unclear licences). PhishTank and OpenPhish are only ever measured against. They are never trained on, and never committed, because their terms restrict derived works or aren't clear enough to rely on. `data/` is not committed.

**To refresh the data:** delete what you want to replace from `data/`, then run:

```bat
python datasets.py
python train.py
python lookalikes.py
python evaluate.py
python test_rules.py
```

Then redo the free-hosting and risky-ending counts described in the comments in `features.py` before changing those lists, using older feed data only.

## Run it locally

You need Python 3 and Git. These steps are for Windows (Command Prompt or PowerShell). The project was built and tested with Python 3.14.

```bat
git clone https://github.com/Ctrl-C-Ctrl-V-Hackfest-2026-OUTR/V1.git
cd V1

python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

python server.py
```

The website opens at http://127.0.0.1:8000. It listens on this computer only and needs no internet. From the page you can check a link, a message, a screenshot or a whole list; download results as CSV, Excel or JSON; compare a saved page with the real one; and add your own brand. For screenshots, also run the two commands in [Screenshot scan](#screenshot-scan): the rest works without them.

If the server isn't running and you open `frontend/index.html` directly, the page falls back to a small rules-only engine in the browser and says so. Screenshot scan, message files and page comparison need the server, and say that instead of faking a result.

**A demo in five steps:** paste `paytrn.com` and show the evidence; pick the "digital arrest" sample message; drop a screenshot of a fake bank page into Screenshot scan; load a list in Bulk scan and download Excel; open How it works to show the measured numbers.

### The JSON API

The website gets every result from these routes on `server.py`, and other local tools can use them too. All return JSON, apart from export downloads.

| Route | What it does |
|---|---|
| `GET /api/health` | Server status and whether OCR is installed |
| `GET /api/stats` | Everything the page shows: metrics, evaluation, signals, sources and live examples |
| `GET /api/brands` | The watchlist |
| `POST /api/brands`, `POST /api/brands/remove` | Add a brand (`{name, domain}`) or remove one you added (`{key}`) |
| `POST /api/check` | Check one link (`{url}`) |
| `POST /api/bulk` | Check a list (`{domains}`, up to 20,000) |
| `POST /api/export` | Download results (`{format, domains}`) |
| `POST /api/message` | Check one message (`{text, sender}`) |
| `POST /api/messages`, `POST /api/messages/export` | Check or export a whole file of messages (`{content, filename}`) |
| `POST /api/image?mode=auto\|sms\|website` | Scan a screenshot (raw image bytes, up to 8 MB) |
| `POST /api/image/text` | Re-check corrected text from a website screenshot (`{text, mode}`) |
| `POST /api/compare` | Compare saved pages (base64 files) |

### The older Streamlit app

`streamlit run app.py` still works and uses the same detection code, but it gets no new features. Everything it does is on the website.

### Command-line tool

Check a list without opening the app. Works with a `.csv` that has a `domain` column, or a `.txt` with one domain per line:

```bat
python kavach_cli.py sample_domains.csv
python kavach_cli.py sample_domains.csv --format json --out results.json
python kavach_cli.py domains.txt --format xlsx --out results.xlsx
```

For messages, use a CSV with a `message` column (and an optional `sender` column). The mode is picked from the columns, or you can say so:

```bat
python kavach_cli.py messages.csv
python kavach_cli.py messages.csv --mode messages --format xlsx --out results.xlsx
```

Each export has these columns: domain, verdict, final score, ML probability, nearest genuine site, closeness %, attack type, evidence, reasons, rule score and what decided it.

### Compare a page (optional)

In the **Compare a page** section of the website, upload saved copies of the suspicious and genuine pages. Saved HTML gives a content similarity % (title, form fields, visible text with TF-IDF cosine, image file names), and screenshots give a visual similarity % (perceptual hash and structural similarity). A close copy on a different domain is shown as strong phishing evidence. Nothing is fetched from the internet, uploaded files are only read, and this doesn't change the risk score.

The trained model (`model.joblib`) is included in the repo, so you do not need to train anything. If it is missing, the app still works with the rule-based score only.

### Run the tests

```bat
python test_rules.py
```

One command runs everything, in about a minute. It prints a table per section, a summary, and exits with code 1 if anything fails:

| Section | What it checks |
|---|---|
| Links | The expected verdict for each test link |
| More links | `test_links.csv`: hundreds of links by category, with false-positive traps |
| Messages, More messages | The expected verdict for each test message (`test_messages.csv`), Hindi and Hinglish included |
| Message details | Link extraction, the genuine-OTP guard, the sender check and message exports |
| Evidence | Nearest genuine site, closeness %, attack type, the exact edits and the reason text |
| Exports and command-line tool | CSV, JSON and Excel columns, formula-safe cells, and `kavach_cli.py` run for real |
| Page comparison | Saved HTML and screenshot similarity, on pages made up inside the test |
| Server | A real `server.py` on a free port: every route, bad inputs, added brands, the local-only guard and the no-OCR message |
| OCR | Known text drawn into an image and read back, with the network blocked. Says "skipped" if OCR isn't installed |
| App (headless) | The real `app.py` driven by Streamlit's test tool |

A case marked `known_gap` in the CSV files is one we know is wrong today. It is listed as a known miss, so it stays visible, but it doesn't fail the run.

To drive the website in a real browser before a demo (it uses Microsoft Edge and starts its own server):

```bat
pip install playwright
python browser_check.py
```

It checks a domain, a message, a list, every download, a screenshot by upload and by paste, adding a brand, the phone layout and what happens when the server stops. Playwright is not a project requirement.

Expected verdicts are what a link *should* get, so if a test fails, look at why before changing it. A few verdicts are decided by the ML model and are marked with a comment: retraining can flip those.

**Check these by eye before a demo** (no test can see them):

- The website in a browser: colours, spacing and the dark look.
- The red and green letters in the evidence box line up as expected.
- That the downloaded CSV, JSON and Excel files open properly.
- The page comparison with a page you really saved from a browser, rather than the made-up ones in the test.
- A real photo of a phone screen in Screenshot scan: the tests use clean screenshots.

### Retrain the model (optional)

```bat
python datasets.py
python train.py
```

`datasets.py` downloads any data that is missing into `data/` (needs internet once) and makes the held-out test set. After that, `train.py` works offline. It prints a leakage check, accuracy, precision, recall, F1, the confusion matrix and calibration, then rewrites `model.joblib`, `feature_importance.csv` and `metrics.json`. Add `--out somefolder` to try something without touching those files.

## Project files

| File | What it does |
|---|---|
| `server.py` | **Start here.** Local web server for the website and its JSON API |
| `frontend/index.html` | The Kavach website (one file) |
| `detector.py` | Detection logic: rule-based score and ML blend |
| `evidence.py` | Similarity evidence: closeness, attack type and exact edits |
| `sms.py` | Message checking: link extraction, scam wording and the sender check |
| `ocr.py` | Screenshot scan: reads an image and checks it. Optional |
| `outputs.py` | Fast list checking and CSV, JSON and Excel export |
| `kavach_cli.py` | Command-line tool |
| `page_compare.py` | Optional comparison of saved pages and screenshots |
| `features.py` | Shared lists, look-alike logic, the watchlist loader and ML features |
| `brands.json` | The watchlist, with the proof for each official domain |
| `brands_custom.json` | Brands you added on the website. Local, not committed |
| `datasets.py` | Data sources and licences, downloads, and the held-out real-world test set |
| `data_sources.json` | Source, date, rows and licence of all the data used |
| `train.py` | Trains and evaluates the model |
| `model.joblib` | Trained RandomForest |
| `metrics.json`, `feature_importance.csv` | Test metrics, calibration and top features from the last training run |
| `lookalikes.py` | Generates synthetic look-alikes into `data/synthetic_pairs.csv` |
| `evaluate.py` | Real-world, synthetic and message results; writes `evaluation.json` |
| `evaluation.json` | Results of the last `evaluate.py` run |
| `test_rules.py` | All the tests in one command |
| `test_links.csv`, `test_messages.csv` | Hand-written test cases |
| `browser_check.py` | Drives the website in a real browser. Optional |
| `popular_domains.txt` | The top popular sites, most popular first |
| `build_popular.py` | Rebuilds `popular_domains.txt` from `data/tranco.csv` and prints what it removed |
| `sample_domains.csv` | 10 test domains, a mix of real and fake |
| `requirements.txt`, `requirements-ocr.txt` | Pinned package versions; OCR is separate and optional |
| `app.py`, `style.css` | The older Streamlit app. It gets no new features |

## Team

Built by Team Ctrl-C-Ctrl-V for Hackfest 2026.
