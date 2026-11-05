"""
Kavach - train the machine-learning model.

Run with:  python datasets.py                (once: downloads the data and makes the held-out test set)
           python train.py                   (the default: PhiUSIIL + Tranco + Phishing.Database)
           python train.py --source phiusiil (PhiUSIIL alone, the previous model)
           python train.py --source tranco   (fallback: Tranco + Phishing.Database)
 - After the first download it works fully offline.
Outputs: model.joblib, feature_importance.csv, metrics.json
         (add --out somefolder to try something without touching the real files)

The model only ever sees our own 12 features of the host name (features.py), so the app and the
training use exactly the same logic. We never use PhiUSIIL's ready-made columns, because they
leak the answer (URLSimilarityIndex alone gets 99.7%) or need the live page.
Everything in the held-out test set (data/realworld_test.csv) is kept out of training, by registered domain.
"""
import io
import json
import random
import sys
import urllib.request
import zipfile
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.tree import DecisionTreeClassifier

from features import FEATURE_NAMES, LEGIT_DOMAINS, POPULAR_SET, extract, extract_features, parse

HERE = Path(__file__).parent
DATA = HERE / "data"
PHIUSIIL_CSV = DATA / "PhiUSIIL_Phishing_URL_Dataset.csv"
TRANCO_CSV = DATA / "tranco.csv"                 # rank,domain  (top 20,000)
PHISH_TXT = DATA / "phishing-domains-ACTIVE.txt"  # one domain per line

PHIUSIIL_PAGE = "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset"
PHIUSIIL_ZIP = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
PHISH_URL = ("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/"
             "master/phishing-domains-ACTIVE.txt")
REALWORLD_CSV = DATA / "realworld_test.csv"       # made by datasets.py, never trained on
N_PER_CLASS = 20_000
SEED = 42
ML_TRUST = 0.70     # the same threshold app.py uses before ML can raise a score
LEAK_LIMIT = 0.98   # a single feature this accurate means the data gives the answer away

# Used to check the labels point the right way after the flip (0 = legit, 1 = phishing)
KNOWN_HOSTS = {"columbia.edu": 0, "euronews.com": 0, "levelup.com": 0,
               "paypal.com.login.prosto-vsem.ru": 1, "metamask-usaz.godaddysites.com": 1}


def download(url: str) -> bytes:
    """Download a file and return its bytes."""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Kavach training)"})
    with urllib.request.urlopen(req, timeout=180) as resp:
        return resp.read()


def get_phiusiil() -> bool:
    """Download PhiUSIIL once. Returns False if it is missing and could not be downloaded."""
    if PHIUSIIL_CSV.exists():
        return True
    DATA.mkdir(exist_ok=True)
    try:
        print("Downloading the PhiUSIIL dataset (about 15 MB)...")
        with zipfile.ZipFile(io.BytesIO(download(PHIUSIIL_ZIP))) as z:
            PHIUSIIL_CSV.write_bytes(z.read(PHIUSIIL_CSV.name))
        return True
    except Exception as err:  # no internet, blocked, URL moved...
        print(f"\nDOWNLOAD FAILED: {err}")
        print(f"Download it by hand from {PHIUSIIL_PAGE}")
        print(f"and save {PHIUSIIL_CSV.name} in the data/ folder, then re-run.\n")
        return False


def get_tranco_data():
    """Download the two fallback datasets once; skip if they are already in data/."""
    DATA.mkdir(exist_ok=True)
    try:
        if not TRANCO_CSV.exists():
            print("Downloading Tranco top sites list (about 10 MB)...")
            with zipfile.ZipFile(io.BytesIO(download(TRANCO_URL))) as z:
                lines = z.read(z.namelist()[0]).decode("utf-8").splitlines()
            TRANCO_CSV.write_text("\n".join(lines[:N_PER_CLASS]) + "\n", encoding="utf-8")
        if not PHISH_TXT.exists():
            print("Downloading Phishing.Database domain list (about 11 MB)...")
            PHISH_TXT.write_bytes(download(PHISH_URL))
    except Exception as err:  # no internet, blocked, URL moved...
        print(f"\nDOWNLOAD FAILED: {err}\n")
        print("Download the data by hand instead and save it in the data/ folder:")
        print(f"  1. Legit domains   -> {TRANCO_CSV.name}  (lines like  1,google.com)")
        print(f"     from {TRANCO_URL}")
        print(f"  2. Phishing domains -> {PHISH_TXT.name}  (one domain per line)")
        print(f"     from {PHISH_URL}")
        print("Or use a Kaggle dataset such as 'Phishing Site URLs' / 'Malicious URLs dataset',")
        print("extract its legit and phishing domains into those two files, then re-run.")
        sys.exit(1)


def registered(host: str) -> str:
    """'login.paytm.com' -> 'paytm.com'"""
    p = extract(host)
    return f"{p.domain}.{p.suffix}" if p.suffix else p.domain


def bare_host(url: str) -> str:
    """'https://www.paytm.com/login' -> 'paytm.com'"""
    return parse(url)[1].removeprefix("www.")


def load_phiusiil():
    """Returns (hosts, labels, registered domains), one row per host name."""
    df = pd.read_csv(PHIUSIIL_CSV, encoding="utf-8-sig", usecols=["URL", "label"])
    print(f"PhiUSIIL rows: {len(df)}")

    # PhiUSIIL uses 1 = LEGITIMATE, 0 = PHISHING. We use 1 = phishing, so flip it.
    df["phishing"] = 1 - df["label"]
    df["host"] = df["URL"].astype(str).map(bare_host)
    df["reg"] = df["host"].map(registered)

    # Stop right here if the labels point the wrong way: the model would learn the exact opposite
    known = df[df["host"].isin(KNOWN_HOSTS)].drop_duplicates("host")
    wrong = [h for h, y in zip(known["host"], known["phishing"]) if KNOWN_HOSTS[h] != y]
    print("Label check on known hosts:", dict(zip(known["host"], known["phishing"])))
    if wrong or len(known) != len(KNOWN_HOSTS):
        sys.exit(f"LABEL CHECK FAILED for {wrong or 'missing hosts'}: stopping before training.")

    # Official brand domains are Safe in the app, so the model never sees them. Their PhiUSIIL
    # rows are redirects like google.com/url?q=evil, and our features don't look at the path.
    df = df[~df["reg"].isin(LEGIT_DOMAINS)]

    # Features only see the host, so one row per host. Drop hosts with both labels.
    hosts = df.groupby("host").agg(phishing=("phishing", "max"), labels=("phishing", "nunique"),
                                   reg=("reg", "first")).reset_index()
    print(f"Unique hosts: {len(hosts)}   dropped because they have both labels: {(hosts['labels'] > 1).sum()}")
    hosts = hosts[hosts["labels"] == 1]
    return hosts["host"].tolist(), hosts["phishing"].tolist(), hosts["reg"].tolist()


def read_tranco():
    return [line.split(",", 1)[1].strip().lower()
            for line in TRANCO_CSV.read_text(encoding="utf-8").splitlines() if "," in line]


def read_feed():
    raw = [l.strip().lower() for l in PHISH_TXT.read_text(encoding="utf-8", errors="ignore").splitlines()
           if l.strip() and not l.startswith("#")]
    return sorted(set(raw))


def load_tranco():
    """Fallback data. Returns (hosts, labels, registered domains)."""
    # Legit: top 20,000 Tranco domains, minus the official brand domains that
    # the app already marks Safe (otherwise "exact brand match" would leak the answer).
    tranco = read_tranco()
    legit_set = set(tranco)
    legit = sorted({d for d in tranco if d not in LEGIT_DOMAINS})

    # Phishing: random sample from the feed, de-duplicated, minus anything on the legit list.
    phish = read_feed()
    # Drop phishing hosts whose registered domain (domain + suffix) is in the Tranco top 20,000,
    # e.g. x.github.io, y.blogspot.com, z.weebly.com. These are abused free-hosting sites and
    # would teach the model "subdomain = phishing" instead of look-alike detection.
    kept = [d for d in phish if registered(d) not in legit_set and registered(d) not in LEGIT_DOMAINS]
    print(f"Phishing hosts in feed: {len(phish)}   dropped (registered domain in Tranco top "
          f"{N_PER_CLASS}): {len(phish) - len(kept)}")
    phish = pd.Series(kept).sample(n=min(N_PER_CLASS, len(kept)), random_state=SEED).tolist()
    hosts = legit + phish
    return hosts, [0] * len(legit) + [1] * len(phish), [registered(h) for h in hosts]


def leakage_check(X_train, y_train, X_test, y_test) -> dict:
    """How accurate is each feature on its own? Near 100% means the data gives the answer away."""
    scores = {c: DecisionTreeClassifier(max_depth=1, random_state=SEED)
              .fit(X_train[[c]], y_train).score(X_test[[c]], y_test) for c in FEATURE_NAMES}
    print("\nLeakage check: accuracy of each feature alone (more than "
          f"{LEAK_LIMIT:.0%} would be a leak)")
    for name, acc in sorted(scores.items(), key=lambda kv: -kv[1]):
        print(f"  {acc:.3f}  {name}")
    leaks = [c for c, acc in scores.items() if acc >= LEAK_LIMIT]
    if leaks:
        sys.exit(f"LEAK: {leaks} give near-100% accuracy alone. Remove them before training.")
    return scores


def calibration_table(y_test, proba) -> list:
    """Are 80% predictions right about 80% of the time? Compare in 10% wide groups."""
    y_test = np.asarray(y_test)
    rows = []
    for low in range(0, 100, 10):
        mask = (proba * 100 >= low) & ((proba * 100 < low + 10) | (low == 90))
        if mask.sum():
            rows.append({"range": f"{low}-{low + 10}%", "count": int(mask.sum()),
                         "predicted": float(proba[mask].mean()), "actual": float(y_test[mask].mean())})
    return rows


def cross_check(model) -> dict:
    """Try the model on the other data source, which it did not train on. A rough real-world check."""
    if not (TRANCO_CSV.exists() and PHISH_TXT.exists()):
        return {}
    random.seed(SEED)
    real = random.sample([d for d in read_tranco() if d not in LEGIT_DOMAINS], 5000)
    feed = [h for h in random.sample(read_feed(), 8000) if registered(h) not in POPULAR_SET][:5000]
    real_p = model.predict_proba(pd.DataFrame([extract_features(d) for d in real], columns=FEATURE_NAMES))[:, 1]
    feed_p = model.predict_proba(pd.DataFrame([extract_features(d) for d in feed], columns=FEATURE_NAMES))[:, 1]
    return {"tranco_flagged": float(np.mean(real_p >= ML_TRUST)), "feed_caught": float(np.mean(feed_p >= ML_TRUST)),
            "n_tranco": len(real), "n_feed": len(feed)}


def held_out_sites() -> set:
    """Registered domains in the real-world test set (datasets.py). Training must never see these."""
    if not REALWORLD_CSV.exists():
        return set()
    return set(pd.read_csv(REALWORLD_CSV, usecols=["reg"])["reg"].dropna())


def load_mixed(extra_legit: int = 60_000, extra_phish: int = 120_000):
    """PhiUSIIL plus newer data. Returns (hosts, labels, registered domains), one row per host.

    Adds real sites from the Tranco top 1M, which teaches the model that small real sites can have
    digits or a cheap ending, and Phishing.Database hosts, which are newer than PhiUSIIL. OpenPhish and
    PhishTank are never used here: see the licence notes in datasets.py.
    Anything in the held-out test set is dropped, and a host with both labels is dropped too.
    """
    from datasets import read_phishing_database, read_tranco_1m
    rng = random.Random(SEED)
    hosts, labels, regs = load_phiusiil()
    table = {host: label for host, label in zip(hosts, labels)}
    held_out = held_out_sites()
    real = [d for d in read_tranco_1m() if d not in LEGIT_DOMAINS and registered(d) not in held_out]
    feed = [h for h in read_phishing_database() if registered(h) not in held_out and registered(h) not in LEGIT_DOMAINS]
    feed_sites = {registered(h) for h in feed}
    real = [d for d in real if d not in feed_sites]
    phish_set = set(feed)
    for host in rng.sample(real, min(extra_legit, len(real))):
        table.setdefault(host, 0)
    for host in rng.sample(feed, min(extra_phish, len(feed))):
        if table.get(host, 1) == 0:   # labelled real elsewhere: unclear, so leave it out
            del table[host]
        else:
            table[host] = 1
    # Sites PhiUSIIL calls real but a feed calls phishing are unclear too
    for host in [h for h, label in table.items() if label == 0 and h in phish_set]:
        del table[host]
    table = {h: label for h, label in table.items() if registered(h) not in held_out}
    print(f"Mixed data: {len(table)} hosts ({sum(table.values())} phishing), {len(held_out)} held-out sites kept apart")
    hosts = list(table)
    return hosts, [table[h] for h in hosts], [registered(h) for h in hosts]


def main():
    wanted = sys.argv[sys.argv.index("--source") + 1] if "--source" in sys.argv else "mixed"
    source = wanted
    if source in ("phiusiil", "mixed") and not get_phiusiil():
        print("Falling back to Tranco + Phishing.Database.")
        source = "tranco"
    if source == "tranco":
        get_tranco_data()
        hosts, y, groups = load_tranco()
    elif source == "mixed":
        hosts, y, groups = load_mixed()
    else:
        hosts, y, groups = load_phiusiil()
    y = np.array(y)
    print(f"Source: {source}   Legit: {(y == 0).sum()}   Phishing: {(y == 1).sum()}")

    print("Extracting features...")
    X = pd.DataFrame([extract_features(h) for h in hosts], columns=FEATURE_NAMES)

    # 80/20 split that keeps every host of one site on the same side, so the test set
    # really is made of sites the model has never seen.
    train_idx, test_idx = next(StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
                               .split(X, y, groups))
    X_train, X_test, y_train, y_test = X.iloc[train_idx], X.iloc[test_idx], y[train_idx], y[test_idx]

    single = leakage_check(X_train, y_train, X_test, y_test)

    print(f"\nTraining RandomForest on {len(X_train)} rows, testing on {len(X_test)} rows...")
    model = RandomForestClassifier(n_estimators=100, max_depth=14, min_samples_leaf=2,
                                   random_state=SEED, n_jobs=-1)
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    proba = model.predict_proba(X_test)[:, 1]

    metrics = {
        "source": source,
        "accuracy": accuracy_score(y_test, pred),
        "precision": precision_score(y_test, pred),
        "recall": recall_score(y_test, pred),
        "f1": f1_score(y_test, pred),
        "confusion_matrix": confusion_matrix(y_test, pred).tolist(),  # [[TN, FP], [FN, TP]]
        "n_train": len(X_train), "n_test": len(X_test),
        "n_legit": int((y == 0).sum()), "n_phishing": int((y == 1).sum()),
        "best_single_feature": max(single.values()),
        "calibration": calibration_table(y_test, proba),
        "cross_check": cross_check(model) if source == "phiusiil" else {},
    }
    # Experiments can save elsewhere: python train.py --source phiusiil --out somewhere
    out = Path(sys.argv[sys.argv.index("--out") + 1]) if "--out" in sys.argv else HERE
    out.mkdir(parents=True, exist_ok=True)
    print("\n=== Test-set results ===")
    for k in ("accuracy", "precision", "recall", "f1"):
        print(f"{k:<10} {metrics[k]:.4f}")
    (tn, fp), (fn, tp) = metrics["confusion_matrix"]
    print("\nConfusion matrix (rows = real, columns = predicted)")
    print(f"                 pred legit   pred phishing")
    print(f"real legit       {tn:>10}   {fp:>13}")
    print(f"real phishing    {fn:>10}   {tp:>13}")

    print("\nCalibration: are 80% predictions right about 80% of the time?")
    print("  range      count   predicted   actually phishing")
    for row in metrics["calibration"]:
        print(f"  {row['range']:<9} {row['count']:>6}   {row['predicted']:>8.1%}   {row['actual']:>8.1%}")

    if metrics["cross_check"]:
        c = metrics["cross_check"]
        print(f"\nOther data source, ML >= {ML_TRUST:.0%}: real Tranco sites flagged {c['tranco_flagged']:.1%}, "
              f"phishing-feed hosts caught {c['feed_caught']:.1%}")

    imp = (pd.DataFrame({"feature": FEATURE_NAMES, "importance": model.feature_importances_})
           .sort_values("importance", ascending=False).head(10))
    print("\nTop 10 feature importances")
    print(imp.to_string(index=False))

    # compress=3 keeps the file small enough to commit to git
    joblib.dump({"model": model, "features": FEATURE_NAMES}, out / "model.joblib", compress=3)
    imp.to_csv(out / "feature_importance.csv", index=False)
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    size_mb = (out / "model.joblib").stat().st_size / 1024 / 1024
    print(f"\nSaved model.joblib ({size_mb:.1f} MB), feature_importance.csv, metrics.json")


if __name__ == "__main__":
    main()
