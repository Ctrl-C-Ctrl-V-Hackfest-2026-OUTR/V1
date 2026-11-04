"""
Kavach - train the machine-learning model.

Run with:  python train.py
 - First run downloads the data into data/ (needs internet once).
 - After that it works fully offline.
Outputs: model.joblib, feature_importance.csv, metrics.json
"""
import io
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import train_test_split

from features import FEATURE_NAMES, LEGIT_DOMAINS, extract, extract_features

HERE = Path(__file__).parent
DATA = HERE / "data"
TRANCO_CSV = DATA / "tranco.csv"                 # rank,domain  (top 20,000)
PHISH_TXT = DATA / "phishing-domains-ACTIVE.txt"  # one domain per line

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
PHISH_URL = ("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/"
             "master/phishing-domains-ACTIVE.txt")
N_PER_CLASS = 20_000
SEED = 42


def download(url: str) -> bytes:
    """Download a file and return its bytes."""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Kavach training)"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def get_data():
    """Download the two datasets once; skip if they are already in data/."""
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


def load_domains():
    # Legit: top 20,000 Tranco domains, minus the official brand domains that
    # the app already marks Safe (otherwise "exact brand match" would leak the answer).
    legit = [line.split(",", 1)[1].strip().lower()
             for line in TRANCO_CSV.read_text(encoding="utf-8").splitlines() if "," in line]
    legit_set = set(legit)
    legit = sorted({d for d in legit if d not in LEGIT_DOMAINS})

    # Phishing: random sample from the feed, de-duplicated, minus anything on the legit list.
    raw = [l.strip().lower() for l in PHISH_TXT.read_text(encoding="utf-8", errors="ignore").splitlines()
           if l.strip() and not l.startswith("#")]
    phish = sorted(set(raw))
    # Drop phishing hosts whose registered domain (domain + suffix) is in the Tranco top 20,000,
    # e.g. x.github.io, y.blogspot.com, z.weebly.com. These are abused free-hosting sites and
    # would teach the model "subdomain = phishing" instead of look-alike detection.
    kept = [d for d in phish if registered(d) not in legit_set and registered(d) not in LEGIT_DOMAINS]
    print(f"Phishing hosts in feed: {len(phish)}   dropped (registered domain in Tranco top "
          f"{N_PER_CLASS}): {len(phish) - len(kept)}")
    print("  free-hosting domains in the Tranco list:",
          {d: d in legit_set for d in ("github.io", "blogspot.com", "weebly.com")})
    phish = pd.Series(kept).sample(n=min(N_PER_CLASS, len(kept)), random_state=SEED).tolist()
    return legit, phish


def main():
    get_data()
    legit, phish = load_domains()
    print(f"Legit domains: {len(legit)}   Phishing domains: {len(phish)}")

    print("Extracting features...")
    domains = legit + phish
    y = [0] * len(legit) + [1] * len(phish)
    X = pd.DataFrame([extract_features(d) for d in domains], columns=FEATURE_NAMES)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=SEED)

    print(f"Training RandomForest on {len(X_train)} rows, testing on {len(X_test)} rows...")
    model = RandomForestClassifier(n_estimators=100, max_depth=14, min_samples_leaf=2,
                                   random_state=SEED, n_jobs=-1)
    model.fit(X_train, y_train)
    pred = model.predict(X_test)

    metrics = {
        "accuracy": accuracy_score(y_test, pred),
        "precision": precision_score(y_test, pred),
        "recall": recall_score(y_test, pred),
        "f1": f1_score(y_test, pred),
        "confusion_matrix": confusion_matrix(y_test, pred).tolist(),  # [[TN, FP], [FN, TP]]
        "n_train": len(X_train), "n_test": len(X_test),
        "n_legit": len(legit), "n_phishing": len(phish),
    }
    print("\n=== Test-set results ===")
    for k in ("accuracy", "precision", "recall", "f1"):
        print(f"{k:<10} {metrics[k]:.4f}")
    (tn, fp), (fn, tp) = metrics["confusion_matrix"]
    print("\nConfusion matrix (rows = real, columns = predicted)")
    print(f"                 pred legit   pred phishing")
    print(f"real legit       {tn:>10}   {fp:>13}")
    print(f"real phishing    {fn:>10}   {tp:>13}")

    imp = (pd.DataFrame({"feature": FEATURE_NAMES, "importance": model.feature_importances_})
           .sort_values("importance", ascending=False).head(10))
    print("\nTop 10 feature importances")
    print(imp.to_string(index=False))

    # compress=3 keeps the file small enough to commit to git
    joblib.dump({"model": model, "features": FEATURE_NAMES}, HERE / "model.joblib", compress=3)
    imp.to_csv(HERE / "feature_importance.csv", index=False)
    (HERE / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    size_mb = (HERE / "model.joblib").stat().st_size / 1024 / 1024
    print(f"\nSaved model.joblib ({size_mb:.1f} MB), feature_importance.csv, metrics.json")


if __name__ == "__main__":
    main()
