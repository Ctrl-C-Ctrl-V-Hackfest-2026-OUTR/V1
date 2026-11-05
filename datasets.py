"""
Kavach - the outside data: where it comes from, its licence, and the held-out real-world test set.

Run with:  python datasets.py
 - Downloads anything missing into data/ (needs internet once; data/ is not committed).
 - Writes data/realworld_test.csv: real phishing hosts and real legitimate sites, kept apart from training.
 - Writes data_sources.json (committed): source, date, row count and licence of everything used.

Detection itself never downloads anything: this is build-time only, like train.py.

The rule that keeps the test honest: the test set is made first, and train.py then drops every registered
domain that is in it. So nothing the model trains on shares a site with what it is tested on.
"""
import csv
import io
import json
import random
import re
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

import pandas as pd

from features import LEGIT_DOMAINS, extract, parse

HERE = Path(__file__).parent
DATA = HERE / "data"
REALWORLD_CSV = DATA / "realworld_test.csv"
SOURCES_JSON = HERE / "data_sources.json"
TIME_CUT = "2026-07-01"   # PhishTank entries submitted on or after this date are test data
SEED = 42
N_TRANCO_TAIL = 5000      # real sites ranked below the top 20,000, so the popular shortcut can't help them
N_INDIA = 3000            # real .in sites below the top 20,000: the closest thing to small Indian businesses
USER_AGENT = "Kavach-hackathon-research/1.0 (phishing detection coursework)"

# name -> where it lives, how it may be used and what we use it for.
# "evaluation only" means it is measured against and never trained on or committed, because its terms
# restrict derived works (OpenPhish) or are not clear enough to rely on for training (PhishTank).
SOURCES = {
    "phiusiil": {"title": "PhiUSIIL Phishing URL dataset", "file": "PhiUSIIL_Phishing_URL_Dataset.csv",
                 "url": "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset",
                 "licence": "CC BY 4.0", "use": "training"},
    "phishing_database": {"title": "Phishing.Database (active domains)", "file": "phishing-domains-ACTIVE.txt",
                          "url": "https://github.com/Phishing-Database/Phishing.Database",
                          "download": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
                          "licence": "MIT", "use": "training candidate"},
    "tranco_1m": {"title": "Tranco top 1 million", "file": "tranco1m/top-1m.csv.zip",
                  "url": "https://tranco-list.eu/", "download": "https://tranco-list.eu/top-1m.csv.zip",
                  "licence": "No licence of its own. Built from Cisco Umbrella, Majestic (CC BY 3.0), Farsight, "
                             "CrUX (CC BY-SA 4.0) and Cloudflare Radar (CC BY-NC 4.0); cite Le Pochat et al., NDSS 2019",
                  "use": "real-site lists: popular sites, training negatives and the held-out legit test"},
    "phishtank": {"title": "PhishTank online-valid (verified phishing, with dates)", "file": "phishtank/online-valid.csv",
                  "url": "https://www.phishtank.com/developer_info.php",
                  "download": "https://data.phishtank.com/data/online-valid.csv",
                  "licence": "Cisco Talos terms; free download, a few per day without a key. Terms not clear for "
                             "training or redistribution",
                  "use": "evaluation only, never committed"},
    "openphish": {"title": "OpenPhish community feed", "file": "openphish/feed.txt",
                  "url": "https://openphish.com/", "download": "https://openphish.com/feed.txt",
                  "licence": "OpenPhish terms: personal and academic research, no redistribution or derivative works",
                  "use": "evaluation only, never committed"},
    "uci_sms": {"title": "UCI SMS Spam Collection", "file": "uci_sms/sms.zip",
                "url": "https://archive.ics.uci.edu/dataset/228/sms+spam+collection",
                "download": "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip",
                "licence": "CC BY 4.0",
                "use": "false-alarm check on real everyday messages (English and Singapore English, not Indian scams)"},
}
# Looked at and not used
REJECTED = {"URLhaus": "Its text feed now answers 410 Gone, and it lists malware, not phishing.",
            "Kaggle phishing URL sets": "Mostly older copies of the same feeds, with unclear licences."}

INDIA_ENDINGS = (".in",)
GOV_ENDINGS = (".gov.in", ".nic.in")


def registered(host: str) -> str:
    """'login.paytm.com' -> 'paytm.com'"""
    parts = extract(host)
    return f"{parts.domain}.{parts.suffix}" if parts.suffix else parts.domain


def bare_host(url: str) -> str:
    """'https://www.paytm.com/login' -> 'paytm.com'"""
    return parse(url)[1].removeprefix("www.")


def path_of(name: str) -> Path:
    return DATA / SOURCES[name]["file"]


def download_missing() -> None:
    """Fetch any file we don't have yet. A failed download is reported, not fatal."""
    for name, source in SOURCES.items():
        target = path_of(name)
        if target.exists() or "download" not in source:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        print(f"Downloading {source['title']}...")
        try:
            request = urllib.request.Request(source["download"], headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=300) as response:
                target.write_bytes(response.read())
        except Exception as err:  # no internet, blocked, moved...
            print(f"  could not download it: {err}. Get it by hand from {source['url']} and save it as {target}")


# ---------------- readers: each returns plain Python data ----------------

def read_tranco_1m() -> list:
    """Every domain on the Tranco list, most popular first."""
    with zipfile.ZipFile(path_of("tranco_1m")) as archive:
        lines = archive.read(archive.namelist()[0]).decode("utf-8").splitlines()
    return [line.split(",", 1)[1].strip().lower() for line in lines if "," in line]


def read_phishtank() -> pd.DataFrame:
    """One row per host: host, reg, when (the first time it was submitted)."""
    table = pd.read_csv(path_of("phishtank"), usecols=["url", "submission_time"])
    table["host"] = table["url"].astype(str).map(bare_host)
    table["reg"] = table["host"].map(registered)
    table["when"] = pd.to_datetime(table["submission_time"], utc=True, errors="coerce")
    table = table[table["host"] != ""].sort_values("when").drop_duplicates("host")
    return table[["host", "reg", "when"]]


def read_openphish() -> list:
    lines = path_of("openphish").read_text(encoding="utf-8", errors="ignore").splitlines()
    return sorted({bare_host(line) for line in lines if line.strip()} - {""})


def read_phishing_database() -> list:
    lines = path_of("phishing_database").read_text(encoding="utf-8", errors="ignore").splitlines()
    return sorted({line.strip().lower().removeprefix("www.") for line in lines if line.strip() and not line.startswith("#")})


def read_uci_sms() -> list:
    """(label, text) pairs: label is 'ham' or 'spam'."""
    with zipfile.ZipFile(path_of("uci_sms")) as archive:
        lines = archive.read("SMSSpamCollection").decode("utf-8", errors="replace").splitlines()
    return [tuple(line.split("\t", 1)) for line in lines if "\t" in line]


# ---------------- the held-out test set ----------------

def build_realworld() -> pd.DataFrame:
    """Real phishing hosts from the newer feeds and hard real sites, one row per host.
    group says which list a row came from: results are always reported per group."""
    rng = random.Random(SEED)
    phishtank = read_phishtank()
    recent = phishtank[phishtank["when"] >= pd.Timestamp(TIME_CUT, tz="UTC")]
    openphish = read_openphish()
    rows = [{"host": h, "label": 1, "group": "phishtank_recent"} for h in recent["host"]]
    seen = set(recent["host"])
    rows += [{"host": h, "label": 1, "group": "openphish_now"} for h in openphish if h not in seen]

    # A "real" site must not be on any phishing feed, old or new, and must not be one we already list
    # as official: that would just measure our own list.
    feeds = set(phishtank["reg"]) | {registered(h) for h in openphish}
    feeds |= {registered(h) for h in read_phishing_database()}
    tranco = read_tranco_1m()
    tail = [d for d in tranco[20_000:] if d not in feeds and d not in LEGIT_DOMAINS]
    government = [d for d in tranco if d.endswith(GOV_ENDINGS) and d not in LEGIT_DOMAINS]
    india = [d for d in tail if d.endswith(INDIA_ENDINGS) and not d.endswith(GOV_ENDINGS)]
    elsewhere = [d for d in tail if not d.endswith(INDIA_ENDINGS)]
    rows += [{"host": d, "label": 0, "group": "gov_nic_in"} for d in government]
    rows += [{"host": d, "label": 0, "group": "india_small"} for d in rng.sample(india, min(N_INDIA, len(india)))]
    rows += [{"host": d, "label": 0, "group": "tranco_tail"} for d in rng.sample(elsewhere, min(N_TRANCO_TAIL, len(elsewhere)))]
    table = pd.DataFrame(rows).drop_duplicates("host")
    table["reg"] = table["host"].map(registered)
    table.to_csv(REALWORLD_CSV, index=False, encoding="utf-8")
    return table


def write_sources(table: pd.DataFrame) -> dict:
    """Source, date, row count and licence of everything, for the README and the website."""
    counts = {
        "phiusiil": lambda: sum(1 for _ in open(path_of("phiusiil"), encoding="utf-8", errors="ignore")) - 1,
        "phishing_database": lambda: len(read_phishing_database()),
        "tranco_1m": lambda: len(read_tranco_1m()),
        "phishtank": lambda: len(read_phishtank()),
        "openphish": lambda: len(read_openphish()),
        "uci_sms": lambda: len(read_uci_sms()),
    }
    sources = []
    for name, source in SOURCES.items():
        path = path_of(name)
        if not path.exists():
            continue
        sources.append({"name": name, "title": source["title"], "url": source["url"], "licence": source["licence"],
                        "use": source["use"], "rows": counts[name](),
                        "date": time.strftime("%Y-%m-%d", time.localtime(path.stat().st_mtime))})
    list_id = DATA / "tranco1m" / "list_id.txt"
    document = {"sources": sources, "rejected": REJECTED, "time_cut": TIME_CUT,
                "tranco_list_id": list_id.read_text(encoding="utf-8").strip() if list_id.exists() else None,
                "realworld_test": {group: int(count) for group, count in table["group"].value_counts().items()}}
    SOURCES_JSON.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return document


def main():
    sys.stdout.reconfigure(errors="backslashreplace")
    download_missing()
    missing = [name for name in SOURCES if not path_of(name).exists()]
    if missing:
        raise SystemExit(f"Still missing: {missing}. See the messages above.")
    table = build_realworld()
    document = write_sources(table)
    print(f"\nSaved {REALWORLD_CSV} and {SOURCES_JSON.name}")
    for source in document["sources"]:
        print(f"  {source['title']:<58}{source['rows']:>10,}  {source['date']}  {source['use']}")
    print("\nHeld-out real-world test set:")
    for group, count in document["realworld_test"].items():
        print(f"  {group:<20}{count:>8,}")


if __name__ == "__main__":
    main()
