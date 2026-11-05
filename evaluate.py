"""
Kavach - how well do we catch synthetic look-alikes, and how often do we cry wolf?

Run with:  python lookalikes.py   (once, makes data/synthetic_pairs.csv)
           python evaluate.py
Prints a table per attack type and saves it to evaluation.json (the app can show that file).

"Caught" means the verdict is Suspicious or Phishing. Two groups are shown, because only our
curated BRANDS get the strong look-alike rules; the top 200 popular sites get one weaker rule.

The synthetic numbers and the real-world numbers answer different questions and are saved separately:
synthetic = "do we catch look-alikes of names we watch?", real-world = "how do we do on real feeds and real sites?".
"""
import csv
import json
import time
from collections import defaultdict
from pathlib import Path

import pandas as pd

import detector
from datasets import REALWORLD_CSV, TIME_CUT, path_of, read_uci_sms
from features import LEGIT_DOMAINS
from lookalikes import ATTACK_TYPES, OUTPUT
from outputs import check_many, speed
from sms import check_message

HERE = Path(__file__).parent
FLAGGED = ("Phishing", "Suspicious")


def main():
    if not OUTPUT.exists():
        raise SystemExit("data/synthetic_pairs.csv is missing. Run: python lookalikes.py")
    pairs = pd.read_csv(OUTPUT, encoding="utf-8")
    bundle = detector.load_model()

    fakes = pairs[pairs["attack_type"] != "negative"]
    negatives = pairs[pairs["attack_type"] == "negative"]

    # counts[(group, attack)] = [total, caught by the rules alone, caught finally, finally Phishing]
    counts = defaultdict(lambda: [0, 0, 0, 0])
    named = defaultdict(int)  # how often evidence.py named the same attack type as the generator
    started = time.perf_counter()
    for genuine, lookalike, attack in fakes.itertuples(index=False):
        r = detector.full_analysis(lookalike, bundle)
        group = "brands" if genuine in LEGIT_DOMAINS else "popular"
        row = counts[(group, attack)]
        row[0] += 1
        row[1] += detector.verdict_for(r["rule_score"]) in FLAGGED
        row[2] += r["verdict"] in FLAGGED
        row[3] += r["verdict"] == "Phishing"
        named[attack] += r["evidence"]["attack_type"] == attack or (
            attack == "keyboard_neighbour" and r["evidence"]["attack_type"] == "changed_letter")
    elapsed = time.perf_counter() - started

    # Real sites are on the popular list, so they would pass instantly. Turn that shortcut off to
    # see what happens to a real site that is NOT on our list, which is the honest test.
    saved = detector.POPULAR_SET
    detector.POPULAR_SET = set()
    results = [detector.full_analysis(d, bundle) for d in negatives["lookalike"]]
    detector.POPULAR_SET = saved
    flagged = sum(r["verdict"] in FLAGGED for r in results)
    phishing = sum(r["verdict"] == "Phishing" for r in results)
    rule_flagged = sum(detector.verdict_for(r["rule_score"]) in FLAGGED for r in results)

    print(f"{'attack type':<20}{'brands':>8}{'rules':>8}{'final':>8}{'phish':>8}   {'popular':>8}{'rules':>8}{'final':>8}{'phish':>8}{'type ok':>9}")
    table = []
    for attack in ATTACK_TYPES:
        b, p = counts[("brands", attack)], counts[("popular", attack)]
        pct = lambda row, i: row[i] / row[0] if row[0] else 0.0
        type_ok = named[attack] / max(b[0] + p[0], 1)
        print(f"{attack:<20}{b[0]:>8}{pct(b, 1):>8.0%}{pct(b, 2):>8.0%}{pct(b, 3):>8.0%}   "
              f"{p[0]:>8}{pct(p, 1):>8.0%}{pct(p, 2):>8.0%}{pct(p, 3):>8.0%}{type_ok:>9.0%}")
        table.append({"attack_type": attack, "type_named_correctly": type_ok,
                      "brands": {"count": b[0], "rules": pct(b, 1), "final": pct(b, 2), "phishing": pct(b, 3)},
                      "popular": {"count": p[0], "rules": pct(p, 1), "final": pct(p, 2), "phishing": pct(p, 3)}})

    n = len(results)
    ms = elapsed / len(fakes) * 1000
    print(f"\nFalse alarms on {n} real sites (popular shortcut off): rules {rule_flagged / n:.1%}, "
          f"final {flagged / n:.1%} ({phishing / n:.1%} Phishing)")
    _, batch_seconds = check_many(fakes["lookalike"].tolist(), bundle)
    batch_ms, batch_per_second = speed(len(fakes), batch_seconds)
    print(f"Speed, one at a time: {ms:.1f} ms per domain ({1000 / ms:.0f} domains/second)")
    print(f"Speed, as a list:     {batch_ms:.1f} ms per domain ({batch_per_second:.0f} domains/second)")

    summary = {"attacks": table, "n_fakes": len(fakes),
               "false_alarms": {"count": n, "rules": rule_flagged / n, "final": flagged / n, "phishing": phishing / n},
               "ms_per_domain": ms, "batch_ms_per_domain": batch_ms, "batch_per_second": batch_per_second}
    summary["real_world"] = real_world(bundle)
    summary["messages"] = message_tests(bundle)
    (HERE / "evaluation.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("Saved evaluation.json")


def real_world(bundle):
    """Real phishing feeds and hard real sites, kept apart from training (datasets.py).
    Reported separately from the synthetic numbers above, and never blended into one headline."""
    if not REALWORLD_CSV.exists():
        print("\ndata/realworld_test.csv is missing, so the real-world test was skipped. Run: python datasets.py")
        return None
    table = pd.read_csv(REALWORLD_CSV)
    rows, _ = check_many(table["host"].tolist(), bundle)
    table["verdict"] = [row["verdict"] for row in rows]
    table["flagged"] = table["verdict"].isin(FLAGGED)
    table["phishing"] = table["verdict"] == "Phishing"
    phish, real = table[table["label"] == 1], table[table["label"] == 0]
    caught, wrong = int(phish["flagged"].sum()), int(real["flagged"].sum())
    caught_p, wrong_p = int(phish["phishing"].sum()), int(real["phishing"].sum())
    result = {
        "n_phishing": len(phish), "n_legit": len(real),
        "flagged": {"recall": caught / len(phish), "false_alarm_rate": wrong / len(real),
                    "precision": caught / max(caught + wrong, 1)},
        "phishing_verdict": {"recall": caught_p / len(phish), "false_alarm_rate": wrong_p / len(real),
                             "precision": caught_p / max(caught_p + wrong_p, 1)},
        "groups": {group: {"count": len(rows_), "label": int(rows_["label"].iloc[0]),
                           "flagged": float(rows_["flagged"].mean()), "phishing": float(rows_["phishing"].mean())}
                   for group, rows_ in table.groupby("group")},
        "time_cut": TIME_CUT,
    }
    print(f"\nReal-world test (held out, {len(phish):,} phishing hosts and {len(real):,} real sites):")
    print(f"{'group':<20}{'count':>8}{'flagged':>10}{'Phishing':>10}")
    for group, row in result["groups"].items():
        print(f"{group:<20}{row['count']:>8,}{row['flagged']:>10.1%}{row['phishing']:>10.1%}")
    print(f"Flagged:  recall {result['flagged']['recall']:.1%}, false alarms {result['flagged']['false_alarm_rate']:.2%}, "
          f"precision {result['flagged']['precision']:.1%} at this mix")
    print(f"Phishing: recall {result['phishing_verdict']['recall']:.1%}, false alarms "
          f"{result['phishing_verdict']['false_alarm_rate']:.2%}, precision {result['phishing_verdict']['precision']:.1%} at this mix")
    return result


def message_tests(bundle):
    """Hand-written messages (test_messages.csv) and, if downloaded, real everyday SMS as a false-alarm check."""
    with open(HERE / "test_messages.csv", encoding="utf-8", newline="") as handle:
        cases = list(csv.DictReader(line for line in handle if not line.startswith("#")))
    tally = defaultdict(lambda: [0, 0])
    for case in cases:
        good = check_message(case["message"], case["sender"] or "", bundle)["verdict"] == case["expected"]
        kind = "genuine" if case["expected"] == "Safe" else "scam"
        for key in (case["set"], f"{case['set']}_{kind}"):
            tally[key][0] += good
            tally[key][1] += 1
    result = {"cases": {key: {"passed": a, "total": b} for key, (a, b) in sorted(tally.items())}}
    print("\nMessages (hand-written):", ", ".join(f"{key} {a}/{b}" for key, (a, b) in sorted(tally.items())))
    if path_of("uci_sms").exists():
        everyday = [check_message(text, "", bundle) for label, text in read_uci_sms() if label == "ham"]
        flagged = sum(r["verdict"] != "Safe" for r in everyday)
        scam = sum(r["verdict"] == "Scam" for r in everyday)
        result["uci_everyday"] = {"count": len(everyday), "flagged": flagged / len(everyday), "scam": scam / len(everyday)}
        print(f"Real everyday SMS (UCI, English): {flagged} of {len(everyday):,} flagged ({flagged / len(everyday):.2%}), {scam} as Scam")
    return result


if __name__ == "__main__":
    main()
