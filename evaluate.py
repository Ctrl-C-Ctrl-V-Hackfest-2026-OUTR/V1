"""
Kavach - how well do we catch synthetic look-alikes, and how often do we cry wolf?

Run with:  python lookalikes.py   (once, makes data/synthetic_pairs.csv)
           python evaluate.py
Prints a table per attack type and saves it to evaluation.json (the app can show that file).

"Caught" means the verdict is Suspicious or Phishing. Two groups are shown, because only our
curated BRANDS get the strong look-alike rules; the top 200 popular sites get one weaker rule.
"""
import json
import time
from collections import defaultdict
from pathlib import Path

import pandas as pd

import detector
from features import LEGIT_DOMAINS
from lookalikes import ATTACK_TYPES, OUTPUT

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
    started = time.perf_counter()
    for genuine, lookalike, attack in fakes.itertuples(index=False):
        r = detector.full_analysis(lookalike, bundle)
        group = "brands" if genuine in LEGIT_DOMAINS else "popular"
        row = counts[(group, attack)]
        row[0] += 1
        row[1] += detector.verdict_for(r["rule_score"]) in FLAGGED
        row[2] += r["verdict"] in FLAGGED
        row[3] += r["verdict"] == "Phishing"
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

    print(f"{'attack type':<20}{'brands':>8}{'rules':>8}{'final':>8}{'phish':>8}   {'popular':>8}{'rules':>8}{'final':>8}{'phish':>8}")
    table = []
    for attack in ATTACK_TYPES:
        b, p = counts[("brands", attack)], counts[("popular", attack)]
        pct = lambda row, i: row[i] / row[0] if row[0] else 0.0
        print(f"{attack:<20}{b[0]:>8}{pct(b, 1):>8.0%}{pct(b, 2):>8.0%}{pct(b, 3):>8.0%}   "
              f"{p[0]:>8}{pct(p, 1):>8.0%}{pct(p, 2):>8.0%}{pct(p, 3):>8.0%}")
        table.append({"attack_type": attack,
                      "brands": {"count": b[0], "rules": pct(b, 1), "final": pct(b, 2), "phishing": pct(b, 3)},
                      "popular": {"count": p[0], "rules": pct(p, 1), "final": pct(p, 2), "phishing": pct(p, 3)}})

    n = len(results)
    ms = elapsed / len(fakes) * 1000
    print(f"\nFalse alarms on {n} real sites (popular shortcut off): rules {rule_flagged / n:.1%}, "
          f"final {flagged / n:.1%} ({phishing / n:.1%} Phishing)")
    print(f"Speed: {ms:.1f} ms per domain ({1000 / ms:.0f} domains/second)")

    summary = {"attacks": table, "n_fakes": len(fakes),
               "false_alarms": {"count": n, "rules": rule_flagged / n, "final": flagged / n, "phishing": phishing / n},
               "ms_per_domain": ms}
    (HERE / "evaluation.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("Saved evaluation.json")


if __name__ == "__main__":
    main()
