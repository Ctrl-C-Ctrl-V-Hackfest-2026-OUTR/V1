"""
Kavach - build popular_domains.txt from the Tranco list (run once).

Run with:  python build_popular.py
Reads data/tranco.csv (made by train.py) and writes the top registered domains, most popular
first, one per line. The output is committed, so teammates don't need data/.

Being popular does not prove a site is real: some look-alikes get a lot of traffic too. Anything
on this list is marked Safe, so domains that imitate a brand are removed. Both groups below
are printed, so a person can check them.
"""
from pathlib import Path

from features import BRANDS, LEGIT_DOMAINS, POPULAR_FILE, brand_match, edit_distance, extract

TRANCO_CSV = Path(__file__).parent / "data" / "tranco.csv"  # lines like  1,google.com
TOP_N = 20_000

# Domains that match the look-alike test but stay on the list.
# "real" = a known real site. "unsure" = could not be confirmed offline, so kept for a human to check.
KEEP = {
    "mail.ru": "real: large Russian email service",
    "mail.com": "real: email service",
    "mail.microsoft": "real: on Microsoft's own .microsoft ending",
    "s-microsoft.com": "real: Microsoft's content delivery domain",
    "telegra.ph": "real: Telegram's publishing site (phishers also abuse it)",
    "telegraf.rs": "real: Serbian news site",
    "kodak.com": "real: camera and film company",
    "kotaku.com": "real: games news site",
    "uidapi.com": "real: Unified ID advertising service",
    "googl.com": "real: Google's own, registered through MarkMonitor with ns1-4.google.com name servers",
    "avple.tv": "unsure: does not look like it is imitating apple",
    "twister.porn": "unsure: does not look like it is imitating twitter",
}


def imitates_brand(domain: str):
    """Why this domain looks like a brand's look-alike, or None if it doesn't.

    Checks every 5+ letter brand directly rather than calling one_typo_brand(), because
    that skips ORDINARY_WORDS and an everyday word should still be shown here for review.
    """
    if domain in LEGIT_DOMAINS:
        return None  # a brand's own official domain
    clean, _, _, is_homoglyph = brand_match(extract(domain).domain)
    if is_homoglyph:
        return f"fake letters copy '{clean}'"
    for brand in BRANDS:
        if len(brand) >= 5 and edit_distance(clean, brand) == 1:
            return f"1 edit from '{brand}'"
    return None


def main():
    domains = {}  # a dict keeps insertion order, so this stays in rank order without repeats
    for line in TRANCO_CSV.read_text(encoding="utf-8").splitlines():
        if "," not in line:
            continue
        parts = extract(line.split(",", 1)[1].strip().lower())
        if parts.domain and parts.suffix:  # 'login.paytm.com' -> 'paytm.com'
            domains[f"{parts.domain}.{parts.suffix}"] = True

    top, removed, kept = [], [], []
    for domain in list(domains)[:TOP_N]:
        why = imitates_brand(domain)
        if why and domain not in KEEP:
            removed.append((domain, why))
            continue
        if why:
            kept.append((domain, why))
        top.append(domain)

    # newline="\n" gives the same file on Windows and Mac/Linux
    with open(POPULAR_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(top) + "\n")
    print(f"Saved {POPULAR_FILE.name}: {len(top)} domains (first: {top[0]}, last: {top[-1]})")

    print(f"\nREMOVED, looks like a brand ({len(removed)}):")
    for domain, why in removed:
        print(f"  {domain:20} {why}")
    print(f"\nKEPT, matches the test but listed in KEEP ({len(kept)}):")
    for domain, why in kept:
        print(f"  {domain:20} {why:20} {KEEP[domain]}")


if __name__ == "__main__":
    main()
