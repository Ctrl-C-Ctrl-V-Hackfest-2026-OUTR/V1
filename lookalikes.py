"""
Kavach - make synthetic look-alike domains to test the detector. No dnstwist needed.

Run with:  python lookalikes.py
Writes data/synthetic_pairs.csv with the columns: genuine, lookalike, attack_type

For every genuine domain (our BRANDS and the top 200 popular sites) it makes fake versions of each
attack type below, plus "negative" pairs: real, unrelated sites that must NOT be flagged.
"""
import csv
import random
from pathlib import Path

from features import BRANDS, CYRILLIC_LETTERS, LEGIT_DOMAINS, POPULAR_DOMAINS, POPULAR_SET, extract

OUTPUT = Path(__file__).parent / "data" / "synthetic_pairs.csv"
MAX_PER_TYPE = 5   # fakes per genuine domain, per attack type (keeps the file a sensible size)
N_NEGATIVES = 2000
SEED = 42

ATTACK_TYPES = ["missing_letter", "extra_letter", "swapped_letters", "keyboard_neighbour", "homoglyph",
                "cyrillic", "hyphen", "combosquat", "tld_swap", "subdomain_abuse"]

# Letters next to each other on a QWERTY keyboard
KEYBOARD = {"q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok",
            "o": "ipl", "p": "ol", "a": "qsz", "s": "adw", "d": "sfe", "f": "dgr", "g": "fht", "h": "gjy",
            "j": "hku", "k": "jli", "l": "ko", "z": "ax", "x": "zc", "c": "xv", "v": "cb", "b": "vn",
            "n": "bm", "m": "n"}
# Fake -> real letters that look the same in Latin characters
LATIN_SWAPS = [("o", "0"), ("l", "1"), ("i", "1"), ("l", "i"), ("i", "l"), ("m", "rn"), ("rn", "m"), ("w", "vv")]
# Latin letter -> the Cyrillic letter that looks exactly like it
CYRILLIC = {latin: cyr for cyr, latin in CYRILLIC_LETTERS.items()}
COMBO_WORDS = ["kyc", "login", "verify", "update", "support", "offer"]
SWAP_TLDS = ["xyz", "top", "in", "co", "net"]


def missing_letter(name):
    return {name[:i] + name[i + 1:] for i in range(len(name))}


def extra_letter(name):
    """A doubled letter (paytmm), or a neighbouring key pressed as well (paytym)."""
    doubled = {name[:i] + name[i] + name[i:] for i in range(len(name))}
    pressed = {name[:i] + k + name[i:] for i in range(len(name)) for k in KEYBOARD.get(name[i], "")}
    return doubled | pressed


def swapped_letters(name):
    return {name[:i] + name[i + 1] + name[i] + name[i + 2:] for i in range(len(name) - 1) if name[i] != name[i + 1]}


def keyboard_neighbour(name):
    return {name[:i] + k + name[i + 1:] for i in range(len(name)) for k in KEYBOARD.get(name[i], "")}


def homoglyph(name):
    """Change one look-alike spot: 0 for o, 1 for l or i, rn for m, vv for w..."""
    found = set()
    for real, fake in LATIN_SWAPS:
        start = name.find(real)
        while start != -1:
            found.add(name[:start] + fake + name[start + len(real):])
            start = name.find(real, start + 1)
    return found


def cyrillic(name):
    """Swap one letter for its Cyrillic twin, and one version with every possible letter swapped."""
    found = {name[:i] + CYRILLIC[c] + name[i + 1:] for i, c in enumerate(name) if c in CYRILLIC}
    found.add("".join(CYRILLIC.get(c, c) for c in name))
    return found


def hyphen(name):
    return {name[:i] + "-" + name[i:] for i in range(1, len(name))}


def combosquat(name):
    found = set()
    for word in COMBO_WORDS:
        found |= {f"{name}-{word}", f"{word}-{name}", f"{name}{word}"}
    return found


# Attack types that change only the name; the ending stays the same
NAME_ATTACKS = {"missing_letter": missing_letter, "extra_letter": extra_letter, "swapped_letters": swapped_letters,
                "keyboard_neighbour": keyboard_neighbour, "homoglyph": homoglyph, "cyrillic": cyrillic,
                "hyphen": hyphen, "combosquat": combosquat}


def variants(domain: str) -> dict:
    """All the fakes of one genuine domain, as {attack_type: [fake domains]}."""
    parts = extract(domain)
    name, suffix = parts.domain, parts.suffix
    fakes = {attack: [f"{fake}.{suffix}" for fake in make(name) if fake and fake != name and fake.strip("-") == fake]
             for attack, make in NAME_ATTACKS.items()}
    fakes["tld_swap"] = [f"{name}.{tld}" for tld in SWAP_TLDS if tld != suffix]
    fakes["subdomain_abuse"] = [f"{name}.secure-login.xyz", f"{name}-login.verify-account.top",
                                f"{name}.{suffix}.account-update.click"]
    return fakes


def is_real(host: str) -> bool:
    """A fake that turns out to be a known real site (amazon.in) is not a fake, so leave it out."""
    parts = extract(host)
    registered = f"{parts.domain}.{parts.suffix}"
    return registered in LEGIT_DOMAINS or registered in POPULAR_SET


def build_pairs() -> list:
    rng = random.Random(SEED)
    brand_domains = [d for domains in BRANDS.values() for d in domains]
    # Skip very short names (t.co, x.com): deleting a letter from them means nothing
    genuine = [d for d in dict.fromkeys(brand_domains + POPULAR_DOMAINS[:200]) if len(extract(d).domain) >= 3]

    pairs = []
    for domain in genuine:
        for attack, fakes in variants(domain).items():
            fakes = sorted(f for f in set(fakes) if not is_real(f))
            pairs += [(domain, fake, attack) for fake in rng.sample(fakes, min(MAX_PER_TYPE, len(fakes)))]

    # Negatives: real sites paired with a brand they have nothing to do with
    real_sites = [d for d in POPULAR_DOMAINS[2000:] if d not in LEGIT_DOMAINS]
    pairs += [(rng.choice(brand_domains), site, "negative") for site in rng.sample(real_sites, N_NEGATIVES)]
    return pairs


def main():
    pairs = build_pairs()
    OUTPUT.parent.mkdir(exist_ok=True)
    with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["genuine", "lookalike", "attack_type"])
        writer.writerows(pairs)
    print(f"Saved {OUTPUT}: {len(pairs)} pairs")
    for attack in ATTACK_TYPES + ["negative"]:
        print(f"  {attack:20} {sum(p[2] == attack for p in pairs)}")


if __name__ == "__main__":
    main()
