"""
Kavach - shared rules and ML features.

Both app.py (the Streamlit app) and train.py (model training) import from here,
so the brand list, scam words and look-alike logic live in exactly one place.
This file must NOT import app.py (app.py starts the Streamlit UI when imported).
"""
import math
import re
from pathlib import Path

import tldextract
from rapidfuzz import fuzz, process
from rapidfuzz.distance import DamerauLevenshtein

# Use tldextract's built-in suffix list, so it works offline
extract = tldextract.TLDExtract(suffix_list_urls=())

# Real brands that phishers like to copy -> list of their real domains
# (a brand can own several real domains, e.g. amazon.in AND amazon.com)
BRANDS = {
    "sbi": ["sbi.co.in"], "onlinesbi": ["onlinesbi.sbi"], "hdfcbank": ["hdfcbank.com"],
    "icicibank": ["icicibank.com"], "axisbank": ["axisbank.com"], "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"], "google": ["google.com"],
    "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"], "irctc": ["irctc.co.in"], "microsoft": ["microsoft.com"],
    "apple": ["apple.com"], "facebook": ["facebook.com"], "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"], "netflix": ["netflix.com"], "paypal": ["paypal.com"],
    "incometax": ["incometax.gov.in"], "uidai": ["uidai.gov.in"],
    "youtube": ["youtube.com"], "gmail": ["gmail.com"], "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"], "telegram": ["telegram.org"],
    # Indian banks
    "kotak": ["kotak.com"], "pnbindia": ["pnbindia.in"], "bankofbaroda": ["bankofbaroda.in"],
    "canarabank": ["canarabank.com"], "yesbank": ["yesbank.in"], "indusind": ["indusind.com"],
    # UPI and payments
    "googlepay": ["pay.google.com"], "bhimupi": ["bhimupi.org.in"], "npci": ["npci.org.in"],
    # Shopping, food delivery, telecom
    "myntra": ["myntra.com"], "meesho": ["meesho.com"], "swiggy": ["swiggy.com"],
    "zomato": ["zomato.com"], "airtel": ["airtel.in"], "jio": ["jio.com"],
    # Government
    "epfindia": ["epfindia.gov.in"], "indiapost": ["indiapost.gov.in"],
}
# Flat set of every official domain -> instant "Safe"
LEGIT_DOMAINS = {d for domains in BRANDS.values() for d in domains}

# Only RBI-verified Indian banks can register under .bank.in, so anything under it is trusted.
TRUSTED_ENDINGS = (".bank.in",)  # the leading dot stops fakebank.in from matching

# Sites where anyone can publish a page, so a subdomain says nothing about who runs it.
# Subdomains of these always go to the ML model, even when the rules find nothing.
# Note: sites.google.com is listed for completeness, but google.com is an official domain,
# so analyze() returns Safe for anything on it before this set is ever checked.
FREE_HOSTING = {
    # Website builders and app hosting
    "weebly.com", "weeblysite.com", "blogspot.com", "github.io", "000webhostapp.com",
    "wixsite.com", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
    "firebaseapp.com", "web.app", "herokuapp.com", "glitch.me", "godaddysites.com",
    "sites.google.com", "ngrok.io", "ngrok-free.app", "r2.dev", "square.site",
    # The hosts below were hand-picked, not an automatic top-N. We counted which popular domains
    # had the most hosts in our phishing feed (data/phishing-domains-ACTIVE.txt) showing Safe with
    # ML skipped, read through that ranking, and added the ones we recognised as hosting or free DNS
    # services. It was a judgement call and the list is incomplete: selcdn.ru, app.link and
    # teachable.com have more feed hosts than some entries here but were left out.
    # Site and app hosting
    "webflow.io", "gitbook.io", "yolasite.com", "mystrikingly.com", "tripod.com",
    "framer.app", "replit.app", "appspot.com", "azurewebsites.net", "pantheonsite.io",
    "mybluehost.me", "cprapid.com", "tmweb.ru", "beget.tech",
    # Free dynamic DNS: anyone can point a free name at their own server
    "duckdns.org", "ddns.net", "hopto.org", "sytes.net", "zapto.org",
    # Sell or give away subdomains that look like normal web addresses
    "eu.org", "sa.com", "ru.com",
}
_FREE_HOSTING_ENDINGS = tuple("." + host for host in FREE_HOSTING)

# Everyday words that are 1 edit from a brand. The +60 one-typo rule ignores these, because
# nobody who types tomato.in meant zomato. Keep this list small: each word is a typo we no
# longer call Phishing. Deliberately NOT here: "goggle", a classic typo of google.
ORDINARY_WORDS = {
    "apply", "ample", "apples",  # apple
    "email", "mail",             # gmail
    "kodak",                     # kotak
    "tomato",                    # zomato
    "mantra",                    # myntra
    "twister",                   # twitter
    "googly",                    # google (the cricket word)
}

# Popular real sites, most popular first. Made once by build_popular.py from data/tranco.csv.
# If the file is missing the lists stay empty and the popular-site checks simply never match.
POPULAR_FILE = Path(__file__).parent / "popular_domains.txt"
POPULAR_DOMAINS = POPULAR_FILE.read_text(encoding="utf-8").split() if POPULAR_FILE.exists() else []
POPULAR_SET = set(POPULAR_DOMAINS)

# name -> real domain, for the top 2,000 sites only ("reddit" -> "reddit.com").
# Names with fewer than 5 letters are left out: nearly any short word is 1 edit from one of them.
# setdefault keeps the highest-ranked domain when a name repeats (google.com, google.co.in).
POPULAR_NAMES = {}
for _domain in POPULAR_DOMAINS[:2000]:
    _name = extract(_domain).domain
    if sum(c.isalpha() for c in _name) >= 5:
        POPULAR_NAMES.setdefault(_name, _domain)
_POPULAR_NAME_LIST = list(POPULAR_NAMES)  # process.extractOne treats a dict differently, so use a list

SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "click",
                   "zip", "shop", "online", "site", "live", "icu", "info"}
SUSPICIOUS_WORDS = ["login", "verify", "secure", "update", "kyc", "account",
                    "bank", "reward", "bonus", "free", "support", "confirm"]
_SCAM_WORDS = "|".join(SUSPICIOUS_WORDS)  # regex piece used by brand_hidden_in()

# Look-alike characters: 0->o, 1->l, rn->m, etc.
HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"),
              ("3", "e"), ("5", "s"), ("@", "a")]


def normalize(text: str) -> str:
    """Turn look-alike characters back into the letters they imitate."""
    for fake, real in HOMOGLYPHS:
        text = text.replace(fake, real)
    return text


def parse(url: str):
    """Split a link/domain into (parts, full_host). Works offline."""
    parts = extract(url.strip().lower())
    full_host = ".".join(p for p in [parts.subdomain, parts.domain, parts.suffix] if p)
    return parts, full_host


def before_at(url: str):
    """Return the part hidden before an "@" in the address, or None if there is no such "@".

    In https://paytm.com@evil.xyz/login the browser goes to evil.xyz. An "@" later on, in the
    path or query (evil.xyz/a@b), is harmless. An empty result still means the "@" is there.
    """
    rest = re.sub(r"^([a-z][a-z0-9+.-]*:)?//", "", url.strip().lower())  # drop https://
    address = re.split(r"[/?#\\]", rest, maxsplit=1)[0]                  # drop the path
    return address.rsplit("@", 1)[0] if "@" in address else None


def is_trusted_bank(host: str) -> bool:
    """True for sbi.bank.in, but not for fakebank.in or sbi.bank.in.evil.com."""
    return host.endswith(TRUSTED_ENDINGS)


def is_free_hosted(host: str) -> bool:
    """True for a subdomain of a free-hosting site, e.g. anything.weebly.com."""
    return host.endswith(_FREE_HOSTING_ENDINGS)


def brand_hidden_in(text: str, brand: str) -> bool:
    """Is this brand really in the text, not just letters that happen to line up?

    Checks each dot-separated part, both word by word and with its hyphens removed
    (hdfc-bank-login -> hdfcbanklogin). The longer the brand, the less likely a chance match:
      - any length, a whole word:  sbi-kyc-update, kyc-paytm
      - 6+ letters, anywhere:      startamazonstore, myflipkartoffer, ama-zon-login
      - 5 letters, start of word:  paytmkyc (so pineapple does not count as apple)
      - 3-4 letters, with nothing else but scam words: sbikyc, sbilogin, kycsbi
        (so lesbian does not count as sbi)
    """
    for part in normalize(text).split("."):
        words = part.split("-")
        joined = part.replace("-", "")
        pieces = words + [joined]
        if brand in pieces:
            return True
        if len(brand) >= 6:
            if brand in joined:
                return True
        elif len(brand) == 5:
            if any(p.startswith(brand) for p in pieces):
                return True
        elif any(re.fullmatch(f"(?:{_SCAM_WORDS})*{brand}(?:{_SCAM_WORDS})*", p) for p in pieces):
            return True
    return False


def subdomain_brand(subdomain: str):
    """Return the first brand used in a subdomain (paytm-login -> paytm), else None."""
    return next((b for b in BRANDS if brand_hidden_in(subdomain, b)), None)


def at_imitates(hidden: str):
    """Which real site does the part before an "@" pretend to be? Returns its domain, else None.
    sbi.bank.in -> sbi.bank.in, paytm.com -> paytm.com, paytm-login -> paytm.com."""
    host = hidden.split(":")[0]  # user:password@host
    for ending in TRUSTED_ENDINGS:
        if ending in host:
            return host[:host.index(ending) + len(ending)]
    # Compare whole dot-separated parts, otherwise netflix.com would match x.com.
    # Longest first, so pay.google.com wins over google.com.
    for domain in sorted(LEGIT_DOMAINS, key=len, reverse=True):
        if f".{domain}." in f".{host}.":
            return domain
    brand = subdomain_brand(host)
    return BRANDS[brand][0] if brand else None


def brand_match(name: str):
    """Compare a domain name with every brand.

    Returns (clean, best_brand, best_sim, is_homoglyph):
      clean        - name with hyphens removed and look-alike characters fixed
      best_brand   - the most similar brand (or None)
      best_sim     - its similarity, 0-100 (a brand hidden inside counts as 90)
      is_homoglyph - True when fake letters turn the name into a brand exactly
    """
    clean = normalize(name.replace("-", ""))
    best_brand, best_sim = None, 0
    for brand in BRANDS:
        sim = fuzz.ratio(clean, brand)
        if clean != brand and brand_hidden_in(name, brand):
            sim = max(sim, 90)  # brand hidden inside, e.g. sbi-kyc-update
        if sim > best_sim:
            best_brand, best_sim = brand, sim
    is_homoglyph = clean in BRANDS and name != clean
    return clean, best_brand, best_sim, is_homoglyph


def edit_distance(a: str, b: str) -> int:
    """Number of typos between two strings. Inserting, deleting or changing a letter,
    or swapping two neighbouring letters, each counts as 1 edit."""
    return DamerauLevenshtein.distance(a, b)


def one_typo_brand(clean: str):
    """Return the brand (5+ letters) that this cleaned name is exactly 1 edit from, else None.
    Everyday words in ORDINARY_WORDS never count."""
    if clean in ORDINARY_WORDS:
        return None
    for brand in BRANDS:
        if len(brand) >= 5 and edit_distance(clean, brand) == 1:
            return brand
    return None


def popular_lookalike(name: str):
    """Return the real domain if the name is exactly 1 edit from a top-2,000 site, else None.

    The scorer must be DamerauLevenshtein.distance itself, not a wrapper: that is how
    rapidfuzz knows lower is better and treats score_cutoff=1 as "at most 1 edit".
    """
    match = process.extractOne(name, _POPULAR_NAME_LIST,
                               scorer=DamerauLevenshtein.distance, score_cutoff=1)
    # A distance of 0 means the same name on another ending, which is not a typo
    if match and match[1] == 1:
        return POPULAR_NAMES[match[0]]
    return None


# ---------------- ML features ----------------

# The order of this list is the column order the model is trained on.
FEATURE_NAMES = [
    "length", "hyphens", "digits", "dots", "subdomain_count",
    "vowel_ratio", "entropy", "suspicious_tld", "scam_words",
    "brand_similarity", "brand_in_subdomain", "homoglyph_match",
]


def _entropy(text: str) -> float:
    """Shannon entropy: how random the characters look (random junk = high)."""
    if not text:
        return 0.0
    counts = {c: text.count(c) for c in set(text)}
    return -sum((n / len(text)) * math.log2(n / len(text)) for n in counts.values())


def extract_features(url: str) -> list:
    """Turn one domain/link into a list of numbers, ordered like FEATURE_NAMES."""
    parts, _ = parse(url)
    name = parts.domain

    # Ignore a leading "www." so example.com and www.example.com score the same. This also stops
    # a data leak: every legit PhiUSIIL row starts https://www. but only 41% of phishing rows do,
    # so a model that sees "www" learns "no www = phishing" and flags every real site typed without it.
    subdomain = "" if parts.subdomain == "www" else parts.subdomain.removeprefix("www.")
    host = ".".join(p for p in [subdomain, parts.domain, parts.suffix] if p)

    letters = [c for c in name if c.isalpha()]
    vowel_ratio = sum(c in "aeiou" for c in letters) / len(letters) if letters else 0.0
    subdomain_count = len(subdomain.split(".")) if subdomain else 0

    _, _, best_sim, is_homoglyph = brand_match(name)

    return [
        len(host),                                          # length
        host.count("-"),                                    # hyphens
        sum(c.isdigit() for c in host),                     # digits
        host.count("."),                                    # dots
        subdomain_count,                                    # subdomain_count
        vowel_ratio,                                        # vowel_ratio
        _entropy(host),                                     # entropy
        int(parts.suffix in SUSPICIOUS_TLDS),               # suspicious_tld
        sum(w in host for w in SUSPICIOUS_WORDS),           # scam_words
        best_sim,                                           # brand_similarity
        int(subdomain_brand(subdomain) is not None),        # brand_in_subdomain
        int(is_homoglyph),                                  # homoglyph_match
    ]
