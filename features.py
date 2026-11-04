"""
Kavach - shared rules and ML features.

Both app.py (the Streamlit app) and train.py (model training) import from here,
so the brand list, scam words and look-alike logic live in exactly one place.
This file must NOT import app.py (app.py starts the Streamlit UI when imported).
"""
import math

import tldextract
from rapidfuzz import fuzz

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
}
# Flat set of every official domain -> instant "Safe"
LEGIT_DOMAINS = {d for domains in BRANDS.values() for d in domains}

SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "click",
                   "zip", "shop", "online", "site", "live", "icu", "info"}
SUSPICIOUS_WORDS = ["login", "verify", "secure", "update", "kyc", "account",
                    "bank", "reward", "bonus", "free", "support", "confirm"]

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
        if brand in clean and clean != brand:
            sim = max(sim, 90)  # brand hidden inside, e.g. sbi-kyc-update
        if sim > best_sim:
            best_brand, best_sim = brand, sim
    is_homoglyph = clean in BRANDS and name != clean
    return clean, best_brand, best_sim, is_homoglyph


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
    parts, host = parse(url)
    name = parts.domain

    letters = [c for c in name if c.isalpha()]
    vowel_ratio = sum(c in "aeiou" for c in letters) / len(letters) if letters else 0.0
    subdomain_count = len(parts.subdomain.split(".")) if parts.subdomain else 0

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
        int(any(b in parts.subdomain for b in BRANDS)),     # brand_in_subdomain
        int(is_homoglyph),                                  # homoglyph_match
    ]
