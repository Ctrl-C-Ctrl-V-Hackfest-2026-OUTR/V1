"""
Kavach - the detection logic: rule score + ML probability -> one verdict.

app.py (the UI), evaluate.py and the command-line tool all call these same functions.
This file must NOT import app.py or streamlit (importing app.py starts the UI).
"""
import re
from pathlib import Path

import joblib
import pandas as pd

# Brand list, scam words, look-alike logic and ML features are shared with train.py
from features import (BRANDS, LEGIT_DOMAINS, POPULAR_SET, SUSPICIOUS_TLDS, SUSPICIOUS_WORDS,
                      at_imitates, before_at, brand_match, decode_idn, extract_features, is_free_hosted,
                      is_trusted_bank, one_typo_brand, parse, popular_lookalike, subdomain_brand,
                      top_site_abuse)

HERE = Path(__file__).parent
OFFICIAL_REASON = "Known official domain"
BANK_REASON = "Verified Indian bank domain (.bank.in)"
POPULAR_REASON = "Popular real website (top 20,000 sites)"
POPULAR_SUB_REASON = "Subdomain of popular real website {}"
ML_TRUST = 0.70  # the ML model only gets a say when it is at least this sure


def verdict_for(score: float) -> str:
    return "Phishing" if score >= 60 else "Suspicious" if score >= 30 else "Safe"


def settled(url: str, domain: str, score: int, reason: str, note: str) -> dict:
    """A result the rules are sure of. The ML model is skipped; explain() shows the note."""
    return {"url": url, "domain": domain, "score": score, "verdict": verdict_for(score),
            "reasons": reason, "note": note}


def analyze(url: str) -> dict:
    """Rule-based risk score (0-100) with the reasons behind it."""
    url = url.strip().lower()
    parts, full_host = parse(url)
    domain = f"{parts.domain}.{parts.suffix}" if parts.suffix else parts.domain
    name = parts.domain

    score, reasons = 0, []
    is_official = domain in LEGIT_DOMAINS
    is_bank = is_trusted_bank(full_host)
    is_popular = domain in POPULAR_SET
    is_popular_site = is_popular and parts.subdomain in ("", "www")
    sub_brand = subdomain_brand(parts.subdomain)
    # A popular site's subdomains belong to the same owner (accounts.spotify.com), unless
    # anyone can publish there (paytm-login.weebly.com) or another brand's name is in them.
    is_same_owner = is_popular and not is_free_hosted(full_host) and not sub_brand

    # The "@" trick comes first: an address hiding part of itself never gets an instant Safe.
    # +60 = Phishing on its own, when the hidden part pretends to be a brand.
    hidden = before_at(url)
    if hidden is not None:
        at_score = 60 if at_imitates(hidden) else 40
        at_reason = f"Uses @ to hide the real address — the browser goes to {full_host}"
        # The host itself is one we trust, so the @ is the only thing wrong with this address
        if is_official or is_bank or is_popular_site or is_same_owner:
            return settled(url, domain, at_score, at_reason,
                           f"The browser really goes to {full_host}, which we trust, but real links "
                           "don't hide part of their address with @, so the ML model was not needed.")
        score += at_score
        reasons.append(at_reason)
    elif is_official:
        return settled(url, domain, 0, OFFICIAL_REASON,
                       "This is a known official domain, so it is Safe and no further checks were needed.")
    elif is_bank:
        return settled(url, full_host, 0, BANK_REASON,
                       "Only RBI-verified banks can register under .bank.in, so it is Safe "
                       "and no further checks were needed.")
    elif is_popular_site:
        return settled(url, domain, 0, POPULAR_REASON,
                       "This is one of the top 20,000 most popular websites, so it is Safe "
                       "and no further checks were needed.")
    elif is_same_owner:
        return settled(url, domain, 0, POPULAR_SUB_REASON.format(domain),
                       f"This is a subdomain of {domain}, a popular website, and belongs to "
                       "the same owner, so it is Safe and the ML model was not needed.")

    # 1. Look-alike name (typosquatting), strongest match first
    if not is_popular:
        clean, best_brand, best_sim, is_homoglyph = brand_match(name)
        typo_brand = one_typo_brand(clean)
        if is_homoglyph:
            score += 70
            reasons.append(f"Fake letters copy '{clean}' (e.g. 0 for o, rn for m)")
        elif typo_brand:
            # +60 = Phishing on its own
            score += 60
            reasons.append(f"One typo away from '{typo_brand}'")
        elif best_sim >= 80:
            score += 45
            reasons.append(f"Looks like '{best_brand}' ({best_sim:.0f}% similar) but is not the real site")
        else:
            # Only +45 (Suspicious): popular-site names cause more false alarms than our brands
            popular_target = popular_lookalike(name)
            abused_site = top_site_abuse(name)
            if popular_target:
                score += 45
                reasons.append(f"One typo away from popular site '{popular_target}'")
            elif abused_site:
                score += 45
                reasons.append(f"Uses the name of popular site '{abused_site}' but is not that site")

    # 2. Brand name sitting in the subdomain, e.g. paytm.secure-login.xyz
    #    +45 so that "brand in subdomain" + a suspicious TLD (+15) always reaches 60 = Phishing
    if sub_brand:
        score += 45
        reasons.append(f"Brand '{sub_brand}' used in subdomain")

    # 3. Cheap / abused TLD
    if parts.suffix in SUSPICIOUS_TLDS:
        score += 15
        reasons.append(f"Suspicious ending '.{parts.suffix}'")

    # 4. Scammy words
    hits = [w for w in SUSPICIOUS_WORDS if w in full_host]
    if hits:
        score += min(10 * len(hits), 20)
        reasons.append("Contains words: " + ", ".join(hits))

    # 5. Structure tricks
    shown_name = decode_idn(name)  # what a person sees: the xn-- code itself has hyphens and digits
    if shown_name.count("-") >= 2:
        score += 10
        reasons.append("Many hyphens")
    if re.search(r"\d", shown_name):
        score += 5
        reasons.append("Digits in name")
    if len(full_host) > 30:
        score += 5
        reasons.append("Very long domain")
    if re.fullmatch(r"[\d.]+", full_host):
        score += 30
        reasons.append("Raw IP address instead of a name")

    score = min(score, 100)
    return {"url": url, "domain": domain, "score": score, "verdict": verdict_for(score),
            "reasons": "; ".join(reasons) or "No red flags found", "note": None}


def load_model():
    """Load model.joblib (made by train.py). Returns None if it does not exist yet."""
    path = HERE / "model.joblib"
    if not path.exists():
        return None
    bundle = joblib.load(path)
    bundle["model"].n_jobs = 1  # one domain at a time is much faster without thread start-up
    return bundle


def full_analysis(url: str, bundle) -> dict:
    """Rule score + ML probability -> final score.

    If ML probability >= 70%:  final = max(rule score, average of rule score and ML x 100)
    Otherwise:                 final = rule score
    "decided_by" says whether the ML model actually raised the score.
    """
    r = analyze(url)
    r["rule_score"] = r["score"]
    r["ml_probability"] = None  # percent, 0-100
    r["decided_by"] = "Rules"

    # Results we are sure of stay Safe; no ML needed. Without a model we keep the rule score only.
    if bundle is None or r["note"]:
        return r

    model = bundle["model"]
    row = pd.DataFrame([extract_features(url)], columns=bundle["features"])
    p = model.predict_proba(row)[0][list(model.classes_).index(1)]
    r["ml_probability"] = round(p * 100, 1)
    if p >= ML_TRUST:
        blended = round((r["rule_score"] + r["ml_probability"]) / 2)
        if blended > r["rule_score"]:
            r["score"] = blended
            r["decided_by"] = "Rules + ML"
        r["verdict"] = verdict_for(r["score"])
    if p >= 0.5:
        note = f"ML model: {r['ml_probability']:.0f}% chance of phishing"
        r["reasons"] = note if r["reasons"] == "No red flags found" else r["reasons"] + "; " + note
    return r


def lookalike_target(url: str):
    """If the link imitates a known brand or popular site, return the real domain, else None.
    Display helper only: it does not change any score."""
    parts, full_host = parse(url)
    domain = f"{parts.domain}.{parts.suffix}" if parts.suffix else parts.domain
    hidden = before_at(url)
    if hidden is not None and at_imitates(hidden):  # sbi.bank.in@evil.com -> sbi.bank.in
        return at_imitates(hidden)
    if domain in LEGIT_DOMAINS or is_trusted_bank(full_host):
        return None
    brand = None
    is_popular = domain in POPULAR_SET
    if not is_popular:  # same as analyze(): the name of a popular site is not a look-alike
        clean, best_brand, best_sim, is_homoglyph = brand_match(parts.domain)
        if is_homoglyph:
            brand = clean
        else:
            brand = one_typo_brand(clean) or (best_brand if best_sim >= 80 else None)
    if not brand:
        brand = subdomain_brand(parts.subdomain)
    if brand:
        return BRANDS[brand][0]
    return None if is_popular else popular_lookalike(parts.domain) or top_site_abuse(parts.domain)


def explain(r: dict, target) -> str:
    """One plain-English sentence about how the rules and the ML model contributed."""
    rule, ml, by = r["rule_score"], r["ml_probability"], r["decided_by"]
    if r["note"]:
        return r["note"]
    if target:
        trick = "Rules found a look-alike trick"
    elif rule >= 30:
        trick = "Rules found warning signs"
    else:
        trick = "Rules found little or nothing suspicious"
    if ml is None:
        return f"{trick}. The ML model is not available, so only the rules were used."
    if by == "Rules + ML":
        return f"{trick}, and the ML model was {ml:.0f}% sure it is phishing, so it raised the final score."
    if ml >= ML_TRUST * 100:
        return (f"{trick}. The ML model agrees ({ml:.0f}% sure), "
                "but the rules already scored higher, so the rules decided.")
    return f"{trick}; the ML model was only {ml:.0f}% sure, so it didn't add extra risk."
