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
from features import (BRANDS, FEATURE_NAMES, GOVERNMENT_ENDINGS, LEGIT_DOMAINS, POPULAR_SET, SUSPICIOUS_TLDS,
                      SUSPICIOUS_WORDS,
                      at_imitates, before_at, brand_match, brand_name_of, decode_idn, extract, extract_features,
                      is_free_hosted, is_trusted_bank, normalize, one_typo_brand, parse, popular_lookalike,
                      scam_words_brand, subdomain_brand, top_site_abuse, top_site_in_subdomain)
from evidence import edits_between, similarity_evidence

HERE = Path(__file__).parent
OFFICIAL_REASON = "Known official domain"
BANK_REASON = "Verified Indian bank domain (.bank.in)"
POPULAR_REASON = "Popular real website (top 20,000 sites)"
GOVERNMENT_REASON = "Indian government domain (.gov.in or .nic.in)"
POPULAR_SUB_REASON = "Subdomain of popular real website {}"
FREE_HOST_REASON = "Hosted on {}, where anyone can publish a page"
FREE_HOST_FLOOR = 30  # at least Suspicious: the address says nothing about who runs the page
ML_TRUST = 0.70  # the ML model only gets a say when it is at least this sure

# Every rule's points, in one place. analyze() uses these and the website's signals grid shows them,
# so the page can't drift from the code.
POINTS = {"at_trick": 40, "at_trick_brand": 60, "homoglyph": 70, "one_typo": 60, "scam_words_brand": 60, "looks_like": 45,
          "popular": 45, "subdomain": 45, "fake_ending": 60, "suspicious_tld": 15, "scam_word": 10, "scam_words_max": 20,
          "hyphens": 10, "digits": 5, "long": 5, "ip": 30}


def signal_catalog() -> list:
    """What the rules look for and what each is worth, for the signals grid on the website."""
    p = POINTS
    return [
        {"name": "Look-alike characters", "points": f"+{p['homoglyph']}",
         "detail": "Fake letters (0 for o, rn for m, Cyrillic) spell a brand: paytrn, \u0430pple."},
        {"name": "One typo from a brand", "points": f"+{p['one_typo']}",
         "detail": "Exactly one edit from a brand with a long enough name to be safe: icicibankk."},
        {"name": "Brand plus scam words", "points": f"+{p['scam_words_brand']}",
         "detail": "A short brand with only scam words around it: sbi-kyc, sbikyc."},
        {"name": "Protected ending as a disguise", "points": f"+{p['fake_ending']}",
         "detail": ".gov.in or .bank.in used inside a longer address: sbi.gov.in.evil.com."},
        {"name": "Looks like a brand", "points": f"+{p['looks_like']}",
         "detail": "80%+ similar to a brand, or a brand hidden in a longer name: sbi-kyc-update-now."},
        {"name": "Popular-site look-alike", "points": f"+{p['popular']}",
         "detail": "One typo from a top site, or a top-200 name on another ending: rediit.com, reddit.xyz."},
        {"name": "Brand in a subdomain", "points": f"+{p['subdomain']}",
         "detail": "A brand placed before an unrelated domain: paytm.verify-account.click."},
        {"name": "Hidden address (@ trick)", "points": f"+{p['at_trick']} or +{p['at_trick_brand']}",
         "detail": "Text before an @ hides where the browser really goes."},
        {"name": "Bare IP address", "points": f"+{p['ip']}", "detail": "A raw IP used where a domain should be."},
        {"name": "Free hosting", "points": f"at least {FREE_HOST_FLOOR}",
         "detail": "Anyone can publish on these, so the address says nothing about who runs the page: x.weebly.com."},
        {"name": "High-abuse ending", "points": f"+{p['suspicious_tld']}",
         "detail": f"{len(SUSPICIOUS_TLDS)} endings where phishing is far more common than real sites: .xyz, .top, .cfd."},
        {"name": "Scam words", "points": f"+{p['scam_word']} each, max {p['scam_words_max']}",
         "detail": "login, verify, kyc, update, reward."},
        {"name": "Name structure", "points": f"+{p['hyphens']} / +{p['digits']} / +{p['long']}",
         "detail": "Two or more hyphens, digits in the name, or more than 30 characters."},
        {"name": "ML second opinion", "points": "can only raise",
         "detail": f"At {ML_TRUST:.0%} or more, the score becomes the average of rules and ML if that is higher."},
    ]


def verdict_for(score: float) -> str:
    return "Phishing" if score >= 60 else "Suspicious" if score >= 30 else "Safe"


def settled(url: str, domain: str, score: int, reason: str, note: str) -> dict:
    """A result the rules are sure of. The ML model is skipped; explain() shows the note."""
    return {"url": url, "domain": domain, "score": score, "verdict": verdict_for(score),
            "reasons": reason, "note": note, "reason_points": [score]}


def analyze(url: str) -> dict:
    """Rule-based risk score (0-100) with the reasons behind it."""
    url = url.strip().lower()
    parts, full_host = parse(url)
    domain = f"{parts.domain}.{parts.suffix}" if parts.suffix else parts.domain
    name = parts.domain

    score, reasons, weights = 0, [], []

    def flag(points: int, text: str) -> int:
        """Record one reason and how many points it added, and return those points to add.
        The UI shows the points as a dot on each reason chip; the score itself is unchanged."""
        reasons.append(text)
        weights.append(points)
        return points

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
        at_score = POINTS["at_trick_brand"] if at_imitates(hidden) else POINTS["at_trick"]
        at_reason = f"Uses @ to hide the real address — the browser goes to {full_host}"
        # The host itself is one we trust, so the @ is the only thing wrong with this address
        if is_official or is_bank or is_popular_site or is_same_owner:
            return settled(url, domain, at_score, at_reason,
                           f"The browser really goes to {full_host}, which we trust, but real links "
                           "don't hide part of their address with @, so the ML model was not needed.")
        score += flag(at_score, at_reason)
    elif is_official:
        return settled(url, domain, 0, OFFICIAL_REASON,
                       "This is a known official domain, so it is Safe and no further checks were needed.")
    elif is_bank:
        if full_host.endswith(GOVERNMENT_ENDINGS):
            return settled(url, full_host, 0, GOVERNMENT_REASON,
                           "Only Indian government bodies can register under .gov.in and .nic.in, so a scammer "
                           "can't buy a look-alike here. It is Safe and no further checks were needed.")
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
        scam_brand = scam_words_brand(name)
        if is_homoglyph:
            trick = "Hyphen added to copy" if decode_idn(name).replace("-", "") == clean else "Fake letters copy"
            real = brand_name_of(clean)
            score += flag(POINTS["homoglyph"], f"{trick} '{real}': " + ", ".join(edits_between(name, real)))
        elif typo_brand:
            # +60 = Phishing on its own
            score += flag(POINTS["one_typo"], f"One typo away from '{typo_brand}': "
                          + ", ".join(edits_between(clean, typo_brand)))
        elif scam_brand:
            # +60 = Phishing on its own: sbikyc is a classic look-alike
            score += flag(POINTS["scam_words_brand"], f"Brand '{scam_brand}' with only scam words added: '{decode_idn(name)}'")
        elif best_sim >= 80:
            score += flag(POINTS["looks_like"], f"Looks like '{best_brand}' but is not the real site")
        else:
            # Only +45 (Suspicious): popular-site names cause more false alarms than our brands
            popular_target = popular_lookalike(name)
            abused_site = top_site_abuse(name)
            if popular_target:
                popular_name = extract(popular_target).domain
                trick = "Fake letters copy" if normalize(name) == popular_name else "One typo away from"
                score += flag(POINTS["popular"], f"{trick} popular site '{popular_target}': "
                              + ", ".join(edits_between(name, popular_name)))
            elif abused_site:
                score += flag(POINTS["popular"], f"Uses the name of popular site '{abused_site}' but is not that site")

    # 2. Brand name sitting in the subdomain, e.g. paytm.secure-login.xyz
    #    +45 so that "brand in subdomain" + a suspicious TLD (+15) always reaches 60 = Phishing
    if sub_brand:
        score += flag(POINTS["subdomain"], f"Brand '{sub_brand}' used in subdomain")
    # A protected ending used as a disguise, e.g. sbi.gov.in.evil.com. Real .gov.in and .bank.in
    # addresses end there, so this is never an accident: +60 = Phishing on its own.
    if re.search(r"(^|\.)(gov|nic|bank)\.in$", parts.subdomain):
        score += flag(POINTS["fake_ending"], f"Pretends to be a government or bank address, but the real domain is {domain}")

    # 3. Cheap / abused TLD
    if parts.suffix in SUSPICIOUS_TLDS:
        score += flag(POINTS["suspicious_tld"], f"Suspicious ending '.{parts.suffix}'")

    # 4. Scammy words
    hits = [w for w in SUSPICIOUS_WORDS if w in full_host]
    if hits:
        score += flag(min(POINTS["scam_word"] * len(hits), POINTS["scam_words_max"]), "Contains words: " + ", ".join(hits))

    # 5. Structure tricks
    shown_name = decode_idn(name)  # what a person sees: the xn-- code itself has hyphens and digits
    if shown_name.count("-") >= 2:
        score += flag(POINTS["hyphens"], f"Many hyphens: {shown_name.count('-')} in '{shown_name}'")
    digits = re.findall(r"\d", shown_name)
    if digits:
        score += flag(POINTS["digits"], "Digits in name: " + "".join(digits))
    if len(full_host) > 30:
        score += flag(POINTS["long"], f"Very long domain: {len(full_host)} characters")
    if re.fullmatch(r"[\d.]+", full_host):
        score += flag(POINTS["ip"], f"Raw IP address instead of a name: {full_host}")

    # 6. Anyone can publish here. A floor, not extra points, so the model's average below stays as it was:
    #    on its own this means Suspicious, never Phishing (many real projects use github.io).
    score = min(score, 100)
    floor_added = 0
    if is_free_hosted(full_host) and score < FREE_HOST_FLOOR:
        floor_added = flag(FREE_HOST_FLOOR - score, FREE_HOST_REASON.format(domain))
        score = FREE_HOST_FLOOR
    return {"url": url, "domain": domain, "score": score, "verdict": verdict_for(score),
            "reasons": "; ".join(reasons) or "No red flags found", "note": None,
            "reason_points": weights, "floor_added": floor_added}


def load_model():
    """Load model.joblib (made by train.py). Returns None if it does not exist yet."""
    path = HERE / "model.joblib"
    if not path.exists():
        return None
    bundle = joblib.load(path)
    bundle["model"].n_jobs = 1  # one domain at a time is much faster without thread start-up
    return bundle


def structure_facts(url: str) -> str:
    """The facts the ML model mostly looks at, in words: '2 subdomains, 31 characters, 4 digits'."""
    values = dict(zip(FEATURE_NAMES, extract_features(url)))
    facts = [f"{values['subdomain_count']} subdomain{'s' if values['subdomain_count'] != 1 else ''}",
             f"{values['length']} characters"]
    if values["digits"]:
        facts.append(f"{values['digits']} digit{'s' if values['digits'] != 1 else ''}")
    if values["hyphens"]:
        facts.append(f"{values['hyphens']} hyphen{'s' if values['hyphens'] != 1 else ''}")
    return ", ".join(facts)


def full_analysis(url: str, bundle, proba=None) -> dict:
    """Everything about one link: the score from score_link() plus the similarity evidence.
    proba is the ML probability (0-1) if it was already worked out, as outputs.check_many() does."""
    r = score_link(url, bundle, proba)
    r["target"] = lookalike_target(url)
    r["evidence"] = similarity_evidence(url, r["target"])
    return r


def score_link(url: str, bundle, proba=None) -> dict:
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

    if proba is None:
        model = bundle["model"]
        row = pd.DataFrame([extract_features(url)], columns=bundle["features"])
        proba = model.predict_proba(row)[0][list(model.classes_).index(1)]
    p = float(proba)
    r["ml_probability"] = round(p * 100, 1)
    if p >= ML_TRUST:
        # The free-hosting floor is left out of the average: it says "unknown owner", not "more risk"
        blended = round((r["rule_score"] - r.get("floor_added", 0) + r["ml_probability"]) / 2)
        if blended > r["rule_score"]:
            r["score"] = blended
            r["decided_by"] = "Rules + ML"
        r["verdict"] = verdict_for(r["score"])
    if p >= 0.5:
        note = f"ML model: {r['ml_probability']:.0f}% chance of phishing, from its structure ({structure_facts(url)})"
        if r["reasons"] == "No red flags found":
            r["reasons"], r["reason_points"] = note, [r["score"] - r["rule_score"]]
        else:
            r["reasons"] += "; " + note
            r["reason_points"] = r["reason_points"] + [r["score"] - r["rule_score"]]
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
            brand = brand_name_of(clean)
        else:
            brand = one_typo_brand(clean) or (best_brand if best_sim >= 80 else None)
    if not brand:
        brand = subdomain_brand(parts.subdomain)
    if brand:
        return BRANDS[brand][0]
    # A popular site's own subdomains are the same owner, unless anyone can publish there
    if is_popular and not is_free_hosted(full_host):
        return None
    return ((None if is_popular else popular_lookalike(parts.domain) or top_site_abuse(parts.domain))
            or top_site_in_subdomain(parts.subdomain))


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
