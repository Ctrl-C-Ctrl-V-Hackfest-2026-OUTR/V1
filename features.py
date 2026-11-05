"""
Kavach - shared rules and ML features.

Both app.py (the Streamlit app) and train.py (model training) import from here,
so the brand list, scam words and look-alike logic live in exactly one place.
This file must NOT import app.py (app.py starts the Streamlit UI when imported).
"""
import json
import math
import os
import re
from functools import lru_cache
from pathlib import Path

import tldextract
from rapidfuzz import fuzz, process
from rapidfuzz.distance import DamerauLevenshtein

# Use tldextract's built-in suffix list, so it works offline
extract = tldextract.TLDExtract(suffix_list_urls=())

# The watchlist lives in a data file, so adding a brand needs no code change. See "_how_to_add" there.
BRANDS_FILE = Path(__file__).parent / "brands.json"
# Brands added on the website, on this computer only (gitignored, made when the first one is added).
CUSTOM_BRANDS_FILE = Path(os.environ.get("KAVACH_CUSTOM_BRANDS", Path(__file__).parent / "brands_custom.json"))  # the tests use a temporary one
MAX_CUSTOM_BRANDS = 200

BRAND_RECORDS = []    # one full record per brand, as in brands.json, plus the custom ones
# Everything below is filled by _load_brands(). They are changed in place, never replaced, because
# other files hold a reference to them through "from features import BRANDS".
BRANDS = {}           # name to look for -> the brand's real domains (aliases included)
LEGIT_DOMAINS = set() # flat set of every official domain -> instant "Safe"
BRAND_ALIASES = set() # other spellings: match when exact or hidden, but never as "one typo away"
WEAK_BRANDS = set()   # names that are also ordinary words: only match with scam words around them
_BRAND_FORMS = {}     # name -> the name after normalize() (karnatakabank -> kamatakabank, see below)
_FORM_TO_KEY = {}     # the reverse
_LEGIT_LONGEST_FIRST = []
_brand_listeners = [] # functions to call when the watchlist changes (evidence.py, sms.py)

# Only RBI-verified Indian banks can register under .bank.in, and only Indian government bodies under
# .gov.in and .nic.in, so a scammer can't buy a look-alike there. The data agrees: none of the 413,000
# hosts in our phishing feeds is on .gov.in or .nic.in, while 33 of 1,192 real ones were being flagged.
# These sites can still be hacked, which no check of the name can see.
TRUSTED_ENDINGS = (".bank.in", ".gov.in", ".nic.in")  # the leading dot stops fakebank.in from matching
GOVERNMENT_ENDINGS = (".gov.in", ".nic.in")

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
    # The hosts below were chosen from the data, not by hand. We counted how many hosts in our
    # phishing feed (data/phishing-domains-ACTIVE.txt) sit on each registered domain in the Tranco
    # top 20,000, ranked them, and went down the ranking adding the first 30 not already listed
    # above: from plesk.page (1,034 hosts) to azurestaticapps.net (88). The rule was to skip one
    # company's own site with no public hosting, and none came up in that stretch.
    # Cloud storage and app hosting
    "amazonaws.com", "appdomain.cloud", "amplifyapp.com", "windows.net", "azurestaticapps.net",
    "linodeobjects.com", "myqcloud.com", "selcdn.ru", "ondigitalocean.app", "digitaloceanspaces.com",
    "b-cdn.net", "trycloudflare.com",
    # Web hosting, including free and temporary addresses
    "plesk.page", "tw1.ru", "secureserver.net", "wpenginepowered.com", "temporary.site", "rf.gd",
    # Website builders and user pages
    "filesusr.com", "teachable.com", "myportfolio.com", "framer.website", "jimdofree.com",
    # Link services anyone can use
    "app.link", "page.link",
    # Free subdomains and dynamic DNS
    "work.gd", "wikaba.com", "otzo.com", "dynv6.net", "ydns.eu",
    # Added November 2026 by the same method, on a newer count: hosts with 14+ entries in the older feeds
    # (Phishing.Database plus PhishTank before the test cut-off, never the held-out test rows) that offer
    # public hosting. Blogger's country addresses (blogspot.fr...) are handled in is_free_hosted().
    # Popular sites, which would otherwise pass as Safe with the model skipped
    "hsforms.com", "typeform.com", "sibforms.com", "wpengine.com", "googleusercontent.com", "translate.goog",
    "onrender.com", "studio.site", "lovable.app", "ghost.io", "cloudfront.net", "azurefd.net", "azureedge.net",
    "fastly.net", "pythonanywhere.com", "myftpupload.com", "systeme.io", "squarespace.com", "kinsta.cloud",
    "myshopify.com", "tumblr.com", "netlify.com", "regruhosting.ru", "linodeusercontent.com", "neocities.org",
    "hostingersite.com", "firebaseio.com", "ovh.net", "cloudwaysapps.com", "mybigcommerce.com", "scw.cloud",
    "webnode.page", "webnode.com", "webhostbox.net", "hs-sites.com", "editmysite.com", "nxcli.io", "railway.app",
    "cpanel.site", "meusitehostgator.com.br", "sslip.io",
    # Free subdomains and dynamic DNS
    "dynamic-dns.net", "gb.net", "co.com", "org.ru", "net.ru", "pp.ru", "pp.ua", "us.com", "eu.com", "eu.cc",
    "serveuser.com", "giize.com", "dedyn.io", "kozow.com", "gleeze.com", "mooo.com", "ath.cx", "dpdns.org",
    "ocry.com", "25u.com", "x24hr.com", "jetos.com", "itemdb.com", "ourhobby.com", "dvrlists.com", "mrbasic.com",
    "onedumb.com", "dumb1.com",
    # Less popular hosting, IPFS gateways and throwaway addresses
    "dweb.link", "repl.co", "replit.dev", "xsph.ru", "swtest.ru", "co.vu", "webcindario.com", "cf-ipfs.com",
    "usrfiles.com", "ewp.live", "wixstudio.com", "nftstorage.link", "w3s.link", "surge.sh", "infura-ipfs.io",
    "typedream.app", "atwebpages.com", "fleek.co", "crabdance.com", "webwave.dev", "runcloud.link", "ic0.app",
    "wcomhost.com", "serveirc.com", "brizy.site", "temp-site.link", "codeanyapp.com", "umbler.net", "start.page",
    "easywp.com", "ubpages.com", "justns.ru", "webspace.re", "csb.app", "preview-domain.com", "zya.me",
    "w3spaces.com", "cu.ma", "temporary.link", "za.com", "pagedemo.co", "myvnc.com", "iceiy.com", "zapier.app",
}
_FREE_HOSTING_ENDINGS = tuple("." + host for host in FREE_HOSTING)
_BLOGGER_ABROAD = re.compile(r"\.blogspot\.[a-z]{2,3}(\.[a-z]{2})?$")  # Blogger's addresses by country

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
    "delivery",                  # delhivery
    "finance",                   # binance
    "protein",                   # protean
    "ecobank",                   # ucobank: not a word, but a real bank elsewhere in the world
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

# The second line was added from the data: endings where phishing sites are at least 6 times as common as
# they are among real sites (older feeds compared with the Tranco top 1M), the level of .click and .buzz.
SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "click",
                   "zip", "shop", "online", "site", "live", "icu", "info",
                   "xin", "bond", "help", "cyou", "cfd", "sbs"}
SUSPICIOUS_WORDS = ["login", "verify", "secure", "update", "kyc", "account",
                    "bank", "reward", "bonus", "free", "support", "confirm"]
_SCAM_WORDS = "|".join(SUSPICIOUS_WORDS)  # regex piece used by brand_hidden_in()
_COMBO_WORDS = _SCAM_WORDS + "|offer"     # regex piece used by top_site_abuse()

# Top-200 sites that are plain words. Someone else can honestly use these names (forms.net,
# office-update.com), so top_site_abuse() leaves them out.
COMMON_WORD_SITES = {"cloud", "forms", "pages", "static", "archive", "example", "workers", "opera",
                     "europa", "sentry", "apache", "office", "windows"}
# name -> real domain for the top 200 sites, hyphens removed ("reddit" -> "reddit.com").
TOP_SITE_NAMES = {}
for _domain in POPULAR_DOMAINS[:200]:
    _name = extract(_domain).domain.replace("-", "")
    if sum(c.isalpha() for c in _name) >= 5 and _name not in COMMON_WORD_SITES:
        TOP_SITE_NAMES.setdefault(_name, _domain)

# Look-alike characters: 0->o, 1->l, rn->m, etc.
HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"),
              ("3", "e"), ("5", "s"), ("@", "a")]


# Cyrillic letters that look exactly like Latin ones. Browsers can show these as the real name.
CYRILLIC_LETTERS = {"а": "a", "с": "c", "е": "e", "һ": "h", "і": "i", "ј": "j",
                    "о": "o", "р": "p", "ѕ": "s", "х": "x", "у": "y"}


def _decode_punycode(match) -> str:
    """xn--pytm-5cd is how a name with foreign letters is really stored; turn it back into letters."""
    try:
        return match.group().encode("ascii").decode("idna")
    except UnicodeError:
        return match.group()  # not valid punycode, so leave it as it is


def decode_idn(text: str) -> str:
    """Turn any xn-- parts of a host back into the letters a person would see."""
    return re.sub(r"xn--[a-z0-9-]+", _decode_punycode, text)


@lru_cache(maxsize=4096)  # called dozens of times per domain, once for every brand
def normalize(text: str) -> str:
    """Turn look-alike characters back into the letters they imitate."""
    text = "".join(CYRILLIC_LETTERS.get(c, c) for c in decode_idn(text))
    for fake, real in HOMOGLYPHS:
        text = text.replace(fake, real)
    return text


# ---------------- loading the watchlist ----------------

def _load_brands() -> None:
    """(Re)build every brand lookup from brands.json and brands_custom.json, in place."""
    records = json.loads(BRANDS_FILE.read_text(encoding="utf-8"))["brands"]
    if CUSTOM_BRANDS_FILE.exists():
        try:
            custom = json.loads(CUSTOM_BRANDS_FILE.read_text(encoding="utf-8"))
            records = records + [{**record, "custom": True} for record in custom]
        except (OSError, ValueError):
            pass  # a damaged local file must not stop the detector
    BRAND_RECORDS[:] = records
    for table in (BRANDS, LEGIT_DOMAINS, BRAND_ALIASES, WEAK_BRANDS, _BRAND_FORMS, _FORM_TO_KEY):
        table.clear()
    for record in records:
        BRANDS[record["key"]] = record["domains"]
        LEGIT_DOMAINS.update(record["domains"])
        if record.get("weak"):
            WEAK_BRANDS.add(record["key"])
        if record.get("no_typo"):
            BRAND_ALIASES.add(record["key"])  # same rule as an alias: exact or hidden, never "looks similar"
    for record in records:
        for alias in record.get("aliases", []):
            BRANDS.setdefault(alias, record["domains"])
            BRAND_ALIASES.add(alias)
        for alias in record.get("weak_aliases", []):
            BRANDS.setdefault(alias, record["domains"])
            WEAK_BRANDS.add(alias)
    # normalize() reads "rn" as "m", so a real name such as karnatakabank must be compared in its
    # normalized form too, otherwise karnatakabank-login.com would never match it.
    for key in BRANDS:
        form = normalize(key)
        _BRAND_FORMS[key] = form
        _FORM_TO_KEY.setdefault(form, key)
    _LEGIT_LONGEST_FIRST[:] = sorted(LEGIT_DOMAINS, key=len, reverse=True)  # pay.google.com before google.com
    for cached in (brand_match, _short_brand_pattern):
        cached.cache_clear()
    for listener in _brand_listeners:
        listener()


def on_brands_changed(listener) -> None:
    """Ask to be told when a brand is added or removed. Also runs the listener once now."""
    _brand_listeners.append(listener)
    listener()


def _custom_records() -> list:
    return [{k: v for k, v in record.items() if k != "custom"} for record in BRAND_RECORDS if record.get("custom")]


def _save_custom(records: list) -> None:
    """Write the local file in one step, so a crash half way can't leave it damaged."""
    temporary = CUSTOM_BRANDS_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(records, indent=1, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, CUSTOM_BRANDS_FILE)


def add_custom_brand(name: str, domain: str) -> dict:
    """Add a brand from the website. It is stored in brands_custom.json and works straight away.

    Being on the watchlist makes a domain instantly Safe, so this refuses anything that could turn a
    fake into a trusted site. Raises ValueError with a message the page can show.
    """
    name = " ".join(str(name).split())[:60]
    if not name:
        raise ValueError("Enter the brand's name.")
    parts, host = parse(str(domain))
    host = host.removeprefix("www.")
    if not re.fullmatch(r"[a-z0-9.-]+", host) or not parts.suffix or before_at(str(domain)) is not None:
        raise ValueError("Enter the brand's own domain, like konarkbank.in.")
    registered = f"{parts.domain}.{parts.suffix}"
    key = parts.domain.replace("-", "")
    if len(key) < 3:
        raise ValueError("That name is too short to protect reliably.")
    if is_free_hosted(host) or registered in FREE_HOSTING:
        raise ValueError(f"{registered} is a free-hosting site, where anyone can publish. Enter the brand's own domain.")
    if host in LEGIT_DOMAINS or registered in LEGIT_DOMAINS or key in BRANDS or is_trusted_bank(host):
        raise ValueError(f"{host} is already on the watchlist.")
    clean, _, _, is_homoglyph = brand_match(parts.domain)
    copied = one_typo_brand(clean) or (_FORM_TO_KEY.get(clean) if is_homoglyph else None)
    if copied:
        raise ValueError(f"{host} looks like a fake of {BRANDS[copied][0]}, so it can't be added as a trusted brand.")
    if len(_custom_records()) >= MAX_CUSTOM_BRANDS:
        raise ValueError(f"The limit is {MAX_CUSTOM_BRANDS} added brands. Remove one first.")
    record = {"key": key, "name": name, "category": "Added by you", "domains": [registered],
              "words": [name.lower()] if len(name) >= 3 else []}
    _save_custom(_custom_records() + [record])
    _load_brands()
    return record


def remove_custom_brand(key: str) -> None:
    """Remove a brand added on the website. Brands from brands.json can't be removed this way."""
    remaining = [record for record in _custom_records() if record["key"] != key]
    if len(remaining) == len(_custom_records()):
        raise ValueError("That brand was not added on this computer.")
    _save_custom(remaining)
    _load_brands()


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
    return host.endswith(_FREE_HOSTING_ENDINGS) or bool(_BLOGGER_ABROAD.search(host))


def brand_hidden_in(text: str, brand: str) -> bool:
    """Is this brand really in the text, not just letters that happen to line up?

    Checks each dot-separated part, both word by word and with its hyphens removed
    (hdfc-bank-login -> hdfcbanklogin). The longer the brand, the less likely a chance match:
      - any length, a whole word:  sbi-kyc-update, kyc-paytm
      - 6+ letters, anywhere:      startamazonstore, myflipkartoffer, ama-zon-login
      - 5 letters, start of word:  paytmkyc (so pineapple does not count as apple)
      - 3-4 letters, with nothing else but scam words: sbikyc, sbilogin, kycsbi
        (so lesbian does not count as sbi)
      - a "weak" name (navi, axis), whatever its length, only with nothing else but scam words
    """
    form = _BRAND_FORMS.get(brand, brand)
    weak = brand in WEAK_BRANDS
    for part in normalize(text).split("."):
        words = part.split("-")
        joined = part.replace("-", "")
        if form not in joined:  # the quick answer for nearly every brand
            continue
        pieces = words + [joined]
        if weak:
            if any(_short_brand_pattern(form).fullmatch(p) and p != form for p in pieces):
                return True
            continue
        if form in pieces:
            return True
        if len(form) >= 6:
            return True  # already known to be inside
        if len(form) == 5:
            if any(p.startswith(form) for p in pieces):
                return True
        elif any(_short_brand_pattern(form).fullmatch(p) for p in pieces):
            return True
    return False


@lru_cache(maxsize=1024)
def _short_brand_pattern(form: str):
    return re.compile(f"(?:{_SCAM_WORDS})*{re.escape(form)}(?:{_SCAM_WORDS})*")


def subdomain_brand(subdomain: str):
    """Return the first brand used in a subdomain (paytm-login -> paytm), else None."""
    if not subdomain:
        return None
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
    for domain in _LEGIT_LONGEST_FIRST:
        if f".{domain}." in f".{host}.":
            return domain
    brand = subdomain_brand(host)
    return BRANDS[brand][0] if brand else None


@lru_cache(maxsize=8192)  # analyze(), lookalike_target() and extract_features() all ask about the same name
def brand_match(name: str):
    """Compare a domain name with every brand.

    Returns (clean, best_brand, best_sim, is_homoglyph):
      clean        - name with hyphens removed and look-alike characters fixed
      best_brand   - the most similar brand (or None)
      best_sim     - its similarity, 0-100 (a brand hidden inside counts as 90)
      is_homoglyph - True when fake letters turn the name into a brand exactly
    """
    # Fix the letters first and remove hyphens after: the hyphens in xn--pytm-53d are part of its code
    clean = normalize(name).replace("-", "")
    # normalize() reads 1 as l, but it can stand for i too: sb1 -> sbi
    one_as_i = normalize(name.replace("1", "i")).replace("-", "")
    if one_as_i in _FORM_TO_KEY:
        clean = one_as_i
    best_brand, best_sim = None, 0
    for brand, form in _BRAND_FORMS.items():
        if brand in WEAK_BRANDS:
            sim = 0                                # an ordinary word: looking similar means nothing
        elif brand in BRAND_ALIASES:
            sim = 100 if clean == form else 0      # canara must not match canada
        else:
            sim = fuzz.ratio(clean, form)
        if clean != form and form in clean and brand_hidden_in(name, brand):
            sim = max(sim, 90)  # brand hidden inside, e.g. sbi-kyc-update
        if sim > best_sim:
            best_brand, best_sim = brand, sim
    copied = _FORM_TO_KEY.get(clean)
    is_homoglyph = copied is not None and copied not in WEAK_BRANDS and name != copied
    return clean, best_brand, best_sim, is_homoglyph


def brand_name_of(clean: str) -> str:
    """The real spelling of a cleaned name: kamatakabank -> karnatakabank. Others stay as they are."""
    return _FORM_TO_KEY.get(clean, clean)


def scam_words_brand(name: str):
    """Return the short or weak brand if the whole name is that brand plus only scam words, else None.
    sbikyc, kycsbi, sbi-login and navi-login count. lesbian and sbi-kyc-update-now don't."""
    clean = normalize(name).replace("-", "")
    for brand, form in _BRAND_FORMS.items():
        if (len(form) <= 4 or brand in WEAK_BRANDS) and clean != form and form in clean \
                and _short_brand_pattern(form).fullmatch(clean):
            return brand
    return None


def edit_distance(a: str, b: str) -> int:
    """Number of typos between two strings. Inserting, deleting or changing a letter,
    or swapping two neighbouring letters, each counts as 1 edit."""
    return DamerauLevenshtein.distance(a, b)


def one_typo_brand(clean: str):
    """Return the brand (5+ letters) that this cleaned name is exactly 1 edit from, else None.
    Everyday words in ORDINARY_WORDS never count."""
    if clean in ORDINARY_WORDS:
        return None
    for brand, form in _BRAND_FORMS.items():
        if (len(form) >= 5 and abs(len(form) - len(clean)) <= 1 and brand not in BRAND_ALIASES
                and brand not in WEAK_BRANDS and edit_distance(clean, form) == 1):
            return brand
    return None


def popular_lookalike(name: str):
    """Return the real domain if the name is exactly 1 edit from a top-2,000 site, else None.

    The scorer must be DamerauLevenshtein.distance itself, not a wrapper: that is how
    rapidfuzz knows lower is better and treats score_cutoff=1 as "at most 1 edit".
    """
    clean = normalize(name)
    if clean in ORDINARY_WORDS:
        return None
    if clean != name and clean in POPULAR_NAMES:  # fake letters spell it exactly: rnozilla, or Cyrillic
        return POPULAR_NAMES[clean]
    match = process.extractOne(clean, _POPULAR_NAME_LIST,
                               scorer=DamerauLevenshtein.distance, score_cutoff=1)
    # A distance of 0 means the same name on another ending, which is not a typo
    if match and match[1] == 1:
        return POPULAR_NAMES[match[0]]
    return None


def top_site_abuse(name: str):
    """Return the real domain if this name abuses a top-200 site, else None:
    the same name on another ending (reddit.xyz), or the name with only scam words around it
    (reddit-login.com, loginreddit.com). Other words next to it don't count: reddit-fans.com is fine."""
    clean = normalize(name).replace("-", "")
    if clean in TOP_SITE_NAMES:
        return TOP_SITE_NAMES[clean]
    for site, domain in TOP_SITE_NAMES.items():
        if site in clean and re.fullmatch(f"(?:{_COMBO_WORDS})*{site}(?:{_COMBO_WORDS})*", clean):
            return domain
    return None


def top_site_in_subdomain(subdomain: str):
    """Return the real domain if a top-200 name is a whole word in the subdomain, else None."""
    for word in re.split(r"[.-]", normalize(subdomain)):
        if word in TOP_SITE_NAMES:
            return TOP_SITE_NAMES[word]
    return None


_load_brands()  # after every function it needs exists


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
