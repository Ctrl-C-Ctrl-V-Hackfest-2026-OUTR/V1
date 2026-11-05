"""
Kavach - check a pasted SMS, WhatsApp or email message for scam signals.

check_message() finds every link in the text and scores it with our existing domain checks,
looks for scam wording, and returns one verdict with the evidence behind it.

Fully offline. No Streamlit here, so app.py, kavach_cli.py and test_rules.py can all use it.
"""
import re

from detector import full_analysis, verdict_for
from features import BRANDS, LEGIT_DOMAINS, extract

# Link shorteners. We cannot expand them offline, so a shortened link is a red flag by itself.
SHORTENERS = {"bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "t.ly", "rb.gy", "shorturl.at",
              "goo.gl", "tiny.cc", "ow.ly", "buff.ly", "bitly.com", "shorte.st", "adf.ly"}
# Chat links: not shorteners, but a "bank" that wants to chat instead of using its own site is odd
CHAT_HOSTS = {"wa.me", "t.me", "chat.whatsapp.com", "api.whatsapp.com", "telegram.me"}

# Common UPI handles, for spotting "pay to xyz@ybl"
UPI_HANDLES = ("ybl", "paytm", "okaxis", "oksbi", "okhdfcbank", "okicici", "upi", "axl", "ibl",
               "apl", "airtel", "freecharge", "jupiteraxis", "naviaxis", "fam", "superyes")


def message_verdict(score: float) -> str:
    """Same thresholds as the domain checks, with "Scam" instead of "Phishing"."""
    return "Scam" if score >= 60 else "Suspicious" if score >= 30 else "Safe"


# ---------------- finding links ----------------

# A plain link: an optional scheme, a host with at least one dot, and an optional path.
# (?<![\w@.-]) stops it matching inside a word or an email address.
LINK_RE = re.compile(r"""(?<![\w@.-])
    (?:(?:https?|ftp)://)?
    (?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}
    (?:/[^\s<>"']*)?""", re.I | re.X)

# Tricks scammers use to stop a link being clickable or detected
HXXP = re.compile(r"\bh[x*]{2}p(s?)\b", re.I)                                  # hxxp://  hxxps://
BRACKET_DOT = re.compile(r"\s*[\[({]\s*(?:\.|dot)\s*[\])}]\s*", re.I)          # [.]  (.)  [dot]
WORD_DOT = re.compile(r"(?<=[a-z0-9])\s+dot\s+(?=[a-z0-9])", re.I)             # sbi dot xyz
# A space BEFORE the dot ("sbi-kyc . xyz"). Normal writing never puts a space before a full stop,
# so this will not glue an ordinary sentence ("blocked today. Update") into a fake domain.
SPACED_DOT = re.compile(r"(?<=[a-z0-9])\s+\.\s*(?=[a-z0-9])", re.I)

TRAILING = ".,!?;:)]}>\"'’”"  # punctuation that ends a sentence, not a link


def deobfuscate(text: str) -> str:
    """Undo the tricks above, so a hidden link can be read normally."""
    text = HXXP.sub(r"http\1", text)
    text = BRACKET_DOT.sub(".", text)
    text = WORD_DOT.sub(".", text)
    return SPACED_DOT.sub(".", text)


def _host_of(link: str) -> str:
    parts = extract(link)
    return f"{parts.domain}.{parts.suffix}" if parts.suffix else ""


def find_links(text: str) -> list:
    """Every link in the message, as a list of {"link", "host", "shown", "span"}.

    Two passes: the first reads the text as written, so we know exactly where each link sits and
    can highlight it. The second reads the de-obfuscated text and picks up anything hidden
    (hxxp, [.], spaces), which has no position in the original, so its span is None.
    """
    found, seen = [], set()

    def add(raw: str, span):
        link = raw.strip().rstrip(TRAILING)
        host = _host_of(link)
        if host and host not in seen:
            seen.add(host)
            found.append({"link": link, "host": host, "shown": link,
                          "span": (span[0], span[0] + len(link)) if span else None})

    for match in LINK_RE.finditer(text):
        add(match.group(), match.span())
    hidden = deobfuscate(text)
    if hidden != text:
        for match in LINK_RE.finditer(hidden):
            add(match.group(), None)
    return found


def is_shortener(host: str) -> bool:
    return host in SHORTENERS


# ---------------- scam wording ----------------

# Each signal: points, the reason shown to the user, and the wordings that trigger it.
# Points are small and the total is capped, so no single phrase decides the verdict.
# Note on word stems: "disconnect" must also match "disconnected", so stems are written
# as "disconnect\w*" and never "disconnect\b", which would only match the exact word.
SIGNALS = [
    {
        "name": "otp_request", "points": 40,
        "reason": "Asks you to share an OTP, PIN or password — real banks never ask for these",
        # Only a REQUEST counts. A genuine "Your OTP is 123456, do not share it" must stay Safe,
        # so these all need an instruction word (share / send / tell / enter...).
        "patterns": [r"\b(share|send|tell|give|provide|forward|confirm|submit|reply with)\b[^.!?\n]{0,25}"
                     r"\b(otp|o\.t\.p|one[\s-]?time\s*(?:password|pin|code)|pin|cvv|password|passcode)\b",
                     r"\b(otp|pin|cvv|password)\b[^.!?\n]{0,20}\b(batao|bhejo|bhej|share\s*kar)",
                     r"\benter\b[^.!?\n]{0,25}\b(upi\s*pin|m-?pin|atm\s*pin)\b",
                     r"\b(upi\s*pin|atm\s*pin)\b[^.!?\n]{0,25}\bto\s+(receive|get|claim|collect)\b"],
    },
    {
        "name": "otp_bait", "points": 30,
        "reason": "Promises money, a prize or a refund you did not ask for",
        "patterns": [r"\b(lottery|lucky\s*draw|jackpot|kbc|kaun\s*banega)\b",
                     r"\byou\s*(have\s*)?(won|win)\b",
                     r"\bcongratulations\b[^.!?\n]{0,40}\b(won|win|prize|claim)\b",
                     r"\b(prize|cash\s*prize|reward\s*points?|cashback|gift\s*(card|voucher)|refund)\b"
                     r"[^.!?\n]{0,30}\b(claim|expir\w*|credit\w*|receive|redeem|pending)\b",
                     r"\b(claim|redeem)\b[^.!?\n]{0,25}\b(prize|reward|cashback|gift|amount|money)\b",
                     r"\b(receive|get|credited?)\b[^.!?\n]{0,20}"
                     r"\b(cashback|refund|prize|reward|bonus|amount)\b",
                     r"\b(inaam|lottery\s*lagi)\b"],
    },
    {
        "name": "kyc_bank", "points": 20,
        "reason": "Asks you to update KYC or bank details",
        "patterns": [r"\bk\.?y\.?c\.?\b",
                     r"\b(pan\s*card|aadhaar|aadhar)\b[^.!?\n]{0,30}\b(update|link|verif\w*|expir\w*)\b",
                     r"\b(update|verify|re-?verify|validate|confirm)\b[^.!?\n]{0,30}"
                     r"\b(your\s+)?(details|account|bank\s*account|profile|information|documents?)\b",
                     r"\b(account|a/c)\b[^.!?\n]{0,25}\b(will\s*be\s*)?"
                     r"(block\w*|suspend\w*|clos\w*|frozen|freeze|deactivat\w*)\b",
                     r"\b(khata|account)\b[^.!?\n]{0,20}\bband\s*ho\b"],
    },
    {
        "name": "urgency", "points": 20,
        "reason": "Pushes you to act immediately, which stops you checking",
        "patterns": [r"\b(immediately|urgent(ly)?|right\s*now|at\s*once|asap)\b",
                     # a threat and a deadline, in either order
                     r"\b(today|tonight|within\s*\d+\s*(hours?|hrs?|minutes?|mins?)|in\s*\d+\s*(hours?|hrs?))\b"
                     r"[^.!?\n]{0,30}\b(block\w*|suspend\w*|expir\w*|disconnect\w*|deactivat\w*|clos\w*|delet\w*)\b",
                     r"\b(block\w*|suspend\w*|expir\w*|disconnect\w*|deactivat\w*|clos\w*|delet\w*)\b"
                     r"[^.!?\n]{0,25}\b(today|tonight|now|immediately|within\s*\d+|before\s*\d)\b",
                     r"\b(expires?\s*(today|tonight|soon)|last\s*(chance|warning|day)|final\s*(notice|reminder))\b",
                     r"\b(turant|abhi\s*hi|jaldi)\b", r"\bband\s*ho\s*ja(yega|ega|egi)\b",
                     r"\b(failing\s*which|or\s*else\s*your)\b"],
    },
    {
        "name": "jobs_income", "points": 30,
        "reason": "Offers easy work or daily earnings, a common task-scam opening",
        "patterns": [r"\b(work\s*from\s*home|part[\s-]?time\s*(job|work)|online\s*job)\b",
                     r"\b(earn|kamao|kamaye)\b[^.!?\n]{0,30}(₹|rs\.?|inr)\s*\d",
                     r"\b(earn|kamao)\b[^.!?\n]{0,20}\b(daily|per\s*day|roz|everyday)\b",
                     r"\b(like|rate|review|subscribe)\b[^.!?\n]{0,20}\b(youtube|video|hotel|product)s?\b"
                     r"[^.!?\n]{0,25}\b(earn|paid|payment|task|money)\b",
                     r"\b(daily\s*task|task\s*complete|join\s*(our\s*)?telegram)\b"],
    },
    {
        "name": "bills_delivery", "points": 20,
        "reason": "Claims a bill, parcel or connection problem to make you act",
        "patterns": [r"\b(electricity|power|gas)\b[^.!?\n]{0,40}"
                     r"\b(disconnect\w*|cut\s*off|bill\s*pending|due)\b",
                     r"\b(parcel|package|shipment|courier|consignment)\b[^.!?\n]{0,40}"
                     r"\b(held|hold|stuck|customs|undeliverable|failed|pending|address)\b",
                     r"\b(customs|handling|delivery|shipping)\s*(fee|charge|duty)\b",
                     r"\b(update\s*(your\s*)?address|reschedule\s*(your\s*)?delivery)\b"],
    },
]

# Phrases that mean the message is TELLING you an OTP, not asking for one. A genuine bank OTP
# always carries one of these, so it must never be read as a request.
GENUINE_OTP = re.compile(r"\b(do\s*not|don'?t|never)\s*(share|disclose|reveal|tell)\b"
                         r"|\bkisi\s*ko\s*(na|mat)\s*(bata|share)", re.I)

# An Indian mobile number, possibly masked (98XXXXXX21) as scam warnings often print it.
# Toll-free numbers (1800...) do not match, because a genuine bank alert often gives one.
MOBILE_RE = re.compile(r"(?<![\d@])(?:\+?91[\s-]?)?[6-9][\dxX]{8}[\dxX](?!\d)")
UPI_RE = re.compile(r"\b[\w.-]{2,}@(" + "|".join(UPI_HANDLES) + r")\b", re.I)
CALL_RE = re.compile(r"\b(call|contact|whats?app|dial|ring|phone|sms)\b", re.I)

# Extra points when two signals together mean more than each alone
BAIT_SIGNALS = ("otp_bait", "jobs_income")
BAIT_WITH_LINK = 15
MOBILE_CALL_POINTS = 20
UPI_POINTS = 30
SHORTENER_POINTS = 20
CHAT_POINTS = 15
BRAND_MISMATCH_POINTS = 30
MAX_TEXT_SCORE = 100
BOTH_HIGH_BONUS = 10  # a dangerous link AND scam wording is worse than either alone

# Message words -> the brand key in BRANDS. Used for "the text says SBI but the link isn't SBI".
BRAND_WORDS = {
    "sbi": "sbi", "state bank": "sbi", "onlinesbi": "onlinesbi", "yono": "sbi",
    "hdfc": "hdfcbank", "icici": "icicibank", "axis bank": "axisbank", "kotak": "kotak",
    "pnb": "pnbindia", "punjab national": "pnbindia", "bank of baroda": "bankofbaroda",
    "canara": "canarabank", "yes bank": "yesbank", "indusind": "indusind",
    "paytm": "paytm", "phonepe": "phonepe", "google pay": "googlepay", "gpay": "googlepay",
    "bhim": "bhimupi", "npci": "npci",
    "amazon": "amazon", "flipkart": "flipkart", "myntra": "myntra", "meesho": "meesho",
    "swiggy": "swiggy", "zomato": "zomato", "irctc": "irctc",
    "netflix": "netflix", "whatsapp": "whatsapp", "instagram": "instagram", "facebook": "facebook",
    "paypal": "paypal", "microsoft": "microsoft", "apple": "apple", "google": "google",
    "airtel": "airtel", "jio": "jio", "income tax": "incometax", "aadhaar": "uidai",
    "aadhar": "uidai", "uidai": "uidai", "epf": "epfindia", "india post": "indiapost",
}


def without_links(text: str, links: list) -> str:
    """The message with its links blanked out, so brand names inside a link don't count as the
    message "saying" that brand. Without this, sbi-kyc.xyz would prove the text claims to be SBI."""
    # De-obfuscate first, so a hidden link (sbi-kyc[.]xyz) is blanked out as well as a plain one
    cleaned = deobfuscate(text)
    for link in links:
        cleaned = re.sub(re.escape(link["host"]), " ", cleaned, flags=re.I)
    return cleaned


def brands_named(text: str) -> list:
    """Which known brands does the message name? Returns [(brand key, the word as written)]."""
    found, seen = [], set()
    for word, brand in BRAND_WORDS.items():
        match = re.search(rf"(?<![a-z]){re.escape(word)}(?![a-z])", text, re.I)
        if match and brand not in seen:
            seen.add(brand)
            found.append((brand, match.group()))
    return found


# ---------------- who sent it ----------------

# Indian bank and company SMS comes from a registered DLT header, not a personal number:
# two letters for the operator and circle, a hyphen, then the brand's short name (AD-SBIBNK).
# Since May 2025 operators add a category letter: -P promotional, -S service, -T transactional,
# -G government. Both forms are accepted here.
# This is a SOFT signal only: the sender field is easy to fake, people paste it inconsistently,
# and plenty of genuine messages (delivery codes, OTPs from small services) use other formats.
# It only adds points when the message also claims to be from a brand we know.
DLT_HEADER = re.compile(r"^[A-Za-z]{2}-[A-Za-z0-9]{3,11}(-[PSTGpstg])?$")
SENDER_POINTS = 15


def check_sender(sender: str, text: str) -> dict:
    """Does the sender look like a company header or like a personal phone number?"""
    sender = (sender or "").strip()
    if not sender:
        return {"kind": "unknown", "points": 0, "reason": None}
    if DLT_HEADER.match(sender):
        return {"kind": "header", "points": 0,
                "reason": f"Sender '{sender}' looks like a registered company SMS header"}
    if MOBILE_RE.fullmatch(sender.replace(" ", "").replace("-", "")):
        named = brands_named(text)
        if named:
            return {"kind": "mobile_claiming_brand", "points": SENDER_POINTS,
                    "reason": f"Sent from a personal mobile number, but the message talks about "
                              f"{named[0][1]} — companies use a registered SMS header"}
        return {"kind": "mobile", "points": 0,
                "reason": "Sent from a personal mobile number, not a company SMS header"}
    return {"kind": "other", "points": 0, "reason": f"Sender '{sender}' is not a standard SMS header"}


# ---------------- putting it together ----------------

WHAT_TO_DO = [
    "Do not click the link, and do not open it just to \"check\".",
    "Never share an OTP, PIN, CVV or password. No bank, company or government office asks for them.",
    "If you have already lost money, call the cybercrime helpline 1930 or report it at cybercrime.gov.in.",
    "To report a spam SMS, forward it to 1909 with the sender's number and the date.",
    "If you are unsure, open the company's own app, or type its website yourself instead of tapping the link.",
]


def check_message(text: str, sender: str = "", bundle=None) -> dict:
    """Check one message. Returns the verdict, the score and all the evidence behind it."""
    text = (text or "").strip()
    reasons, spans, fired = [], [], set()

    # 1. Every link goes through the normal domain checks
    results = []
    for link in find_links(text):
        domain_result = full_analysis(link["link"], bundle)
        shortener = is_shortener(link["host"])
        score = max(domain_result["score"], 45) if shortener else domain_result["score"]
        results.append({**link, "result": domain_result, "score": score,
                        "verdict": verdict_for(score), "shortener": shortener,
                        "chat": link["host"] in CHAT_HOSTS})
        if link["span"]:
            spans.append(link["span"])
    link_score = max((r["score"] for r in results), default=0)

    # 2. Scam wording
    text_score = 0
    for signal in SIGNALS:
        hits, matched_patterns = [], 0
        for pattern in signal["patterns"]:
            found = list(re.finditer(pattern, text, re.I))
            matched_patterns += bool(found)
            hits += found
        if not hits:
            continue
        fired.add(signal["name"])
        # Two or more different wordings of the same signal are stronger than a single phrase,
        # so the signal counts for half as much again.
        text_score += signal["points"] + (signal["points"] // 2 if matched_patterns >= 2 else 0)
        spans += [m.span() for m in hits]
        words = sorted({m.group().strip() for m in hits}, key=len, reverse=True)[:3]
        quoted = ", ".join(f'"{word}"' for word in words)
        reasons.append(f"{signal['reason']}: {quoted}")

    # 3. Message-level flags about the links themselves
    for r in sorted(results, key=lambda r: -r["score"]):
        if r["shortener"]:
            text_score += SHORTENER_POINTS
            fired.add("shortener")
            reasons.append(f"Shortened link hides the real address: {r['host']}")
        elif r["chat"]:
            text_score += CHAT_POINTS
            reasons.append(f"Links to a chat account ({r['host']}) rather than a company website")
        elif r["result"]["verdict"] != "Safe":
            target = r["result"]["target"]
            imitates = f", which imitates {target}" if target else ""
            reasons.append(f"Link {r['host']} looks dangerous "
                           f"({r['result']['verdict']}, {r['score']}/100){imitates}")

    # Bait plus somewhere to click is the whole scam: "you won a prize, claim it here"
    if results and fired & set(BAIT_SIGNALS):
        text_score += BAIT_WITH_LINK
        reasons.append("Promises easy money and sends you to a link to claim it")

    # 4. Asks you to call, chat or pay someone directly
    mobiles = [m for m in MOBILE_RE.finditer(text)
               if not any(start <= m.start() < end for start, end in spans)]
    if mobiles and CALL_RE.search(text):
        text_score += MOBILE_CALL_POINTS
        spans += [m.span() for m in mobiles]
        fired.add("mobile_call")
        reasons.append(f"Tells you to call a personal mobile number: {mobiles[0].group()}")
    upi_ids = list(UPI_RE.finditer(text))
    if upi_ids:
        text_score += UPI_POINTS
        spans += [m.span() for m in upi_ids]
        fired.add("upi_ask")
        reasons.append(f"Asks you to pay a UPI ID directly: {upi_ids[0].group()}")

    # 5. The message names a brand, but the link does not belong to that brand
    named = brands_named(without_links(text, results))
    official = {d for brand, _ in named for d in BRANDS.get(brand, [])}
    stray = [r for r in results if r["host"] not in official and r["host"] not in LEGIT_DOMAINS]
    if named and stray:
        text_score += BRAND_MISMATCH_POINTS
        fired.add("brand_mismatch")
        real = BRANDS[named[0][0]][0] if named[0][0] in BRANDS else named[0][1]
        reasons.append(f"Says it is from {named[0][1]} but links to {stray[0]['host']}, not {real}")

    # 6. Who sent it (soft)
    sender_check = check_sender(sender, text)
    text_score += sender_check["points"]
    if sender_check["points"]:
        reasons.append(sender_check["reason"])

    text_score = min(text_score, MAX_TEXT_SCORE)
    score = max(link_score, text_score)
    if link_score >= 60 and text_score >= 30:
        score = min(score + BOTH_HIGH_BONUS, 100)

    verdict = message_verdict(score)
    return {"text": text, "sender": sender, "score": score, "verdict": verdict,
            "link_score": link_score, "text_score": text_score, "links": results,
            "reasons": reasons or ["No scam signals found"], "spans": merge_spans(spans),
            "brands_named": named, "sender_check": sender_check, "signals": sorted(fired),
            "explanation": explain_message(verdict, named, results, fired)}


# The columns of a message export, in order
MESSAGE_COLUMNS = ["message", "sender", "verdict", "score", "text_score", "link_score",
                   "links_found", "worst_link", "worst_link_verdict", "signals", "reasons"]


def flat_message_row(r: dict) -> dict:
    """One check_message() result as one flat row, ready for a table or an export."""
    worst = max(r["links"], key=lambda link: link["score"], default=None) if r["links"] else None
    return {"message": r["text"], "sender": r["sender"], "verdict": r["verdict"], "score": r["score"],
            "text_score": r["text_score"], "link_score": r["link_score"],
            "links_found": ", ".join(link["host"] for link in r["links"]),
            "worst_link": worst["host"] if worst else "",
            "worst_link_verdict": worst["verdict"] if worst else "",
            "signals": ", ".join(r["signals"]), "reasons": "; ".join(r["reasons"])}


def merge_spans(spans: list) -> list:
    """Join overlapping highlight ranges, so the UI can colour them in one pass."""
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [tuple(span) for span in merged]


# What each signal is called in the one-line explanation
CLAUSES = {"otp_request": "asks for an OTP or PIN", "urgency": "creates urgency",
           "otp_bait": "promises a prize", "jobs_income": "offers easy money",
           "kyc_bank": "asks you to update KYC", "bills_delivery": "claims a bill or parcel problem",
           "shortener": "hides where its link really goes",
           "upi_ask": "asks you to pay a UPI ID", "mobile_call": "tells you to call a mobile number"}


def explain_message(verdict: str, named: list, results: list, fired: set) -> str:
    """One plain-English sentence, e.g. "This message pretends to be SBI, creates urgency,
    and links to sbi-kyc-update.xyz, which is not SBI's real site." """
    if verdict == "Safe":
        return ("Nothing in this message looks like a scam, but never share an OTP or PIN, "
                "whoever asks.")

    clauses = [f"pretends to be {named[0][1]}"] if named else []
    clauses += [CLAUSES[name] for name in CLAUSES if name in fired]

    worst = max(results, key=lambda r: r["score"]) if results else None
    if worst and worst["score"] >= 30:
        target = worst["result"]["target"]
        tail = f", which is not {target}" if target else ""
        clauses.append(f"links to {worst['host']}{tail}")

    if not clauses:
        return "This message has warning signs, so treat it carefully."
    if len(clauses) == 1:
        return f"This message {clauses[0]}."
    return f"This message {', '.join(clauses[:-1])}, and {clauses[-1]}."
