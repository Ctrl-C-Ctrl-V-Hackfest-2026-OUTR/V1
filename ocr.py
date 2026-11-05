"""
Kavach - read a screenshot and check what it says.

read_image(bytes)        -> the text, line by line, with a confidence for each line
scan_image(bytes, mode)  -> the verdict for a screenshot of a message or of a website
scan_text(text, mode)    -> the same checks on text the person corrected by hand

Optional: needs requirements-ocr.txt. Everything else in Kavach works without it, and ocr_status() says so.
Why RapidOCR: on our phone-style test screenshots it read 15 of 16 web addresses (EasyOCR 4 of 16, because
it drops dots and turns digits into Hindi numerals), took 0.6 s an image (EasyOCR 6.9 s) and installs in
285 MB (EasyOCR about 1.2 GB with torch and its Hindi model). Tesseract has no wheel and needs a separate
Windows installer. English and Hindi work. Odia does not: no bundled model has that script.

Rules this file keeps:
 - Images stay in memory. They are never written to disk or logged.
 - Models are installed once by "python ocr.py --setup". At check time we pass exact file paths, so nothing
   can be downloaded, and nothing found in an image is ever fetched.
 - OCR text is untrusted input. The page escapes it, and it only ever goes to our own text checks.
 - OCR is never presented as certain, because its mistakes (l and 1, rn and m, O and 0) are exactly the
   tricks look-alike domains use.
This file must NOT import app.py or streamlit.
"""
import importlib.util
import io
import os
import re
import sys
import threading
import time
from pathlib import Path

from PIL import Image, ImageOps, UnidentifiedImageError

from detector import full_analysis, verdict_for
from features import LEGIT_DOMAINS, POPULAR_SET, is_trusted_bank
from sms import (DLT_HEADER, LINK_RE, MOBILE_RE, SIGNALS, TRAILING, WHAT_TO_DO, brands_named, check_message, deobfuscate,
                 find_links, without_links)

MAX_BYTES = 8 * 1024 * 1024      # the largest upload we accept
MAX_PIXELS = 40_000_000          # about 6,300 x 6,300; stops a tiny file that unpacks into a huge image
SMALLEST_SIDE = 900              # narrower images are enlarged, because small text reads badly
LARGEST_SIDE = 2800              # larger ones are shrunk, which is faster and reads just as well
LOW_CONFIDENCE = 0.85            # below this a line or link is marked "check this by eye"
POOR_READ_SHARE = 0.25           # this share of the letters unsure, and a Safe verdict becomes Unclear
TOP_STRIP = 0.20                 # a browser's address bar sits in the top fifth of the screen...
BOTTOM_STRIP = 0.14              # ...or at the very bottom in some phone browsers
ALLOWED_MODES = ("auto", "sms", "website")
HINDI_MODEL = "devanagari_PP-OCRv5_rec_mobile.onnx"

# What each kind of image starts with. We trust these bytes, not the file name or the Content-Type.
_SIGNATURES = ((b"\x89PNG\r\n\x1a\n", "image/png"), (b"\xff\xd8\xff", "image/jpeg"))

_lock = threading.Lock()   # the models are shared, so one image at a time
_engines = {}


class OcrError(Exception):
    """A problem the page can explain. code is one of: not_installed, wrong_type, too_large, too_many_pixels,
    corrupt, no_text, bad_mode."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _model_folder():
    """Where RapidOCR keeps its models, without importing it (importing it takes a second)."""
    spec = importlib.util.find_spec("rapidocr")
    return Path(spec.origin).parent / "models" if spec and spec.origin else None


def ocr_status() -> dict:
    """Is OCR ready? Cheap enough to ask on every health check. KAVACH_NO_OCR=1 pretends it isn't installed."""
    how = "pip install -r requirements-ocr.txt, then python ocr.py --setup"
    if os.environ.get("KAVACH_NO_OCR") or importlib.util.find_spec("onnxruntime") is None:
        return {"available": False, "languages": [], "reason": "OCR is not installed.", "how_to_enable": how}
    folder = _model_folder()
    if folder is None or not (folder / "PP-OCRv6_rec_small.onnx").exists():
        return {"available": False, "languages": [], "reason": "OCR is not installed.", "how_to_enable": how}
    hindi = (folder / HINDI_MODEL).exists()
    return {"available": True, "languages": ["English", "Hindi"] if hindi else ["English"], "hindi": hindi,
            "reason": None if hindi else "The Hindi model is not installed, so only English is read.",
            "how_to_enable": None if hindi else "python ocr.py --setup"}


def _engine(name: str):
    """Load a model once. The exact file paths mean RapidOCR has no reason to download anything."""
    if name in _engines:
        return _engines[name]
    from rapidocr import LangRec, ModelType, OCRVersion, RapidOCR
    folder = _model_folder()
    params = {"Global.log_level": "error", "Global.use_cls": False, "Global.text_score": 0.0,
              "Det.model_path": str(folder / "PP-OCRv6_det_small.onnx"),
              "Cls.model_path": str(folder / "ch_ppocr_mobile_v2.0_cls_mobile.onnx")}
    if name == "hindi":
        params.update({"Rec.lang_type": LangRec.DEVANAGARI, "Rec.ocr_version": OCRVersion.PPOCRV5,
                       "Rec.model_type": ModelType.MOBILE, "Rec.model_path": str(folder / HINDI_MODEL)})
    else:
        params["Rec.model_path"] = str(folder / "PP-OCRv6_rec_small.onnx")
    _engines[name] = RapidOCR(params=params)
    return _engines[name]


# ---------------- reading the image ----------------

def image_type(data: bytes):
    """The real type of the file from its first bytes, or None if it isn't PNG, JPEG or WebP."""
    for signature, kind in _SIGNATURES:
        if data.startswith(signature):
            return kind
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def _open_image(data: bytes) -> Image.Image:
    """Bytes -> an upright RGB image of a sensible size. Raises OcrError with a clear message."""
    if len(data) > MAX_BYTES:
        raise OcrError("too_large", f"That image is larger than {MAX_BYTES // (1024 * 1024)} MB.")
    if image_type(data) is None:
        raise OcrError("wrong_type", "That file isn't a PNG, JPEG or WebP image.")
    try:
        image = Image.open(io.BytesIO(data))
        # Image.open only reads the header, so this check runs before the pixels are unpacked
        if image.width * image.height > MAX_PIXELS:
            raise OcrError("too_many_pixels", f"That image has too many pixels (limit {MAX_PIXELS // 1_000_000} million).")
        image = ImageOps.exif_transpose(image)
        if image.mode in ("RGBA", "LA", "P"):
            image = image.convert("RGBA")
            backing = Image.new("RGB", image.size, "white")
            backing.paste(image, mask=image.getchannel("A"))
            image = backing
        else:
            image = image.convert("RGB")
    except OcrError:
        raise
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError, Image.DecompressionBombError) as err:
        raise OcrError("corrupt", "That image is damaged and could not be read.") from err
    longest, narrowest = max(image.size), min(image.size)
    if image.width < SMALLEST_SIDE:
        scale = min(SMALLEST_SIDE / image.width, LARGEST_SIDE / max(longest, 1), 3)
        if scale > 1:
            image = image.resize((round(image.width * scale), round(image.height * scale)), Image.LANCZOS)
    elif longest > LARGEST_SIDE:
        scale = LARGEST_SIDE / longest
        image = image.resize((round(image.width * scale), round(image.height * scale)), Image.LANCZOS)
    return image


def _box_key(box) -> tuple:
    return tuple(round(float(value)) for point in box for value in point)


def _devanagari_share(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    return sum("ऀ" <= c <= "ॿ" for c in letters) / max(len(letters), 1)


def read_image(data: bytes) -> dict:
    """Read the text in an image. Returns {text, lines, ms, width, height, languages}.
    Each line is {text, confidence (0-1), position (x, y, width, height as a share of the image), low_confidence}."""
    status = ocr_status()
    if not status["available"]:
        raise OcrError("not_installed", status["reason"])
    started = time.perf_counter()
    image = _open_image(data)
    import numpy as np
    pixels = np.asarray(image)[:, :, ::-1].copy()  # OpenCV order
    with _lock:
        try:
            latin = _engine("latin")
            # Find every line first: the full pass below leaves out a line it reads as nothing, and a
            # Hindi line often is nothing to the Latin model.
            boxes = latin(pixels, use_det=True, use_cls=False, use_rec=False).boxes
            result = latin(pixels, use_det=True, use_cls=False, use_rec=True)  # it remembers flags, so name them all
            read = {_box_key(box): (str(text), float(score)) for box, text, score in
                    zip(result.boxes if result.boxes is not None else [], result.txts or [], result.scores or [])}
            found = []
            for box in (boxes if boxes is not None else []):
                xs, ys = [point[0] for point in box], [point[1] for point in box]
                text, score = read.get(_box_key(box), ("", 0.0))
                found.append({"text": text, "score": score, "x": min(xs), "y": min(ys), "right": max(xs), "bottom": max(ys)})
            if status.get("hindi"):
                hindi = _engine("hindi")
                for item in found:
                    top, bottom = max(int(item["y"]) - 3, 0), int(item["bottom"]) + 3
                    left, right = max(int(item["x"]) - 3, 0), int(item["right"]) + 3
                    other = hindi(pixels[top:bottom, left:right], use_det=False, use_cls=False, use_rec=True)
                    if other.txts and _devanagari_share(other.txts[0]) >= 0.5 and float(other.scores[0]) >= 0.5:
                        item.update(text=str(other.txts[0]), score=float(other.scores[0]))  # it really read Hindi
        except ImportError as err:
            raise OcrError("not_installed", "OCR is not installed.") from err
    height, width = pixels.shape[:2]
    lines = _reading_order(found, width, height)
    return {"text": _join_lines(lines), "lines": lines, "ms": round((time.perf_counter() - started) * 1000),
            "width": width, "height": height, "languages": status["languages"]}


def _reading_order(found: list, width: int, height: int) -> list:
    """Top to bottom, and left to right on the same row. Empty and very unsure pieces are dropped."""
    found = [item for item in found if item["text"].strip() and item["score"] >= 0.3]
    found.sort(key=lambda item: item["y"])
    rows = []
    for item in found:
        tall = item["bottom"] - item["y"]
        row = rows[-1] if rows else None
        if row and abs((item["y"] + item["bottom"]) / 2 - row["middle"]) < tall * 0.6:
            row["items"].append(item)
        else:
            rows.append({"middle": (item["y"] + item["bottom"]) / 2, "items": [item]})
    lines = []
    for row_number, row in enumerate(rows):
        for item in sorted(row["items"], key=lambda piece: piece["x"]):
            lines.append({"text": item["text"].strip(), "confidence": round(item["score"], 3), "row": row_number,
                          "low_confidence": item["score"] < LOW_CONFIDENCE,
                          "position": {"x": round(item["x"] / width, 4), "y": round(item["y"] / height, 4),
                                       "width": round((item["right"] - item["x"]) / width, 4),
                                       "height": round((item["bottom"] - item["y"]) / height, 4)}})
    return lines


def _join_lines(lines: list) -> str:
    out, last_row = "", None
    for line in lines:
        out += ("\n" if last_row is not None and line["row"] != last_row else " " if last_row is not None else "") + line["text"]
        last_row = line["row"]
    return out


# ---------------- tidying what OCR gives us ----------------

_ENDS_MID_LINK = re.compile(r"(https?://[^\s]*[^\s.,;:!?)])\s*\n\s*(\S+)")
_BROKEN_AT_HYPHEN = re.compile(r"\b([a-z0-9][a-z0-9.-]*-)\s+([a-z0-9][a-z0-9-]*\.[a-z]{2,})", re.I)
_BROKEN_AT_DOT = re.compile(r"\b([a-z0-9]+-[a-z0-9-]+)\.\s+([a-z]{2,6})\b", re.I)
# A capital I read as a small L inside a word in capitals: SBl -> SBI, lCICI -> ICICI
_CAPS_WITH_L = re.compile(r"(?<![A-Za-z0-9.@/-])(?=[A-Zl0-9]*l)(?=[A-Zl0-9]*[A-Z]{2})[A-Zl0-9]{3,}(?![A-Za-z0-9.@/-])")


def repair_text(text: str) -> str:
    """Undo what wrapping and OCR do to links and short words. A message bubble breaks a long link over two
    lines, and OCR often puts a space after a hyphen: 'sbi-kyc- update.top' -> 'sbi-kyc-update.top'."""
    def join_if_broken(match):
        # Only a link with no ending yet is unfinished: https://sbi-kyc-upd + ate.xyz
        return match.group(1) + match.group(2) if "." not in match.group(1).split("://", 1)[-1] else match.group()
    text = _ENDS_MID_LINK.sub(join_if_broken, text)
    text = _BROKEN_AT_HYPHEN.sub(r"\1\2", text)
    text = _BROKEN_AT_DOT.sub(r"\1.\2", text)
    return _CAPS_WITH_L.sub(lambda match: match.group().replace("l", "I"), text)


# Pairs that OCR mixes up, and that fakes use on purpose
_CONFUSABLE = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("1", "i"), ("l", "i"), ("5", "s")]


def _could_be_misread(shown: str, real: str) -> bool:
    """True if swapping letters OCR confuses could turn what we read into the real name."""
    for a, b in _CONFUSABLE:
        if shown.replace(a, b) == real or shown.replace(b, a) == real:
            return True
    return False


def _read_note(result: dict) -> str:
    """Why this one reading might be wrong, in words. Empty if there is nothing specific to say."""
    target, evidence = result.get("target"), result.get("evidence") or {}
    if target:
        shown, real = result["domain"].split(".")[0], target.split(".")[0]
        if _could_be_misread(shown, real) or evidence.get("attack_type") == "homoglyph":
            return (f"We read {result['domain']}. Reading text from an image can confuse look-alike letters, so "
                    f"it may really say {target}. Check the image, or copy the link as text.")
    return ""


CAUTIONS = [
    "Text read from an image can be wrong, and its mistakes (l and 1, rn and m, O and 0) are the same tricks fake sites use. "
    "Compare the address with your image, and correct the text in the box if needed.",
    "Cyrillic and other look-alike letters are invisible in a screenshot, so a fake can read exactly like the real name. "
    "To be sure, copy the link as text and check it in Domain check.",
]


def _confidence_of(host: str, lines: list):
    """The confidence of the line(s) a link was read from: the lowest, because a chain is as weak as its weakest link."""
    scores = [line["confidence"] for line in lines if host and host in line["text"].lower().replace(" ", "")]
    if scores:
        return min(scores)
    # The link was joined from two broken pieces, so look for its first word
    first = host.split(".")[0].split("-")[0]
    scores = [line["confidence"] for line in lines if first and first in line["text"].lower()]
    return min(scores) if scores else None


# ---------------- website screenshots ----------------

# What a page asks for. Each entry: (the name shown to the person, wording that means the page asks for it)
SENSITIVE_INPUTS = [
    ("card number", r"\b(debit|credit|atm)?\s*card\s*(number|no\b|details)|कार्ड नंबर|कार्ड संख्या"),
    ("CVV", r"\bcvv\b|\bcvc\b"),
    ("card expiry date", r"\b(expiry|expiration|valid\s*thru)\b"),
    ("UPI PIN or ATM PIN", r"\b(upi|atm|m|t)-?\s*pin\b|\bpin\b|पिन"),
    ("OTP", r"\botp\b|one[\s-]?time\s*password|ओटीपी"),
    ("Aadhaar number", r"\baadh?aar\b|आधार"),
    ("PAN", r"\bpan\s*(number|no\b|card)?\b|पैन"),
    ("net banking password", r"\bpassword\b|\bpasscode\b|पासवर्ड"),
    ("net banking user name", r"\b(user\s*name|user\s*id|customer\s*id|login\s*id)\b"),
]
SENSITIVE_FLOOR = 45     # the page claims a brand, asks for secrets, and the address isn't that brand: Suspicious
BOTH_AGREE_FLOOR = 60    # ...and the address itself already looks wrong: Phishing


def _candidates(lines: list) -> list:
    """Web addresses in the text, in reading order: [{link, host, in_address_strip, confidence}].
    in_address_strip means it sits where a browser shows its address bar."""
    found, seen = [], set()
    for line in lines:
        text = repair_text(line["text"])
        position = line.get("position") or {"y": 0, "height": 0}
        # An address bar holds the address and little else, unlike a link inside a sentence
        in_strip = ((position["y"] <= TOP_STRIP or position["y"] + position["height"] >= 1 - BOTTOM_STRIP)
                    and len(text.split()) <= 2)
        for link in find_links(text):
            if link["host"] not in seen:
                seen.add(link["host"])
                found.append({"link": link["link"], "host": link["host"], "in_address_strip": in_strip,
                              "confidence": line["confidence"], "low_confidence": line.get("low_confidence", False)})
    return found


def _is_trusted_address(host: str) -> bool:
    return host in LEGIT_DOMAINS or host in POPULAR_SET or is_trusted_bank(host)


def _official_for(named: list) -> set:
    from features import BRANDS
    return {domain for brand, _ in named for domain in BRANDS.get(brand, [])}


def _check_page(text: str, lines: list, bundle) -> dict:
    """The website check: the address, what the page claims to be and what it asks for.

    The address score is exactly what Domain check gives. Page evidence is shown separately, the way
    page_compare.py shows its evidence, and may only RAISE the verdict, by a clear rule, in two cases where
    the page and the address disagree: it never decides on its own wording alone, because plenty of honest
    pages mention banks or have a password box. It never lowers a verdict.
    """
    candidates = _candidates(lines)
    address = next((c for c in candidates if c["in_address_strip"]), candidates[0] if candidates else None)
    links = []
    for candidate in candidates[:8]:
        result = full_analysis(candidate["link"], bundle)
        links.append({**candidate, "shown": candidate["link"], "score": result["score"], "verdict": result["verdict"],
                      "result": result, "is_address": candidate is address, "read_note": _read_note(result)})
    address_row = next((link for link in links if link["is_address"]), None)
    address_score = address_row["score"] if address_row else None

    page_words = without_links(text, links)
    named = brands_named(page_words)
    asks = [name for name, pattern in SENSITIVE_INPUTS if re.search(pattern, page_words, re.I)]
    host = address_row["host"] if address_row else ""
    mismatch = bool(named and host and host not in _official_for(named) and not _is_trusted_address(host))

    notes = []
    if mismatch:
        word = named[0][1]
        notes.append(f"The page says it is {word}, but the address is {host}, which is not a {word} address.")
    if asks:
        notes.append("The page asks for: " + ", ".join(asks) + ".")
    if named and not host:
        notes.append(f"The page says it is {named[0][1]}, but no web address could be read, so that can't be checked.")

    # Page evidence may only raise the verdict
    score, raised = address_score if address_score is not None else 0, None
    if mismatch and asks:
        floor = BOTH_AGREE_FLOOR if address_score >= 30 else SENSITIVE_FLOOR
        if score < floor:
            raised = f"The address alone scored {address_score}. The page claims to be {named[0][1]} and asks for secrets on an address that isn't theirs, so the verdict was raised to {floor}."
            score = floor
    elif not host and named and asks:
        raised, score = (f"No address could be read, but the page claims to be {named[0][1]} and asks for secrets, "
                         f"so treat it as Suspicious."), SENSITIVE_FLOOR
    verdict = verdict_for(score)
    if address_row is None and raised is None:
        verdict = "Unclear"
    return {"verdict": verdict, "score": score, "address": address_row, "address_score": address_score, "links": links,
            "brands_named": named, "asks_for": asks, "brand_mismatch": mismatch, "page_notes": notes, "raised_by_page": raised,
            "explanation": _explain_page(verdict, address_row, mismatch, named, asks, raised)}


def _explain_page(verdict, address, mismatch, named, asks, raised) -> str:
    if verdict == "Unclear":
        return "No web address could be read in this image, so Kavach can't say whose page it is. Type the address into Domain check."
    if address is None:
        return raised or ""
    if mismatch and asks:
        return f"This page claims to be {named[0][1]} and asks for {asks[0]}, but its address is {address['host']}."
    if verdict == "Safe":
        return f"The address {address['host']} looks fine. Check that it matches your image, because a screenshot can hide look-alike letters."
    return address["result"].get("explain") or f"The address {address['host']} looks risky."


# ---------------- messages and the mode guess ----------------

_CHAT_WORDS = re.compile(r"\b(text\s*message|sms|imessage|delivered|type\s*a\s*message|today|yesterday|forwarded|whatsapp|"
                         r"\d{1,2}[:.]\d{2}\s*(am|pm))\b", re.I)
_PAGE_WORDS = re.compile(r"\b(sign\s*in|log\s*in|login|home|submit|username|contact\s*us|privacy|menu)\b", re.I)


def _sender_in(lines: list) -> str:
    """A chat screenshot often shows who it is from at the top: AD-SBIBNK, or a mobile number."""
    for line in lines[:8]:
        text = line["text"].strip()
        if (line.get("position") or {"y": 0})["y"] <= TOP_STRIP and (
                DLT_HEADER.match(text) or MOBILE_RE.fullmatch(text.replace(" ", "").replace("-", ""))):
            return text
    return ""


def _guess_mode(text: str, lines: list) -> tuple:
    """Is this a chat or a website? Returns (mode, the reason in words)."""
    candidates = _candidates(lines)
    address_like = [c for c in candidates if c["in_address_strip"]]
    web, chat, why_web, why_chat = 0, 0, [], []
    if address_like:
        web += 3
        why_web.append(f"a web address ({address_like[0]['host']}) where a browser's address bar sits")
    if any(re.search(pattern, text, re.I) for _, pattern in SENSITIVE_INPUTS[:3]) or _PAGE_WORDS.search(text):
        web += 1
        why_web.append("words like a web page")
    if _sender_in(lines):
        chat += 3
        why_chat.append("a sender at the top")
    if _CHAT_WORDS.search(text):
        chat += 2
        why_chat.append("message times or chat words")
    if any(re.search(pattern, text, re.I) for signal in SIGNALS for pattern in signal["patterns"]):
        chat += 1
        why_chat.append("wording like a message")
    if web > chat:
        return "website", "It looks like a website: " + " and ".join(why_web) + "."
    return "sms", "It looks like a message or chat: " + (" and ".join(why_chat) if why_chat else "no browser address bar") + "."


def _poorly_read(lines: list) -> bool:
    """Was much of the image unreadable? Usually a language we can't read (Odia), or a blurry picture.
    Then "no scam found" means nothing, so a Safe verdict must not stand."""
    total = sum(len(line["text"]) for line in lines) or 1
    return sum(len(line["text"]) for line in lines if line["low_confidence"]) / total >= POOR_READ_SHARE


def _lines_from_text(text: str) -> list:
    """Corrected text has no positions, so the first lines stand in for the top of the screen."""
    rows = [row.strip() for row in text.splitlines() if row.strip()]
    total = max(len(rows), 1)
    return [{"text": row, "confidence": 1.0, "low_confidence": False, "row": number,
             "position": {"x": 0, "y": 0 if number == 0 else min(0.21 + number / total, 0.8), "width": 1, "height": 0}}
            for number, row in enumerate(rows)]


def _build(mode: str, text: str, lines: list, bundle, guess_reason: str = None, from_image: bool = True) -> dict:
    """Run the right check and put the answer into one shape for the page."""
    text = repair_text(text)
    common = {"mode": mode, "text": text, "lines": lines, "guess_reason": guess_reason,
              "cautions": CAUTIONS if from_image else [CAUTIONS[1]], "what_to_do": WHAT_TO_DO}
    if mode == "sms":
        sender = _sender_in(lines)
        message = check_message(text, sender, bundle)
        for link in message["links"]:
            link["confidence"] = _confidence_of(link["host"], lines)
            link["low_confidence"] = link["confidence"] is not None and link["confidence"] < LOW_CONFIDENCE
            link["read_note"] = _read_note(link["result"])
        result = {**common, **message, "sender_read": sender}
    else:
        result = {**common, **_check_page(text, lines, bundle)}
    result["poorly_read"] = from_image and _poorly_read(lines)
    if result["poorly_read"] and result["verdict"] == "Safe":
        result["verdict"] = "Unclear"
        result["explanation"] = ("Much of this image could not be read, so \"nothing found\" means little. It may be in a "
                                 "language Kavach can't read yet, such as Odia, or too blurry. Check any link by typing it into Domain check.")
    return result


def scan_image(data: bytes, mode: str, bundle) -> dict:
    """Read a screenshot and give one verdict. mode is auto, sms or website.
    The image is only ever held in memory, and nothing in it is fetched."""
    if mode not in ALLOWED_MODES:
        raise OcrError("bad_mode", "mode must be auto, sms or website.")
    read = read_image(data)
    if not read["text"].strip():
        raise OcrError("no_text", "No text could be read in this image. Try a sharper screenshot, or type the text instead.")
    reason = None
    if mode == "auto":
        mode, reason = _guess_mode(repair_text(read["text"]), read["lines"])
    result = _build(mode, read["text"], read["lines"], bundle, reason)
    result.update(ms=read["ms"], image={"width": read["width"], "height": read["height"]}, languages=read["languages"])
    return result


def scan_text(text: str, mode: str, bundle) -> dict:
    """The same checks on text the person corrected by hand. The first address counts as the address bar."""
    if mode not in ("sms", "website"):
        raise OcrError("bad_mode", "mode must be sms or website.")
    return _build(mode, text, _lines_from_text(text), bundle, from_image=False)


def _setup() -> None:
    """python ocr.py --setup : download the Hindi model once, then check that reading really works."""
    if importlib.util.find_spec("rapidocr") is None or importlib.util.find_spec("onnxruntime") is None:
        raise SystemExit("OCR isn't installed yet. Run: pip install -r requirements-ocr.txt")
    from rapidocr import LangRec, ModelType, OCRVersion, RapidOCR
    print("Getting the Hindi model (about 8 MB, once)...")
    import numpy as np
    engine = RapidOCR(params={"Global.log_level": "error", "Rec.lang_type": LangRec.DEVANAGARI,
                              "Rec.ocr_version": OCRVersion.PPOCRV5, "Rec.model_type": ModelType.MOBILE})
    # RapidOCR fetches a missing model the first time it is used, so use it once here. From now on _engine()
    # names the exact file, so a check can never trigger a download.
    engine(np.full((48, 320, 3), 255, dtype=np.uint8), use_det=False, use_cls=False, use_rec=True)
    from PIL import ImageDraw
    buffer = io.BytesIO()
    picture = Image.new("RGB", (900, 200), "white")
    ImageDraw.Draw(picture).text((30, 80), "Kavach OCR test sbi-kyc.xyz", fill="black", font_size=48)
    picture.save(buffer, "PNG")
    print("Read back:", read_image(buffer.getvalue())["text"])
    print("Ready:", ", ".join(ocr_status()["languages"]))


if __name__ == "__main__":
    sys.stdout.reconfigure(errors="backslashreplace")
    if "--setup" in sys.argv:
        _setup()
    else:
        print("Run: python ocr.py --setup")
