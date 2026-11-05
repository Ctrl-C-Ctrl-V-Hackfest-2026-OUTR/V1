"""
Kavach - optional page comparison: does a saved page look like the genuine one?

Works only on files the user uploads. It never fetches a website (the offline rule) and never
runs or displays the uploaded HTML; it only reads its text. Results are extra evidence shown next
to the verdict and do not change the risk score.
"""
import io
import re
from html.parser import HTMLParser

import imagehash
import numpy as np
from PIL import Image, UnidentifiedImageError
from rapidfuzz import fuzz
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# How much each part counts towards content similarity. A part neither page has is left out.
CONTENT_WEIGHTS = {"title": 25, "form_fields": 15, "visible_text": 45, "image_names": 15}
HIGH_VISUAL = 80   # judgement calls: at or above these, a page counts as a close copy
HIGH_CONTENT = 70
OTP_HINT = re.compile(r"otp|one.?time|verification.?code|\bpin\b|cvv", re.I)
SKIP_TAGS = {"script", "style", "noscript", "template"}


class _PageReader(HTMLParser):
    """Collects the title, form fields, visible text and image file names of a page."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self.text = [], []
        self.fields, self.images = set(), set()
        self.has_password = self.has_otp = False
        self._stack = []

    def handle_starttag(self, tag, attrs):
        attrs = {key: value or "" for key, value in attrs}
        if tag in SKIP_TAGS or tag == "title":
            self._stack.append(tag)
        if tag in ("input", "select", "textarea") and attrs.get("type", "").lower() not in ("hidden", "submit", "button"):
            label = " ".join(attrs.get(k, "") for k in ("name", "id", "placeholder", "autocomplete"))
            self.fields.add((attrs.get("name") or attrs.get("id") or attrs.get("type") or tag).lower())
            self.has_password = self.has_password or attrs.get("type", "").lower() == "password"
            self.has_otp = self.has_otp or bool(OTP_HINT.search(label))
        source = attrs.get("src", "") if tag == "img" else attrs.get("href", "") if (
            tag == "link" and "icon" in attrs.get("rel", "").lower()) else ""
        if source and not source.startswith("data:"):
            self.images.add(re.split(r"[?#]", source)[0].rsplit("/", 1)[-1].lower())

    def handle_endtag(self, tag):
        if self._stack and self._stack[-1] == tag:
            self._stack.pop()

    def handle_data(self, data):
        if "title" in self._stack:
            self.title.append(data)
        elif not any(tag in SKIP_TAGS for tag in self._stack):
            self.text.append(data)


def read_page(data: bytes) -> dict:
    """The parts of a saved HTML page we compare."""
    reader = _PageReader()
    reader.feed(data.decode("utf-8", errors="replace"))
    return {"title": " ".join(" ".join(reader.title).split()), "text": " ".join(" ".join(reader.text).split()),
            "fields": reader.fields, "images": reader.images - {""},
            "has_password": reader.has_password, "has_otp": reader.has_otp}


def _overlap(a: set, b: set) -> float:
    """How much two sets share, 0-100."""
    return 100 * len(a & b) / len(a | b)


def _text_similarity(a: str, b: str) -> float:
    """TF-IDF cosine similarity of two texts, 0-100."""
    try:
        vectors = TfidfVectorizer().fit_transform([a, b])
    except ValueError:  # neither text has any real words
        return 0.0
    return float(cosine_similarity(vectors[0], vectors[1])[0, 0]) * 100


def compare_html(suspicious: bytes, genuine: bytes) -> dict:
    """Content similarity % of two saved pages, with the score of each part."""
    a, b = read_page(suspicious), read_page(genuine)
    parts = {}
    if a["title"] or b["title"]:
        parts["title"] = fuzz.token_set_ratio(a["title"].lower(), b["title"].lower())
    if a["fields"] or b["fields"]:
        parts["form_fields"] = _overlap(a["fields"], b["fields"])
    if a["text"] or b["text"]:
        parts["visible_text"] = _text_similarity(a["text"], b["text"])
    if a["images"] or b["images"]:
        parts["image_names"] = _overlap(a["images"], b["images"])
    total = sum(CONTENT_WEIGHTS[name] for name in parts)
    score = sum(CONTENT_WEIGHTS[name] * value for name, value in parts.items()) / total if total else 0.0
    return {"content_similarity": round(score), "parts": {name: round(value) for name, value in parts.items()},
            "shared_images": sorted(a["images"] & b["images"]), "shared_fields": sorted(a["fields"] & b["fields"]),
            "asks_for_password": a["has_password"], "asks_for_otp": a["has_otp"]}


def _structural_similarity(a: np.ndarray, b: np.ndarray, block: int = 8) -> float:
    """SSIM: compares brightness, contrast and structure in small blocks, then averages. 0-1."""
    c1, c2 = (0.01 * 255) ** 2, (0.03 * 255) ** 2
    scores = []
    for y in range(0, a.shape[0] - block + 1, block):
        for x in range(0, a.shape[1] - block + 1, block):
            p, q = a[y:y + block, x:x + block], b[y:y + block, x:x + block]
            covariance = ((p - p.mean()) * (q - q.mean())).mean()
            scores.append(((2 * p.mean() * q.mean() + c1) * (2 * covariance + c2))
                          / ((p.mean() ** 2 + q.mean() ** 2 + c1) * (p.var() + q.var() + c2)))
    return float(np.clip(np.mean(scores), 0, 1))


def compare_images(suspicious: bytes, genuine: bytes) -> dict:
    """Visual similarity % of two screenshots. Raises ValueError if a file isn't a readable image."""
    try:
        a, b = [Image.open(io.BytesIO(data)).convert("RGB") for data in (suspicious, genuine)]
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as err:
        raise ValueError("Could not read one of the screenshots. Please upload a PNG or JPG image.") from err

    # A perceptual hash has 64 bits, and two unrelated images match on about half of them by
    # chance, so 32 differing bits counts as 0% similar.
    bits_different = int(imagehash.phash(a) - imagehash.phash(b))
    hash_score = max(0.0, 1 - bits_different / 32)

    # Compare in grey at one fixed size, so the screenshots can be different sizes
    grey_a, grey_b = [np.asarray(image.convert("L").resize((256, 256)), dtype=float) for image in (a, b)]
    structure = _structural_similarity(grey_a, grey_b)
    return {"visual_similarity": round(100 * (hash_score + structure) / 2),
            "hash_similarity": round(100 * hash_score), "structural_similarity": round(100 * structure)}


def conclusion(content, visual, domain_differs) -> tuple:
    """What the page comparison means: (level, sentence). Level is 'strong', 'none' or 'same_site'."""
    is_close = (visual is not None and visual >= HIGH_VISUAL) or (content is not None and content >= HIGH_CONTENT)
    if not is_close:
        return "none", "These pages aren't close copies, so this comparison adds no phishing evidence."
    if domain_differs is False:
        return "same_site", "The pages match, and this link is the genuine site."
    if domain_differs is None:
        return "strong", ("These pages are close copies. Paste the suspicious link above: "
                          "a close copy on a different domain is strong phishing evidence.")
    return "strong", "Strong phishing evidence: this page copies the genuine one, but it is on a different domain."
