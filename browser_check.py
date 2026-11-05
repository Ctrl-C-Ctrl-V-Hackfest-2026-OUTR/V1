"""
Kavach - drive the real website in a real browser, the way a person would. Run this before a demo.

    pip install playwright            (once; it is not a project requirement)
    python browser_check.py           (uses Microsoft Edge, which every Windows 11 computer has)
    python browser_check.py --shots myfolder     (also saves screenshots to look at)

It starts its own server on a free port with a temporary list of added brands, so your data isn't touched.
Exits with code 1 if anything fails. test_rules.py covers the logic; this covers the page.
"""
import argparse
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from playwright.sync_api import sync_playwright

HERE = Path(__file__).parent
results = []


def check(name: str, ok, detail="") -> None:
    results.append(bool(ok))
    print(f"{'PASS' if ok else 'FAIL'}  {ascii(name)[1:-1]:<58} {ascii(str(detail))[1:-1][:70]}", flush=True)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def start_server(folder: Path, **env):
    port = free_port()
    process = subprocess.Popen([sys.executable, str(HERE / "server.py"), "--port", str(port), "--no-browser"], cwd=HERE,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               env={**os.environ, "KAVACH_CUSTOM_BRANDS": str(folder / "brands_custom.json"), **env})
    for _ in range(240):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=2).read()
            return process, f"http://127.0.0.1:{port}"
        except OSError:
            time.sleep(0.25)
    process.kill()
    raise SystemExit("server.py did not start")


def sms_picture(path: Path) -> None:
    """A made-up scam SMS screenshot."""
    image = Image.new("RGB", (1000, 600), "white")
    draw, font = ImageDraw.Draw(image), ImageFont.truetype("arial.ttf", 36)
    draw.text((40, 30), "AD-SBIBNK", fill="black", font=font)
    for number, line in enumerate(["Your SBI account will be blocked today.", "Update KYC now: sbi-kyc-update.xyz"]):
        draw.text((40, 140 + number * 70), line, fill="black", font=font)
    draw.text((40, 320), "10:32 AM", fill="gray", font=font)
    image.save(path)


def browser_picture(path: Path) -> None:
    """A made-up browser window showing a fake bank page."""
    image = Image.new("RGB", (1280, 800), "white")
    draw = ImageDraw.Draw(image)
    small, large = ImageFont.truetype("arial.ttf", 22), ImageFont.truetype("arial.ttf", 34)
    draw.rectangle([0, 0, 1280, 70], fill=(225, 228, 232))
    draw.text((40, 22), "https://secure-netbank-portal.com/login", fill="black", font=small)
    for number, line in enumerate(["State Bank of India", "Enter your debit card number", "Enter CVV", "Enter password"]):
        draw.text((120, 170 + number * 110), line, fill="black", font=large)
    image.save(path)


def no_side_scroll(page, label: str) -> None:
    width = page.evaluate("[document.documentElement.scrollWidth, window.innerWidth]")
    check(f"no side scrolling: {label}", width[0] <= width[1], f"page {width[0]}px, window {width[1]}px")


def wait_for_engine(page, text: str) -> None:
    page.wait_for_function("t => document.getElementById('engineName').textContent.includes(t)", arg=text, timeout=30000)


def full_run(browser, base: str, folder: Path, shots) -> None:
    context = browser.new_context(viewport={"width": 1366, "height": 860}, accept_downloads=True)
    page = context.new_page()
    problems = []
    page.on("pageerror", lambda err: problems.append(str(err)))
    page.on("console", lambda msg: problems.append(msg.text) if msg.type == "error" and "fonts.g" not in msg.text and "ERR_" not in msg.text and "status of 4" not in msg.text else None)
    alerts = []
    page.on("dialog", lambda dialog: (alerts.append(dialog.message), dialog.dismiss()))
    page.goto(base)
    wait_for_engine(page, "Python engine")
    check("uses the Python engine", True, page.inner_text("#engineName"))
    page.wait_for_function("document.getElementById('nReal').textContent.includes('%')", timeout=20000)

    # ---- numbers come from the server ----
    stats = json.loads(page.evaluate("fetch('/api/stats').then(r=>r.text())"))
    check("numbers strip: brand count", page.inner_text("#nBrands") == str(stats["brands"]), page.inner_text("#nBrands"))
    check("numbers strip: real-feed number", f"{stats['real_world']['n_phishing']:,}"[:1] in page.inner_text("#nRealLbl"), page.inner_text("#nRealLbl")[:60])
    check("watchlist strip shows the new brands", "Zerodha" in page.inner_text("#track") and "DigiLocker" in page.inner_text("#track"), "")
    check("How it works example is live", "sbi-kyc-update-now.top" in page.inner_text("#howScoreEx") and str(stats["examples"]["combo"]["score"]) in page.inner_text("#howScoreEx"), "")
    check("measured panel keeps real and synthetic apart", "Real phishing feeds" in page.inner_text("#mReal") and "Synthetic" in page.inner_text("#mSynth"), "")
    check("full numbers: sources and licences", "CC BY 4.0" in page.inner_text("#mFull", timeout=5000) or page.locator("#mFull details").count() >= 5, f"{page.locator('#mFull details').count()} groups")
    check("signals grid comes from the server", "Protected ending" in page.inner_text("#sigGrid"), "")
    check("no 'today's registrations' claim left", "today's new registrations" not in page.content(), "")

    # ---- domain check ----
    page.fill("#domainInput", "paytrn.com")
    page.click("#checkForm button[type=submit]")
    page.wait_for_function("document.getElementById('rHost').textContent==='paytrn.com'")
    page.wait_for_selector("#rStats:not([hidden])")
    check("domain: a fake is Phishing", page.inner_text("#verdict") == "Phishing likely", page.inner_text("#verdict"))
    check("domain: closeness and rules shown", page.inner_text("#stClose") == "99%", page.inner_text("#stClose"))
    check("domain: did you mean", "paytm.com" in page.inner_text("#didMean"), page.inner_text("#didMean"))
    check("domain: evidence shows the edit", "rn" in page.inner_text("#cmpNote"), page.inner_text("#cmpNote")[:60])
    with page.expect_download() as download:
        page.click("#saveJson")
    saved = json.loads(Path(download.value.path()).read_text(encoding="utf-8"))
    check("domain: result downloads as JSON", saved["attack_type"] == "homoglyph", saved["attack_type"])
    page.fill("#domainInput", "mha.gov.in")
    page.click("#checkForm button[type=submit]")
    page.wait_for_function("document.getElementById('rHost').textContent==='mha.gov.in'")
    page.wait_for_function("document.getElementById('verdict').textContent==='Verified official'")
    check("domain: .gov.in is verified", True, "")
    page.fill("#domainInput", "<img src=x onerror=alert(1)>.com")
    page.click("#checkForm button[type=submit]")
    page.wait_for_timeout(600)
    check("domain: pasted HTML is shown as text", not alerts and page.locator("#rHost img").count() == 0, "")
    if shots:
        page.fill("#domainInput", "sbi-kyc-update-now.top")
        page.click("#checkForm button[type=submit]")
        page.wait_for_timeout(800)
        page.screenshot(path=str(shots / "desktop_hero.png"))

    # ---- message scan ----
    page.select_option("#sample", "3")  # digital arrest
    page.wait_for_function("document.getElementById('msgVerdict').textContent==='Likely scam'", timeout=10000)
    check("message: digital arrest sample is a scam", "threatens arrest" in page.inner_text("#scanOut"), "")
    page.select_option("#sample", "8")  # Hindi
    page.wait_for_function("document.getElementById('scanOut').textContent.includes('sbi-kyc-update.top')", timeout=10000)
    check("message: Hindi sample is a scam", page.inner_text("#msgVerdict") == "Likely scam", page.inner_text("#msgVerdict"))
    page.select_option("#sample", "10")  # genuine OTP
    page.wait_for_function("document.getElementById('msgVerdict').textContent==='Looks fine'", timeout=10000)
    check("message: genuine OTP looks fine", "What to do" not in page.inner_text("#scanOut"), "")
    page.fill("#msgInput", "<img src=x onerror=alert(2)> Your SBI account is blocked: sbi-kyc.top")
    page.click("#scanBtn")
    page.wait_for_function("document.getElementById('msgVerdict').textContent==='Likely scam'", timeout=10000)
    check("message: pasted HTML is shown as text", not alerts and page.locator("#scanOut img").count() == 0, "")

    # ---- a whole file of messages ----
    messages = folder / "msgs.csv"
    messages.write_text("message,sender\nYou won! Claim at bit.ly/x,\nYour OTP is 1234. Do not share it.,AD-HDFCBK\n", encoding="utf-8")
    page.set_input_files("#msgFile", str(messages))
    page.wait_for_selector("#msgTable:not([hidden])", timeout=20000)
    check("message file: table and counts", "2 messages" in page.inner_text("#msgFileName") and "1 scam" in page.inner_text("#msgFileName"), page.inner_text("#msgFileName")[:70])
    with page.expect_download() as download:
        page.click("[data-mdl=xlsx]")
    check("message file: Excel download", Path(download.value.path()).read_bytes()[:2] == b"PK", download.value.suggested_filename)

    # ---- screenshots ----
    sms, web = folder / "sms.png", folder / "site.png"
    sms_picture(sms)
    browser_picture(web)
    (folder / "note.txt").write_text("not an image", encoding="utf-8")
    page.set_input_files("#shotFile", str(folder / "note.txt"))
    page.wait_for_function("document.getElementById('shotStatus').classList.contains('err')", timeout=5000)
    check("screenshot: wrong file gets a clear message", "PNG" in page.inner_text("#shotStatus"), page.inner_text("#shotStatus")[:60])
    page.set_input_files("#shotFile", str(sms))
    check("screenshot: progress message", "Reading text" in page.inner_text("#shotStatus"), page.inner_text("#shotStatus")[:50])
    page.wait_for_selector("#shotText", timeout=60000)
    check("screenshot: preview has alt text", page.get_attribute("#shotImg", "alt") and page.is_visible("#shotImg"), page.get_attribute("#shotImg", "alt"))
    check("screenshot: SMS verdict", page.inner_text("#shotVerdict") == "Likely scam", page.inner_text("#shotVerdict"))
    check("screenshot: says what it guessed", "message or chat" in page.inner_text("#shotOut"), "")
    check("screenshot: link shown, never as certain", "sbi-kyc-update.xyz" in page.inner_text("#shotOut") and "Compare it with your screenshot" in page.inner_text("#shotOut"), "")
    check("screenshot: warns about look-alike letters", "Cyrillic" in page.inner_text("#shotOut"), "")
    check("screenshot: what to do", "1930" in page.inner_text("#shotOut"), "")
    if shots:
        page.locator("#screenshot").screenshot(path=str(shots / "desktop_screenshot_sms.png"))
    # Correct the text by hand and check again. Anything typed here goes through esc() too.
    page.fill("#shotText", "<img src=x onerror=alert(3)> Your OTP is 482913. Do not share it with anyone.")
    page.click("#shotAgain")
    page.wait_for_function("document.getElementById('shotVerdict').textContent==='Looks fine'", timeout=10000)
    check("screenshot: corrected text is checked again", "corrected text" in page.inner_text("#shotOut") and not alerts and page.locator("#shotOut img").count() == 0, "")
    # Paste from the clipboard, as Ctrl+V does
    page.click("#shotMode button[data-m=auto]")
    page.evaluate("""b64 => {
        const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
        const data = new DataTransfer();
        data.items.add(new File([bytes], 'clip.png', {type: 'image/png'}));
        document.dispatchEvent(new ClipboardEvent('paste', {clipboardData: data, bubbles: true}));
    }""", __import__("base64").b64encode(web.read_bytes()).decode())
    page.wait_for_function("document.getElementById('shotOut').textContent.includes('secure-netbank-portal.com')", timeout=60000)
    text = page.inner_text("#shotOut")
    check("screenshot: paste works, and it is read as a website", "looks like a website" in text, "")
    check("screenshot: brand mismatch note", "State Bank" in text and "not a State Bank address" in text, "")
    check("screenshot: what the page asks for", "CVV" in text, "")
    check("screenshot: says page evidence raised it", "raised" in text or "Address bar" in text, "")
    if shots:
        page.locator("#screenshot").screenshot(path=str(shots / "desktop_screenshot_web.png"))

    # ---- bulk list and downloads ----
    page.click("#pasteToggle")
    page.fill("#pasteInput", "sbi-kyc-update.in\npaytrn.com\nmytuitionnotes.in\nzerodha-login.xyz\nmha.gov.in")
    page.click("#pasteScan")
    page.wait_for_function("document.getElementById('feedNote').textContent.includes('5 domains')", timeout=20000)
    check("bulk: list scanned by Python", "Python engine" in page.inner_text("#feedNote"), page.inner_text("#feedNote")[:70])
    check("bulk: closeness column", "99%" in page.inner_text("#feedBody") or "%" in page.inner_text("#feedBody"), "")
    for fmt, start in (("csv", b"\xef\xbb\xbf"), ("xlsx", b"PK"), ("json", b"[")):
        with page.expect_download() as download:
            page.click(f"[data-dl={fmt}]")
        data = Path(download.value.path()).read_bytes()
        check(f"bulk: {fmt} download", data.startswith(start) and len(data) > 100, f"{len(data):,} bytes")

    # ---- compare a page ----
    fake = folder / "fake.html"
    real = folder / "real.html"
    fake.write_text("<title>Paytm - Sign in</title><h1>Sign in to Paytm</h1><p>Pay bills and send money securely.</p><form action='https://evil.example/x'><input name=mobile><input type=password name=password><input name=otp placeholder='Enter OTP'></form>", encoding="utf-8")
    real.write_text("<title>Paytm - Sign in</title><h1>Sign in to Paytm</h1><p>Pay bills and send money securely.</p><form><input name=mobile><input type=password name=password></form>", encoding="utf-8")
    page.fill("#compareUrl", "paytrn.com")
    page.set_input_files("#cmpBadHtml", str(fake))
    page.set_input_files("#cmpGoodHtml", str(real))
    page.click("#compareBtn")
    page.wait_for_selector("#compareOut .pill", timeout=15000)
    check("compare: close copy is strong evidence", "Strong phishing evidence" in page.inner_text("#compareOut"), page.inner_text("#compareOut")[:60])
    check("compare: says it doesn't change the score", "does not change the risk score" in page.inner_text("#compareOut"), "")

    # ---- add a brand: it must reach the Python engine ----
    page.fill("#abName", "Konark Bank")
    page.fill("#abDomain", "konarkbank.in")
    page.click("#addBrand button[type=submit]")
    page.wait_for_function("document.getElementById('abMsg').textContent.includes('Python engine')", timeout=10000)
    check("brand: selected in the list", "Konark Bank" in page.inner_text("#genBrand"), "")
    page.wait_for_function("document.getElementById('nBrands').textContent==String(%d)" % (stats["brands"] + 1), timeout=10000)
    page.fill("#domainInput", "konarkbnak.in")
    page.click("#checkForm button[type=submit]")
    page.wait_for_function("document.getElementById('rHost').textContent==='konarkbnak.in'")
    page.wait_for_function("document.getElementById('verdict').textContent==='Phishing likely'", timeout=10000)
    check("brand: Python flags its look-alike", "konarkbank.in" in page.inner_text("#didMean"), page.inner_text("#didMean"))
    page.fill("#abName", "Fake")
    page.fill("#abDomain", "paytrn.com")
    page.click("#addBrand button[type=submit]")
    page.wait_for_function("document.getElementById('abMsg').classList.contains('err')", timeout=10000)
    check("brand: a fake domain is refused", "fake" in page.inner_text("#abMsg").lower(), page.inner_text("#abMsg")[:70])
    page.click("#mine button")
    page.wait_for_function("document.getElementById('abMsg').textContent.includes('removed')", timeout=10000)
    check("brand: removed again", "Konark" not in page.inner_text("#mineWrap") or page.locator("#mine button").count() == 0, "")

    # ---- report text and links ----
    check("section links work", page.locator("a[href='#signal-guide']").count() == 1 and page.locator("section#signal-guide").count() == 1, "")
    check("no page errors", not problems, "; ".join(problems)[:100])
    check("nothing pasted ever ran", not alerts, str(alerts))
    no_side_scroll(page, "desktop")
    if shots:
        page.locator("#how").screenshot(path=str(shots / "desktop_how.png"))
        page.locator("#compare-pages").screenshot(path=str(shots / "desktop_compare.png"))
        page.locator("#numbers").screenshot(path=str(shots / "desktop_numbers.png"))
        page.locator("#messages").screenshot(path=str(shots / "desktop_messages.png"))
    context.close()


def phone_run(browser, base: str, folder: Path, shots) -> None:
    context = browser.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2, is_mobile=True, has_touch=True)
    page = context.new_page()
    page.goto(base)
    wait_for_engine(page, "Python engine")
    page.wait_for_timeout(800)
    no_side_scroll(page, "phone, on opening")
    page.set_input_files("#shotFile", str(folder / "site.png"))
    page.wait_for_selector("#shotText", timeout=60000)
    no_side_scroll(page, "phone, after a screenshot scan")
    page.select_option("#sample", "3")
    page.wait_for_function("document.getElementById('msgVerdict').textContent==='Likely scam'", timeout=10000)
    page.click("#pasteToggle")
    page.fill("#pasteInput", "averyveryveryveryveryveryveryverylongdomainname-sbi-kyc-update-login.xyz\npaytrn.com")
    page.click("#pasteScan")
    page.wait_for_function("document.getElementById('feedNote').textContent.includes('2 domains')", timeout=20000)
    no_side_scroll(page, "phone, everything open")
    for selector in ("#screenshot", "#compare-pages", "#msgBatch", "#measured"):
        box = page.locator(selector).bounding_box()
        check(f"phone: {selector} fits the screen", box and box["x"] >= -1 and box["x"] + box["width"] <= 391, str(box and round(box["width"])))
    if shots:
        page.locator("#screenshot").screenshot(path=str(shots / "phone_screenshot.png"))
        page.locator("#messages").screenshot(path=str(shots / "phone_messages.png"))
        page.screenshot(path=str(shots / "phone_full.png"), full_page=True)
    context.close()


def without_ocr_run(browser, folder: Path) -> None:
    process, base = start_server(folder, KAVACH_NO_OCR="1")
    try:
        context = browser.new_context(viewport={"width": 1280, "height": 800})
        page = context.new_page()
        page.goto(base)
        wait_for_engine(page, "Python engine")
        page.wait_for_selector("#shotOff:not([hidden])")
        check("no OCR: section explains how to turn it on", "requirements-ocr" in page.inner_text("#shotOff"), page.inner_text("#shotOff")[:70])
        check("no OCR: the file box is off", page.is_disabled("#shotFile"), "")
        page.fill("#domainInput", "paytrn.com")
        page.click("#checkForm button[type=submit]")
        page.wait_for_function("document.getElementById('verdict').textContent==='Phishing likely'", timeout=10000)
        check("no OCR: everything else still works", True, "")
        context.close()
    finally:
        process.terminate()


def stopped_server_run(browser, folder: Path, shots) -> None:
    process, base = start_server(folder)
    context = browser.new_context(viewport={"width": 1280, "height": 800})
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda err: errors.append(str(err)))
    page.goto(base)
    wait_for_engine(page, "Python engine")
    process.terminate()
    process.wait(timeout=15)
    # The very next check notices the server is gone and moves to the browser engine
    page.fill("#domainInput", "paytrn.com")
    page.click("#checkForm button[type=submit]")
    wait_for_engine(page, "Browser demo engine")
    check("server stopped: page says so", True, page.inner_text("#engineName"))
    page.wait_for_function("document.getElementById('verdict').textContent==='Phishing likely'", timeout=5000)
    check("server stopped: rules-only domain check still works", True, "")
    check("server stopped: screenshot scan explains", "needs the server" in page.inner_text("#shotOff") and page.is_disabled("#shotFile"), page.inner_text("#shotOff")[:60])
    check("server stopped: message file explains", page.is_visible("#msgBatchOff"), "")
    check("server stopped: compare explains", page.is_visible("#compareOff") and page.is_disabled("#compareBtn"), "")
    check("server stopped: downloads hidden", not page.is_visible("#dlGroup"), "")
    page.select_option("#sample", "0")
    page.wait_for_function("document.getElementById('msgVerdict').textContent==='Likely scam'", timeout=5000)
    check("server stopped: message scan still works", True, "")
    page.fill("#abName", "Offline Bank")
    page.fill("#abDomain", "offlinebank.in")
    page.click("#addBrand button[type=submit]")
    page.wait_for_function("document.getElementById('abMsg').textContent.includes('this browser')", timeout=5000)
    check("server stopped: an added brand says it stays in this browser", True, page.inner_text("#abMsg")[:70])
    check("server stopped: no page errors", not errors, "; ".join(errors)[:100])
    if shots:
        page.screenshot(path=str(shots / "fallback.png"))
    context.close()

    # Opened as a plain file, with no server at all
    context = browser.new_context(viewport={"width": 1280, "height": 800})
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda err: errors.append(str(err)))
    page.goto((HERE / "frontend" / "index.html").as_uri())
    wait_for_engine(page, "Browser demo engine")
    page.fill("#domainInput", "sbi-kyc-update.in")
    page.click("#checkForm button[type=submit]")
    page.wait_for_timeout(300)
    check("plain file: works without a server", page.inner_text("#verdict") == "Phishing likely" and not errors, "; ".join(errors)[:80])
    check("plain file: How it works still has an example", len(page.inner_text("#howScoreEx")) > 10, "")
    context.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shots", help="folder to save screenshots in")
    parser.add_argument("--channel", default="msedge", help="browser: msedge (default) or chrome")
    args = parser.parse_args()
    shots = Path(args.shots) if args.shots else None
    if shots:
        shots.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as folder, sync_playwright() as playwright:
        folder = Path(folder)
        browser = playwright.chromium.launch(channel=args.channel, headless=True)
        process, base = start_server(folder)
        try:
            full_run(browser, base, folder, shots)
            phone_run(browser, base, folder, shots)
        finally:
            process.terminate()
            process.wait(timeout=15)
        without_ocr_run(browser, folder)
        stopped_server_run(browser, folder, shots)
        browser.close()
    print(f"\n{sum(results)}/{len(results)} passed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
