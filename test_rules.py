"""
Kavach - regression tests. Run after every change:

    python test_rules.py

Prints a table and a summary, and exits with code 1 if anything fails. No pytest needed.

To add a test, add a line to LINK_CASES. Expected verdicts are what the link SHOULD get, so if a
test fails, look at why before changing the expected verdict.
"""
import sys

# The shared logic only. Don't import app.py here: that starts the Streamlit UI.
from detector import full_analysis, load_model

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

    # --- Brand hidden inside the name ---
    ("sbi-kyc-update-now.top", "Phishing"),
    ("onlinesbi-kyc-update.xyz", "Phishing"),
    ("ama-zon-login.net", "Phishing"),
    ("hdfc-bank-login.com", "Phishing"),
    ("hdfc-bank-login.net", "Phishing"),
    ("my-sbi-login.net", "Phishing"),
    ("startamazonstore.net", "Phishing"),          # 45 from rules; ML raises it, so a retrain can change it
    ("sbikyc.net", "Suspicious"),
    ("sbilogin.net", "Suspicious"),
    ("kycsbi.net", "Suspicious"),
    ("paytmkyc.net", "Suspicious"),
    ("myflipkartoffer.net", "Suspicious"),
    ("sbi-bank.in", "Suspicious"),

    # --- Brand in a subdomain ---
    ("amazon.security-check.icu", "Phishing"),
    ("paytm-login.weebly.com", "Phishing"),
    ("startamazonstore.weebly.com", "Phishing"),
    ("paytm-kyc-verify-login.github.io", "Phishing"),
    ("paytm.spotify.com", "Suspicious"),           # 45 from rules; ML raises it, so a retrain can change it
    ("sbi-login.wikipedia.org", "Phishing"),
    ("sbi.bank.in.evil.com", "Phishing"),

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
    ("reddit-login.com", "Phishing"),              # 55 from rules; ML raises it, so a retrain can change it
    ("spotify-offer.net", "Suspicious"),
    ("reddit.biz", "Suspicious"),
    ("reddit.xyz", "Phishing"),                    # 45 for the name + 15 for .xyz

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

    # --- Popular real sites ---
    ("reddit.com", "Safe"),
    ("www.reddit.com", "Safe"),
    ("HTTPS://WWW.Reddit.com/r/india", "Safe"),
    ("weebly.com", "Safe"),
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
#   3. add ("Messages", MESSAGE_CASES, check_message) to SUITES at the bottom


def check_link(link: str, bundle) -> tuple:
    """Returns (verdict, score) for one link."""
    result = full_analysis(link, bundle)
    return result["verdict"], result["score"]


def run_suite(title: str, cases: list, check, bundle) -> int:
    """Print one table of results. Returns how many cases passed."""
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
    return passed


# (title, cases, function that checks one case)
SUITES = [("Links", LINK_CASES, check_link)]


def main():
    bundle = load_model()
    if bundle is None:
        print("model.joblib is missing, so the expected verdicts don't apply. Run: python train.py")
        sys.exit(1)

    passed = sum(run_suite(title, cases, check, bundle) for title, cases, check in SUITES)
    total = sum(len(cases) for _, cases, _ in SUITES)
    print(f"\n{passed}/{total} passed")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
