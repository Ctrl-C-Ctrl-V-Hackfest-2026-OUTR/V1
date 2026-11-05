"""
Kavach - the main way to run the project: the website in frontend/ and its JSON API.

It serves the page and calls the detection code directly (detector.py, sms.py, outputs.py, ocr.py,
page_compare.py), so the website shows the real rules + ML verdicts.
Standard library only (no Flask). It listens on this computer only and never goes online: it never
fetches a link it is asked about, and never a link found in an image or message.

Run:   python server.py          (then open http://127.0.0.1:8000)
Other: python server.py --port 9000 --no-browser

If this server is not running, the page still works for simple checks: it falls back to a small rules-only
engine inside the browser and says so. Everything else on the page says it needs the server.
This file must NOT import app.py or streamlit (importing app.py starts the Streamlit UI).
"""
import argparse
import base64
import binascii
import csv
import json
import mimetypes
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pandas as pd

import ocr
import page_compare
from detector import ML_TRUST, explain, full_analysis, load_model, signal_catalog
from features import (BRAND_RECORDS, BRANDS, CUSTOM_BRANDS_FILE, FREE_HOSTING, POPULAR_DOMAINS, SUSPICIOUS_TLDS,
                      add_custom_brand, extract_features, remove_custom_brand)
from outputs import EXPORTERS, FORMATS, check_messages, flat_row, read_messages
from sms import MESSAGE_COLUMNS, SIGNALS, WHAT_TO_DO, check_message

HERE = Path(__file__).parent
FRONTEND = HERE / "frontend"
MAX_BODY = 4_000_000     # bytes in one ordinary request
MAX_COMPARE_BODY = 24_000_000   # two pages and two screenshots, as JSON
MAX_DOMAINS = 20_000     # domains in one bulk request or export
MAX_TEXT = 5_000         # characters in one message
MAX_MESSAGES = 5_000     # messages in one file
MAX_DRAIN = 64_000_000   # read and throw away at most this much of a request that is too large
IMAGE_TYPES = ("image/png", "image/jpeg", "image/webp")

BUNDLE = load_model()    # None if model.joblib is missing: the rules still work
# One lock around everything that reads the model or the watchlist, because a brand can be added while
# another request is running. RLock, because a check can call another check.
MODEL_LOCK = threading.RLock()


def brand_list() -> list:
    """The watchlist for the page: one entry per brand, in file order."""
    return [{"key": record["key"], "name": record["name"], "category": record.get("category", ""),
             "domains": record["domains"], "custom": bool(record.get("custom"))} for record in BRAND_RECORDS]


def watch_summary() -> dict:
    return {"brands": len(BRAND_RECORDS), "brand_keys": list(BRANDS),
            "brand_names": [record["name"] for record in BRAND_RECORDS]}


# ---------------- the checks ----------------

def check_one(url: str) -> dict:
    started = time.perf_counter()
    with MODEL_LOCK:
        result = full_analysis(url, BUNDLE)
        result["explain"] = explain(result, result["target"])
    result["flat"] = flat_row(result)   # the same columns as an export, for "Copy result as JSON"
    result["ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def check_batch(domains: list) -> tuple:
    """Full results for a list of domains. The model scores the whole list in one call, which is
    much faster than one domain at a time (the same trick as outputs.check_many)."""
    started = time.perf_counter()
    with MODEL_LOCK:
        if BUNDLE is None:
            probabilities = [None] * len(domains)
        else:
            table = pd.DataFrame([extract_features(d) for d in domains], columns=BUNDLE["features"])
            model = BUNDLE["model"]
            probabilities = model.predict_proba(table)[:, list(model.classes_).index(1)]
        results = []
        for domain, proba in zip(domains, probabilities):
            result = full_analysis(domain, BUNDLE, proba=proba)
            result["explain"] = explain(result, result["target"])
            results.append(result)
    return results, round((time.perf_counter() - started) * 1000, 1)


def clean_domains(value) -> list:
    if not isinstance(value, list):
        raise ValueError("'domains' must be a list of strings.")
    domains = [str(item).strip()[:300] for item in value if str(item).strip()]
    if not domains:
        raise ValueError("No domains were sent.")
    if len(domains) > MAX_DOMAINS:
        raise ValueError(f"Too many domains: the limit is {MAX_DOMAINS:,} per request.")
    return domains


def message_rows(data: dict) -> tuple:
    """Check a whole file of messages, read by the same function the command-line tool uses."""
    content = str(data.get("content", ""))
    if not content.strip():
        raise ValueError("That file is empty.")
    pairs = read_messages(content.encode("utf-8"), str(data.get("filename", "messages.txt"))[:200])
    if len(pairs) > MAX_MESSAGES:
        raise ValueError(f"Too many messages: the limit is {MAX_MESSAGES:,} per file.")
    with MODEL_LOCK:
        return check_messages([(text[:MAX_TEXT], sender[:40]) for text, sender in pairs], BUNDLE)


def _decode_file(value, what: str):
    """A base64 file from the page, or None if it wasn't sent."""
    if not value:
        return None
    try:
        return base64.b64decode(str(value), validate=True)
    except (binascii.Error, ValueError) as err:
        raise ValueError(f"Could not read the {what}.") from err


def compare_pages(data: dict) -> dict:
    """The saved-page comparison from page_compare.py. Files are only read, and nothing is fetched."""
    html_a, html_b = _decode_file(data.get("bad_html"), "suspicious page"), _decode_file(data.get("good_html"), "genuine page")
    image_a, image_b = _decode_file(data.get("bad_image"), "suspicious screenshot"), _decode_file(data.get("good_image"), "genuine screenshot")
    if not (html_a and html_b) and not (image_a and image_b):
        raise ValueError("Upload both HTML files and/or both screenshots to compare them.")
    content = page_compare.compare_html(html_a, html_b) if html_a and html_b else None
    visual = page_compare.compare_images(image_a, image_b) if image_a and image_b else None
    url = str(data.get("url", "")).strip()[:2000]
    differs = None
    if url:
        with MODEL_LOCK:
            differs = not full_analysis(url, BUNDLE)["evidence"]["is_genuine"]
    level, sentence = page_compare.conclusion(content and content["content_similarity"],
                                              visual and visual["visual_similarity"], differs)
    return {"content": content, "visual": visual, "level": level, "conclusion": sentence, "url": url or None,
            "changes_risk_score": False}


def read_json_file(name: str):
    try:
        return json.loads((HERE / name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def live_example(domain: str) -> dict:
    """One worked example for the How it works steps, computed now, so it can't go stale."""
    result = check_one(domain)
    return {"domain": domain, "rule_score": result["rule_score"], "ml_probability": result["ml_probability"],
            "score": result["score"], "verdict": result["verdict"], "reasons": result["reasons"].split("; "),
            "reason_points": result["reason_points"], "target": result["target"],
            "closeness": result["evidence"]["closeness"], "edits": result["evidence"]["edits"]}


def stats() -> dict:
    """Every number the page shows. These come from metrics.json, evaluation.json and the code itself,
    so re-running train.py or evaluate.py updates the website with nothing else to change."""
    out = {"model_loaded": BUNDLE is not None, "brands": len(BRAND_RECORDS), "metrics": read_json_file("metrics.json"),
           "popular_sites": len(POPULAR_DOMAINS), "free_hosts": len(FREE_HOSTING), "risky_endings": len(SUSPICIOUS_TLDS),
           "ml_trust": ML_TRUST, "signals": signal_catalog(),
           "message_signals": [{"name": s["name"], "points": s["points"], "reason": s["reason"]} for s in SIGNALS],
           "sources": read_json_file("data_sources.json"),
           "examples": {"typo": live_example("paytrn.com"), "combo": live_example("sbi-kyc-update-now.top")}}
    evaluation = read_json_file("evaluation.json")
    out["attacks"] = evaluation.get("attacks") if evaluation else None
    out["real_world"] = evaluation.get("real_world") if evaluation else None
    out["messages"] = evaluation.get("messages") if evaluation else None
    try:
        total = brands_caught = popular_caught = brands_n = popular_n = 0
        for attack in evaluation["attacks"]:
            brands_n += attack["brands"]["count"]
            brands_caught += attack["brands"]["count"] * attack["brands"]["final"]
            popular_n += attack["popular"]["count"]
            popular_caught += attack["popular"]["count"] * attack["popular"]["final"]
        total = brands_n + popular_n
        out["evaluation"] = {
            "n_fakes": evaluation["n_fakes"],
            "caught": (brands_caught + popular_caught) / total if total else None,
            "caught_brands": brands_caught / brands_n if brands_n else None,
            "caught_popular": popular_caught / popular_n if popular_n else None,
            "false_alarms": evaluation["false_alarms"]["final"],
            "false_alarms_phishing": evaluation["false_alarms"]["phishing"],
            "false_alarm_count": evaluation["false_alarms"]["count"],
            "batch_ms_per_domain": evaluation["batch_ms_per_domain"],
            "batch_per_second": evaluation["batch_per_second"],
        }
    except (KeyError, TypeError):
        out["evaluation"] = None
    try:
        with open(HERE / "feature_importance.csv", encoding="utf-8", newline="") as handle:
            out["features"] = list(csv.DictReader(handle))
    except OSError:
        out["features"] = []
    return out


# ---------------- the web server ----------------

def json_default(value):
    try:
        return value.item()  # numpy numbers
    except AttributeError:
        raise TypeError(f"Cannot send {type(value).__name__}") from None


class Handler(BaseHTTPRequestHandler):
    server_version = "Kavach"
    allowed_hosts = {"localhost", "127.0.0.1", "[::1]"}  # set to None when --host is not local

    def log_message(self, format, *args):  # keep the console quiet, and never log what was checked
        pass

    # -- helpers --
    def send_bytes(self, code: int, body: bytes, content_type: str, headers: dict = None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, code: int, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=json_default).encode("utf-8")
        self.send_bytes(code, body, "application/json; charset=utf-8")

    def fail(self, code: int, message: str, error_code: str = None) -> None:
        self.send_json(code, {"error": message, **({"code": error_code} if error_code else {})})

    def allowed(self) -> bool:
        """Only this computer's own page may talk to the API (blocks other websites and DNS tricks)."""
        host = self.headers.get("Host", "")
        if self.allowed_hosts is not None and host.rsplit(":", 1)[0] not in self.allowed_hosts:
            return False
        origin = self.headers.get("Origin")
        return origin is None or urlparse(origin).netloc == host

    def body_length(self):
        """The Content-Length as a number, or None after sending the error."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.fail(400, "Bad Content-Length.")
            return None
        if length < 0:
            self.fail(400, "Bad Content-Length.")
            return None
        return length

    def drain(self, length: int) -> None:
        """Read and throw away a request that is too large. Hanging up on an upload in progress would make
        the browser report a broken connection instead of our clear message."""
        left = min(length, MAX_DRAIN)
        while left > 0:
            chunk = self.rfile.read(min(left, 65536))
            if not chunk:
                break
            left -= len(chunk)

    # -- routes --
    def do_GET(self):
        if not self.allowed():
            return self.fail(403, "Not allowed from this address.")
        path = urlparse(self.path).path
        if path == "/api/health":
            return self.send_json(200, {"ok": True, "model": BUNDLE is not None, "ocr": ocr.ocr_status(), **watch_summary()})
        if path == "/api/stats":
            return self.send_json(200, stats())
        if path == "/api/brands":
            return self.send_json(200, {"brands": brand_list(), "local_file": CUSTOM_BRANDS_FILE.name})
        if path.startswith("/api/"):
            return self.fail(404, "Unknown API route.")
        self.serve_file(path)

    def serve_file(self, path: str) -> None:
        relative = "index.html" if path in ("", "/") else path.lstrip("/")
        target = (FRONTEND / relative).resolve()
        if FRONTEND.resolve() not in target.parents or not target.is_file():
            return self.send_bytes(404, b"Not found", "text/plain; charset=utf-8")
        kind = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if kind.startswith("text/") or kind in ("application/javascript", "application/json"):
            kind += "; charset=utf-8"
        self.send_bytes(200, target.read_bytes(), kind)

    def handle_image(self, length: int) -> None:
        """POST /api/image?mode=auto|sms|website. The body is the raw image, not multipart: the cgi module
        is gone in Python 3.13+, and one file needs no form encoding. The image stays in memory."""
        kind = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if kind not in IMAGE_TYPES:
            self.drain(length)
            return self.fail(415, "Send a PNG, JPEG or WebP image.", "wrong_type")
        if length == 0:
            return self.fail(400, "No image was sent.", "wrong_type")
        if length > ocr.MAX_BYTES:
            self.drain(length)
            return self.fail(413, f"That image is larger than {ocr.MAX_BYTES // (1024 * 1024)} MB.", "too_large")
        status = ocr.ocr_status()
        if not status["available"]:
            self.drain(length)
            return self.fail(503, f"{status['reason']} To turn it on, run: {status['how_to_enable']}", "not_installed")
        data = self.rfile.read(length)
        query = parse_qs(urlparse(self.path).query)
        mode = (query.get("mode") or [self.headers.get("X-Kavach-Mode", "auto")])[0].strip().lower()
        try:
            with MODEL_LOCK:
                self.send_json(200, ocr.scan_image(data, mode, BUNDLE))
        except ocr.OcrError as err:
            codes = {"wrong_type": 415, "too_large": 413, "too_many_pixels": 413, "corrupt": 422, "no_text": 422,
                     "bad_mode": 400, "not_installed": 503}
            self.fail(codes.get(err.code, 400), err.message, err.code)

    def do_POST(self):
        if not self.allowed():
            return self.fail(403, "Not allowed from this address.")
        path = urlparse(self.path).path
        length = self.body_length()
        if length is None:
            return None
        try:
            if path == "/api/image":   # the only route that takes raw bytes
                return self.handle_image(length)
        except Exception as err:  # one bad image must not stop the demo. The image itself is never logged.
            return self.fail(500, f"Something went wrong while reading the image: {type(err).__name__}")

        limit = MAX_COMPARE_BODY if path == "/api/compare" else MAX_BODY
        if length > limit:
            self.drain(length)
            return self.fail(413, "That request is too large.")
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(data, dict):
                raise ValueError("The request body must be a JSON object.")
        except ValueError as err:
            return self.fail(400, f"Could not read the request: {err}")

        try:
            if path == "/api/check":
                url = str(data.get("url", "")).strip()[:2000]
                if not url:
                    return self.fail(400, "Send a domain or link in 'url'.")
                return self.send_json(200, check_one(url))

            if path == "/api/bulk":
                results, ms = check_batch(clean_domains(data.get("domains")))
                return self.send_json(200, {"rows": results, "ms": ms, "engine": "python"})

            if path == "/api/message":
                text = str(data.get("text", "")).strip()[:MAX_TEXT]
                if not text:
                    return self.fail(400, "Send the message in 'text'.")
                started = time.perf_counter()
                with MODEL_LOCK:
                    result = check_message(text, str(data.get("sender", "")).strip()[:40], BUNDLE)
                result["what_to_do"] = WHAT_TO_DO
                result["ms"] = round((time.perf_counter() - started) * 1000, 1)
                return self.send_json(200, result)

            if path == "/api/image/text":
                # Text the person corrected on a website screenshot. For a message, the page uses /api/message.
                text = str(data.get("text", "")).strip()[:MAX_TEXT]
                if not text:
                    return self.fail(400, "Send the text in 'text'.")
                with MODEL_LOCK:
                    return self.send_json(200, ocr.scan_text(text, str(data.get("mode", "website")), BUNDLE))

            if path == "/api/export":
                fmt = str(data.get("format", "csv")).lower()
                if fmt not in EXPORTERS:
                    return self.fail(400, "format must be csv, json or xlsx.")
                results, _ = check_batch(clean_domains(data.get("domains")))
                content_type, filename = FORMATS[fmt]
                body = EXPORTERS[fmt]([flat_row(r) for r in results])
                return self.send_bytes(200, body, content_type,
                                       {"Content-Disposition": f'attachment; filename="{filename}"'})

            if path == "/api/messages":
                rows, seconds = message_rows(data)
                return self.send_json(200, {"rows": rows, "columns": MESSAGE_COLUMNS, "ms": round(seconds * 1000, 1)})

            if path == "/api/messages/export":
                fmt = str(data.get("format", "csv")).lower()
                if fmt not in EXPORTERS:
                    return self.fail(400, "format must be csv, json or xlsx.")
                rows, _ = message_rows(data)
                content_type, _ = FORMATS[fmt]
                body = EXPORTERS[fmt](rows, MESSAGE_COLUMNS)
                return self.send_bytes(200, body, content_type,
                                       {"Content-Disposition": f'attachment; filename="kavach_messages.{fmt}"'})

            if path == "/api/compare":
                return self.send_json(200, compare_pages(data))

            if path == "/api/brands":
                with MODEL_LOCK:
                    record = add_custom_brand(data.get("name", ""), data.get("domain", ""))
                return self.send_json(200, {**watch_summary(), "added": record, "brands": brand_list()})

            if path == "/api/brands/remove":
                with MODEL_LOCK:
                    remove_custom_brand(str(data.get("key", "")))
                return self.send_json(200, {**watch_summary(), "brands": brand_list()})
        except ocr.OcrError as err:
            return self.fail(400, err.message, err.code)
        except ValueError as err:
            return self.fail(400, str(err))
        except OSError as err:
            return self.fail(500, f"Could not save that: {type(err).__name__}")
        except Exception as err:  # one bad input must not stop the demo
            return self.fail(500, f"Something went wrong while checking: {type(err).__name__}")
        self.fail(404, "Unknown API route.")


def main():
    parser = argparse.ArgumentParser(description="Kavach website + API (runs on this computer only)")
    parser.add_argument("--host", default="127.0.0.1", help="address to listen on (default: this computer only)")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-browser", action="store_true", help="do not open the page automatically")
    args = parser.parse_args()

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        Handler.allowed_hosts = None  # the person chose to share it on their network
    if not FRONTEND.joinpath("index.html").is_file():
        raise SystemExit("frontend/index.html is missing.")

    server = None
    for port in range(args.port, args.port + 10):  # if 8000 is busy, try the next ports
        try:
            server = ThreadingHTTPServer((args.host, port), Handler)
            break
        except OSError:
            continue
    if server is None:
        raise SystemExit(f"Ports {args.port}-{args.port + 9} are all busy. Try: python server.py --port 9000")

    check_one("paytrn.com")  # warm up the model and the domain parser so the first click is fast
    url = f"http://{'127.0.0.1' if args.host in ('127.0.0.1', 'localhost') else args.host}:{server.server_port}"
    status = ocr.ocr_status()
    print(f"Kavach is running at {url}", flush=True)
    print("Engine: " + ("rules + ML model" if BUNDLE else "rules only (model.joblib not found)"), flush=True)
    print("Screenshots: " + (", ".join(status["languages"]) if status["available"] else "off. " + status["how_to_enable"]), flush=True)
    print("Press Ctrl+C to stop.", flush=True)
    if not args.no_browser:
        threading.Timer(0.8, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
