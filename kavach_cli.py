"""
Kavach command-line tool: check a list of domains without opening the app.

Examples (Windows, with the venv active):
  python kavach_cli.py sample_domains.csv
  python kavach_cli.py sample_domains.csv --format json --out results.json
  python kavach_cli.py domains.txt --format xlsx --out results.xlsx
  python kavach_cli.py messages.csv --mode messages

Input: a .csv with a column named 'domain' (or 'message' for the message mode, plus an optional
'sender' column), or a .txt with one domain or message per line.
"""
import argparse
import sys
from collections import Counter
from pathlib import Path

from detector import load_model
from outputs import (EXPORTERS, check_many, check_messages, read_domains, read_messages, speed)
from sms import MESSAGE_COLUMNS


def main():
    parser = argparse.ArgumentParser(description="Check a list of domains for phishing look-alikes. Works offline.")
    parser.add_argument("input", help="a .csv with a 'domain' column, or a .txt with one domain per line")
    parser.add_argument("--format", choices=sorted(EXPORTERS), help="output format (default: from --out, else csv)")
    parser.add_argument("--out", help="output file (default: <input name>_results.<format>)")
    parser.add_argument("--mode", choices=("links", "messages", "auto"), default="auto",
                        help="check web links or whole SMS messages (default: auto, from the CSV columns)")
    args = parser.parse_args()

    source = Path(args.input)
    if not source.is_file():
        sys.exit(f"Error: can't find the file '{source}'.")

    # Work out the format and the file name from whatever was given
    suffix = Path(args.out).suffix.lower().lstrip(".") if args.out else ""
    fmt = args.format or (suffix if suffix in EXPORTERS else "csv")
    out = Path(args.out) if args.out else source.with_name(f"{source.stem}_results.{fmt}")
    if out.resolve() == source.resolve():
        sys.exit("Error: the output file would overwrite the input file. Choose another name with --out.")

    data = source.read_bytes()
    mode = args.mode
    if mode == "auto":
        # A CSV with a 'message' column is a message file; anything else is a list of links
        head = data[:2000].decode("utf-8-sig", errors="replace").splitlines()[:1]
        mode = "messages" if head and "message" in head[0].lower().split(",") else "links"

    try:
        items = read_messages(data, source.name) if mode == "messages" else read_domains(data, source.name)
    except ValueError as err:
        sys.exit(f"Error: {err}")

    bundle = load_model()
    if bundle is None:
        print("Warning: model.joblib not found, so only the rule-based score is used.")

    if mode == "messages":
        rows, seconds = check_messages(items, bundle)
        columns = MESSAGE_COLUMNS
    else:
        rows, seconds = check_many(items, bundle)
        columns = None
    try:
        out.write_bytes(EXPORTERS[fmt](rows, columns))
    except PermissionError:
        sys.exit(f"Error: can't write '{out}'. If it's open in Excel, close it and try again.")
    except ImportError:
        sys.exit(f"Error: {fmt} output needs one more package. Run: pip install -r requirements.txt")

    counts = Counter(row["verdict"] for row in rows)
    ms, per_second = speed(len(rows), seconds)
    if mode == "messages":
        print(f"Checked {len(rows)} messages: {counts['Scam']} scam, "
              f"{counts['Suspicious']} suspicious, {counts['Safe']} safe")
    else:
        print(f"Checked {len(rows)} domains: {counts['Phishing']} phishing, "
              f"{counts['Suspicious']} suspicious, {counts['Safe']} safe")
    unit = "message" if mode == "messages" else "domain"
    print(f"Speed: {ms:.1f} ms per {unit} ({per_second:.0f} {unit}s/second)")
    print(f"Saved {out}")


if __name__ == "__main__":
    main()
