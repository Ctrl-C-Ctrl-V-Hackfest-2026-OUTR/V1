"""
Kavach command-line tool: check a list of domains without opening the app.

Examples (Windows, with the venv active):
  python kavach_cli.py sample_domains.csv
  python kavach_cli.py sample_domains.csv --format json --out results.json
  python kavach_cli.py domains.txt --format xlsx --out results.xlsx

Input: a .csv with a column named 'domain', or a .txt with one domain per line.
"""
import argparse
import sys
from collections import Counter
from pathlib import Path

from detector import load_model
from outputs import EXPORTERS, check_many, read_domains, speed


def main():
    parser = argparse.ArgumentParser(description="Check a list of domains for phishing look-alikes. Works offline.")
    parser.add_argument("input", help="a .csv with a 'domain' column, or a .txt with one domain per line")
    parser.add_argument("--format", choices=sorted(EXPORTERS), help="output format (default: from --out, else csv)")
    parser.add_argument("--out", help="output file (default: <input name>_results.<format>)")
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

    try:
        domains = read_domains(source.read_bytes(), source.name)
    except ValueError as err:
        sys.exit(f"Error: {err}")

    bundle = load_model()
    if bundle is None:
        print("Warning: model.joblib not found, so only the rule-based score is used.")

    rows, seconds = check_many(domains, bundle)
    try:
        out.write_bytes(EXPORTERS[fmt](rows))
    except PermissionError:
        sys.exit(f"Error: can't write '{out}'. If it's open in Excel, close it and try again.")

    counts = Counter(row["verdict"] for row in rows)
    ms, per_second = speed(len(rows), seconds)
    print(f"Checked {len(rows)} domains: {counts['Phishing']} phishing, "
          f"{counts['Suspicious']} suspicious, {counts['Safe']} safe")
    print(f"Speed: {ms:.1f} ms per domain ({per_second:.0f} domains/second)")
    print(f"Saved {out}")


if __name__ == "__main__":
    main()
