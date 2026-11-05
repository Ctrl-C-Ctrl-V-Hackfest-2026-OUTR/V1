"""
Kavach - check many domains quickly and export the results as CSV, JSON or Excel.

The app (app.py) and the command-line tool (kavach_cli.py) both use these functions.
"""
import io
import json
import time

import pandas as pd

from detector import full_analysis
from features import extract_features
from sms import MESSAGE_COLUMNS, check_message, flat_message_row

# The columns of every export, in order
COLUMNS = ["domain", "verdict", "final_score", "ml_probability", "nearest_genuine", "closeness_percent",
           "attack_type", "evidence", "reasons", "rule_score", "decided_by"]
FORMATS = {"csv": ("text/csv", "kavach_results.csv"),
           "json": ("application/json", "kavach_results.json"),
           "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "kavach_results.xlsx")}


def read_domains(data: bytes, filename: str) -> list:
    """Domains from a CSV with a 'domain' column, or a text file with one per line.
    Raises ValueError with a clear message if the file can't be used."""
    if filename.lower().endswith(".csv"):
        try:
            df = pd.read_csv(io.BytesIO(data), dtype=str, encoding="utf-8-sig")
        except (ValueError, pd.errors.ParserError, pd.errors.EmptyDataError) as err:
            raise ValueError(f"Could not read this CSV file: {err}") from err
        if "domain" not in df.columns:
            raise ValueError("Could not find a column named 'domain' in this CSV.")
        domains = df["domain"].dropna().astype(str).tolist()
    else:
        lines = data.decode("utf-8-sig", errors="replace").splitlines()
        domains = [line for line in lines if not line.strip().startswith("#")]
    domains = [d.strip() for d in domains if d.strip()]
    if not domains:
        raise ValueError("No domains found in this file.")
    return domains


def read_messages(data: bytes, filename: str) -> list:
    """Messages from a CSV with a 'message' column, or a text file with one message per line."""
    if filename.lower().endswith(".csv"):
        try:
            df = pd.read_csv(io.BytesIO(data), dtype=str, encoding="utf-8-sig")
        except (ValueError, pd.errors.ParserError, pd.errors.EmptyDataError) as err:
            raise ValueError(f"Could not read this CSV file: {err}") from err
        if "message" not in df.columns:
            raise ValueError("Could not find a column named 'message' in this CSV.")
        rows = df["message"].dropna().astype(str).tolist()
        senders = df["sender"].fillna("").astype(str).tolist() if "sender" in df.columns else [""] * len(rows)
    else:
        rows = data.decode("utf-8-sig", errors="replace").splitlines()
        senders = [""] * len(rows)
    pairs = [(m.strip(), s.strip()) for m, s in zip(rows, senders) if m.strip()]
    if not pairs:
        raise ValueError("No messages found in this file.")
    return pairs


def check_messages(pairs: list, bundle) -> tuple:
    """Check a list of (message, sender). Returns (rows, seconds taken)."""
    started = time.perf_counter()
    rows = [flat_message_row(check_message(text, sender, bundle)) for text, sender in pairs]
    return rows, time.perf_counter() - started


def flat_row(r: dict) -> dict:
    """One full_analysis() result as one flat row, ready for a table or an export."""
    ev = r["evidence"]
    return {"domain": r["url"], "verdict": r["verdict"], "final_score": r["score"],
            "ml_probability": r["ml_probability"], "nearest_genuine": ev["nearest_genuine"],
            "closeness_percent": ev["closeness"], "attack_type": ev["attack_type"],
            "evidence": "; ".join(ev["edits"]), "reasons": r["reasons"],
            "rule_score": r["rule_score"], "decided_by": r["decided_by"]}


def check_many(domains: list, bundle) -> tuple:
    """Check a list of domains. Returns (rows, seconds taken).
    The model scores the whole list in one call, which is much faster than one domain at a time."""
    started = time.perf_counter()
    if bundle is None:
        probabilities = [None] * len(domains)
    else:
        table = pd.DataFrame([extract_features(d) for d in domains], columns=bundle["features"])
        model = bundle["model"]
        probabilities = model.predict_proba(table)[:, list(model.classes_).index(1)]
    rows = [flat_row(full_analysis(d, bundle, proba=p)) for d, p in zip(domains, probabilities)]
    return rows, time.perf_counter() - started


def speed(count: int, seconds: float) -> tuple:
    """Returns (milliseconds per domain, domains per second)."""
    return seconds / count * 1000, count / seconds


def _safe_cell(value):
    """Excel runs a cell starting with = + - @ as a formula, and domains in a list can be anything
    (=cmd|'/c calc'!A1), so make sure a spreadsheet shows them as plain text."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def _safe_table(rows: list, columns=None) -> pd.DataFrame:
    table = pd.DataFrame(rows, columns=columns or COLUMNS)
    for column in table.columns:
        table[column] = table[column].map(_safe_cell)
    return table


def to_csv(rows: list, columns=None) -> bytes:
    # the BOM lets Excel read Cyrillic
    return _safe_table(rows, columns).to_csv(index=False).encode("utf-8-sig")


def to_json(rows: list, columns=None) -> bytes:
    return json.dumps(rows, indent=2, ensure_ascii=False, default=float).encode("utf-8")


def to_xlsx(rows: list, columns=None) -> bytes:
    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        _safe_table(rows, columns).to_excel(writer, index=False, sheet_name="Kavach results")
        sheet = writer.sheets["Kavach results"]
        sheet.freeze_panes = "A2"
        for cells in sheet.columns:  # wide enough to read, without one long cell taking over
            longest = max(len(str(c.value)) for c in cells if c.value is not None)
            sheet.column_dimensions[cells[0].column_letter].width = min(longest + 2, 60)
    return buffer.getvalue()


EXPORTERS = {"csv": to_csv, "json": to_json, "xlsx": to_xlsx}
