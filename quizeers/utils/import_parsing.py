"""
Parsing logic for the admin "import questions" feature (JSON or CSV
payloads). Separated out because parsing/validation is a distinct concern
from the route that receives the HTTP request and flashes the result.
"""
import csv
import io
import json


def letter_for_correct_answer(form):
    """Accept either a letter (A-D) or the option's exact text in correct_answer."""
    raw = form["correct_answer"].strip()
    if raw.upper() in ("A", "B", "C", "D"):
        return raw.upper()

    for letter, field in zip("ABCD", ["option_a", "option_b", "option_c", "option_d"]):
        if form[field].strip() == raw:
            return letter

    raise ValueError("correct_answer must match one of the options, or be A/B/C/D")


def parse_import_payload(raw, fmt):
    if fmt == "csv":
        reader = csv.DictReader(io.StringIO(raw))
        rows = list(reader)
        required = {"question_text", "option_a", "option_b", "option_c", "option_d", "correct_answer"}
        for row in rows:
            missing = required - row.keys()
            if missing:
                raise ValueError(f"missing column(s): {', '.join(sorted(missing))}")
        return rows

    data = json.loads(raw)
    if not isinstance(data, list):
        raise ValueError("expected a JSON array of question objects")
    return data
