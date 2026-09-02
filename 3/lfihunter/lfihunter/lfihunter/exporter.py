"""
This file handles saving scan results to a file on disk, either as JSON
or CSV, so results can be looked at later or attached to a report instead
of only existing as terminal output.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from .scanner import ScanSummary


def export_json(summary: ScanSummary, path: str) -> None:
    """
    Writes the scan results out as a JSON file.

    We build a plain Python dictionary first (data), then hand it to
    json.dumps() which turns it into JSON text. indent=2 just makes the
    output file nicely formatted and readable instead of one giant
    single line.
    """
    data = {
        "total_sent": summary.total_sent,
        "errors": summary.errors,
        # This is a list comprehension: for every Finding object (f) in
        # summary.findings, build a small dictionary describing it, and
        # collect all of those dictionaries into one list. It's the same
        # as writing a for loop that appends to an empty list, just more
        # compact.
        "findings": [
            {
                "target": f.payload.target,
                "category": f.payload.category,
                "payload": f.payload.value,
                "url": f.url_used,
                "status_code": f.status_code,
                "snippet": f.response_snippet,
            }
            for f in summary.findings
        ],
    }

    # Path(path) turns the string path into a Path object, which gives
    # us the convenient .write_text() method. json.dumps() converts our
    # Python dictionary into an actual JSON-formatted string.
    Path(path).write_text(json.dumps(data, indent=2))


def export_csv(summary: ScanSummary, path: str) -> None:
    """
    Writes the scan results out as a CSV file, one row per finding.
    """


    fieldnames = ["target", "category", "payload", "url", "status_code", "snippet"]

    # newline="" here is a small Python-specific quirk: without it, the
    # csv module can end up writing an extra blank line between rows on
    # some operating systems. This avoids that.
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)

        # writeheader() writes the very first row: the column names
        # themselves, so the CSV file makes sense when opened later.
        writer.writeheader()

        for finding in summary.findings:
            # writerow() takes a dictionary and writes it as one line in
            # the CSV, matching each key in the dictionary to the
            # correct column based on fieldnames above.
            writer.writerow({
                "target": finding.payload.target,
                "category": finding.payload.category,
                "payload": finding.payload.value,
                "url": finding.url_used,
                "status_code": finding.status_code,
                "snippet": finding.response_snippet,
            })
