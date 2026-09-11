#!/usr/bin/env python3
"""Regenerates internal/scanner/data/oui.json from the official IEEE MA-L
(24-bit MAC block) public registry.

Usage:
    python3 scripts/update-oui.py
"""
import csv
import json
import os
import urllib.request

SOURCE_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUT_PATH = os.path.join(
    os.path.dirname(__file__), "..", "internal", "scanner", "data", "oui.json"
)


def main() -> None:
    with urllib.request.urlopen(SOURCE_URL, timeout=30) as resp:
        text = resp.read().decode("utf-8")

    out = {}
    reader = csv.DictReader(text.splitlines())
    for row in reader:
        if row.get("Registry") != "MA-L":
            continue
        prefix = row["Assignment"].strip().upper()
        name = row["Organization Name"].strip()
        if len(prefix) == 6 and name:
            out[prefix] = name

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    print(f"wrote {len(out)} OUI entries to {OUT_PATH}")


if __name__ == "__main__":
    main()
