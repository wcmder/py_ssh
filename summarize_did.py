#!/usr/bin/env python3
"""
Summarize phone DID list (xxx-yyy-nnnn) from an Excel file into ranges.

Input:
  - Excel file containing DIDs in Column A (default), format xxx-yyy-nnnn

Output:
  - Excel file with two sheets:
      1) Ranges: per-prefix contiguous ranges
      2) Summary: per-prefix combined ranges string

Usage examples:
  python summarize_did.py input.xlsx
  python summarize_did.py input.xlsx -o did_ranges.xlsx
  python summarize_did.py input.xlsx --sheet "Sheet1" --column A
"""

import argparse
import sys
import re
from collections import defaultdict
from typing import Dict, List, Tuple

import pandas as pd


DID_RE = re.compile(r"^\s*(\d{3})[- ]?(\d{3})[- ]?(\d{4})\s*$")

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Summarize DIDs into contiguous ranges by prefix (xxx-yyy).")
    p.add_argument("input", help="Path to input Excel file")
    p.add_argument("-o", "--output", default="did_ranges.xlsx", help="Path to output Excel file (default: did_ranges.xlsx)")
    p.add_argument("--sheet", default=None, help="Worksheet name to read (default: first sheet)")
    p.add_argument("--column", default="A",
                   help="Column to read (letter like 'A' or header name). Default: A")
    return p.parse_args()

def excel_col_to_index(col: str) -> int:
    """Convert Excel column letter(s) to zero-based index (A -> 0)."""
    col = col.strip()
    if col.isdigit():
        # If user passed a number, treat as 0-based index
        return int(col)
    # Letters
    col = col.upper()
    idx = 0
    for ch in col:
        if not ('A' <= ch <= 'Z'):
            raise ValueError(f"Invalid column specifier: {col}")
        idx = idx * 26 + (ord(ch) - ord('A') + 1)
    return idx - 1

def read_dids(path: str, sheet: str | None, column: str) -> List[str]:
    # Read excel
    df = pd.read_excel(path, sheet_name=sheet, dtype=str, header=0)  # try with header first
    # If column looks like a letter and doesn't exist, fall back to index
    if column in df.columns:
        series = df[column]
    else:
        try:
            col_idx = excel_col_to_index(column)
        except Exception:
            # If not a letter/number, assume header that isn't present; try first column
            col_idx = 0
        # If reading with header failed to expose correct column, try without header
        try:
            series = df.iloc[:, col_idx]
        except Exception:
            # Try reload without header
            df2 = pd.read_excel(path, sheet_name=sheet, dtype=str, header=None)
            series = df2.iloc[:, col_idx]
    return [str(x) for x in series.dropna().tolist()]

def normalize_and_group(dids: List[str]) -> Tuple[Dict[str, List[int]], List[str]]:
    """
    Returns:
      - groups: { 'xxx-yyy': sorted unique [nnnn ints] }
      - bad_rows: list of original strings that failed to parse
    """
    groups: Dict[str, List[int]] = defaultdict(list)
    bad_rows: List[str] = []
    seen_per_group: Dict[str, set] = defaultdict(set)

    for raw in dids:
        m = DID_RE.match(raw)
        if not m:
            bad_rows.append(raw)
            continue
        a, b, c = m.groups()
        prefix = f"{a}-{b}"
        n = int(c)
        if n not in seen_per_group[prefix]:
            groups[prefix].append(n)
            seen_per_group[prefix].add(n)

    # sort each group's numbers
    for k in groups:
        groups[k].sort()
    return groups, bad_rows

def ranges_from_sorted(nums: List[int]) -> List[Tuple[int, int]]:
    """
    Given sorted unique integers, return list of (start, end) contiguous ranges.
    """
    if not nums:
        return []
    out: List[Tuple[int, int]] = []
    start = prev = nums[0]
    for x in nums[1:]:
        if x == prev + 1:
            prev = x
            continue
        # gap -> close range
        out.append((start, prev))
        start = prev = x
    out.append((start, prev))
    return out

def format_range(start: int, end: int) -> str:
    return f"{start:04d} to {end:04d}"

def build_outputs(groups: Dict[str, List[int]]) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Returns:
      - df_ranges: columns [prefix, start, end, formatted]
      - df_summary: columns [prefix, ranges]
    """
    rows_ranges = []
    rows_summary = []

    for prefix in sorted(groups.keys()):
        rlist = ranges_from_sorted(groups[prefix])
        # Ranges sheet rows
        for (s, e) in rlist:
            rows_ranges.append({
                "prefix": prefix,
                "start": f"{s:04d}",
                "end": f"{e:04d}",
                "formatted": f"{prefix}-({format_range(s, e)})",
            })
        # Summary combined string
        combined = ", ".join([f"({format_range(s, e)})" for (s, e) in rlist])
        rows_summary.append({
            "prefix": prefix,
            "ranges": f"{prefix}-{combined}" if combined else f"{prefix}-()"
        })

    df_ranges = pd.DataFrame(rows_ranges, columns=["prefix", "start", "end", "formatted"])
    df_summary = pd.DataFrame(rows_summary, columns=["prefix", "ranges"])
    return df_ranges, df_summary

def main():
    args = parse_args()
    dids = read_dids(args.input, args.sheet, args.column)
    groups, bad = normalize_and_group(dids)
    df_ranges, df_summary = build_outputs(groups)

    with pd.ExcelWriter(args.output, engine="openpyxl") as xw:
        df_ranges.to_excel(xw, sheet_name="Ranges", index=False)
        df_summary.to_excel(xw, sheet_name="Summary", index=False)

        # Add a small note sheet if there were bad rows
        if bad:
            pd.DataFrame({"unparsed_rows": bad}).to_excel(xw, sheet_name="Unparsed", index=False)

    # Console summary
    print(f"Wrote: {args.output}")
    print(f"Prefixes found: {len(groups)}")
    total_dids = sum(len(v) for v in groups.values())
    print(f"Unique DIDs processed: {total_dids}")
    if bad:
        print(f"Unparsed rows: {len(bad)} (see 'Unparsed' sheet)")

if __name__ == "__main__":
    main()