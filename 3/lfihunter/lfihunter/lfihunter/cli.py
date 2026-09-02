"""
This is the entry point of lfihunter, the file that actually runs when
you type "python -m lfihunter.cli ...". Its job is simple: read the
command-line flags the user typed, then call the real logic that lives
in scanner.py, reporter.py, and exporter.py.

Think of this file as the conductor. It doesn't do any scanning or
printing itself, it just reads what the user asked for and hands the
work off to the right place.

Usage:
    python -m lfihunter.cli --url "http://target/index.php?page=FUZZ"
    python -m lfihunter.cli --url "http://target/index.php?page=FUZZ" --category wrapper
    python -m lfihunter.cli --url "http://target/index.php?page=FUZZ" --json out.json --csv out.csv
"""

from __future__ import annotations

import argparse
import sys

from .exporter import export_csv, export_json
from .payloads import PAYLOADS
from .reporter import print_banner, print_finding, print_summary
from .scanner import FUZZ_MARKER, scan


def build_arg_parser() -> argparse.ArgumentParser:
    """
    Sets up every command-line flag lfihunter understands. argparse is a
    built-in Python module that handles reading things like --url and
    --category from the command line for us, including printing a
    helpful error message automatically if the user gets something
    wrong (like forgetting a required flag).
    """
    p = argparse.ArgumentParser(
        prog="lfihunter",
        description=f"LFI and path traversal fuzzer. The URL must contain the literal marker {FUZZ_MARKER}.",
    )

    # required=True means the program will refuse to run at all if this
    # flag is missing, since there's genuinely nothing useful we could
    # do without a target URL.
    p.add_argument("--url", required=True, help=f"Target URL containing the literal marker {FUZZ_MARKER}")

    # type=float means argparse automatically converts whatever text the
    # user types (like "5.0") into an actual float value we can use in
    # calculations, rather than leaving it as a plain string.
    p.add_argument("--timeout", type=float, default=5.0, help="Per-request timeout in seconds (default: 5.0)")

    # choices=[...] restricts this flag to only these three exact values.
    # If someone types --category banana, argparse rejects it
    # automatically with a clear error message, we don't have to check
    # that ourselves.
    p.add_argument("--category", choices=["traversal", "bypass", "wrapper"], help="Only send payloads from this category")

    p.add_argument("--json", metavar="PATH", help="Export findings to a JSON file")
    p.add_argument("--csv", metavar="PATH", help="Export findings to a CSV file")

    # action="store_true" means this is a simple on/off flag with no
    # value attached. If --quiet is present on the command line, quiet
    # becomes True. If it's absent, it defaults to False.
    p.add_argument("--quiet", action="store_true", help="Suppress the banner")

    return p


def run(argv: list[str] | None = None) -> int:
    """
    The actual entry point. Returns an integer exit code: 0 means
    success, 1 means something went wrong. This matters if lfihunter is
    ever called from a script that checks whether it succeeded or not.
    """
    args = build_arg_parser().parse_args(argv)

    # We double-check the FUZZ marker is present here too, even though
    # scan() also checks it. Doing it here lets us print a friendlier,
    # more specific error message with an example, before we've even
    # started trying to build the payload list.
    if FUZZ_MARKER not in args.url:
        print(f"Error: URL must contain the literal marker '{FUZZ_MARKER}' where the payload should go.", file=sys.stderr)
        print(f'Example: --url "http://target/index.php?page={FUZZ_MARKER}"', file=sys.stderr)
        return 1

    if not args.quiet:
        print_banner()
        print(f"target={args.url}  payloads={len(PAYLOADS)}\n")

    # By default we use every payload we have. If the user passed
    # --category, we filter the list down to only payloads matching
    # that category using a list comprehension: "give me every payload p
    # from PAYLOADS, but only keep it if p.category matches what the
    # user asked for."
    payload_list = PAYLOADS
    if args.category:
        payload_list = [p for p in PAYLOADS if p.category == args.category]

    summary = scan(args.url, timeout=args.timeout, payloads=payload_list)

    for finding in summary.findings:
        print_finding(finding)

    print_summary(summary)

    # These are optional, only run if the user actually asked for an
    # export by passing --json or --csv. args.json is None if the flag
    # wasn't used, and "if args.json:" treats None as falsy, so this
    # block gets skipped entirely when the flag is absent.
    if args.json:
        export_json(summary, args.json)
        print(f"Wrote JSON export -> {args.json}")
    if args.csv:
        export_csv(summary, args.csv)
        print(f"Wrote CSV export -> {args.csv}")

    return 0


if __name__ == "__main__":
    sys.exit(run())
