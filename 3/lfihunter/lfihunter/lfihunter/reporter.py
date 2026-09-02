"""
This file only handles printing things to the terminal in a readable way.
None of the actual scanning logic lives here, it's purely presentation.
If you deleted this whole file and just used plain print() statements
everywhere else, the tool would still work exactly the same, it would
just look plainer.

The \033[...m codes you'll see below are called ANSI escape codes. They
are a special sequence of characters that most terminals understand as
"change the text color from here" rather than as literal text to print.
"""

from __future__ import annotations

from .scanner import Finding, ScanSummary

# Each of these is one ANSI escape code. RESET turns all styling back off,
# so we always print RESET after we're done with a colored bit of text,
# otherwise the color would "leak" into everything printed after it.
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
CYAN = "\033[36m"
RED = "\033[31m"

# Just a plain text banner printed at the start of a run, purely
# cosmetic, has zero effect on how the tool actually works.
BANNER = r"""
 _  __ _ _                 _
| |/ _(_) |__  _   _ _ __ | |_ ___ _ __
| | |_| | '_ \| | | | '_ \| __/ _ \ '__|
| |  _| | | | | |_| | | | | ||  __/ |
|_|_| |_|_| |_|\__,_|_| |_|\__\___|_|
        LFI / path traversal fuzzer
"""


def print_banner() -> None:
    print(f"{BOLD}{CYAN}{BANNER}{RESET}")


def print_finding(finding: Finding) -> None:
    """
    Prints one confirmed hit. We break it into a few lines so it's easy
    to read: which file we were targeting, exactly what payload string
    we used, the full URL that was actually requested, the HTTP status
    code, and a short piece of the response body as proof.
    """
    print(f"{GREEN}{BOLD}[HIT]{RESET} {finding.payload.target}")
    print(f"      {DIM}payload : {finding.payload.value}{RESET}")
    print(f"      {DIM}url     : {finding.url_used}{RESET}")
    print(f"      {DIM}status  : {finding.status_code}{RESET}")
    print(f"      {DIM}snippet : {finding.response_snippet}{RESET}\n")


def print_summary(summary: ScanSummary) -> None:
    """
    Prints the final tally after the scan finishes: how many payloads
    were sent, how many actually turned into confirmed hits, and how
    many requests failed outright due to network errors.
    """
    print(f"{DIM}{'-' * 60}{RESET}")
    print(f"{BOLD}Summary{RESET}")
    print(f"  payloads sent : {summary.total_sent}")
    print(f"  confirmed hits: {len(summary.findings)}")
    print(f"  request errors: {summary.errors}")
    print(f"{DIM}{'-' * 60}{RESET}")

    if not summary.findings:
        # Worth being explicit about this: a scan with zero hits does
        # not prove the target is safe. It only proves that none of the
        # specific payloads and target files we tried happened to work.
        # A different payload list, or a different vulnerable parameter
        # entirely, might still find something.
        print(f"{DIM}No confirmed hits. This does not mean the target is safe,{RESET}")
        print(f"{DIM}it just means this payload list and these target files did not work here.{RESET}")
