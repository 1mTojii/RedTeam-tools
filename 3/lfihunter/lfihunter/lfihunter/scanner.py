"""
This is the core of lfihunter. Everything else (the CLI, the reporter,
the exporter) is just wrapping around what happens in this file.

The basic idea, in plain English:
    1. Take a URL that has the word FUZZ somewhere in it.
    2. For every payload in our list, swap FUZZ for that payload's value
       and send the request.
    3. Look at what comes back. If it contains the signature we expect
       for that payload, record it as a hit.
    4. Move on to the next payload.

That's really it. There's no cleverness beyond "try things, check the
response." The only slightly fiddly part is handling the base64 wrapper
payloads differently, since their output doesn't have one fixed string
we can search for.
"""

from __future__ import annotations

import base64
import http.client
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .payloads import PAYLOADS, Payload

# This is the literal text we look for in the URL the user gives us. When
# we find it, we know that's the spot to substitute each payload into.
FUZZ_MARKER = "FUZZ"

# A regular expression that matches "only base64-looking characters".
# Base64 output only ever uses letters, digits, +, /, and = (for padding
# at the end), plus whitespace/newlines if the server wraps long lines.
# ^ and $ anchor the pattern to the start and end of the string, so this
# only matches if the ENTIRE string looks like base64, not just part of it.
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")


@dataclass
class Finding:
    """
    One confirmed hit. We keep the whole payload object (not just its
    name) so the reporter/exporter can show details like which category
    it belonged to.
    """
    payload: Payload
    url_used: str
    status_code: int
    response_snippet: str


@dataclass
class ScanSummary:
    """
    The overall result of a full scan run. total_sent counts every
    payload we tried, findings is the list of confirmed hits, and errors
    counts requests that failed for network reasons (timeout, connection
    refused, and so on) rather than failing to match a signature.
    """
    total_sent: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: int = 0


def _looks_like_base64_blob(text: str, min_len: int = 40) -> bool:
    """
    A rough guess at "does this response look like raw base64 output".

    We use this specifically for the php://filter payloads, since their
    output changes every time (it depends on the actual source code of
    the file being read) so there's no single fixed string we can search
    for like we do with /etc/passwd's "root:".

    Two checks happen here:
      1. Is the string at least min_len characters long? A tiny string
         is probably just a short error message, not real base64 output.
      2. Does the string contain "<" or ">"? If so, it's probably still
         an HTML error page, not raw base64 text, so we reject it.
    """
    stripped = text.strip()

    if len(stripped) < min_len:
        return False

    if "<" in stripped or ">" in stripped:
        return False

    # .match() checks the string against our base64 regular expression
    # from the start. bool(...) turns the match object (or None) into a
    # plain True/False.
    return bool(_BASE64_RE.match(stripped))


def scan(url_template: str, timeout: float = 5.0, payloads: list[Payload] | None = None) -> ScanSummary:
    """
    Runs every payload against url_template and returns a ScanSummary.

    url_template must contain the literal text FUZZ somewhere in it,
    e.g. "http://target/index.php?page=FUZZ". We check for that up front
    and raise an error immediately if it's missing, rather than silently
    sending the same unmodified URL over and over.
    """
    if FUZZ_MARKER not in url_template:
        raise ValueError(f"URL template must contain the literal marker '{FUZZ_MARKER}'")

    # If the caller didn't pass in a specific payload list (used by the
    # --category flag to filter down to just one category), we default
    # to using every payload we have.
    payload_list = payloads if payloads is not None else PAYLOADS

    summary = ScanSummary()

    # This is the main loop. We go through every payload one at a time,
    # send a request, and check the result. There's no threading or
    # concurrency here (unlike pyscan's port scanner), so this runs one
    # request after another, which is slower but simpler to follow.
    for payload in payload_list:
        # .replace() here does the actual substitution: it finds the
        # literal text "FUZZ" in the URL and swaps it for this payload's
        # value. Example: "http://target/?page=FUZZ" with payload.value
        # of "../../etc/passwd" becomes
        # "http://target/?page=../../etc/passwd"
        target_url = url_template.replace(FUZZ_MARKER, payload.value)

        summary.total_sent += 1

        # Everything from here down is wrapped in try/except because
        # network requests can fail in a bunch of ways that have nothing
        # to do with our payload being right or wrong: the server might
        # be down, the connection might time out, the URL might end up
        # malformed after substitution, and so on. We want the scan to
        # keep going even if one single request fails, rather than
        # crashing the whole program.
        try:
            # We set a custom User-Agent just so it's obvious in server
            # logs that this traffic came from lfihunter, rather than
            # looking like a normal browser request.
            req = urllib.request.Request(target_url, headers={"User-Agent": "lfihunter/1.0"})

            # urlopen() actually sends the request and waits for a
            # response. The "with" block makes sure the connection gets
            # closed properly once we're done reading it, even if
            # something goes wrong inside the block.
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                # We only read the first 8192 bytes (8 KB) of the
                # response. We don't need the whole page, just enough to
                # search for our signature. This also protects us from
                # a target that returns a huge response and slows the
                # scan down for no reason.
                body = resp.read(8192).decode(errors="replace")

        except urllib.error.HTTPError as e:
            # HTTPError happens when the server responds, but with an
            # error status code like 404 or 500. We still want to look
            # at the body of that response though, since some LFI bugs
            # actually show file contents even on a "404" page (some
            # frameworks return odd status codes for weird input).
            status = e.code
            try:
                body = e.read(8192).decode(errors="replace")
            except Exception:
                body = ""

        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
            # This covers actual network failures: the host doesn't
            # exist, the connection timed out, the connection was
            # refused, or the URL ended up malformed after we substituted
            # the payload into it (this can happen with some of the
            # encoding-bypass payloads). In all of these cases, we just
            # count it as an error and move on to the next payload
            # rather than stopping the whole scan.
            summary.errors += 1
            continue

        # At this point we successfully got a response (status + body),
        # whether it was a clean 200 or an error page, so now we check
        # whether it actually matches what we were looking for.
        hit = False

        if payload.signature == "__BASE64_LIKELY__":
            # This is the special case for php://filter payloads,
            # explained in payloads.py. Instead of searching for a fixed
            # string, we check if the whole response looks like base64.
            if _looks_like_base64_blob(body):
                hit = True
        elif payload.signature.lower() in body.lower():
            # For every normal payload, this is the actual detection
            # logic: does our expected signature appear anywhere in the
            # response body? We lowercase both sides first so that
            # capitalization differences (like "ROOT:" vs "root:") don't
            # cause us to miss a real hit.
            hit = True

        if hit:
            # We only keep a short snippet of the response (200
            # characters), not the whole thing, since that's plenty to
            # show the user what we found without flooding the terminal.
            # We also strip out newlines so it prints on one line.
            snippet = body[:200].replace("\n", " ").replace("\r", "")
            summary.findings.append(Finding(
                payload=payload,
                url_used=target_url,
                status_code=status,
                response_snippet=snippet,
            ))

    return summary
