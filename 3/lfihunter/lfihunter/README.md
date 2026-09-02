# lfihunter

An LFI / path traversal fuzzer. Point it at a parameter with a `FUZZ`
marker, and it throws a curated payload list at it. Traversal depths,
encoding and null byte bypasses, and PHP wrapper tricks. It confirms hits
by checking the response against known file signatures, not just
guessing from status codes.

## How it works

The target URL needs the literal marker `FUZZ` somewhere in it, typically
in the vulnerable parameter's value:

```
http://target/index.php?page=FUZZ
```

For every payload in the list, `FUZZ` gets swapped for that payload's
value, the request goes out, and the response is checked against an
expected signature. For example `root:` for `/etc/passwd`, `[extensions]`
for `win.ini`. A status code alone isn't enough to confirm a hit, since
plenty of apps return `200 OK` for their own error pages too, so every
payload is paired with something that should only appear in the real
file's contents.

### Payload categories

- **`traversal`**: plain `../` sequences at multiple depths (1 through
  10). The correct depth needed depends on how deeply nested the
  vulnerable parameter's base directory is, which isn't knowable ahead
  of time.
- **`bypass`**: filter evasion tricks. Double dot bypass (`....//`),
  single/double URL encoding, null byte truncation (`%00`, a legacy PHP
  quirk), and backslash style traversal for Windows targets.
- **`wrapper`**: PHP stream wrapper abuse, specifically
  `php://filter/convert.base64-encode/resource=X` for source code
  disclosure. This is a very common HTB box technique: LFI alone might
  not show `.php` file contents since the server executes them, but
  wrapping the read in a base64 filter dumps the raw source instead of
  running it. Detected using a base64 blob heuristic rather than a fixed
  string, since the encoded output obviously doesn't contain one literal
  signature.

## Usage

```bash
python -m lfihunter.cli --url "http://target/index.php?page=FUZZ"

# Only run one category of payloads
python -m lfihunter.cli --url "http://target/index.php?page=FUZZ" --category wrapper

# Export findings
python -m lfihunter.cli --url "http://target/index.php?page=FUZZ" --json out.json --csv out.csv
```

## Sample output

```
[HIT] /etc/passwd (Linux)
      payload : ../../../../etc/passwd
      url     : http://target/index.php?page=../../../../etc/passwd
      status  : 200
      snippet : root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:...

------------------------------------------------------------
Summary
  payloads sent : 53
  confirmed hits: 1
  request errors: 0
------------------------------------------------------------
```

## Testing it yourself

`test_server/vuln_server.py` is a small, deliberately vulnerable local
server used to validate lfihunter during development. It simulates a
classic `?page=` LFI against a fake in-memory filesystem (no real system
files touched) and a `php://filter` style base64 wrapper. Run it and
point lfihunter at it to see the tool work end to end without needing a
real target:

```bash
python3 test_server/vuln_server.py &
python -m lfihunter.cli --url "http://127.0.0.1:8877/index.php?page=FUZZ"
```

This is also how the tool was actually verified during development.
Tested against both this deliberately vulnerable server (48/53 payloads
correctly flagged) and a genuinely safe server serving a static page
(0/53 false positives).

## Project structure

```
lfihunter/
├── lfihunter/
│   ├── payloads.py    # payload list and expected signatures per target file
│   ├── scanner.py     # core request/detection logic
│   ├── reporter.py    # colored terminal output
│   ├── exporter.py    # JSON/CSV export
│   └── cli.py          # argument parsing and orchestration
├── test_server/
│   └── vuln_server.py # deliberately vulnerable local server, for testing
└── tests/
    └── test_scanner.py
```

Every file in `lfihunter/` is commented heavily, line by line in most
places, since the goal was to actually understand every part of it, not
just have it work.

## Running tests

```bash
python tests/test_scanner.py
```

## A note on legality

This is an active exploitation tool, not a passive scanner. It sends
traversal and wrapper payloads intended to pull real file contents off a
target. Only run this against systems you own or have explicit written
permission to test: HTB boxes, CTF targets, your own lab. Running this
against a target you don't have authorization for is unauthorized
computer access in most jurisdictions, regardless of intent.

## Why this exists

Built while working through HTB Academy's LFI module. Automates the
manual `../` fumbling and wrapper guessing into something that tries the
common variations in one pass, and confirms hits properly instead of
eyeballing responses. AI assisted build, understood and tested by me,
including building and running the vulnerable test server myself to
verify detection actually works.

## Ideas for extending it

- Auto detect the right traversal depth by probing with an unambiguous
  marker file first, instead of brute forcing every depth 1 through 10
- Add a `--wordlist` flag to load custom target files/payloads from an
  external file instead of the hardcoded list
- Log poisoning follow-through. If `/var/log/apache2/access.log` is
  readable, automatically attempt to poison it with a PHP payload via a
  crafted User-Agent, then include it via the same LFI to get code
  execution
- Support POST based fuzzing for parameters that aren't in the URL

## License

MIT
