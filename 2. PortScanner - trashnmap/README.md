# PortScanner (Java)
NOTE: The same port scanner is in the blue team tool portfolio. The reason i reuploaded it here is the exact same tool can be used for red team activities

I made a very, very  ancient version of nmap its just a simple TCP connect scan tool. Given a host and a port range it tries to
open a connection to each port and reports which ones respond. It a very flimsy tool at that point just use Nmap this is just a tool i made for my portfolio c:

## How it works

For each port in the range, the scanner tries to open a `Socket` connection
with a short timeout:

- **Connects successfully** → port is OPEN
- **Connection refused** → port is CLOSED
- **Times out** (no response at all) → treated as closed/filtered (likely a firewall silently dropping the attempt)

That's the whole algorithm — a loop, a socket connection attempt, and a
timeout. No external libraries.

## Usage

```bash
javac PortScanner.java
java PortScanner <host> <startPort> <endPort>
```

Example:
```bash
java PortScanner scanme.nmap.org 20 100
```

"scanme.nmap.org" is a host the Nmap project specifically set up to be
safely and legally scanned for testing tools like this one — a good default
target while you're experimenting.

## Sample output

```
Scanning scanme.nmap.org from port 20 to 100 ...

Port 22 -- OPEN
Port 80 -- OPEN

------------------------------------------------------------
Scan complete.
  ports scanned : 81
  open ports    : 2
  time taken    : 4.2s
------------------------------------------------------------
```

## A note on legality

Only scan hosts you own or have explicit permission to test
("scanme.nmap.org" is the one public exception, set up for exactly this
purpose). Port scanning systems you don't have permission for can be
illegal depending on jurisdiction, even if no damage is done. It is the same stuff as nmap.
if you point my tool at lets say mnemonic you will get a knock on your door... 


## License

MIT
