#!/usr/bin/env python3

# Called from OpenDNSSEC when DS records need to be added to or removed from a
# reverse DNS zone managed by APNIC.  Tries to use the APNIC Services API for
# the operation.  Formats the key for manual handling if that fails.

import base64
import hashlib
import ipaddress
import json
import requests
import struct
import sys

# APNIC Services API.
# XXX: Is this documented somewhere public yet?
# See email from TomH on 2024-02-25 for docs.
try:
    with open("apnic.secret") as f:
        account, apikey = f.read().rstrip().split(":")
except:
    sys.exit("couldn't read secrets from apnic.secret")
endpoint = "https://registry-api.apnic.net/v1/" + account
headers = {"Authorization": "Bearer " + apikey}


# OpenDNSSEC knows about domains.  The APNIC API wants prefixes.
# XXX: This is ugly and fragile.
def domain_to_prefix(domain: str) -> str:
    if domain.endswith(".in-addr.arpa."):
        p = ".".join(reversed(domain[0:-14].split(".")))
        bits = p.count(".") * 8 + 8
        while p.count(".") < 3:
            p += ".0"
        p += f"/{bits}"
        return p
    elif domain.endswith(".ip6.arpa."):
        p = domain
        p = [p[i] for i in range(len(p) - 10, -1, -1) if p[i] != "."]
        bits = len(p) * 4
        while len(p) % 4:
            p.append("0")
        p = ["".join(p[i : i + 4]) for i in range(0, len(p), 4)]
        p = ":".join(p)
        p += f"::/{bits}"
        p = ipaddress.ip_network(p).compressed
        return p
    else:
        raise SyntaxError("Couldn't determine address family")


# OpenDNSSEC feeds us a DNSKEY on stdin.  Calculate the bits we need to
# construct a DS record from that.  Assume we will always get a KSK.
def _parse_stdin() -> dict:
    d = dict(
        zip(
            [
                "domain",
                "ttl",
                "class",
                "type",
                "flags",
                "proto",
                "algo",
                "pubkey",
            ],
            [
                int(v) if v.isdigit() else v
                for v in sys.stdin.readline().rstrip().split()
            ],
        )
    )

    # Need the domain ("owner") in wire-format for the digest.
    # Assume OpenDNSSEC will give us a trailing dot.
    owner = b""
    for i in d["domain"].split("."):
        owner += struct.pack("B", len(i)) + i.encode("ascii")

    # Need the rdata for the keytag and the digest.
    rdata = struct.pack("!HBB", d["flags"], d["proto"], d["algo"])
    rdata += base64.b64decode(d["pubkey"])

    # From RFC 4034 Appendix B.
    ac = 0
    for i in range(len(rdata)):
        k = struct.unpack("B", rdata[i : i + 1])[0]
        if (i % 2) == 0:
            ac += k << 8
        else:
            ac += k
    d["keytag"] = ((ac & 0xFFFF) + (ac >> 16)) & 0xFFFF

    # Only bother with SHA-256.
    d["digesttype"] = 2
    m = hashlib.sha256()
    m.update(owner)
    m.update(rdata)
    d["digest"] = m.hexdigest()

    return d


# Action is our first command line argument.
action = sys.argv[1]
if action not in ["submit", "retract"]:
    print("Usage: " + sys.argv[0] + " <submit | retract>")
    print("Takes a DNSKEY on stdin.")
    exit()

# We get a DNSKEY record on stdin.
d = _parse_stdin()

# The APNIC Services API operates on prefixes, not domains.
prefix = domain_to_prefix(d["domain"])

print("Trying APNIC Services API for " + d["domain"])

url = endpoint + "/rdns/" + prefix
try:
    r = requests.get(url, headers=headers)
    r.raise_for_status()
    keys = r.json()
except requests.exceptions.HTTPError as e:
    print(json.dumps(e.response.json(), indent=4))
    print(json.dumps(d, indent=4))
    sys.exit(1)
except:
    print(">>> Unknown error.")
    json.dumps(d, indent=4)
    sys.exit(1)

#
# XXX Untested with multiple RDNS records for a prefix.  Check with Tom if this
# is correct.  Or find a way to test it.  Is there a spare /23 for science? :-)
#
# For IPv6, this is probably correct, and there shouldn't be multiple RDNS
# records for a prefix.  For IPv4, do we need to search for the containing
# prefix?  It would be nice if the APNIC API could give us domains. ;-)
#

# Find the rdns-record that belongs to our prefix.
record = None
for r in keys["_embedded"]["rdns-record"]:
    if r["range"] == prefix:
        record = r
if record == None:
    print(">>> Couldn't find rdns-record matching prefix.")
    json.dumps(d, indent=4)
    sys.exit(1)

# Check if the DS record is already known to APNIC.
rdata = None
for ds in record["ds_rdatas"]:
    if ds.startswith(str(d["keytag"])):
        rdata = ds


if action == "submit":
    if rdata != None:
        print("Found existing matching key.")
        print("No action needed.")
        sys.exit(0)

    # Construct a DS record from our parsed DNSKEY.
    ds = f"{d['keytag']} {d['algo']} {d['digesttype']} {d['digest']}"

    # Append our DS record to the the rdns-record we have.
    data = {}
    data["update"] = []
    data["update"].append(record)
    record["ds_rdatas"].append(ds)

    url = endpoint + "/rdns"
    try:
        r = requests.post(url, headers=headers, json=data)
        r.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(">>> HTTP error.")
        print(r.status_code)
        print(json.dumps(d, indent=4))
        sys.exit(1)
    except:
        print(">>> Unknown error.")
        print(json.dumps(d, indent=4))
        sys.exit(1)

    print(f">>> DS record for key tag {d['keytag']} submitted.")
    print(json.dumps(r.json(), indent=4))
    sys.exit(0)


if action == "retract":
    if rdata == None:
        print("No matching key found.")
        print("No action needed.")
        sys.exit(0)

    # Remove the DS record to retract from the record.
    ds = record["ds_rdatas"]
    newds = filter(lambda r: not r.startswith(str(d["keytag"])), ds)
    record["ds_rdatas"] = list(newds)

    data = {}
    data["update"] = []
    data["update"].append(record)

    url = endpoint + "/rdns"
    try:
        r = requests.post(url, headers=headers, json=data)
        r.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(">>> HTTP error.")
        print(r.status_code)
        print(json.dumps(d, indent=4))
        sys.exit(1)
    except:
        print(">>> Unknown error.")
        print(json.dumps(d, indent=4))
        sys.exit(1)

    print(f">>> DS record for key tag {d['keytag']} retracted.")
    print(json.dumps(r.json(), indent=4))
    sys.exit(0)

exit(0)
