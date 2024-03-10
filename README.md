# apnic-dnssec

Maintain RDNS DS records using the experimental APNIC API.

> [!WARNING]
> This has only seen very light testing.  Please read (and understand) the
> comments before putting this in production!

## Installation

Set up a new virtual environment and install dependencies:

```shell
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Configuration

Put authentication details in a file named `apnic.secret`:

MEMBER-ACCOUNT:TOKEN

## Example use

### Submit a DS record

```
echo 8.b.d.0.1.0.0.2.ip6.arpa. 86400 IN DNSKEY 257 3 13 H3UC/s7jy15fyddPD1/aDyaDwItIA0OIiqmo4z7q4hqf45dT8DGKm3Fv9XPoIncr3RuGLLpoNIwFV9xkG1k6dw== | python3 ./apnic-dnssec.py submit
Trying APNIC Services API for 8.b.d.0.1.0.0.2.ip6.arpa.
>>> DS record for key tag 43640 submitted.
{
    "location": "https://registry-api.apnic.net/v1/{mem-account}/task/{id}"
}
```

### Retract a DS record

```
echo 8.b.d.0.1.0.0.2.ip6.arpa. 86400 IN DNSKEY 257 3 13 H3UC/s7jy15fyddPD1/aDyaDwItIA0OIiqmo4z7q4hqf45dT8DGKm3Fv9XPoIncr3RuGLLpoNIwFV9xkG1k6dw== | python3 ./apnic-dnssec.py retract
Trying APNIC Services API for 8.b.d.0.1.0.0.2.ip6.arpa.
>>> DS record for key tag 43640 retracted.
{
    "location": "https://registry-api.apnic.net/v1/{mem-account}/task/{id}"
}
```
