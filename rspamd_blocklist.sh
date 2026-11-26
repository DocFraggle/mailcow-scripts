#!/bin/bash

MAILCOW_DIR="/opt/mailcow-dockerized"

# Check if mailcow directory exists
if [ ! -f "$MAILCOW_DIR/mailcow.conf" ]; then
  echo "ERROR: mailcow.conf not found in $MAILCOW_DIR, did you install mailcow in a different directory? Please check MAILCOW_DIR in this script"
  exit 1
fi

BLOCKLIST_SRC="https://raw.githubusercontent.com/bitwire-it/ipblocklist/refs/heads/main/inbound.txt"
BLOCKLIST_DST="${MAILCOW_DIR}/data/conf/rspamd/local.d/ipblocklist.map"
BLOCKLIST_CFG="${MAILCOW_DIR}/data/conf/rspamd/override.d/multimap.conf"

# Allowlist: the outbound mail servers of these domains are never blocked, even if they show up
# in the blocklist (big providers get listed now and then because of abuse reports, and with
# action = reject that bounces legitimate mail). Their networks are taken from their SPF records.
ALLOWLIST_SPF_DOMAINS="web.de gmx.net gmx.de ionos.de 1und1.de kundenserver.de t-online.de gmail.com googlemail.com
  outlook.com hotmail.com icloud.com yahoo.com aol.com posteo.de mailbox.org freenet.de
  vodafone.de arcor.de ewe.net kabelmail.de gmx.at gmx.ch bluewin.ch protonmail.ch"
# Additional networks/IPs to allow (one per line or space separated, IPv4/IPv6, CIDR ok)
# 1&1 (web.de, GMX, IONOS) only lists a few current hosts via "a:mout.web.de" in SPF, and its
# forwarding servers (mout-xforward) are not in SPF at all, so allow their mail networks as a whole.
ALLOWLIST_EXTRA="
  212.227.15.0/24 212.227.17.0/24 212.227.24.0/24 212.227.126.0/24 217.72.192.0/24 82.165.159.0/24
  170.203.16.0/20
"
# Optional local allowlist file, one entry per line, '#' comments allowed
ALLOWLIST_FILE="$(dirname "$(readlink -f "$0")")/rspamd_blocklist_allow.txt"
# (170.203.16.0/20 = Klaviyo, sends newsletters for many shops)

# Create rspamd multimap config
read -r -d '' BLOCKLIST_CONTENT <<'CFG'
BAD_IPS {
  type = "ip";
  map = "/etc/rspamd/local.d/ipblocklist.map";
  action = "reject";
  symbol = "BAD_IPS";
  description = "Blocked sender IPs";
}
CFG

# Ensure override.d directory exists
mkdir -p "$(dirname "$BLOCKLIST_CFG")"

# Check if the file already contains the BAD_IPS block
if [ -f "$BLOCKLIST_CFG" ] && cmp -s <(echo "$BLOCKLIST_CONTENT") "$BLOCKLIST_CFG"; then
  echo "Blocklist config is up-to-date."
else
  echo "$BLOCKLIST_CONTENT" > "$BLOCKLIST_CFG"
  echo "Config updated."
fi

# Download blocklist into a temp file first, the live map is only replaced after all checks passed
TMP_DL=$(mktemp)
TMP_MAP=$(mktemp)
trap 'rm -f "$TMP_DL" "$TMP_MAP"' EXIT
if ! curl -sSf --max-time 300 -o "$TMP_DL" "$BLOCKLIST_SRC"; then
  echo "ERROR: Download of $BLOCKLIST_SRC failed, keeping the current blocklist"
  exit 1
fi

# Sanity checks
echo "Performing sanity checks"
echo "Counting lines of downloaded blocklist"
TOTAL_LINES=$(wc -l < "$TMP_DL")

if [ "$TOTAL_LINES" -lt 10 ]; then
  echo "ERROR: Blocklist file has fewer than 10 entries. Exiting."
  exit 1
else
  echo "Counted $TOTAL_LINES lines, looking good"
fi

# Regex for IPv4 and IPv6 (with optional CIDR)
# IPv4: 0-255.0-255.0-255.0-255(/0-32)
# IPv6: standard notation (/0-128)
IPV4_REGEX='^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$'
IPV6_REGEX='^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$'

# Check for invalid lines
echo "Checking for invalid IPv4 or IPv6 entries, could take a few seconds..."
INVALID_LINES=$(grep -Ev "($IPV4_REGEX)|($IPV6_REGEX)" "$TMP_DL")

if [ -n "$INVALID_LINES" ]; then
  echo "WARNING: Some lines do not look like valid IPv4 or IPv6 addresses/CIDRs:"
  echo "$INVALID_LINES"
  exit 1
else
  echo "All lines look like valid IPv4 or IPv6 addresses/CIDRs"
fi

# Remove allowlisted networks from the blocklist
echo "Removing allowlisted mail provider networks from the blocklist..."
ALLOW_FILE_CONTENT=""
[ -r "$ALLOWLIST_FILE" ] && ALLOW_FILE_CONTENT=$(sed 's/#.*//' "$ALLOWLIST_FILE")
if ! python3 - "$TMP_DL" "$TMP_MAP" "$ALLOWLIST_SPF_DOMAINS" "$ALLOWLIST_EXTRA $ALLOW_FILE_CONTENT" <<'PY'
import ipaddress
import subprocess
import sys

src, dst, spf_domains, extra = sys.argv[1:5]


def txt(name):
    out = subprocess.run(["dig", "+short", "+time=5", "+tries=2", "TXT", name],
                         capture_output=True, text=True).stdout
    return ["".join(part.strip('"') for part in line.split('" "')) for line in out.splitlines()]


def addrs(name):
    nets = []
    for rr in ("A", "AAAA"):
        out = subprocess.run(["dig", "+short", rr, name], capture_output=True, text=True).stdout
        for line in out.split():
            try:
                nets.append(ipaddress.ip_network(line))
            except ValueError:
                pass  # CNAME targets etc.
    return nets


def spf_networks(domain, depth=0, seen=None):
    """Networks from the SPF record of domain (ip4/ip6/a/include/redirect)."""
    seen = seen if seen is not None else set()
    if depth > 10 or domain in seen:
        return []
    seen.add(domain)
    nets = []
    for record in txt(domain):
        if not record.lower().startswith("v=spf1"):
            continue
        for term in record.split()[1:]:
            term = term.lstrip("+?~")
            low = term.lower()
            if term.startswith("-"):
                continue
            if low.startswith(("ip4:", "ip6:")):
                try:
                    nets.append(ipaddress.ip_network(term[4:], strict=False))
                except ValueError:
                    pass
            elif low.startswith("include:"):
                nets += spf_networks(term[8:], depth + 1, seen)
            elif low.startswith("redirect="):
                nets += spf_networks(term[9:], depth + 1, seen)
            elif low == "a" or low.startswith("a:"):
                nets += addrs(term[2:] if ":" in term else domain)
    return nets


allow = []
for domain in spf_domains.split():
    found = spf_networks(domain)
    if not found:
        print(f"  WARNING: no SPF networks found for {domain}")
    allow += found
for entry in extra.split():
    try:
        allow.append(ipaddress.ip_network(entry, strict=False))
    except ValueError:
        print(f"  WARNING: invalid allowlist entry {entry}")
if not allow:
    print("ERROR: allowlist is empty (DNS problem?)")
    sys.exit(1)
allow4 = list(ipaddress.collapse_addresses(n for n in allow if n.version == 4))
allow6 = list(ipaddress.collapse_addresses(n for n in allow if n.version == 6))
print(f"  Allowlist: {len(allow4)} IPv4 and {len(allow6)} IPv6 networks")

# Index allow networks by first IPv4 octet / first IPv6 hextet so that only candidate lines
# have to be parsed. Networks shorter than /8 (/16 for IPv6) go to the "wide" lists.
buckets4, wide4, buckets6, wide6 = {}, [], {}, []
for n in allow4:
    if n.prefixlen < 8:
        wide4.append(n)
    else:
        buckets4.setdefault(str(int(n.network_address) >> 24), []).append(n)
for n in allow6:
    if n.prefixlen < 16:
        wide6.append(n)
    else:
        buckets6.setdefault(int(n.network_address) >> 112, []).append(n)

removed = changed = 0
with open(src) as fin, open(dst, "w") as fout:
    for line in fin:
        entry = line.strip()
        if not entry:
            continue
        if ":" in entry:
            net = ipaddress.ip_network(entry, strict=False)
            cands = buckets6.get(int(net.network_address) >> 112, []) + wide6
        else:
            if not wide4 and "/" not in entry and entry.split(".", 1)[0] not in buckets4:
                fout.write(entry + "\n")
                continue
            net = ipaddress.ip_network(entry, strict=False)
            cands = buckets4.get(str(int(net.network_address) >> 24), []) + wide4
        hits = [a for a in cands if a.overlaps(net)]
        if not hits:
            fout.write(entry + "\n")
            continue
        if any(net.subnet_of(a) for a in hits):
            removed += 1
            continue
        # blocklist entry is bigger than an allowed network: keep only the parts outside of it
        parts = [net]
        for a in hits:
            parts = [p for part in parts for p in (part.address_exclude(a) if a.subnet_of(part) else [part])]
        for p in ipaddress.collapse_addresses(parts):
            fout.write(f"{p}\n")
        changed += 1
print(f"  Removed {removed} entries, split {changed} networks around allowlisted ranges")
PY
then
  echo "ERROR: Filtering the blocklist failed, keeping the current blocklist"
  exit 1
fi

# Activate the new map (same file, mode and owner as before)
cat "$TMP_MAP" > "$BLOCKLIST_DST"

# Reload rspamd
echo "Reloading rspamd to enable new config"
cd $MAILCOW_DIR && \
docker compose exec rspamd-mailcow kill -HUP 1 && \
echo "Finished"
