#!/bin/bash

MAILCOW_DIR="/opt/mailcow-dockerized"
BLOCKLIST_SRC="https://raw.githubusercontent.com/bitwire-it/ipblocklist/refs/heads/main/inbound.txt"
BLOCKLIST_DST="${MAILCOW_DIR}/data/conf/rspamd/local.d/ipblocklist.map"
BLOCKLIST_CFG="${MAILCOW_DIR}/data/conf/rspamd/override.d/multimap.conf"

# Create rspamd multimap config
read -r -d '' BLOCKLIST_CONTENT <<'EOF'
BAD_IPS {
  type = "ip";
  map = "/etc/rspamd/local.d/ipblocklist.map";
  action = "reject";
  symbol = "BAD_IPS";
  description = "Blocked sender IPs";
}
EOF

# Ensure override.d directory exists
mkdir -p "$(dirname "$BLOCKLIST_CFG")"

# Check if the file already contains the BAD_IPS block
if [ -f "$BLOCKLIST_CFG" ] && cmp -s <(echo "$BLOCKLIST_CONTENT") "$BLOCKLIST_CFG"; then
  echo "Blocklist config is up-to-date."
else
  echo "$BLOCKLIST_CONTENT" > "$BLOCKLIST_CFG"
  echo "Config updated."
fi

# Download blocklist
curl -s -o $BLOCKLIST_DST $BLOCKLIST_SRC

# Sanity checks
echo "Performing sanity checks"
echo "Counting lines of downloaded blocklist"
TOTAL_LINES=$(wc -l < "$BLOCKLIST_DST")

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
INVALID_LINES=$(grep -Ev "($IPV4_REGEX)|($IPV6_REGEX)" "$BLOCKLIST_DST")

if [ -n "$INVALID_LINES" ]; then
  echo "WARNING: Some lines do not look like valid IPv4 or IPv6 addresses/CIDRs:"
  echo "$INVALID_LINES"
  exit 1
else
  echo "All lines look like valid IPv4 or IPv6 addresses/CIDRs"
fi

# Reload rspamd
echo "Reloading rspamd to enable new config"
cd $MAILCOW_DIR && \
docker compose exec rspamd-mailcow kill -HUP 1 && \
echo "Finished"
