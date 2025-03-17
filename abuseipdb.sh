#!/bin/bash

# Adjust the values of the following variables
ABUSEIP_API_KEY="XXXXXXXXXXXXXXXXXXXXXXXXXXX"
ABUSEIPDB_LIST="/tmp/abuseipdb_blacklist.txt"

echo "Retrieve IPs from AbuseIPDB"
curl -sG https://api.abuseipdb.com/api/v2/blacklist \
  -d confidenceMinimum=90 \
  -d plaintext \
  -H "Key: $ABUSEIP_API_KEY" \
  -H "Accept: application/json" \
  -o $ABUSEIPDB_LIST

# Capture the exit code from curl
exit_code=$?

# Check if curl encountered an error
if [ $exit_code -ne 0 ]; then
  echo "Curl encountered an error with exit code $exit_code while rertieving the AbuseIPDB IPs"
  exit 1
fi

# iptables variables
CHAIN_NAME="MAILCOW" # DO NOT CHANGE THIS!
IPSET_V4="abuseipdb_blacklist_v4"
IPSET_V6="abuseipdb_blacklist_v6"
IPTABLES_RULE_V4="-m set --match-set $IPSET_V4 src -j DROP"
IPTABLES_RULE_V6="-m set --match-set $IPSET_V6 src -j DROP"

echo "Ensure the ipsets exist"
# Create IPv4 ipset if missing
if ! ipset list $IPSET_V4 &>/dev/null; then
  echo "Creating ipset $IPSET_V4"
  ipset create $IPSET_V4 hash:ip family inet
fi
# Create IPv6 ipset if missing
if ! ipset list $IPSET_V6 &>/dev/null; then
  echo "Creating ipset $IPSET_V6"
  ipset create $IPSET_V6 hash:ip family inet6
fi

echo "Flush existing ipset entries"
ipset flush $IPSET_V4
ipset flush $IPSET_V6

echo "Process each IP and add it to the appropriate ipset"
while IFS= read -r ip; do
  [[ -z "$ip" ]] && continue  # Skip empty lines
  if [[ "$ip" =~ : ]]
  then
    ipset add $IPSET_V6 "$ip" 2>/dev/null
  else
    ipset add $IPSET_V4 "$ip" 2>/dev/null
  fi
done < $ABUSEIPDB_LIST

echo "Ensure iptables/ip6tables rules exist at the top"

ensure_rule_at_top() {
  local chain=$1
  local rule=$2
  local cmd=$3  # iptables or ip6tables

  if ! $cmd -S $chain | grep -q -- "$rule"; then
    $cmd -I $chain 1 $rule  # Add rule if missing
  else
    FIRST_RULE=$($cmd -S $chain | sed -n '2p')
    if [[ "$FIRST_RULE" != *"$rule"* ]]; then
      $cmd -D $chain $rule  # Remove old rule
      $cmd -I $chain 1 $rule  # Reinsert at the top
    fi
  fi
}

ensure_rule_at_top "$CHAIN_NAME" "$IPTABLES_RULE_V4" "iptables"
ensure_rule_at_top "$CHAIN_NAME" "$IPTABLES_RULE_V6" "ip6tables"

# Save ipset rules to persist across reboots
ipset save > /etc/ipset.rules

echo -e "\n\nAll done, have fun.\n\nCheck your current iplist entries with 'ipset list | less'"
