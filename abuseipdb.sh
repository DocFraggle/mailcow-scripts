#!/bin/bash

# Adjust the values of the following variables
ABUSEIP_API_KEY="XXXXXXXXXXXXXX"
MAILCOW_API_KEY="YYYYYYYYYYYYYYY"
MAILSERVER_FQDN="your.mail.server"

# Add your own personal blacklist to this file in vaild CIDR notation
# i.e. 1.2.3.4/32
#      5.6.7.0/24
#      2001:db8:abcd:1234::1/64  

PERSONAL_BLACKLIST_FILE="/path/to/your/blacklist.txt"

echo "Retrieve IPs from AbuseIPDB"
curl -sG https://api.abuseipdb.com/api/v2/blacklist \
  -d confidenceMinimum=90 \
  -d plaintext \
  -H "Key: $ABUSEIP_API_KEY" \
  -H "Accept: application/json" \
  -o /tmp/abuseipdb_blacklist.txt

# Capture the exit code from curl
exit_code=$?

# Check if curl encountered an error
if [ $exit_code -ne 0 ]; then
  echo "Curl encountered an error with exit code $exit_code while rertieving the AbuseIPDB IPs"
  exit 1
fi

# Add a newline to the end of the blacklist file
echo >> /tmp/abuseipdb_blacklist.txt

echo "Get current Fail2Ban config, extract active_bans IPs and add them to the blacklist file"
curl -s --header "Content-Type: application/json" \
     --header "X-API-Key: $MAILCOW_API_KEY" \
      "https://${MAILSERVER_FQDN}/api/v1/get/fail2ban" |\
      jq -r 'if .active_bans | length > 0 then .active_bans[].ip else "" end' >> /tmp/abuseipdb_blacklist.txt

BLACKLIST=$(awk 'NF {if (index($0, ":") > 0) printf "%s%s/128", sep, $0; else printf "%s%s/32", sep, $0; sep=","} END {print ""}' /tmp/abuseipdb_blacklist.txt)

cat <<EOF > /tmp/request.json
{
  "items":["none"],
  "attr": {
    "blacklist": "$BLACKLIST"
  }
}
EOF

# Vaildate CIDR notation of personal blacklist file and add content to the "blacklist" key of the json file
if [ -f $PERSONAL_BLACKLIST_FILE ]
then
  echo "Adding personal blacklist"
  grep -E '^(([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[12][0-9]|3[0-2])|([0-9a-fA-F:]+\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])))$' $PERSONAL_BLACKLIST_FILE > /tmp/personal_blacklist.txt
  jq --arg new "$(paste -sd, /tmp/personal_blacklist.txt)" '.attr.blacklist += ("," + $new)' /tmp/request.json > /tmp/request.json.tmp
  mv /tmp/request.json.tmp /tmp/request.json
else
  echo "No personal blacklist file present, skipping this step"
fi

echo "Add IPs to Fail2Ban" 
curl -s --include \
     --request POST \
     --header "Content-Type: application/json" \
     --header "X-API-Key: $MAILCOW_API_KEY" \
     --data-binary @/tmp/request.json \
     "https://${MAILSERVER_FQDN}/api/v1/edit/fail2ban"

# Capture the exit code from curl
exit_code=$?

# Check if curl encountered an error
if [ $exit_code -ne 0 ]; then
  echo "Curl encountered an error with exit code $exit_code while rertieving the AbuseIPDB IPs"
  exit 1
fi

echo -e "\n\nAll done, have fun"
