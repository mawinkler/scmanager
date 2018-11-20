#!/bin/sh
echo "Adding image to Smart Check engine at ${DSSC_SERVICE}"
# Get bearer token from Smart Check
TOKEN=$(curl -sk -X POST $DSSC_SERVICE/api/sessions -H 'content-type:application/json' -H 'x-argus-api-version:2017-10-16' -d '{"user":{"userid":"'$DSSC_USERNAME'","password":"'$DSSC_PASSWORD'"}}' | jq -r '.token')
# Create scan
SCAN_ID=$(curl -sk -X POST $DSSC_SERVICE/api/scans -H 'authorization:Bearer '$TOKEN -H 'cache-control:no-cache' -H 'content-type:application/json' -H 'x-argus-api-version:2017-11-15' -d '{"name":"test","source":{"type":"docker","registry":"'$CI_REGISTRY'","repository":"'$CI_PROJECT_PATH'","tag":"latest","credentials":{"username":"'$CI_REGISTRY_USER'","password":"'$CI_REGISTRY_TOKEN'"}}}}' | jq -r '.id')
# Wait for scan completed
echo "Waiting for analysis to complete"
STATUS=""
RETRIES="1"
while [ "$STATUS" != "completed-with-findings" -a "$STATUS" != "completed-no-findings" -a "$STATUS" != "failed" -a "$RETRIES" -le "$POLL_RETRIES" ] ; do sleep $POLL_INTERVAL ; echo -n "." ; RETRIES=$(($RETRIES+1)) ; STATUS=$(curl -sk -H 'authorization:Bearer '$TOKEN'' -H 'content-Type:application/vnd.com.trendmicro.argus.webhook.v1+json' $DSSC_SERVICE/api/scans/$SCAN_ID | jq -r '.status') ; done
# Analyse scan results
# Pass if no Defcon1, critical, high or malware has been found
echo "Get scan results"
REPORT=$(curl -sk -H 'authorization:Bearer '$TOKEN'' -H 'content-Type:application/vnd.com.trendmicro.argus.webhook.v1+json' $DSSC_SERVICE/api/scans/$SCAN_ID | jq '{unresolved:.findings.vulnerabilities.unresolved, malware:.findings.malware}')
REPORT_FULL=$(curl -sk -H 'authorization:Bearer '$TOKEN'' -H 'content-Type:application/vnd.com.trendmicro.argus.webhook.v1+json' $DSSC_SERVICE/api/scans/$SCAN_ID)
CRITICALITY=$(echo $REPORT | jq -r '(.unresolved | (0 + .defcon1 + .critical + .high)) + (.malware)')
echo $REPORT
echo $CRITICALITY
echo $CRITICALITY > criticality
echo $REPORT_FULL > gl-container-scanning-report.json
