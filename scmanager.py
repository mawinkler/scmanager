#!/usr/bin/python

import ssl
ssl._create_default_https_context = ssl._create_unverified_context

import requests
import json
import sys
import os

def run_module():

    print(os.environ)

    print("Adding image to Smart Check engine at " + os.environ["DSSC_SERVICE"])
    print("Get bearer token from Smart Check")
    url = os.environ["DSSC_SERVICE"] + "/api/sessions"
    data = { "user": { "userid": os.environ["DSSC_USERNAME"],
                       "password": os.environ["DSSC_PASSWORD"]
                     }
           }
    post_header = { "Content-type": "application/json",
                    "x-argus-api-version": "2017-10-16"
                  }
    response = requests.post(url, data=json.dumps(data), headers=post_header, verify=False).json()

    # Error handling
    if 'message' in response:
        if response['message'] == "Invalid DSSC credentials":
            raise ValueError("Invalid DSSC credentials or SmartCheck not available")

    response_token = response['token']

    print(response_token)

    url = os.environ["DSSC_SERVICE"] + "/api/scans"
    data = { "name": "test",
             "source": { "type": "docker",
                         "registry": os.environ["CI_REGISTRY"],
                         "repository": os.environ["CI_PROJECT_PATH"],
                         "tag": "latest",
                         "credentials": { "username": os.environ["CI_REGISTRY_USER"],
                                          "password": os.environ["CI_REGISTRY_TOKEN"]
                                        }
                       }
           }
    post_header = { "Content-type": "application/json",
                    "x-argus-api-version": "2017-11-15",
                    "authorization": "Bearer " + response_token,
                    "cache-control": "no-cache"
                  }
    response = requests.post(url, data=json.dumps(data), headers=post_header, verify=False).json()

    # Error handling
    if 'message' in response:
        if response['message'] == "Invalid DSSC credentials":
            raise ValueError("Invalid DSSC credentials or SmartCheck not available")

    response_scanId = response['id']

    print(response_scanId)

    url = os.environ["DSSC_SERVICE"] + "/api/webhooks"
    data = { "name": "alert-scan-complete-2",
             "events": ["scan-completed"],
             "active": True,
             "hookurl": "http://scantoslack/api/scans"
           }
    post_header = { "Content-type": "application/vnd.com.trendmicro.argus.webhook.v1+json",
                    "x-argus-api-version": "2017-11-15",
                    "authorization": "Bearer " + response_token,
                    "cache-control": "no-cache"
                  }

    response = requests.post(url, data=json.dumps(data), headers=post_header, verify=False).json()

    print(response)

def main():
    run_module()

if __name__ == '__main__':
    main()



#POLL_INTERVAL=2
#POLL_RETRIES=150
#STATUS=""
#RETRIES="1"
# Wait for scan completed
#echo "Waiting for analysis to complete"
#while [ "$STATUS" != "completed-with-findings" -a "$STATUS" != "completed-no-findings" -a "$STATUS" != "failed" -a "$RETRIES" -le "$POLL_RETRIES" ] ; do sleep $POLL_INTERVAL ; echo -n "." ; RETRIES
#=$(($RETRIES+1)) ; STATUS=$(curl -sk -H 'authorization:Bearer '$TOKEN'' -H 'content-Type:application/vnd.com.trendmicro.argus.webhook.v1+json' $DSSC_SERVICE/api/scans/$SCAN_ID | jq -r '.status') ;
#done

# Analyse scan results
# Pass if no Defcon1, critical, high or malware has been found
#echo "Get scan results"
#REPORT=$(curl -sk -H 'authorization:Bearer '$TOKEN'' -H 'content-Type:application/vnd.com.trendmicro.argus.webhook.v1+json' $DSSC_SERVICE/api/scans/$SCAN_ID | jq '{unresolved:.findings.vulnerabilit
#ies.unresolved, malware:.findings.malware}')
#REPORT_FULL=$(curl -sk -H 'authorization:Bearer '$TOKEN'' -H 'content-Type:application/vnd.com.trendmicro.argus.webhook.v1+json' $DSSC_SERVICE/api/scans/$SCAN_ID)
#CRITICALITY=$(echo $REPORT | jq -r '(.unresolved | (0 + .defcon1 + .critical + .high)) + (.malware)')
#echo $REPORT
#echo $CRITICALITY
#echo $CRITICALITY > criticality
#echo $REPORT_FULL > gl-container-scanning-report.json
