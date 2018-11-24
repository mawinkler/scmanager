#!/usr/bin/python

import ssl
ssl._create_default_https_context = ssl._create_unverified_context

import requests
import json
import simplejson
import hashlib
import hmac
import sys
import os
import time

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

    if 'message' in response:
        if response['message'] == "Invalid DSSC credentials":
            raise ValueError("Invalid DSSC credentials or SmartCheck not available")

    response_token = response['token']

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

    if 'message' in response:
        if response['message'] == "Invalid DSSC credentials":
            raise ValueError("Invalid DSSC credentials or SmartCheck not available")

    response_scanId = response['id']

#    url = os.environ["DSSC_SERVICE"] + "/api/webhooks"
#    data = { "name": "alert-scan-complete-2",
#             "events": ["scan-completed"],
#             "active": True,
#             "hookurl": "http://scantoslack/api/scans"
#           }
#    post_header = { "Content-type": "application/vnd.com.trendmicro.argus.webhook.v1+json",
#                    "x-argus-api-version": "2017-11-15",
#                    "authorization": "Bearer " + response_token,
#                    "cache-control": "no-cache"
#                  }

#    response = requests.post(url, data=json.dumps(data), headers=post_header, verify=False).json()

    poll_interval = 2
    poll_retries = 150
    status = ""
    retries = 1
    print("Wait for scan completed")
    while (status != "completed-with-findings" and status != "completed-no-findings" and status != "failed" and retries < poll_retries):
      time.sleep(poll_interval)
      print(".")
      url = os.environ["DSSC_SERVICE"] + "/api/scans/" + response_scanId
      data = {}
      post_header = { "Content-type": "application/vnd.com.trendmicro.argus.webhook.v1+json",
                      "authorization": "Bearer " + response_token
                    }
      response = requests.get(url, data=json.dumps(data), headers=post_header, verify=False).json()
      status = response["status"]
      retries += 1

    url = os.environ["DSSC_SERVICE"] + "/api/scans/" + response_scanId
    data = { }
    post_header = { "Content-type": "application/vnd.com.trendmicro.argus.webhook.v1+json",
                    "authorization": "Bearer " + response_token
                  }
    response = requests.get(url, data=json.dumps(data), headers=post_header, verify=False).json()

    # Error handling
    if 'message' in response:
        if response['message'] == "Invalid DSSC credentials":
            raise ValueError("Invalid DSSC credentials or SmartCheck not available")

    status = evaluate_findings(response['findings'])
    if (status == 'success'):
        return 0
    else:
        return 1

def evaluate_findings(findings):
    """Evaluate the findings of the scan against local policy."""
    total = 0
    total += findings.get('malware', 0)
    print('Malware : %d' % (findings.get('malware', 0)))
    total += findings['vulnerabilities'].get('unresolved', {}).get('defcon1', 0)
    print('Defcon1 : %d' % (findings['vulnerabilities'].get('unresolved', {}).get('defcon1', 0)))
    total += findings['vulnerabilities'].get('unresolved', {}).get('critical', 0)
    print('Critical: %d' % (findings['vulnerabilities'].get('unresolved', {}).get('critical', 0)))
    total += findings['vulnerabilities'].get('unresolved', {}).get('high', 0)
    print('High    : %d' % (findings['vulnerabilities'].get('unresolved', {}).get('high', 0)))
#    total += findings['vulnerabilities'].get('unresolved', {}).get('medium', 0)
    print('Medium  : %d' % (findings['vulnerabilities'].get('unresolved', {}).get('medium', 0)))
#    total += findings['vulnerabilities'].get('unresolved', {}).get('low', 0)
    print('Low     : %d' % (findings['vulnerabilities'].get('unresolved', {}).get('low', 0)))

    return 'failed' if total > 0 else 'success'

def main():
    run_module()
if __name__ == '__main__':
    main()
