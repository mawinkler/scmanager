#!/usr/bin/python

import ssl
ssl._create_default_https_context = ssl._create_unverified_context

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
import json
import simplejson
import hashlib
import hmac
import sys
import os
import time

def run_module():

    print("Adding image to Smart Check engine at " + os.environ["DSSC_SERVICE"], flush=True)
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

    reg_username = ""
    reg_password = ""
    if os.environ["CI_DEPLOY_USER"]:
        reg_username = os.environ["CI_DEPLOY_USER"]
    else:
        reg_username = os.environ["CI_REGISTRY_USER"]
    if os.environ["CI_DEPLOY_PASSWORD"]:
        reg_password = os.environ["CI_DEPLOY_PASSWORD"]
    else:
        reg_password = os.environ["CI_REGISTRY_PASSWORD"]
    url = os.environ["DSSC_SERVICE"] + "/api/scans"
    data = { "name": "test",
             "source": { "type": "docker",
                         "registry": os.environ["CI_REGISTRY"],
                         "repository": os.environ["CI_PROJECT_PATH"],
                         "tag": "latest",
                         "credentials": { "username": reg_username,
                                          "password": reg_password
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

    status = ""
    retries = 1
    print("Wait for scan completed", flush=True)
    while (status != "completed-with-findings" and status != "completed-no-findings" and status != "failed" and retries < int(os.environ["POLL_RETRIES"])):
        time.sleep(int(os.environ["POLL_INTERVAL"]))
        print('.', end='', flush=True)
        url = os.environ["DSSC_SERVICE"] + "/api/scans/" + response_scanId
        data = {}
        post_header = { "Content-type": "application/vnd.com.trendmicro.argus.webhook.v1+json",
                        "authorization": "Bearer " + response_token
                      }
        response = requests.get(url, data=json.dumps(data), headers=post_header, verify=False).json()
        status = response["status"]
        retries += 1

    print("\nQuery Report", flush=True)
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

    print("Evaluating finding", flush=True)
    status = evaluate_findings(response['findings'])

    if (status == 'success'):
        return 0
    else:
        return 1

def evaluate_findings(findings):
    """Evaluate the findings of the scan against local policy."""
    total = 0
    if os.environ.get('NO_MALWARE', True):
        total += findings.get('malware', 0)
    print('Malware : %d (accepted=%s)' % (findings.get('malware', 0), str(os.environ.get('NO_MALWARE', True))), flush=True)
    if os.environ.get('NO_DEFCON1', True):
        total += findings['vulnerabilities'].get('unresolved', {}).get('defcon1', 0)
    print('Defcon1 : %d (accepted=%s)' % (findings['vulnerabilities'].get('unresolved', {}).get('defcon1', 0), str(os.environ.get('NO_DEFCON1', True))), flush=True)
    if os.environ.get('NO_CRITICAL', True):
        total += findings['vulnerabilities'].get('unresolved', {}).get('critical', 0)
    print('Critical: %d (accepted=%s)' % (findings['vulnerabilities'].get('unresolved', {}).get('critical', 0), str(os.environ.get('NO_CRITICAL', True))), flush=True)
    if os.environ.get('NO_HIGH', True):
        total += findings['vulnerabilities'].get('unresolved', {}).get('high', 0)
    print('High    : %d (accepted=%s)' % (findings['vulnerabilities'].get('unresolved', {}).get('high', 0), str(os.environ.get('NO_HIGH', True))), flush=True)
    if os.environ.get('NO_MEDIUM', False):
        total += findings['vulnerabilities'].get('unresolved', {}).get('medium', 0)
    print('Medium  : %d (accepted=%s)' % (findings['vulnerabilities'].get('unresolved', {}).get('medium', 0), str(os.environ.get('NO_MEDIUM', False))), flush=True)
    if os.environ.get('NO_LOW', False):
        total += findings['vulnerabilities'].get('unresolved', {}).get('low', 0)
    print('Low     : %d (accepted=%s)' % (findings['vulnerabilities'].get('unresolved', {}).get('low', 0), str(os.environ.get('NO_LOW', False))), flush=True)
    print('Criticality: %d' % (total))

    return 'failed' if total > 0 else 'success'

def main():
    if (run_module()):
        sys.exit(-1)

if __name__ == '__main__':
    main()
