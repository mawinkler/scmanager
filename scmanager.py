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

    print("Authenticating to Smart Check engine at https://" + os.environ["DSSC_SERVICE"], flush=True)
    url = "https://" + os.environ["DSSC_SERVICE"] + "/api/sessions"
    data = { "user": { "userid": os.environ["DSSC_USERNAME"],
                       "password": os.environ["DSSC_PASSWORD"]
                     }
           }
    post_header = { "Content-type": "application/json",
                    "x-argus-api-version": "2017-10-16"
                  }
    response = requests.post(url, data=json.dumps(data), headers=post_header, verify=False).json()

    if 'message' in response:
        print("Authentication response: " + response['message'], flush=True)
        if response['message'] == "Invalid DSSC credentials":
            raise ValueError("Invalid DSSC credentials or SmartCheck not available")

    response_token = response['token']

    reg_username = ""
    reg_password = ""
    reg_image = ""
    reg_image_tag = ""

    if os.environ["CI_DEPLOY_USER"]:
        reg_username = os.environ["CI_DEPLOY_USER"]
    else:
        reg_username = os.environ["CI_REGISTRY_USER"]
    if os.environ["CI_DEPLOY_PASSWORD"]:
        reg_password = os.environ["CI_DEPLOY_PASSWORD"]
    else:
        reg_password = os.environ["CI_REGISTRY_PASSWORD"]

    reg_image = os.environ["CI_PROJECT_PATH"]
    try:
        if os.environ["TARGET_IMAGE"]:
            reg_image = os.environ["CI_PROJECT_PATH"] + "/" + os.environ["TARGET_IMAGE"]
    except KeyError:
        print("TARGET_IMAGE not set, defaulting to CI_PROJECT_PATH", flush=True)

    reg_image_tag = "latest"
    try:
        if os.environ["TARGET_IMAGE_TAG"]:
            reg_image_tag = os.environ["TARGET_IMAGE_TAG"]
    except KeyError:
        print("TARGET_IMAGE_TAG not set, defaulting to latest", flush=True)

    print("Initiating scan for " + os.environ["CI_REGISTRY"] + "/" + reg_image + ":" + reg_image_tag, flush=True)
    url = "https://" + os.environ["DSSC_SERVICE"] + "/api/scans"
    data = { "name": "test",
             "source": { "type": "docker",
                         "registry": os.environ["CI_REGISTRY"],
                         "repository": reg_image,
                         "tag": reg_image_tag,
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
        print("Scan request response: " + response['message'], flush=True)
        if response['message'] == "Invalid DSSC credentials":
            raise ValueError("Invalid DSSC credentials or SmartCheck not available")

    response_scanId = response['id']
    print("Scan ID: " + response_scanId, flush=True)

    status = ""
    retries = 1
    print("Wait for scan completed", flush=True)
    while (status != "completed-with-findings" and status != "completed-no-findings" and status != "failed" and retries < int(os.environ["POLL_RETRIES"])):
        time.sleep(int(os.environ["POLL_INTERVAL"]))
        print('.', end='', flush=True)
        url = "https://" + os.environ["DSSC_SERVICE"] + "/api/scans/" + response_scanId
        data = {}
        post_header = { "Content-type": "application/vnd.com.trendmicro.argus.webhook.v1+json",
                        "authorization": "Bearer " + response_token
                      }
        response = requests.get(url, data=json.dumps(data), headers=post_header, verify=False).json()
        status = response["status"]
        retries += 1

    print("\nFinal Scan Status: " + status, flush=True)
    if status == "failed":
        # Scan failed
        return 2

    print("Query Report", flush=True)
    url = "https://" + os.environ["DSSC_SERVICE"] + "/api/scans/" + response_scanId
    data = { }
    post_header = { "Content-type": "application/vnd.com.trendmicro.argus.webhook.v1+json",
                    "authorization": "Bearer " + response_token
                  }
    response = requests.get(url, data=json.dumps(data), headers=post_header, verify=False).json()

    # Error handling
    if 'message' in response:
        print("Query report response: " + response['message'], flush=True)
        if response['message'] == "Invalid DSSC credentials":
            raise ValueError("Invalid DSSC credentials or SmartCheck not available")

    # export scan report
    with open('scan_report.json', 'w') as f:
        json.dump(response, f)

    print("Evaluating finding", flush=True)
    status = evaluate_findings(response['findings'])

    if (status == 'success'):
        return 0
    else:
        return 1

def evaluate_findings(findings):
    """Evaluate the findings of the scan against local policy."""
    total = 0

    print(findings, flush=True)

    if (os.environ.get('NO_MALWARE', True) == True):
        total += findings.get('malware', 0)
    print('Malware : %d' % (findings.get('malware', 0)), flush=True)

    if (os.environ.get('NO_CONTENT', True) == True):
        total += findings['contents'].get('total', {}).get('high', 0)
    print('Content : %d' % (findings['contents'].get('total', {}).get('high', 0)), flush=True)

    if (os.environ.get('NO_DEFCON1', True) == True):
        total += findings['vulnerabilities'].get('unresolved', {}).get('defcon1', 0)
    print('Defcon1 : %d' % (findings['vulnerabilities'].get('unresolved', {}).get('defcon1', 0)), flush=True)

    if (os.environ.get('NO_CRITICAL', True == True)):
        total += findings['vulnerabilities'].get('unresolved', {}).get('critical', 0)
    print('Critical: %d' % (findings['vulnerabilities'].get('unresolved', {}).get('critical', 0)), flush=True)

    if (os.environ.get('NO_HIGH', True) == True):
        total += findings['vulnerabilities'].get('unresolved', {}).get('high', 0)
    print('High    : %d' % (findings['vulnerabilities'].get('unresolved', {}).get('high', 0)), flush=True)

    if (os.environ.get('NO_MEDIUM', False) == True):
        total += findings['vulnerabilities'].get('unresolved', {}).get('medium', 0)
    print('Medium  : %d' % (findings['vulnerabilities'].get('unresolved', {}).get('medium', 0)), flush=True)

    if (os.environ.get('NO_LOW', False) == True):
        total += findings['vulnerabilities'].get('unresolved', {}).get('low', 0)
    print('Low     : %d' % (findings['vulnerabilities'].get('unresolved', {}).get('low', 0)), flush=True)

    print('Criticality: %d' % (total))

    return 'failed' if total > 0 else 'success'

def main():
    if (run_module()):
        sys.exit(-1)

if __name__ == '__main__':
    main()
