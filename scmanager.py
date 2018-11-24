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

from http.server import HTTPServer, BaseHTTPRequestHandler, HTTPStatus
from urllib.parse import urljoin

ADDRESS = os.environ.get('LISTEN_ADDRESS', '')
PORT = int(os.environ.get('LISTEN_PORT', '8082'))
CONTEXT = os.environ.get('CONTEXT', 'Deep Security Smart Check')

MAX_PAYLOAD_SIZE = 5 * 1024 * 1024

class RequestHandler(BaseHTTPRequestHandler):
    """
    Handles POST requests: validate the payload HMAC if a shared secret has been
    defined, check any findings against policy (see `evaluate_findings`), and
    then post the status to Github.
    """
    protocol_version = 'HTTP/1.1'

    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_POST(self):  # pylint: disable=invalid-name
        """Handle the POST from the web hook and write a commit status record."""
        try:
            # Get the (authenticated) body as parsed JSON
            self._set_headers()
            self.data_string = self.rfile.read(int(self.headers['Content-Length']))
            event = simplejson.loads(self.data_string)

            # We are only interested in the `scan-completed` event
            if event['event'] != 'scan-completed':
                self.respond(HTTPStatus.OK)
                return

            scan_url = urljoin(os.environ["DSSC_SERVICE"], event['scan']['href'])

            registry = event['scan']['source']['registry']
            repository = event['scan']['source']['repository']
            tag = event['scan']['source']['tag']
            digest = event['scan']['details']['digest']

            self.log_message('Processing results for image %s/%s:%s@%s',
                             registry, repository, tag, digest)

            status = evaluate_findings(event['scan']['findings'])
            self.log_message('Image scan status: %s', status)

            result = dict()
            result = { "vulnerabilities": event['scan']['findings']['vulnerabilities'].get('unresolved', {}),
                       "malware": event['scan']['findings'].get('malware', 0),
                       "status": status }
            with open('../results/gl-container-scanning-report.json', 'w') as outfile:
                json.dump(result, outfile)

            self.respond(HTTPStatus.OK)
            # if (status == "success"):
            #     sys.exit()
            # else:
            #     sys.exit(1)
        except InvalidPayloadSizeException:
            self.log_error('Invalid payload size for request')
            self.respond(HTTPStatus.BAD_REQUEST)
        except BadHMACException:
            self.log_error('Invalid HMAC for request')
            self.respond(HTTPStatus.UNAUTHORIZED)
        except KeyError as exception:
            self.log_error('Did not find expected key: %s', exception)
            self.respond(HTTPStatus.BAD_REQUEST)
        except Exception as exception:  # pylint: disable=broad-except
            self.log_error('Unexpected exception: %s', exception)
            self.respond(HTTPStatus.INTERNAL_SERVER_ERROR)

    def json_body(self):
        """Parse the event payload and validate the HMAC against the shared secret."""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0 or content_length > MAX_PAYLOAD_SIZE:
            raise InvalidPayloadSizeException()

        content = self.rfile.read(content_length)

        hmac_secret = os.environ.get('HMAC_SECRET', None)

        if hmac_secret is not None:
            actual = hmac.new(bytes(hmac_secret, 'utf-8'),
                              msg=bytes(content),
                              digestmod=hashlib.sha256).hexdigest()

            expected = self.headers.get('X-Scan-Event-Signature', '')

            if not hmac.compare_digest(actual, expected):
                raise BadHMACException()

        return json.loads(content)

    def respond(self, status):
        """Respond to the HTTP request with a status code and no body."""
        self.send_response(status)
        self.send_header('Content-Length', 0)
        self.end_headers()
        self.close_connection = True  # pylint: disable=attribute-defined-outside-init

    def send_header(self, keyword, value):
        """Override the superclass behaviour to suppress sending the `Server` header."""
        if keyword != 'Server':
            super(RequestHandler, self).send_header(keyword, value)


class InvalidPayloadSizeException(Exception):
    """Exception raised when either there is not enough or too much payload."""
    pass


class BadHMACException(Exception):
    """Exception raised when HMAC authentication fails."""
    pass

def evaluate_findings(findings):
    """Evaluate the findings of the scan against local policy."""
    total = 0
    total += findings.get('malware', 0)
    total += findings['vulnerabilities'].get('unresolved', {}).get('defcon1', 0)
    total += findings['vulnerabilities'].get('unresolved', {}).get('critical', 0)
    total += findings['vulnerabilities'].get('unresolved', {}).get('high', 0)
    total += findings['vulnerabilities'].get('unresolved', {}).get('medium', 0)
    total += findings['vulnerabilities'].get('unresolved', {}).get('low', 0)

    return 'failed' if total > 0 else 'success'


def run_module():

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

    print('serving at %s:%d' % (ADDRESS, PORT))
    HTTPServer((ADDRESS, PORT), RequestHandler).serve_forever()

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
