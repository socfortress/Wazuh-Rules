#!/var/ossec/framework/python/bin/python3

# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import sys
import json
import requests
import logging
import datetime
from socket import socket, AF_UNIX, SOCK_DGRAM

################################################## Global variables ##################################################

# Microsoft resource
resource = "https://manage.office.com"

# Office 365 management activity API available content types
availableContentTypes = ["Audit.AzureActiveDirectory", "Audit.Exchange", "Audit.SharePoint", "Audit.General", "DLP.All"]

# Wazuh manager analisysd socket address
socketAddr = '/var/ossec/queue/sockets/queue'

################################################## Common functions ##################################################

# Send event to Wazuh manager
def send_event(msg):
    logging.debug('Sending {} to {} socket.'.format(msg, socketAddr))
    string = '1:office_365:{}'.format(msg)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socketAddr)
    sock.send(string.encode())
    sock.close()

# Perform HTTP request
def make_request(method, url, headers, data=None):
    response = requests.request(method, url, headers=headers, data=data)

    # If the request succeed 
    if response.status_code >= 200 and response.status_code < 210:
        return response
    if method == "POST" and response.status_code == 400:
        return response
    else:
        raise Exception('Request ', method, ' ', url, ' failed with ', response.status_code, ' - ', response.text)

# Obtain a token for accessing the Office 365 management activity API
def obtain_access_token(tenantId, clientId, clientSecret):
    # Add header and payload
    headers = {'Content-Type':'application/x-www-form-urlencoded'}
    payload = 'client_id={}&scope={}/.default&grant_type=client_credentials&client_secret={}'.format(clientId, resource, clientSecret)

    # Request token
    response = make_request("POST", "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(tenantId), headers=headers, data=payload)
    logging.info("Microsoft token was successfully fetched.")

    return json.loads(response.text)['access_token']

# Perform an API request to Office 365 management API
def make_api_request(method, url, token):
    # Create a valid header using the token
    headers = {'Content-Type':'application/json', 'Authorization':'Bearer {0}'.format(token)}

    # Make API request
    response = make_request(method, url, headers=headers)

    # If this is a POST request just return
    if (method == "POST"):
        return None

    json_data = json.loads(response.text)

    # If NextPageUri is included in the header and it has content in it
    if 'NextPageUri' in response.headers.keys() and response.headers['NextPageUri']:
        logging.info("New data page detected in {}.".format(url))

        # Request new page and append to existing data
        record = make_api_request(method, response.headers['NextPageUri'], token)
        json_data.extend(record)

    return json_data

# Manage content type subscriptions
def manage_content_type_subscriptions(contentTypes, clientId, token):
    # For every available content type
    for contentType in availableContentTypes:
        # If it was added as a parameter then start the subscription
        if contentType in contentTypes:
            make_api_request("POST", "{}/api/v1.0/{}/activity/feed/subscriptions/start?contentType={}".format(resource, clientId, contentType), token)
            logging.info("{} subscription was successfully started.".format(contentType))

################################################## Main workflow ##################################################

if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser(description='Wazuh - Office 365 activity information.')
    parser.add_argument('--contentTypes', metavar='contentTypes', type=str, nargs='+', required = True, help='Office 365 activity content type subscriptions.')
    parser.add_argument('--hours', metavar='hours', type=int, required = True, help='How many hours to fetch activity logs.')
    parser.add_argument('--tenantId', metavar='tenantId', type=str, required = True, help='Application tenant ID.')
    parser.add_argument('--clientId', metavar='clientId', type=str, required = True, help='Application client ID.')
    parser.add_argument('--clientSecret', metavar='clientSecret', type=str, required = True, help='Client secret.')
    parser.add_argument('--label', metavar='clientLabel', type=str, required = False, help='A tag to differentiate multiple office365 wodles.')
    parser.add_argument('--debug', action='store_true', required = False, help='Enable debug mode logging.')
    args = parser.parse_args()

    # Start logging config
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s: [%(levelname)s] %(message)s', datefmt="%Y-%m-%d %H:%M:%S",)
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s: [%(levelname)s] %(message)s', datefmt="%Y-%m-%d %H:%M:%S",)

    # Disable warnings
    requests.packages.urllib3.disable_warnings()

    try:
        # Obtain access token
        token = obtain_access_token(args.tenantId, args.clientId, args.clientSecret)

        # Start/stop subscriptions depending on the content_types parameter
        manage_content_type_subscriptions(args.contentTypes, args.clientId, token)

        # Build time range filter 
        currentTime = datetime.datetime.now(datetime.timezone.utc)
        endTime = str(currentTime).replace(' ', 'T').rsplit('.', maxsplit=1)[0]
        startTime = str(currentTime - datetime.timedelta(hours=args.hours)).replace(' ', 'T').rsplit('.', maxsplit=1)[0]

        # For every content_type in the content_types parameter
        for contentType in args.contentTypes:
            # If it is a valid content_type
            if contentType in availableContentTypes:
                # List the subscription content
                subscription_content = make_api_request("GET", "{}/api/v1.0/{}/activity/feed/subscriptions/content?contentType={}&startTime={}&endTime={}".format(resource, args.clientId, contentType, startTime, endTime), token)
                logging.info("{} subscription was successfully listed.".format(contentType))

                # For every blob in the subscription
                for blob in subscription_content:
                    # Request activity information
                    data = make_api_request("GET", blob["contentUri"], token)
                    logging.info("Blob in {} subscription was successfully fetched.".format(contentType))

                    # Loop every event and send it to the Wazuh manager
                    for event in data:
                        office_365_event = {}
                        office_365_event['office_365'] = event
                        office_365_event['label'] = args.label
                        send_event(json.dumps(office_365_event))

    except Exception as e:
        logging.error("Error while retrieving Office 365 activity logs: {}.".format(e))
