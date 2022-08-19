#!/usr/bin/env python
# SOCFortress
# https://www.socfortress.co
# info@socfortress.co
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import date, datetime, timedelta
import time
import requests
from requests.exceptions import ConnectionError
import json
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = '{0}/queue/sockets/queue'.format(pwd)
def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        string = '1:dns_stats:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->dns_stats:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()
false = False
# Read configuration parameters
alert_file = open(sys.argv[1])
# Read the alert file
alert = json.loads(alert_file.read())
alert_file.close()
# New Alert Output if DNS Stat Alert or Error calling the API
alert_output = {}
# DNS Stats Base URL
dns_stats_base_url = 'http://127.0.0.1:5730/'
# Extract Queried Hostname from Sysmon Event
dns_query_name = alert["data"]["win"]["eventdata"]["queryName"]
dns_stats_url = ''.join([dns_stats_base_url, dns_query_name])
# DNS Stat API Call
try:
 dns_stats_response = requests.get(dns_stats_url)
except ConnectionError:
    alert_output["dnsstat"] = {}
    alert_output["integration"] = "dnsstat"
    alert_output["dnsstat"]["error"] = 'Connection Error to DNS Stats API'
    send_event(alert_output, alert["agent"])
else:
    dns_stats_response = dns_stats_response.json()
# Check if response includes alerts or New Domain
    if (dns_stats_response["alerts"] and dns_stats_response["category"] != 'ERROR') or  dns_stats_response["category"] == 'NEW':
# Generate Alert Output from DNS Stats Response
        alert_output["dnsstat"] = {}
        alert_output["integration"] = "dnsstat"
        alert_output["dnsstat"]["query"] = dns_query_name
        alert_output["dnsstat"]["alerts"] = dns_stats_response["alerts"]
        alert_output["dnsstat"]["category"] = dns_stats_response["category"]
        alert_output["dnsstat"]["freq_score"] = dns_stats_response["freq_score"]
        alert_output["dnsstat"]["seen_by_isc"] = dns_stats_response["seen_by_isc"]
        alert_output["dnsstat"]["seen_by_web"] = dns_stats_response["seen_by_web"]
        alert_output["dnsstat"]["seen_by_you"] = dns_stats_response["seen_by_you"]
        send_event(alert_output, alert["agent"])
