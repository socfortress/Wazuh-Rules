#!/var/ossec/framework/python/bin/python3
# SOCFortress
# https://www.socfortress.co
# info@socfortress.co
import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)
# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
# Set paths
log_file = '{0}/logs/integrations.log'.format(pwd)
socket_addr = '{0}/queue/sockets/queue'.format(pwd)
def main(args):
    debug("# Starting")
# Read args
    alert_file_location = args[1]
    apikey = args[2]
debug("# API Key")
    debug(apikey)
debug("# File location")
    debug(alert_file_location)
# Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    debug("# Processing alert")
    debug(json_alert)
# Request AbuseIPDB info
    msg = request_abuseipdb_info(json_alert,apikey)
# If positive match, send event to Wazuh Manager
    if msg:
        send_event(msg, json_alert["agent"])
def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
print(msg)
f = open(log_file,"a")
        f.write(msg)
        f.close()
def collect(data):
  abuse_confidence_score = data['abuseConfidenceScore']
  country_code = data['countryCode']
  usage_type = data['usageType']
  isp = data['isp']
  domain = data['domain']
  total_reports = data['totalReports']
  last_reported_at = data['lastReportedAt']
  return abuse_confidence_score, country_code, usage_type, isp, domain, total_reports, last_reported_at
def in_database(data, srcip):
  result = data['totalReports']
  if result == 0:
    return False
  return True
def query_api(srcip, apikey):
  params = {'maxAgeInDays': '90', 'ipAddress': srcip,}
  headers = {
  "Accept-Encoding": "gzip, deflate",
  'Accept': 'application/json',
  "Key": apikey
  }
  response = requests.get('https://api.abuseipdb.com/api/v2/check',params=params, headers=headers)
  if response.status_code == 200:
      json_response = response.json()
      data = json_response["data"]
      return data
  else:
      alert_output = {}
      alert_output["abuseipdb"] = {}
      alert_output["integration"] = "custom-abuseipdb"
      json_response = response.json()
      debug("# Error: The AbuseIPDB encountered an error")
      alert_output["abuseipdb"]["error"] = response.status_code
      alert_output["abuseipdb"]["description"] = json_response["errors"][0]["detail"]
      send_event(alert_output)
      exit(0)
def request_abuseipdb_info(alert, apikey):
    alert_output = {}
    # If there is no source ip address present in the alert. Exit.
    if not "srcip" in alert["data"]:
return(0)
# Request info using AbuseIPDB API
    data = query_api(alert["data"]["srcip"], apikey)
# Create alert
    alert_output["abuseipdb"] = {}
    alert_output["integration"] = "custom-abuseipdb"
    alert_output["abuseipdb"]["found"] = 0
    alert_output["abuseipdb"]["source"] = {}
    alert_output["abuseipdb"]["source"]["alert_id"] = alert["id"]
    alert_output["abuseipdb"]["source"]["rule"] = alert["rule"]["id"]
    alert_output["abuseipdb"]["source"]["description"] = alert["rule"]["description"]
    alert_output["abuseipdb"]["source"]["full_log"] = alert["full_log"]
    alert_output["abuseipdb"]["source"]["srcip"] = alert["data"]["srcip"]
    srcip = alert["data"]["srcip"]
    # Check if AbuseIPDB has any info about the srcip
    if in_database(data, srcip):
      alert_output["abuseipdb"]["found"] = 1
# Info about the IP found in AbuseIPDB
    if alert_output["abuseipdb"]["found"] == 1:
        abuse_confidence_score, country_code, usage_type, isp, domain, total_reports, last_reported_at = collect(data)
# Populate JSON Output object with AbuseIPDB request
        alert_output["abuseipdb"]["abuse_confidence_score"] = abuse_confidence_score
        alert_output["abuseipdb"]["country_code"] = country_code
        alert_output["abuseipdb"]["usage_type"] = usage_type
        alert_output["abuseipdb"]["isp"] = isp
        alert_output["abuseipdb"]["domain"] = domain
        alert_output["abuseipdb"]["total_reports"] = total_reports
        alert_output["abuseipdb"]["last_reported_at"] = last_reported_at
debug(alert_output)
return(alert_output)
def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        string = '1:abuseipdb:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->abuseipdb:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()
if __name__ == "__main__":
    try:
        # Read arguments
        bad_arguments = False
        if len(sys.argv) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(now, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else '')
            debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == 'debug')
        else:
            msg = '{0} Wrong arguments'.format(now)
            bad_arguments = True
# Logging the call
        f = open(log_file, 'a')
        f.write(msg +'\n')
        f.close()
if bad_arguments:
            debug("# Exiting: Bad arguments.")
            sys.exit(1)
# Main function
        main(sys.argv)
except Exception as e:
        debug(str(e))
        raise
