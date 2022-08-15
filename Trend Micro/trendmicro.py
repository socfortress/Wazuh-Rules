#!/var/ossec/framework/python/bin/python3
import sys
import time
import requests
import json
from pathlib import Path
from datetime import datetime, timedelta
#File to store the alerts
output_file = '/tmp/trendmicro.json'
#Function to append new lines to output file
def append_new_line(text_to_append):
    """Append given text as a new line at the end of file"""
    # Open the file in append & read mode ('a+')
    with open(output_file, "a+") as file_object:
        # Move read cursor to the start of file.
        file_object.seek(0)
        # If file is not empty then append '\n'
        data = file_object.read(100)
        if len(data) > 0:
            file_object.write("\n")
        # Append text at the end of file
        file_object.write(text_to_append)
#TRENDMICRO API Details
url_base = 'https://api.xdr.trendmicro.com'
url_path = '/v3.0/workbench/alerts'
token = 'replace with your API token'
#Pass Query Param - Start Date = An hour ago
d = datetime.today() - timedelta(hours=1, minutes=0)
startDateTime = d.strftime("%Y-%m-%dT%H:%M:%SZ")
query_params = "startDateTime="f"{startDateTime}"
headers = {'Authorization': 'Bearer ' + token}
#Initialise Output Array
alert_output = {}
#API CALL and Append Response
r = requests.get(url_base + url_path, params=query_params, headers=headers)
if 'application/json' in r.headers.get('Content-Type', '') and len(r.content):
    if r.status_code == 200:
        r_json = r.json()
        try:
            total_count = r_json["totalCount"]
        except IndexError:
            sys.exit()    
        for c in range(total_count):
            entities_count = len(r_json["items"][c]["impactScope"]["entities"])
            #Wait 0.2 secs before next loop (avoid flooding the queue)
            time.sleep(0.2)
            for e in range(entities_count):
                alert_output["id"] = r_json["items"][c]["id"]
                alert_output["investigationStatus"] = r_json["items"][c]["investigationStatus"]
                alert_output["score"] = r_json["items"][c]["score"]
                alert_output["severity"] = r_json["items"][c]["severity"]
                alert_output["createdDateTime"] = r_json["items"][c]["createdDateTime"]
                alert_output["updatedDateTime"] = r_json["items"][c]["updatedDateTime"]
                alert_output["severity"] = r_json["items"][c]["severity"]
                alert_output["description"] = r_json["items"][c]["description"]
                alert_output["indicators"] = len(r_json["items"][c]["indicators"])
                alert_output["entityType"] = r_json["items"][c]["impactScope"]["entities"][e]["entityType"]
                alert_output["entityValue"] = r_json["items"][c]["impactScope"]["entities"][e]["entityValue"]
                append_new_line(json.dumps(alert_output))
    else:
        sys.exit()
else:
    sys.exit()
