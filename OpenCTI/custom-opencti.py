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
import ipaddress
import hashlib
import re
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = '{0}/queue/sockets/queue'.format(pwd)
null = "null"
opencti_key_valyue_type="value"
def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        string = '1:opencti:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->opencti:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
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
# New Alert Output if OpenCTI Alert or Error calling the API
alert_output = {}
# OpenCTI Server Base URL
opencti_base_url = "http://your_opencti_instance/graphql"
# OpenCTI Server API AUTH KEY
opencti_api_auth_key = "Bearer your_opencti_token"
# API - HTTP Headers
opencti_apicall_headers = {"Content-Type":"application/json", "Authorization":f"{opencti_api_auth_key}", "Accept":"*/*"}
## Extract Sysmon for Windows/Sysmon for Linux and Sysmon Event ID
event_source = alert["rule"]["groups"][0]
event_type = alert["rule"]["groups"][2]
## Regex Pattern used based on SHA256 lenght (64 characters)
regex_file_hash = re.compile('\w{64}')
if event_source == 'windows':
    if event_type == 'sysmon_event1':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
            opencti_key_valyue_type="hashes_SHA256"
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event3' and alert["data"]["win"]["eventdata"]["destinationIsIpv6"] == 'false':
        try:
            dst_ip = alert["data"]["win"]["eventdata"]["destinationIp"]
            if ipaddress.ip_address(dst_ip).is_global:
                wazuh_event_param = dst_ip
            else:
                sys.exit()
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event3' and alert_output["data"]["win"]["eventdata"]["destinationIsIpv6"] == 'true':
        sys.exit()
    elif event_type == 'sysmon_event6':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
            opencti_key_valyue_type="hashes_SHA256"
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event7':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
            opencti_key_valyue_type="hashes_SHA256"
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event_15':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
            opencti_key_valyue_type="hashes_SHA256"
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event_22':
        try:
            wazuh_event_param = alert["data"]["win"]["eventdata"]["queryName"]
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event_23':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
            opencti_key_valyue_type="hashes_SHA256"
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event_24':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
            opencti_key_valyue_type="hashes_SHA256"
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event_25':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
            opencti_key_valyue_type="hashes_SHA256"
        except IndexError:
            sys.exit()
    else:
        sys.exit()
    api_json_body={"query": "\nquery StixCyberObservables($types: [String], $filters: [StixCyberObservablesFiltering], $search: String, $first: Int, $after: ID, $orderBy: StixCyberObservablesOrdering, $orderMode: OrderingMode) {\nstixCyberObservables(types: $types, filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {\nedges {\nnode {\n\nid\nstandard_id\nentity_type\nparent_types\nspec_version\ncreated_at\nupdated_at\ncreatedBy {\n... on Identity {\nid\nstandard_id\nentity_type\nparent_types\nspec_version\nidentity_class\nname\ndescription\nroles\ncontact_information\nx_opencti_aliases\ncreated\nmodified\nobjectLabel {\nedges {\nnode {\nid\nvalue\ncolor\n}\n}\n}\n}\n... on Organization {\nx_opencti_organization_type\nx_opencti_reliability\n}\n... on Individual {\nx_opencti_firstname\nx_opencti_lastname\n}\n}\nobjectMarking {\nedges {\nnode {\nid\nstandard_id\nentity_type\ndefinition_type\ndefinition\ncreated\nmodified\nx_opencti_order\nx_opencti_color\n}\n}\n}\nobjectLabel {\nedges {\nnode {\nid\nvalue\ncolor\n}\n}\n}\nexternalReferences {\nedges {\nnode {\nid\nstandard_id\nentity_type\nsource_name\ndescription\nurl\nhash\nexternal_id\ncreated\nmodified\nimportFiles {\nedges {\nnode {\nid\nname\nsize\nmetaData {\nmimetype\nversion\n}\n}\n}\n}\n}\n}\n}\nobservable_value\nx_opencti_description\nx_opencti_score\nindicators {\nedges {\nnode {\nid\npattern\npattern_type\n}\n}\n}\n... on AutonomousSystem {\nnumber\nname\nrir\n}\n... on Directory {\npath\npath_enc\nctime\nmtime\natime\n}\n... on DomainName {\nvalue\n}\n... on EmailAddr {\nvalue\ndisplay_name\n}\n... on EmailMessage {\nis_multipart\nattribute_date\ncontent_type\nmessage_id\nsubject\nreceived_lines\nbody\n}\n... on Artifact {\nmime_type\npayload_bin\nurl\nencryption_algorithm\ndecryption_key\nhashes {\nalgorithm\nhash\n}\nimportFiles {\nedges {\nnode {\nid\nname\nsize\n}\n}\n}\n}\n... on StixFile {\nextensions\nsize\nname\nname_enc\nmagic_number_hex\nmime_type\nctime\nmtime\natime\nx_opencti_additional_names\nhashes {\n  algorithm\n  hash\n}   \n}\n... on X509Certificate {\nis_self_signed\nversion\nserial_number\nsignature_algorithm\nissuer\nsubject\nsubject_public_key_algorithm\nsubject_public_key_modulus\nsubject_public_key_exponent\nvalidity_not_before\nvalidity_not_after\nhashes {\n  algorithm\n  hash\n}\n}\n... on IPv4Addr {\nvalue\n}\n... on IPv6Addr {\nvalue\n}\n... on MacAddr {\nvalue\n}\n... on Mutex {\nname\n}\n... on NetworkTraffic {\nextensions\nstart\nend\nis_active\nsrc_port\ndst_port\nprotocols\nsrc_byte_count\ndst_byte_count\nsrc_packets\ndst_packets\n}\n... on Process {\nextensions\nis_hidden\npid\ncreated_time\ncwd\ncommand_line\nenvironment_variables\n}\n... on Software {\nname\ncpe\nswid\nlanguages\nvendor\nversion\n}\n... on Url {\nvalue\n}\n... on UserAccount {\nextensions\nuser_id\ncredential\naccount_login\naccount_type\ndisplay_name\nis_service_account\nis_privileged\ncan_escalate_privs\nis_disabled\naccount_created\naccount_expires\ncredential_last_changed\naccount_first_login\naccount_last_login\n}\n... on WindowsRegistryKey {\nattribute_key\nmodified_time\nnumber_of_subkeys\n}\n... on WindowsRegistryValueType {\nname\ndata\ndata_type\n}\n... on X509V3ExtensionsType {\nbasic_constraints\nname_constraints\npolicy_constraints\nkey_usage\nextended_key_usage\nsubject_key_identifier\nauthority_key_identifier\nsubject_alternative_name\nissuer_alternative_name\nsubject_directory_attributes\ncrl_distribution_points\ninhibit_any_policy\nprivate_key_usage_period_not_before\nprivate_key_usage_period_not_after\ncertificate_policies\npolicy_mappings\n}\n... on XOpenCTICryptographicKey {\nvalue\n}\n... on XOpenCTICryptocurrencyWallet {\nvalue\n}\n... on XOpenCTIHostname {\nvalue\n}\n... on XOpenCTIText {\nvalue\n}\n... on XOpenCTIUserAgent {\nvalue\n}\nimportFiles {\nedges {\nnode {\nid\nname\nsize\nmetaData {\nmimetype\nversion\n}\n}\n}\n}\n\n}\n}\npageInfo {\nstartCursor\nendCursor\nhasNextPage\nhasPreviousPage\nglobalCount\n}\n}\n}\n", "variables": {"types": null, "filters": [{"key": f"{opencti_key_valyue_type}", "values": [f"{wazuh_event_param}"]}]}}
    try:
        opencti_api_response = requests.post(opencti_base_url, headers=opencti_apicall_headers,json=api_json_body)
    except ConnectionError:
        alert_output["opencti"] = {}
        alert_output["integration"] = "opencti"
        alert_output["opencti"]["error"] = 'Connection Error to OpenCTI API'
        send_event(alert_output, alert["agent"])
    else:
        opencti_api_response = opencti_api_response.json()
    # Check if response includes Attributes (IoCs)
        if (opencti_api_response["data"]["stixCyberObservables"]["edges"]):
    # Generate Alert Output from OpenCTI Response
            labels_length = len(opencti_api_response["data"]["stixCyberObservables"]["edges"][0]["node"]["objectLabel"]["edges"])
            alert_output["opencti"] = {}
            alert_output["integration"] = "opencti"
            alert_output["opencti"] = opencti_api_response["data"]["stixCyberObservables"]["edges"][0]["node"]
            for i in range(labels_length):
              alert_output["opencti"][i] = opencti_api_response["data"]["stixCyberObservables"]["edges"][0]["node"]["objectLabel"]["edges"][i]
            send_event(alert_output, alert["agent"])
elif event_source == 'linux':
    if event_type == 'sysmon_event3' and alert["data"]["eventdata"]["destinationIsIpv6"] == 'false':
        try:
            dst_ip = alert["data"]["eventdata"]["DestinationIp"]
            if ipaddress.ip_address(dst_ip).is_global:
                wazuh_event_param = dst_ip
                api_json_body={"query": "\nquery StixCyberObservables($types: [String], $filters: [StixCyberObservablesFiltering], $search: String, $first: Int, $after: ID, $orderBy: StixCyberObservablesOrdering, $orderMode: OrderingMode) {\nstixCyberObservables(types: $types, filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {\nedges {\nnode {\n\nid\nstandard_id\nentity_type\nparent_types\nspec_version\ncreated_at\nupdated_at\ncreatedBy {\n... on Identity {\nid\nstandard_id\nentity_type\nparent_types\nspec_version\nidentity_class\nname\ndescription\nroles\ncontact_information\nx_opencti_aliases\ncreated\nmodified\nobjectLabel {\nedges {\nnode {\nid\nvalue\ncolor\n}\n}\n}\n}\n... on Organization {\nx_opencti_organization_type\nx_opencti_reliability\n}\n... on Individual {\nx_opencti_firstname\nx_opencti_lastname\n}\n}\nobjectMarking {\nedges {\nnode {\nid\nstandard_id\nentity_type\ndefinition_type\ndefinition\ncreated\nmodified\nx_opencti_order\nx_opencti_color\n}\n}\n}\nobjectLabel {\nedges {\nnode {\nid\nvalue\ncolor\n}\n}\n}\nexternalReferences {\nedges {\nnode {\nid\nstandard_id\nentity_type\nsource_name\ndescription\nurl\nhash\nexternal_id\ncreated\nmodified\nimportFiles {\nedges {\nnode {\nid\nname\nsize\nmetaData {\nmimetype\nversion\n}\n}\n}\n}\n}\n}\n}\nobservable_value\nx_opencti_description\nx_opencti_score\nindicators {\nedges {\nnode {\nid\npattern\npattern_type\n}\n}\n}\n... on AutonomousSystem {\nnumber\nname\nrir\n}\n... on Directory {\npath\npath_enc\nctime\nmtime\natime\n}\n... on DomainName {\nvalue\n}\n... on EmailAddr {\nvalue\ndisplay_name\n}\n... on EmailMessage {\nis_multipart\nattribute_date\ncontent_type\nmessage_id\nsubject\nreceived_lines\nbody\n}\n... on Artifact {\nmime_type\npayload_bin\nurl\nencryption_algorithm\ndecryption_key\nhashes {\nalgorithm\nhash\n}\nimportFiles {\nedges {\nnode {\nid\nname\nsize\n}\n}\n}\n}\n... on StixFile {\nextensions\nsize\nname\nname_enc\nmagic_number_hex\nmime_type\nctime\nmtime\natime\nx_opencti_additional_names\nhashes {\n  algorithm\n  hash\n}   \n}\n... on X509Certificate {\nis_self_signed\nversion\nserial_number\nsignature_algorithm\nissuer\nsubject\nsubject_public_key_algorithm\nsubject_public_key_modulus\nsubject_public_key_exponent\nvalidity_not_before\nvalidity_not_after\nhashes {\n  algorithm\n  hash\n}\n}\n... on IPv4Addr {\nvalue\n}\n... on IPv6Addr {\nvalue\n}\n... on MacAddr {\nvalue\n}\n... on Mutex {\nname\n}\n... on NetworkTraffic {\nextensions\nstart\nend\nis_active\nsrc_port\ndst_port\nprotocols\nsrc_byte_count\ndst_byte_count\nsrc_packets\ndst_packets\n}\n... on Process {\nextensions\nis_hidden\npid\ncreated_time\ncwd\ncommand_line\nenvironment_variables\n}\n... on Software {\nname\ncpe\nswid\nlanguages\nvendor\nversion\n}\n... on Url {\nvalue\n}\n... on UserAccount {\nextensions\nuser_id\ncredential\naccount_login\naccount_type\ndisplay_name\nis_service_account\nis_privileged\ncan_escalate_privs\nis_disabled\naccount_created\naccount_expires\ncredential_last_changed\naccount_first_login\naccount_last_login\n}\n... on WindowsRegistryKey {\nattribute_key\nmodified_time\nnumber_of_subkeys\n}\n... on WindowsRegistryValueType {\nname\ndata\ndata_type\n}\n... on X509V3ExtensionsType {\nbasic_constraints\nname_constraints\npolicy_constraints\nkey_usage\nextended_key_usage\nsubject_key_identifier\nauthority_key_identifier\nsubject_alternative_name\nissuer_alternative_name\nsubject_directory_attributes\ncrl_distribution_points\ninhibit_any_policy\nprivate_key_usage_period_not_before\nprivate_key_usage_period_not_after\ncertificate_policies\npolicy_mappings\n}\n... on XOpenCTICryptographicKey {\nvalue\n}\n... on XOpenCTICryptocurrencyWallet {\nvalue\n}\n... on XOpenCTIHostname {\nvalue\n}\n... on XOpenCTIText {\nvalue\n}\n... on XOpenCTIUserAgent {\nvalue\n}\nimportFiles {\nedges {\nnode {\nid\nname\nsize\nmetaData {\nmimetype\nversion\n}\n}\n}\n}\n\n}\n}\npageInfo {\nstartCursor\nendCursor\nhasNextPage\nhasPreviousPage\nglobalCount\n}\n}\n}\n", "variables": {"types": null, "filters": [{"key": f"{opencti_key_valyue_type}", "values": [f"{wazuh_event_param}"]}]}}
                try:
                    opencti_api_response = requests.post(opencti_base_url, headers=opencti_apicall_headers,json=api_json_body)
                except ConnectionError:
                    alert_output["opencti"] = {}
                    alert_output["integration"] = "opencti"
                    alert_output["opencti"]["error"] = 'Connection Error to OpenCTI API'
                    send_event(alert_output, alert["agent"])
                else:
                    opencti_api_response = opencti_api_response.json()
        # Check if response includes Attributes (IoCs)
                    if (opencti_api_response["data"]["stixCyberObservables"]["edges"]):
                # Generate Alert Output from OpenCTI Response
                        labels_length = len(opencti_api_response["data"]["stixCyberObservables"]["edges"][0]["node"]["objectLabel"]["edges"])
                        alert_output["opencti"] = {}
                        alert_output["integration"] = "opencti"
                        alert_output["opencti"] = opencti_api_response["data"]["stixCyberObservables"]["edges"][0]["node"]
                        for i in range(labels_length):
                          alert_output["opencti"][i] = opencti_api_response["data"]["stixCyberObservables"]["edges"][0]["node"]["objectLabel"]["edges"][i]
                        send_event(alert_output, alert["agent"])
            else:
                sys.exit()
        except IndexError:
            sys.exit()
    else:
        sys.exit()
elif event_source == 'ossec' and event_type == "syscheck_entry_added":
    try:
        wazuh_event_param = alert["syscheck"]["sha256_after"]
        opencti_key_valyue_type="hashes_SHA256"
    except IndexError:
        sys.exit()
    api_json_body={"query": "\nquery StixCyberObservables($types: [String], $filters: [StixCyberObservablesFiltering], $search: String, $first: Int, $after: ID, $orderBy: StixCyberObservablesOrdering, $orderMode: OrderingMode) {\nstixCyberObservables(types: $types, filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {\nedges {\nnode {\n\nid\nstandard_id\nentity_type\nparent_types\nspec_version\ncreated_at\nupdated_at\ncreatedBy {\n... on Identity {\nid\nstandard_id\nentity_type\nparent_types\nspec_version\nidentity_class\nname\ndescription\nroles\ncontact_information\nx_opencti_aliases\ncreated\nmodified\nobjectLabel {\nedges {\nnode {\nid\nvalue\ncolor\n}\n}\n}\n}\n... on Organization {\nx_opencti_organization_type\nx_opencti_reliability\n}\n... on Individual {\nx_opencti_firstname\nx_opencti_lastname\n}\n}\nobjectMarking {\nedges {\nnode {\nid\nstandard_id\nentity_type\ndefinition_type\ndefinition\ncreated\nmodified\nx_opencti_order\nx_opencti_color\n}\n}\n}\nobjectLabel {\nedges {\nnode {\nid\nvalue\ncolor\n}\n}\n}\nexternalReferences {\nedges {\nnode {\nid\nstandard_id\nentity_type\nsource_name\ndescription\nurl\nhash\nexternal_id\ncreated\nmodified\nimportFiles {\nedges {\nnode {\nid\nname\nsize\nmetaData {\nmimetype\nversion\n}\n}\n}\n}\n}\n}\n}\nobservable_value\nx_opencti_description\nx_opencti_score\nindicators {\nedges {\nnode {\nid\npattern\npattern_type\n}\n}\n}\n... on AutonomousSystem {\nnumber\nname\nrir\n}\n... on Directory {\npath\npath_enc\nctime\nmtime\natime\n}\n... on DomainName {\nvalue\n}\n... on EmailAddr {\nvalue\ndisplay_name\n}\n... on EmailMessage {\nis_multipart\nattribute_date\ncontent_type\nmessage_id\nsubject\nreceived_lines\nbody\n}\n... on Artifact {\nmime_type\npayload_bin\nurl\nencryption_algorithm\ndecryption_key\nhashes {\nalgorithm\nhash\n}\nimportFiles {\nedges {\nnode {\nid\nname\nsize\n}\n}\n}\n}\n... on StixFile {\nextensions\nsize\nname\nname_enc\nmagic_number_hex\nmime_type\nctime\nmtime\natime\nx_opencti_additional_names\nhashes {\n  algorithm\n  hash\n}   \n}\n... on X509Certificate {\nis_self_signed\nversion\nserial_number\nsignature_algorithm\nissuer\nsubject\nsubject_public_key_algorithm\nsubject_public_key_modulus\nsubject_public_key_exponent\nvalidity_not_before\nvalidity_not_after\nhashes {\n  algorithm\n  hash\n}\n}\n... on IPv4Addr {\nvalue\n}\n... on IPv6Addr {\nvalue\n}\n... on MacAddr {\nvalue\n}\n... on Mutex {\nname\n}\n... on NetworkTraffic {\nextensions\nstart\nend\nis_active\nsrc_port\ndst_port\nprotocols\nsrc_byte_count\ndst_byte_count\nsrc_packets\ndst_packets\n}\n... on Process {\nextensions\nis_hidden\npid\ncreated_time\ncwd\ncommand_line\nenvironment_variables\n}\n... on Software {\nname\ncpe\nswid\nlanguages\nvendor\nversion\n}\n... on Url {\nvalue\n}\n... on UserAccount {\nextensions\nuser_id\ncredential\naccount_login\naccount_type\ndisplay_name\nis_service_account\nis_privileged\ncan_escalate_privs\nis_disabled\naccount_created\naccount_expires\ncredential_last_changed\naccount_first_login\naccount_last_login\n}\n... on WindowsRegistryKey {\nattribute_key\nmodified_time\nnumber_of_subkeys\n}\n... on WindowsRegistryValueType {\nname\ndata\ndata_type\n}\n... on X509V3ExtensionsType {\nbasic_constraints\nname_constraints\npolicy_constraints\nkey_usage\nextended_key_usage\nsubject_key_identifier\nauthority_key_identifier\nsubject_alternative_name\nissuer_alternative_name\nsubject_directory_attributes\ncrl_distribution_points\ninhibit_any_policy\nprivate_key_usage_period_not_before\nprivate_key_usage_period_not_after\ncertificate_policies\npolicy_mappings\n}\n... on XOpenCTICryptographicKey {\nvalue\n}\n... on XOpenCTICryptocurrencyWallet {\nvalue\n}\n... on XOpenCTIHostname {\nvalue\n}\n... on XOpenCTIText {\nvalue\n}\n... on XOpenCTIUserAgent {\nvalue\n}\nimportFiles {\nedges {\nnode {\nid\nname\nsize\nmetaData {\nmimetype\nversion\n}\n}\n}\n}\n\n}\n}\npageInfo {\nstartCursor\nendCursor\nhasNextPage\nhasPreviousPage\nglobalCount\n}\n}\n}\n", "variables": {"types": null, "filters": [{"key": f"{opencti_key_valyue_type}", "values": [f"{wazuh_event_param}"]}]}}
    try:
        opencti_api_response = requests.post(opencti_base_url, headers=opencti_apicall_headers,json=api_json_body)
    except ConnectionError:
        alert_output["opencti"] = {}
        alert_output["integration"] = "opencti"
        alert_output["opencti"]["error"] = 'Connection Error to OpenCTI API'
        send_event(alert_output, alert["agent"])
    else:
        opencti_api_response = opencti_api_response.json()
    # Check if response includes Attributes (IoCs)
        if (opencti_api_response["data"]["stixCyberObservables"]["edges"]):
    # Generate Alert Output from OpenCTI Response
            labels_length = len(opencti_api_response["data"]["stixCyberObservables"]["edges"][0]["node"]["objectLabel"]["edges"])
            alert_output["opencti"] = {}
            alert_output["integration"] = "opencti"
            alert_output["opencti"] = opencti_api_response["data"]["stixCyberObservables"]["edges"][0]["node"]
            for i in range(labels_length):
              alert_output["opencti"][i] = opencti_api_response["data"]["stixCyberObservables"]["edges"][0]["node"]["objectLabel"]["edges"][i]
            send_event(alert_output, alert["agent"])
else:
    sys.exit()
