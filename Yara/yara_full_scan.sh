#!/bin/bash
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

#------------------------- Set Memory Limit (KB)-------------------------#
ulimit -v 128000
#------------------------- Aadjust IFS to read files -------------------------#
SAVEIFS=$IFS
IFS=$(echo -en "\n\b")
# Static active response parameters
LOCAL=`dirname $0`
#------------------------- Folders to scan. Modify array as required -------------------------#
folders_to_scan=( "/home/" "/root/" "/opt/" )

#------------------------- Files extensions to scan. Modify array as required -------------------------#
file_extenstions_to_scan=( ".sh" ".bin" ".js" )
#------------------------- Active Response Log File -------------------------#

LOG_FILE="/var/ossec/logs/active-responses.log"

#------------------------- Main workflow --------------------------#

# Execute YARA scan on home folder and subfolders
for f in "${folders_to_scan[@]}"
do
  for f1 in $( find $f -type f); do
  yara_output=$(/usr/bin/yara -C -w -r -f -m /usr/share/yara/yara_base_ruleset_compiled.yar "$f1")
  if [[ $yara_output != "" ]]
  then
      # Iterate every detected rule and append it to the LOG_FILE
      while read -r line; do
          echo "wazuh-yara: info: $line" >> ${LOG_FILE}
      done <<< "$yara_output"
  fi
  done
done
# Execute YARA scan on files types, all locations
for e in "${file_extenstions_to_scan[@]}"
do
  for f1 in $( find / -type f | grep -F $e ); do
    yara_output=$(/usr/bin/yara -C -w -r -f -m /usr/share/yara/yara_base_ruleset_compiled.yar "$f1")
    if [[ $yara_output != "" ]]
    then
    # Iterate every detected rule and append it to the LOG_FILE
      while read -r line; do
        echo "wazuh-yara: info: $line" >> ${LOG_FILE}
      done <<< "$yara_output"
    fi
  done
done
IFS=$SAVEIFS
exit 1;
