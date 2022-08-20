################################
### Script to run Snyk CLI Vuln Scan on Docker Images
### SOCFortress
### https://www.socfortress.co
### info@socfortress.co
################################
##########
# docker image list --> Obtain the list of Docker Images in the system
# The Snyk Scan is run on each image detected in the system
# Minimum Severity = Medium (change severity threshold if required)
# The scan result is appended to active-responses.log
##########
#!/bin/bash
# Static active response parameters
# Static active response parameters
LOCAL=`dirname $0`
#------------------------- Active Response Log File -------------------------#

LOG_FILE="/var/ossec/logs/active-responses.log"

#------------------------- Main workflow --------------------------#
#------------------------- Function to run scan on Docker Image --------------------------#
snyk_execution(){
  docker_image=$1
  /opt/snyk/snyk-linux container test "$docker_image" --json --severity-threshold=medium | jq '.vulnerabilities' | jq ".[] | {packageName, severity, id, name, version, nearestFixedInVersion, dockerfileInstruction, dockerBaseImage, nvdSeverity, publicationTime, malicious, title, cvssScore, identifiers}" | jq -c '.'
}
#------------------------- Get Docker Images and call scan function --------------------------#
docker_images_list=( $(/bin/docker image ls | tail -n +2 | awk '{ print $1 }') )
#------------------------- Append Scan Outoput to Active Response Log  --------------------------#
for docker_image in "${docker_images_list[@]}"
do
  snyk_output=$(snyk_execution $docker_image)
    if [[ $snyk_output != "" ]]
    then
        # Iterate every detected rule and append it to the LOG_FILE
        while read -r line; do
            echo $line >> ${LOG_FILE}
            sleep 0.1
        done <<< "$snyk_output"
    fi
   >> ${LOG_FILE}
  sleep 0.3
done
