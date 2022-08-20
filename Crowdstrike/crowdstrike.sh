#!/bin/bash
results_file=/tmp/crowdstrike.json
current_file=/tmp/crowdstrike_run.json
output_file=/tmp/crowdstrike_results.json
compare_file=/tmp/crowdstrike_compare.json
/usr/bin/cat /var/log/crowdstrike/falconhoseclient/output | /usr/bin/jq -c '.' > $current_file

/usr/bin/diff -u $compare_file $current_file > /tmp/results.patch
/usr/bin/patch $results_file /tmp/results.patch

/usr/bin/mv $current_file $compare_file
