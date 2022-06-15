#!/bin/bash

# suricata -c $1 -r $2$3 -l $4

cat /var/log/suricata/eve?*.json > $4/eve.json
rm /var/log/suricata/eve?*.json

# rm $4/fast.log
# rm $4/stats.log
