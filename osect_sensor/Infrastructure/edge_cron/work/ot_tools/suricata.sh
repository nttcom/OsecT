#!/bin/bash

# suricata -c $1 -r $2$3 -l $4

tmp_files=$(ls /var/log/suricata/eve?*.json)
cat ${tmp_files} > $4/eve.json
rm ${tmp_files}

# rm $4/fast.log
# rm $4/stats.log
