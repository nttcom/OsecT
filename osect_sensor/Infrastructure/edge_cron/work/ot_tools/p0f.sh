#!/bin/bash

cd $1/$2
tmp_files=$(ls /var/log/p0f-k.log.*)
cat ${tmp_files} > p0f-k.log
chmod 644 p0f-k.log
rm ${tmp_files}
