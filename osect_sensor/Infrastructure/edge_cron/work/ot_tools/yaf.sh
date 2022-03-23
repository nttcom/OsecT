#!/bin/bash

cd $1/$2 || exit
/usr/local/bin/yaf --mac -i ../$3 -o flow.yaf
/usr/local/bin/yafscii --tabular --print-header --mac --in flow.yaf --out flow.csv
cat flow.csv | /opt/ot_tools/yaf.awk > yaf_flow.log

rm flow.csv
rm flow.yaf
