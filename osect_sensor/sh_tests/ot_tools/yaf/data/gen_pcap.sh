#!/bin/bash

# 参考: https://tools.netsa.cert.org/yaf/yaf.html

if [[ "$(which tcprewrite)" == "" ]]; then
    apt-get install -y　tcpreplay
fi

# NOTE: seedのプレフィックスが0の場合、pcapが正常に生成されないことがある
seed="$(echo ${1} | sed 's/^0*//g')"
outfile="${2}"
tcprewrite --fixcsum --seed=${seed} --infile=$(dirname $0)/init/udplite.pcap --outfile=${outfile}
