#!/bin/bash

WORK_PATH=$(cd $(dirname $0); pwd)

COMPRESSION_TYPE=gzip
EXEC_PLUGIN_NAME=osect_probe_on_docker

PLUGINS_FILE_NAME=osect_probe_on_docker.py
PLUGINS_IN_PATH=${WORK_PATH}/plugins
PLUGINS_OUT_PATH=/usr/lib/python3/dist-packages/sos/report/plugins

LOGS_PATH=$(cd ${WORK_PATH}/../..; pwd)

export SOS_LOGS_PATH=${LOGS_PATH}


if [[ `whoami` != "root" ]]; then
    echo "Please execute with root privileges."
    exit 1
fi

if [ ! -d ${PLUGINS_OUT_PATH} ]; then
    echo "sos report plugins folder does not exist."
    exit 1
fi

cp -p ${PLUGINS_IN_PATH}/${PLUGINS_FILE_NAME} ${PLUGINS_OUT_PATH}/${PLUGINS_FILE_NAME}

sos report --batch --all-logs -z ${COMPRESSION_TYPE} -o ${EXEC_PLUGIN_NAME}
