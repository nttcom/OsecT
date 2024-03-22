#!/bin/bash

if [ ! -e /.dockerenv ]; then
  echo '[ERROR] This script must be run in a Docker container'
  exit 1
fi
echo "[INFO] Running tests in a Docker container"


TEST_DIR_TARGET=/opt/ot_tools/
TEST_DIR_ROOT=/home/work/sh_tests/

cd ${TEST_DIR_ROOT}/ot_tools/p0f
bash test.sh

cd ${TEST_DIR_ROOT}/ot_tools/bro
bash test.sh

cd ${TEST_DIR_ROOT}/ot_tools/suricata
bash test.sh

cd ${TEST_DIR_ROOT}/ot_tools/yaf
bash test.sh

echo "[END] All tests have been successfully completed"
