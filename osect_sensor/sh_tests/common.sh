#!/bin/bash

if [ ! -e /.dockerenv ]; then
  echo '[ERROR] This script must be run in a Docker container'
  exit 1
fi

DATA_DIR="data/"
INIT_DIR="${DATA_DIR}init/"
EXPECTED_DIR="${DATA_DIR}expected/"
WORK_DIR="work/"
ACTUAL_DIR="${WORK_DIR}actual/"
test_init() {
    local name=$1
    echo ""
    echo "[TEST_NAME] ${name}"
    rm -rf ${WORK_DIR}
    mkdir -p ${WORK_DIR}
    cp -rp ${INIT_DIR} ${ACTUAL_DIR}
}

test_line_num() {
    local cmd="test \$(cat ${1} | wc -l) -eq ${2}"
    echo "[TEST_CMD] ${cmd}"
    bash -c "${cmd}"
    sts="$?"
    if [ $sts -eq 0 ]; then
        echo "<<< OK >>> ${FUNCNAME[0]}"
        echo "----------"
    else
        echo "!!! NG !!! ${FUNCNAME[0]}"
        echo "actual: $(cat ${1} | wc -l)"
        exit 1
    fi
}

test_fullmatch_dir() {
    local cmd="diff -r ${ACTUAL_DIR} ${EXPECTED_DIR} $*"
    echo "[TEST_CMD] ${cmd}"
    bash -c "${cmd}"
    sts="$?"
    if [ $sts -eq 0 ]; then
        echo "<<< OK >>> ${FUNCNAME[0]}"
        echo "----------"
    else
        echo "!!! NG !!! ${FUNCNAME[0]}"
        exit 1
    fi
}

test_fullmatch_file() {
    local cmd="diff -r $*"
    echo "[TEST_CMD] ${cmd}"
    bash -c "${cmd}"
    sts="$?"
    if [ $sts -eq 0 ]; then
        echo "<<< OK >>> ${FUNCNAME[0]}"
        echo "----------"
    else
        echo "!!! NG !!! ${FUNCNAME[0]}"
        exit 1
    fi
}

test_unmatch_file() {
    local cmd="diff $* > /dev/null"
    echo "[TEST_CMD] ${cmd}"
    bash -c "${cmd}"
    sts="$?"
    if [ $sts -ne 0 ]; then
        echo "<<< OK >>> ${FUNCNAME[0]}"
        echo "----------"
        return 0
    fi
    echo "!!! NG !!! ${FUNCNAME[0]}"
    exit 1
}

test_no_empty_files() {
    local cmd="ls $* | xargs -I{} bash -c 'cat {} | grep -cE ^.+$'"
    echo "[TEST_CMD] ${cmd}"
    for c in $(bash -c "${cmd}"); do
        if [ $c -eq 0 ]; then
            echo "<<< NG >>> ${FUNCNAME[0]}"
            ls $* | xargs -I{} bash -c 'if [ $(cat {} | grep -cE ^.+$) -eq 0 ]; then echo "> empty file: {}"; fi'
            exit 1
        fi
    done
    echo "<<< OK >>> ${FUNCNAME[0]}"
    echo "----------"
    return 0
}

test_files_contain_digits() {
    local cmd="ls $* | xargs -I{} bash -c 'cat {} | grep -cE ^[0-9]+$'"
    echo "[TEST_CMD] ${cmd}"
    for c in $(bash -c "${cmd}"); do
        if [ $c -eq 0 ]; then
            echo "<<< NG >>> ${FUNCNAME[0]}"
            ls $* | xargs -I{} bash -c 'if [ $(cat {} | grep -cE ^[0-9]+$) -eq 0 ]; then echo "> empty file: {}"; fi'
            exit 1
        fi
    done
    echo "<<< OK >>> ${FUNCNAME[0]}"
    echo "----------"
    return 0
}