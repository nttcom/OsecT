#!/bin/bash

source ../../common.sh

target_script_path="/opt/ot_tools/suricata.sh"
log_file_path_prefix="/var/log/suricata/"


### 以降、ログの欠損が生じる可能性がある問題の解消を確認するテスト ###
# テスト条件の設定
log_num=399
seq -w 1 ${log_num} > ${EXPECTED_DIR}eve.json  # Create expected file
log_gen_cmd="seq -w 1 ${log_num} | xargs -I{} bash -c 'sleep 0.001; echo {} > ${log_file_path_prefix}eve-{}-{}-{}-{}:{}.json'"

# 設定した条件で問題を再現できることを確認する
max_try=3
for i in $(seq -w 1 ${max_try}); do
    test_init "suricata unfixed ${i}/${max_try}"
    # Clean up
    rm -f ${log_file_path_prefix}*.json

    # Create log files in background
    bash -c "${log_gen_cmd}" &
    bk_pid=$!

    # Execute the target script
    function exec_target_script()
    {
        bash $(pwd)/suricata_unfixed.sh PADDING PADDING PADDING $(pwd)/work/
        cat $(pwd)/work/eve.json >> ${ACTUAL_DIR}eve.json
    }
    while ps -p ${bk_pid} > /dev/null; do
        sleep 0.1
        exec_target_script 2>/dev/null
    done
    sleep 0.1
    exec_target_script 2>/dev/null

    test_files_contain_digits ${ACTUAL_DIR}eve.json ${EXPECTED_DIR}eve.json
    test_unmatch_file ${ACTUAL_DIR}eve.json ${EXPECTED_DIR}eve.json
done



# 問題の解消を確認する
test_init "suricata current"
# Clean up
rm -f ${log_file_path_prefix}*.json

# Create log files in background
bash -c "${log_gen_cmd}" &
bk_pid=$!

# Execute the target script
function exec_target_script()
{
    bash ${target_script_path} PADDING PADDING PADDING $(pwd)/work/
    cat $(pwd)/work/eve.json >> ${ACTUAL_DIR}eve.json
}
while ps -p ${bk_pid} > /dev/null; do
    sleep 0.1
    exec_target_script 2>/dev/null
done
sleep 0.1
exec_target_script 2>/dev/null

test_files_contain_digits ${ACTUAL_DIR}eve.json ${EXPECTED_DIR}eve.json
test_fullmatch_file ${ACTUAL_DIR}eve.json ${EXPECTED_DIR}eve.json
### 以上、ログの欠損が生じる可能性がある問題の解消を確認するテスト ###
