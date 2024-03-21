#!/bin/bash

source ../../common.sh

target_script_path="/opt/ot_tools/p0f.sh"
log_file_path_prefix="/var/log/p0f-k.log."


### 以降、ログの欠損が生じる可能性がある問題の解消を確認するテスト ###
# テスト条件の設定
log_num=199
seq -w 1 ${log_num} > ${EXPECTED_DIR}/p0f-k.log  # Create expected file
log_gen_cmd="seq -w 1 ${log_num} | xargs -I{} bash -c 'sleep 0.01; echo {} > ${log_file_path_prefix}{}'"

# 設定した条件で問題を再現できることを確認する
max_try=3
for i in $(seq -w 1 ${max_try}); do
    test_init "p0f unfixed ${i}/${max_try}"
    # Clean up
    rm -f ${log_file_path_prefix}*

    # Create log files in background
    bash -c "${log_gen_cmd}" &
    bk_pid=$!

    # Execute the target script
    function exec_target_script()
    {
        bash $(pwd)/p0f_unfixed.sh $(pwd)/work
        cat $(pwd)/work/p0f-k.log >> ${ACTUAL_DIR}/p0f-k.log
    }
    while ps -p ${bk_pid} > /dev/null; do
        sleep 0.1
        exec_target_script 2>/dev/null
    done
    sleep 0.1
    exec_target_script 2>/dev/null

    test_files_contain_digits ${ACTUAL_DIR}/p0f-k.log ${EXPECTED_DIR}/p0f-k.log
    test_unmatch_file ${ACTUAL_DIR}/p0f-k.log ${EXPECTED_DIR}/p0f-k.log
done



# 問題の解消を確認する
test_init "p0f current"
# Clean up
rm -f ${log_file_path_prefix}*

# Create log files in background
bash -c "${log_gen_cmd}" &
bk_pid=$!

# Execute the target script
function exec_target_script()
{
    bash ${target_script_path} $(pwd)/work
    cat $(pwd)/work/p0f-k.log >> ${ACTUAL_DIR}/p0f-k.log
}
while ps -p ${bk_pid} > /dev/null; do
    sleep 0.1
    exec_target_script 2>/dev/null
done
sleep 0.1
exec_target_script 2>/dev/null

test_files_contain_digits ${ACTUAL_DIR}/p0f-k.log ${EXPECTED_DIR}/p0f-k.log
test_fullmatch_file ${ACTUAL_DIR}/p0f-k.log ${EXPECTED_DIR}/p0f-k.log
### 以上、ログの欠損が生じる可能性がある問題の解消を確認するテスト ###

