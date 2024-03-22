#!/bin/bash

source ../../common.sh

target_script_path="/opt/ot_tools/yaf.sh"
unfixed_script_path=$(pwd)/yaf_unfixed.sh
log_file_path_prefix="/var/log/yaf/"
pcap_gen_script_path=$(pwd)/data/gen_pcap.sh

### 以降、ログの欠損が生じる可能性がある問題の解消を確認するテスト ###
# テスト条件の設定
log_num=199

rm -rf ${WORK_DIR}
pcap_dir=$(dirname $0)/data/init/tmp.pcap/
rm -rf ${pcap_dir}
mkdir -p ${pcap_dir}

# yafのログを生成するためのpcapデータの作成
seq -w 1 ${log_num} | xargs -I{} ${pcap_gen_script_path} {} ${pcap_dir}flow.{}.pcap 2>/dev/null
log_gen_cmd="seq -w 1 ${log_num} | xargs -I{} bash -c '/usr/local/bin/yaf --mac --in ${pcap_dir}flow.{}.pcap --out ${log_file_path_prefix}flow{}.yaf'"
bash -c "${log_gen_cmd}"

# 正解データの作成
mkdir -p ${ACTUAL_DIR}
bash ${unfixed_script_path} ${ACTUAL_DIR}
cat ${ACTUAL_DIR}yaf_flow.log | tail -n +2 > ${EXPECTED_DIR}yaf_flow.log

# 以下、問題の再現が出来なかったためコメントアウト
# 設定した条件で問題を再現できることを確認する
# max_try=3
# for i in $(seq -w 1 ${max_try}); do
#     test_init "yaf unfixed ${i}/${max_try}"

#     # Create log files in background
#     bash -c "${log_gen_cmd}" &
#     bk_pid=$!

#     # Execute the target script
#     function exec_target_script()
#     {
#         # ls -lh ${log_file_path_prefix}*.yaf | wc -l
#         bash ${unfixed_script_path} ${ACTUAL_DIR}
#         cat ${ACTUAL_DIR}yaf_flow.log | tail -n +2 >> ${ACTUAL_DIR}result.log
#     }
#     while ps -p ${bk_pid} > /dev/null; do
#         sleep 0.1
#         exec_target_script 2>/dev/null
#     done
#     sleep 0.1
#     exec_target_script 2>/dev/null

#     test_no_empty_files ${ACTUAL_DIR}result.log
#     test_fullmatch_file ${ACTUAL_DIR}result.log ${EXPECTED_DIR}yaf_flow.log
#     # test_unmatch_file ${ACTUAL_DIR}result.log ${EXPECTED_DIR}yaf_flow.log
# done


# 問題の解消を確認する
test_init "yaf current"

bash -c "${log_gen_cmd}" &
bk_pid=$!

# Execute the target script
function exec_target_script()
{
    bash ${unfixed_script_path} ${ACTUAL_DIR}
    cat ${ACTUAL_DIR}yaf_flow.log | tail -n +2 >> ${ACTUAL_DIR}result.log
}
while ps -p ${bk_pid} > /dev/null; do
    sleep 0.1
    exec_target_script 2>/dev/null
done
sleep 0.1
exec_target_script 2>/dev/null

test_no_empty_files ${ACTUAL_DIR}result.log
test_fullmatch_file ${ACTUAL_DIR}result.log ${EXPECTED_DIR}yaf_flow.log
test_line_num ${ACTUAL_DIR}result.log $((${log_num}*2))
### 以上、ログの欠損が生じる可能性がある問題の解消を確認するテスト ###
