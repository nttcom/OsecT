#!/bin/bash

source ../../common.sh

target_script_path="/opt/ot_tools/bro.sh"
export raw_log_file_dir="/usr/local/zeek/logs/"
export merged_log_file_dir="realtime-1970-01-01-00:00:00/"
export merged_log_file_names=$( cat << EOS
    conn.log
    arp.log
    ns.log
    dns.log
    http.log
    mswin-browser.log
    dhcp2.log
    dhcpv6.log
    netbios-ns.log
    ssdp.log
    cclink-ief-basic.log
    cclink-ie.log
    cclink-ie-tsn.log
    cclink-ie-tsn-slmp.log
    cclink-ie-tsn-ptp.log
    bacnet_service.log
    modbus_detailed.log
EOS
)

function merged_log_to_raw_log_name_template()
{
    declare -A dict=(
            ["conn.log"]="conn*.log"
            ["arp.log"]="arp.*.log"
            ["ns.log"]="ns.*.log"
            ["dns.log"]="dns.*.log"
            ["http.log"]="http.*.log"
            ["mswin-browser.log"]="cifs.*.log"
            ["dhcp2.log"]="mydhcp.*.log"
            ["dhcpv6.log"]="dhcpv6.*.log"
            ["netbios-ns.log"]="nbns.*.log"
            ["ssdp.log"]="ssdp.*.log"
            ["cclink-ief-basic.log"]="cclink-ief-basic.*.log"
            ["cclink-ie.log"]="cclink-ie.*.log"
            ["cclink-ie-tsn.log"]="cclink-ie-tsn.*.log"
            ["cclink-ie-tsn-slmp.log"]="cclink-ie-tsn-slmp.*.log"
            ["cclink-ie-tsn-ptp.log"]="cclink-ie-tsn-ptp.*.log"
            ["bacnet_service.log"]="bacnet_service.*.log"
            ["modbus_detailed.log"]="modbus_detailed.*.log"
    )
    if [[ "${2}" == "." && "${1}" == "conn.log" ]]; then
        echo "conn.*.log"
        return 0
    fi
    if [ -n "${dict["${1}"]}" ]; then
        echo "${dict["${1}"]}"
        return 0
    fi
    echo ""
    return 1
}
export -f merged_log_to_raw_log_name_template

# gen_raw_logs <value(log_num)>
function gen_raw_logs()
{
    for f in ${merged_log_file_names}; do
        f=$(merged_log_to_raw_log_name_template ${f} .)
        echo "echo ${1} > ${raw_log_file_dir}${f}" | \
            sed -e "s/\*/${1}/g" | \
            bash
    done
    # ls -lh ${raw_log_file_dir}
}
export -f gen_raw_logs

### 以降、ログの欠損が生じる可能性がある問題の解消を確認するテスト ###
# テスト条件の設定
log_num=99

## 以降、正解データの作成 ##
rm -rf ${raw_log_file_dir}*
expected_log_dir=${EXPECTED_DIR}${merged_log_file_dir}
rm -rf ${expected_log_dir}
mkdir -p ${expected_log_dir}
for f in ${merged_log_file_names}; do
    f=$(merged_log_to_raw_log_name_template ${f} .)
    f=${raw_log_file_dir}$(echo ${f} | sed -e 's/\*/0/g')
    seq -w 1 ${log_num} > ${f}
done
# 下記、ログ生成処理とログ結合処理が同時に実行されないため、以前のスクリプトで正解データの作成しても問題ない
bash -c "$(pwd)/bro_unfixed.sh ${EXPECTED_DIR} ${merged_log_file_dir} PADDING True True"
## 以上、正解データの作成 ##


# 以下、ログ生成コマンド
log_gen_cmd="seq -w 1 ${log_num} | xargs -I{} bash -c 'sleep 0.005; gen_raw_logs {}'"

## 以降、設定した条件で問題を再現できることを確認する ##
max_try=3
for i in $(seq -w 1 ${max_try}); do
    test_init "bro unfixed ${i}/${max_try}"
    actual_log_dir=${ACTUAL_DIR}${merged_log_file_dir}
    mkdir -p ${actual_log_dir}
    
    # Create log files in background
    bash -c "${log_gen_cmd}" &
    bk_pid=$!
    
    # Execute the target script
    function exec_target_script()
    {
        bash $(pwd)/bro_unfixed.sh ${ACTUAL_DIR} ${merged_log_file_dir} PADDING True True
        for f in ${merged_log_file_names}; do
            # とりあえずマージする（要後処理）
            cat ${actual_log_dir}${f} >> ${actual_log_dir}tmp.${f}.swap_merged
        done
    }
    while ps -p ${bk_pid} > /dev/null; do
        sleep 0.05
        exec_target_script 2>/dev/null
    done
    sleep 0.1
    exec_target_script 2>/dev/null  # 後処理、取り込み残しログの取り込み
    i=0
    for log_file_name in ${merged_log_file_names}; do
        # 後処理準備(余計なコメント行の削除を行うため)
        f=$(merged_log_to_raw_log_name_template ${log_file_name} . | sed -e "s/\*/$((${log_num}+1))/g")
        cat ${actual_log_dir}tmp.${log_file_name}.swap_merged | sort > ${raw_log_file_dir}${f}
    done
    exec_target_script v 2>/dev/null  # 後処理
    rm -f tmp.${actual_log_dir}*.swap_merged

    for log_file_name in ${merged_log_file_names}; do
        test_no_empty_files ${actual_log_dir}${log_file_name} ${expected_log_dir}${log_file_name}
        test_unmatch_file ${actual_log_dir}${log_file_name} ${expected_log_dir}${log_file_name}
    done
done
## 以上、設定した条件で問題を再現できることを確認する ##


## 以降、問題の解消を確認する ##
test_init "bro current"
mkdir -p ${actual_log_dir}

actual_log_dir=${ACTUAL_DIR}${merged_log_file_dir}
mkdir -p ${actual_log_dir}

# Create log files in background
bash -c "${log_gen_cmd}" &
bk_pid=$!

# Execute the target script
function exec_target_script()
{
    bash ${target_script_path} ${ACTUAL_DIR} ${merged_log_file_dir} PADDING True True
    for f in ${merged_log_file_names}; do
        # とりあえずマージする（要後処理）
        cat ${actual_log_dir}${f} >> ${actual_log_dir}tmp.${f}.swap_merged
    done
}
while ps -p ${bk_pid} > /dev/null; do
    sleep 0.05
    exec_target_script 2>/dev/null
done
sleep 0.1
exec_target_script 2>/dev/null  # 後処理、取り込み残しログの取り込み
i=0
for log_file_name in ${merged_log_file_names}; do
    # 後処理準備(余計なコメント行の削除を行うため)
    f=$(merged_log_to_raw_log_name_template ${log_file_name} . | sed -e "s/\*/$((${log_num}+1))/g")
    cat ${actual_log_dir}tmp.${log_file_name}.swap_merged | sort > ${raw_log_file_dir}${f}
done
exec_target_script v 2>/dev/null  # 後処理
rm -f tmp.${actual_log_dir}*.swap_merged

for log_file_name in ${merged_log_file_names}; do
    test_no_empty_files ${actual_log_dir}${log_file_name} ${expected_log_dir}${log_file_name}
    test_fullmatch_file ${actual_log_dir}${log_file_name} ${expected_log_dir}${log_file_name}
done
## 以上、問題の解消を確認する ##

### 以上、ログの欠損が生じる可能性がある問題の解消を確認するテスト ###
