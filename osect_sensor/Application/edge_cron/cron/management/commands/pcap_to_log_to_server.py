import gc
import glob
import io
import logging
import math
import mimetypes
import os
import platform
import random
import shutil
import tarfile
import time
import datetime
from multiprocessing import Pool
from subprocess import Popen

import requests
import zstandard as zstd
import serial
from common.common_config import (
    ALLOWED_LOG_EXT,  # BACNET_SHELL_COMMAND,
    ALLOWED_PCAP_EXT,
    API_URL,
    BACNET_ENABLE,
    BRO_SHELL_COMMAND,
    CLIENT_CERTIFICATE_PATH,
    COMPRESS_LEVEL,
    FUNC_RESTRICTION,
    LABEL_ID,
    MODBUS_ENABLE,
    P0F_SHELL_COMMAND,
    PCAP_ANALYZE_FILE_PATH,
    PCAP_COMPLETE_FILE_PATH,
    PCAP_SERVER_UPLOADING_FILE_PATH,
    PCAP_TO_DB_CPU,
    PCAP_UPLOADED_FILE_PATH,
    SEND_REQUST_TIMEOUT,
    SURICATA_ENABLE,
    SURICATA_SHELL_COMMAND,
    SURICATA_YAML,
    YAF_ENABLE,
    YAF_SHELL_COMMAND,
    BACNET_ENABLE,
    MODBUS_ENABLE,
    PCAP_TO_DB_CPU,
    PCAP_SERVER_UPLOADING_FILE_PATH,
    API_URL,
    LABEL_ID,
    CLIENT_CERTIFICATE_PATH,
    IS_CLOSED_NETWORK,
)

# from common.common_function import pcap2log
from django.core.management.base import BaseCommand
from edge_cron.settings import BASE_DIR

logger = logging.getLogger("edge_cron")


class Command(BaseCommand):
    # python manage.py help pcap_to_log_to_serverで表示されるメッセージ
    help = "pcap_to_log_to_server function"

    # コマンドが実行された際に呼ばれるメソッド
    def handle(self, *args, **options):
        """
        pcapファイルをログファイルに変換後、ログファイルをSaaSに送付するカスタムコマンド。
        :param args:
        :param options:
        """
        logger.info("pcap to log to server start")
        start_time = time.perf_counter()

        # プラットフォームの取得
        os_name = platform.system()
        if os_name == "Windows":
            logger.error("no support platform")
            return

        # PCAPの一覧を読み込む
        pcap_list, allowed_ext_list = get_pcap_list()
        pcap_num = len(pcap_list)
        logger.debug("DEBUG pcap_num=" + str(pcap_num))
        logger.debug(str(pcap_list))

        # if pcap_num == 0:
        #    logger.info(
        #        "There is no target file [" + ", ".join(allowed_ext_list) + "]"
        #    )
        #    return

        start = time.time()
        logger.info("{} ".format("start pcap_to_log"))
        # PCAP ファイルをログファイルに変換する
        analyze_pcap_dir_list, analyze_pcap_list = pcap_to_log(pcap_list)
        log_info(start, "end pcap_to_log")

        # 処理済みのPCAPファイルを移動
        # move_pcap_file(analyze_pcap_list)
        # log_info(start, "end move_pcap_file")

        # 処理済みのログが含まれるディレクトリを完了ディレクトリに移動
        move_pcap_dir(analyze_pcap_dir_list, PCAP_COMPLETE_FILE_PATH)

        # 圧縮対象のログが含まれるディレクトリを取得
        complete_dir_list = []
        for dir_path in analyze_pcap_dir_list:
            complete_dir_list.append(
                PCAP_COMPLETE_FILE_PATH + os.path.basename(dir_path)
            )

        # ログファイルを圧縮する
        for log_dir in complete_dir_list:
            dir_name = os.path.basename(log_dir)

            bio = io.BytesIO()
            # アーカイブ (tar)
            with tarfile.open(
                fileobj=bio,
                mode="w",
            ) as tar:
                for file_name in os.listdir(log_dir):
                    tar.add(os.path.join(log_dir, file_name), arcname=file_name)

            # 圧縮 (zstandard)
            compress_name = dir_name + ALLOWED_LOG_EXT
            cctx = zstd.ZstdCompressor(level=COMPRESS_LEVEL)
            with zstd.open(
                PCAP_SERVER_UPLOADING_FILE_PATH + compress_name,
                "wb",
                cctx=cctx,
            ) as zst:
                zst.write(bio.getvalue())

        # 送信するログファイルのリストを作成する。送信漏れを考慮しディレクトリ内にあるzipファイルすべてを探索する
        tar_list = sorted(
            glob.glob(
                PCAP_SERVER_UPLOADING_FILE_PATH + "**/*" + ALLOWED_LOG_EXT,
                recursive=True,
            )
        )
        end_time = time.perf_counter()

        # 乱数 < 処理時間の場合はsleepしない
        # processing_time = math.ceil(end_time - start_time)
        # sleep_time = max(0, (random.randrange(1, 60, 1) - processing_time))
        # time.sleep(sleep_time)
        # logger.info("sleep " + str(sleep_time) + "s")

        try:
            if IS_CLOSED_NETWORK:
                # コア網チェック
                with serial.Serial("/dev/ttyUSB1", baudrate=115200, timeout=1) as sara:
                    sara.write(b"at\r\n")
                    b = sara.read(16)
                    cnum = b.decode().split("\n")

                if "OK\r" in cnum:
                    # ログ送信
                    send_server(tar_list)
                else:
                    logger.error(
                        "can not send compressed file. Unable to connect to closed network. "
                    )
            else:
                # ログ送信
                send_server(tar_list)
        except Exception as e:
            logger.error("can not send compressed file. " + str(e))

        gc.collect()
        log_info(start, "end send compressed log")
        logger.info("pcap to log done")


def wrapper_log_function(func_type, analyze_full_path, dir_name, pcap_name):
    if func_type == 0:
        # broログの処理
        logger.info("execute: " + BRO_SHELL_COMMAND)
        proc = Popen(
            BRO_SHELL_COMMAND
            + " "
            + analyze_full_path
            + " "
            + dir_name
            + " "
            + pcap_name
            + " "
            + str(BACNET_ENABLE)
            + " "
            + str(MODBUS_ENABLE),
            shell=True,
        )
        proc.wait()
    elif func_type == 1:
        # p0fのログ作成処理
        logger.info("execute: " + P0F_SHELL_COMMAND)
        proc = Popen(
            P0F_SHELL_COMMAND
            + " "
            + analyze_full_path
            + " "
            + dir_name
            + " "
            + pcap_name,
            shell=True,
        )
        proc.wait()
    elif func_type == 2:
        # pcap2logのログ作成処理
        logger.info("pcap to log")
        # pcap2log(
        #    PCAP_ANALYZE_FILE_PATH + pcap_name,
        #    PCAP_ANALYZE_FILE_PATH + dir_name,
        # )
        # proc.wait()
    elif func_type == 4:
        if SURICATA_ENABLE:
            # suricataログの処理
            logger.info("execute: " + SURICATA_SHELL_COMMAND)
            proc = Popen(
                SURICATA_SHELL_COMMAND
                + " "
                + SURICATA_YAML
                + " "
                + analyze_full_path
                + " "
                + pcap_name
                + " "
                + analyze_full_path
                + dir_name,
                shell=True,
            )
            proc.wait()
    elif func_type == 5:
        # yaf logの処理
        logger.info("execute: " + YAF_SHELL_COMMAND)
        proc = Popen(
            YAF_SHELL_COMMAND
            + " "
            + analyze_full_path
            + " "
            + dir_name
            + " "
            + pcap_name,
            shell=True,
        )
        proc.wait()


def log_info(start, message):
    """
    処理進捗状況をログに出力する
    :param start:
    :param message:
    """

    process_time = time.time() - start
    logger.info("{} ---Time:{}(sec)---".format(message, str(process_time)))


def get_pcap_list():
    """
    PCAPファイルの一覧を取得する
    """
    # 定義している拡張子を対象にファイルのリストを作成
    allowed_ext_list = ALLOWED_PCAP_EXT.split(",")
    pcap_list = []
    extend_pcap_list = pcap_list.extend
    for ext in allowed_ext_list:
        extend_pcap_list(
            sorted(glob.glob(PCAP_UPLOADED_FILE_PATH + "**/*" + ext, recursive=True))
        )

    return pcap_list, allowed_ext_list


def pcap_to_log(pcap_list):
    """
    pcapファイルからログファイルを作成する
    :param pcap_list: pcapファイルのパスが格納されたリスト
    """
    logger.debug("DEBUG start pcap_to_log")

    err_msg = " " + "[ERROR] "
    analyze_full_path = os.path.join(BASE_DIR, PCAP_ANALYZE_FILE_PATH)
    analyze_pcap_dir_list = []
    analyze_pcap_list = []
    # for index, pcap in enumerate(pcap_list, 1):
    # pcap_name = os.path.basename(pcap)
    # dir_name = os.path.splitext(os.path.basename(pcap))[0]
    dir_name = "realtime-" + datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
    pcap_name = "paper"  # ダミー
    analyze_pcap_dir = analyze_full_path + dir_name
    analyze_pcap_dir_list.append(analyze_pcap_dir)

    # try:
    #    # pcap移動処理
    #    logger.info("move pcap file")
    #    analyze_pcap = shutil.move(pcap, PCAP_ANALYZE_FILE_PATH)
    #    logger.info("end move pcap file")
    #    analyze_pcap_list.append(analyze_pcap)
    #    logger.info("end append pcap list")
    # except Exception as e:
    #    logger.error("pcap move error (to analyze directory): " + str(e))
    #    continue

    try:
        # broログ格納用ディレクトリ作成処理
        logger.info("make analyze directory [" + analyze_pcap_dir + "]")
        os.mkdir(analyze_pcap_dir)
    except Exception as e:
        logger.error(err_msg + "make directory error: " + str(e))
        # continue

    try:
        if YAF_ENABLE:
            func_type_list = [0, 1, 2, 4, 5]
        else:
            func_type_list = [0, 1, 2, 4]
        analyze_full_path_list = [analyze_full_path] * len(func_type_list)
        dir_name_list = [dir_name] * len(func_type_list)
        pcap_name_list = [pcap_name] * len(func_type_list)

        with Pool(PCAP_TO_DB_CPU) as pool:
            args = list(
                zip(
                    func_type_list,
                    analyze_full_path_list,
                    dir_name_list,
                    pcap_name_list,
                )
            )
            pool.starmap(wrapper_log_function, args)

    except Exception as e:
        logger.error("analyze error: " + str(e))
        # continue

    logger.info(str(analyze_pcap_dir_list))
    logger.info(str(analyze_pcap_list))

    return analyze_pcap_dir_list, analyze_pcap_list


def move_pcap_file(analyze_pcap_list):
    """
    処理済みのPCAPファイルを移動
    :param analyze_pcap_list: 解析済みpcapファイルのパスが格納されたリスト
    """
    for index, analyze_pcap in enumerate(analyze_pcap_list, 1):
        try:
            # 解析済みpcapファイル移動
            logger.info("move analyzed pcap file [" + analyze_pcap + "]")
            shutil.move(analyze_pcap, PCAP_COMPLETE_FILE_PATH)
        except Exception as e:
            logger.error("pcap move error (to complete directory): " + str(e))
            continue


def move_pcap_dir(log_dir_list, dst_dir):
    """
    処理済みのPCAPからログに変換したときのディレクトリを移動
    :param log_dir_list: 移動するログディレクトリのリスト
    :param dst_dir: 移動先のディレクトリパス
    """

    for index, pcap_dir in enumerate(log_dir_list, 1):
        try:
            # 解析済みディレクトリ移動
            logger.info("move analyzed log directory [" + pcap_dir + "]")
            shutil.move(pcap_dir, dst_dir)
        except Exception as e:
            logger.error("log directory move error (to " + dst_dir + "): " + str(e))
            continue


def send_server(zip_list):
    """
    ログファイルをサーバーに送付する。
    :param zip_list: 送付対象のtar.zstファイルのlist
    """

    for zip_file in zip_list:
        file_name = os.path.basename(zip_file)
        file_data_binary = open(zip_file, "rb").read()
        mime_type = mimetypes.guess_type(file_name)[0]
        files = {"file_uploaded": (zip_file, file_data_binary, mime_type)}
        data = {"label_id": LABEL_ID}

        resp = requests.post(
            API_URL,
            cert=CLIENT_CERTIFICATE_PATH,
            files=files,
            data=data,
            timeout=SEND_REQUST_TIMEOUT,
        )
        if resp.status_code != 200:
            raise Exception(
                "Bad response from application: {!r} / {!r} / {!r}".format(
                    resp.status_code, resp.headers, resp.text
                )
            )

        logger.info("send compressed file: " + file_name)
        # ファイルが正常に送信できた場合は、tar.zstファイルを削除する
        os.remove(zip_file)
