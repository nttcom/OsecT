import logging
import os
import glob
import shutil
import zipfile

from datetime import datetime, timedelta
from decimal import Decimal

from django.core.management.base import BaseCommand

from common.common_config import (
    PCAP_COMPLETE_FILE_PATH,
    PCAP_COMPLETE_ARCHIVES_FILE_PATH,
    PCAP_COMPLETE_COMPRESSION_LIMIT_DATE,
    PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_DATE,
    PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_CAPACITY,
)

logger = logging.getLogger("edge_complete_to_archives")


class Command(BaseCommand):
    def handle(self, *args, **options):
        logger.info("complete to archives start")

        try:
            exec_complete_to_archives(logger)
        except Exception as e:
            logger.error("exec_complete_to_archives error: ", exc_info=True)
            exit(1)

        logger.info("complete to archives done")


def exec_complete_to_archives(logger):
    # complete配下の保持期限切れファイルとディレクトリを圧縮
    file_compression_date_infos = _get_file_date_info(PCAP_COMPLETE_FILE_PATH)
    target_compression_list = _get_target_list(
        file_compression_date_infos, PCAP_COMPLETE_COMPRESSION_LIMIT_DATE
    )
    _compress_file(target_compression_list)

    if len(target_compression_list):
        for target_compression in target_compression_list:
            logger.info("compression: %s" % (target_compression))
    else:
        logger.info("There is no compression file or directory")

    # complete_archives配下の保持期限切れファイルの削除
    file_date_archives_infos = _get_file_date_info(
        PCAP_COMPLETE_ARCHIVES_FILE_PATH
    )
    target_archives_list = _get_target_list(
        file_date_archives_infos, PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_DATE
    )
    _delete_file_and_dir(target_archives_list)

    if len(target_archives_list):
        for target_archives in target_archives_list:
            logger.info("delete archives: %s" % (target_archives))
    else:
        logger.info("There is no archives file to delete")

    # 保持容量上限超過ファイルの削除
    file_size_infos = _get_file_size_info()
    # サイズ容量合計計算
    total_path_size = _calc_size_sum(file_size_infos)
    # ギガバイトに変換
    total_size = _convert_size_giga_byte(total_path_size)

    if _is_capacity_over(total_size):
        target_capacity_over_list = _get_target_capacity_over_list(
            file_size_infos, total_size
        )
        _delete_file_and_dir(target_capacity_over_list)

        for target_capacity_over in target_capacity_over_list:
            logger.info("capacity over: %s" % (target_capacity_over))
    else:
        logger.info(
            "There is no capacity over file. %.9g/%s GB"
            % (total_size, PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_CAPACITY)
        )


def _get_file_date_info(target_path):
    """
    引数に指定されたパス配下に存在するファイルとディレクトリの名前と日付の情報を取得する
    :param target_path: 対象パス
    :return: file_date_infos
    """
    file_names = glob.glob(os.path.join(target_path, "**"))
    file_date_infos = [
        {
            "file_name": file_name,
            "file_date": datetime.fromtimestamp(
                os.path.getmtime(file_name)
            ).strftime("%Y%m%d"),
        }
        for file_name in file_names
    ]

    file_date_infos = sorted(file_date_infos, key=lambda x: x["file_name"])

    return file_date_infos


def _get_target_list(file_date_infos, limit_date):
    """
    引数で指定した保有日付を超過している対象を取得する
    :param file_date_infos: ファイル情報一覧
    :param limit_date: 保有日付
    :return: target_file_list
    """
    limit_date = (datetime.now() + timedelta(days=-limit_date)).strftime(
        "%Y%m%d"
    )

    target_file_list = []
    for file_date_info in file_date_infos:
        file_name = file_date_info["file_name"]
        file_date = file_date_info["file_date"]

        if file_date < limit_date:
            target_file_list.append(file_name)

    target_file_list = sorted(target_file_list)

    return target_file_list


def _compress_file(target_compression_list):
    """
    引数に指定されたパス対象を圧縮する、圧縮後は対象を削除する
    :param target_compression_list: 対象パス一覧
    """
    for target_compression in target_compression_list:
        file_name = os.path.basename(target_compression)
        compression_file = os.path.join(
            PCAP_COMPLETE_ARCHIVES_FILE_PATH, "%s.zip" % (file_name)
        )
        compression_path = os.path.join(
            PCAP_COMPLETE_ARCHIVES_FILE_PATH, file_name
        )

        if os.path.isfile(target_compression):
            # ファイル
            with zipfile.ZipFile(
                compression_file, "w", compression=zipfile.ZIP_DEFLATED
            ) as compression_zip:
                compression_zip.write(target_compression, arcname=file_name)
            # 圧縮後ファイル削除
            os.remove(target_compression)
        else:
            # ディレクトリ
            shutil.make_archive(
                compression_path, "zip", root_dir=target_compression
            )
            # 圧縮後ディレクトリ削除
            shutil.rmtree(target_compression)


def _delete_file_and_dir(target_path_list):
    """
    引数に指定されたパス対象を削除する
    :param target_path_list: 対象パス一覧
    """
    for target_path in target_path_list:
        if os.path.isfile(target_path):
            # ファイル削除
            os.remove(target_path)
        else:
            # ディレクトリ削除
            shutil.rmtree(target_path)


def _get_file_size_info():
    """
    completeとarchivesのパス配下に存在するファイルとディレクトリの名前、日付、サイズの情報を取得する
    :return: file_size_infos
    """
    target_path_dict = {
        "complete": PCAP_COMPLETE_FILE_PATH,
        "archives": PCAP_COMPLETE_ARCHIVES_FILE_PATH,
    }

    file_size_infos = {}
    for path_type, target_path in target_path_dict.items():
        file_paths = glob.glob(os.path.join(target_path, "**"))

        file_info_list = []
        for file_path in file_paths:
            if os.path.isfile(file_path):
                # ファイル
                file_info = {
                    "file_name": file_path,
                    "file_size": os.path.getsize(file_path),
                    "file_date": datetime.fromtimestamp(
                        os.path.getmtime(file_path)
                    ).strftime("%Y%m%d"),
                    "file_type": "file",
                }
                file_info_list.append(file_info)
            else:
                # ディレクトリ
                file_names = glob.glob(
                    os.path.join(file_path, "**"), recursive=True
                )
                total_path_size = sum(
                    (
                        os.path.getsize(file_name)
                        for file_name in file_names
                        if os.path.isfile(file_name)
                    )
                )
                file_info = {
                    "file_name": file_path,
                    "file_size": total_path_size,
                    "file_date": datetime.fromtimestamp(
                        os.path.getmtime(file_path)
                    ).strftime("%Y%m%d"),
                    "file_type": "dir",
                }
                file_info_list.append(file_info)

        file_info_list = sorted(
            file_info_list, key=lambda x: (x["file_date"], x["file_name"])
        )
        file_size_infos[path_type] = file_info_list

    return file_size_infos


def _calc_size_sum(file_size_infos):
    """
    引数で指定されたファイル情報の合計ファイルサイズを計算する
    :param file_size_infos: ファイル情報一覧
    :return: total_size
    """
    total_size = sum(
        (
            file_info["file_size"]
            for path_type, file_infos in file_size_infos.items()
            for file_info in file_infos
        )
    )

    return total_size


def _convert_size_giga_byte(size_bytes):
    """
    引数で指定されたファイル情報の合計ファイルサイズを計算する
    :param size_bytes: バイト値
    :return: giga_byte
    """
    giga_byte = round(Decimal(size_bytes / 1024**3), 9)

    return giga_byte


def _is_capacity_over(total_size):
    """
    保持容量を超過しているか判断
    :param total_size: 合計バイト値
    :return: boolean型（True/False）
    """
    if total_size > PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_CAPACITY:
        # 保持容量以上
        return True
    else:
        # 保持容量以下
        return False


def _get_target_capacity_over_list(file_size_infos, total_size):
    """
    保持容量以下になるように削除対象を取得する
    :param file_size_infos: ファイル情報一覧
    :param total_size: 合計バイト値
    :return: target_delete_files
    """
    archives_info_file_list = [
        file_size_info
        for file_size_info in file_size_infos["archives"]
        if file_size_info["file_type"] == "file"
    ]
    complete_info_dir_list = [
        file_size_info
        for file_size_info in file_size_infos["complete"]
        if file_size_info["file_type"] == "dir"
    ]
    complete_info_file_list = [
        file_size_info
        for file_size_info in file_size_infos["complete"]
        if file_size_info["file_type"] == "file"
    ]

    target_delete_files = []
    delete_file_size = 0
    limit_size = total_size - delete_file_size
    for info_file in archives_info_file_list:
        if limit_size < PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_CAPACITY:
            return target_delete_files

        target_delete_files.append(info_file["file_name"])
        delete_file_size = _convert_size_giga_byte(info_file["file_size"])
        limit_size -= delete_file_size

    for info_file in complete_info_dir_list:
        if limit_size < PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_CAPACITY:
            return target_delete_files

        target_delete_files.append(info_file["file_name"])
        delete_file_size = _convert_size_giga_byte(info_file["file_size"])
        limit_size -= delete_file_size

    for info_file in complete_info_file_list:
        if limit_size < PCAP_COMPLETE_ARCHIVES_DELETE_LIMIT_CAPACITY:
            return target_delete_files

        target_delete_files.append(info_file["file_name"])
        delete_file_size = _convert_size_giga_byte(info_file["file_size"])
        limit_size -= delete_file_size

    return target_delete_files
