import logging
import os
import shutil
import time
from subprocess import Popen

import scapy
from scapy.all import *
from scapy.contrib.gtp import *
from scapy.layers.l2 import *
from scapy.utils import *

from common.common_config import (
    PCAP_BEFORE_FILE_PATH,
    PCAP_UPLOADED_FILE_PATH,
    TUNNEL_ENABLE,
)
from django.core.management import BaseCommand
import glob

logger = logging.getLogger("tunnel_batch")


class Command(BaseCommand):
    help = "control tunnel batch"

    def handle(self, *args, **options):
        """
        カプセル化解除の起動と停止をコントロールする。
        :param args:
        :param options:
        """

        logger.info("recap tunnel start")
        logger.info("recap mode is " + str(TUNNEL_ENABLE))
        start = time.time()
        log_info(start, "start recap")

        if TUNNEL_ENABLE:
            # カプセル化解除->Pcapの移動
            for p in glob.glob(PCAP_BEFORE_FILE_PATH + "*.pcap", recursive=True):
                input_output_pcap(p, PCAP_UPLOADED_FILE_PATH)
        else:
            # Pcapの移動のみ
            for p in glob.glob(PCAP_BEFORE_FILE_PATH + "*.pcap", recursive=True):
                shutil.move(p, PCAP_UPLOADED_FILE_PATH)

        log_info(start, "end recap")
        logger.info("recap tunnel end")


def input_output_pcap(pcap_path, output_dir):
    writer = PcapWriter(output_dir + os.path.basename(pcap_path), append=True)

    for pkt in PcapReader(pcap_path):
        new_pkt = pkt

        if GTP_U_Header in pkt:
            a = pkt[GTP_U_Header][GTPPDUSessionContainer].payload
            pkt[Ether].remove_payload()
            b = pkt
            new_pkt = b / a

        writer.write(new_pkt)

    os.remove(pcap_path)


def log_info(start, message):
    """
    処理進捗状況をログに出力する
    :param start:
    :param message:
    """

    process_time = time.time() - start
    logger.info("{} ---Time:{}(sec)---".format(message, str(process_time)))
