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
            for p in sorted(glob.glob(PCAP_BEFORE_FILE_PATH + "*.pcap")):
                logger.info("recap " + p)
                input_output_pcap(p, PCAP_UPLOADED_FILE_PATH)
                logger.info("remove pcap file: %s", p)
                os.remove(p)
        else:
            # Pcapの移動のみ
            for p in sorted(glob.glob(PCAP_BEFORE_FILE_PATH + "*.pcap")):
                shutil.move(p, PCAP_UPLOADED_FILE_PATH)

        log_info(start, "end recap")
        logger.info("recap tunnel end")

def input_output_pcap(pcap_path, output_dir):
    writer = PcapWriter(output_dir + os.path.basename(pcap_path), append=True)

    logger.info("start input_output_pcap")
    
    for pkt in PcapReader(pcap_path):
        new_pkt = pkt

        # N3
        if GTP_U_Header in pkt:
            try:
                a = pkt[GTP_U_Header][GTPPDUSessionContainer].payload
                # vlanの有無
                if Dot1Q in pkt:
                    pkt[Dot1Q].remove_payload()
                else:
                    pkt[Ether].remove_payload()
                b = pkt
                new_pkt = b / a
                writer.write(new_pkt)
                # logger.info(new_pkt.summary())
                # logger.info("GTPU header")
            except IndexError as e:
                # logger.info(pkt.time)
                logger.info(new_pkt.summary())
                # writer.write(new_pkt)
                # logger.info((pkt.payload).decode('utf-8'))
        else:
            # logger.info("no GTPU header")
            # logger.info(new_pkt.summary())
            writer.write(new_pkt)

    logger.info("end input_output_pcap")
    
        
def log_info(start, message):
    """
    処理進捗状況をログに出力する
    :param start:
    :param message:
    """

    process_time = time.time() - start
    logger.info("{} ---Time:{}(sec)---".format(message, str(process_time)))
