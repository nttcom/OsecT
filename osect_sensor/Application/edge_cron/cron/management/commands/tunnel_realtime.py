import subprocess
import sys

from scapy.all import *
from scapy.contrib.gtp import *

from common.common_config import SURICATA_CAP_IF, TUNNEL_ENABLE
from django.core.management import BaseCommand

logger = logging.getLogger("tunnel_realtime")


class Command(BaseCommand):
    help = "control tunnel realtime"

    def handle(self, *args, **options):
        """
        カプセル化解除の起動と停止をコントロールする。
        :param args:
        :param options:
        """

        logger.info("recap tunnel start")
        logger.info("recap mode is" + str(TUNNEL_ENABLE))

        # トンネルプロトコル対応するときのみ実行
        if TUNNEL_ENABLE:
            # ダミーインタフェースの作成
            output = subprocess.run(["ip", "link", "add", "dummy1", "type", "dummy"])
            if output.returncode == 0:
                # ダミーインタフェースがない場合は設定
                subprocess.run(["ip", "addr", "add", "1.1.1.1/24", "dev", "dummy1"])
                subprocess.run(["ip", "link", "set", "dummy1", "up"])
                subprocess.run(["ip", "link", "set", "dummy1", "mtu", "9000"])

            while True:
                sniff(iface=SURICATA_CAP_IF, prn=lambda pkt: gtpu_send(pkt, "dummy1"))


def gtpu_send(pkt, send_iface):
    new_pkt = pkt

    if GTP_U_Header in pkt:
        a = pkt[GTP_U_Header][GTPPDUSessionContainer].payload
        pkt[Ether].remove_payload()
        b = pkt
        new_pkt = b / a

    try:
        sendpfast(new_pkt, iface=send_iface)
    except OSError:
        print("MTU Error", len(new_pkt))
    except KeyboardInterrupt:
        print("Keyboard Interrupt")
        sys.exit(0)
