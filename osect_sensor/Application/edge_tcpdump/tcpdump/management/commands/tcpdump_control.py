import time
import os
import glob
from django.core.management import BaseCommand
from subprocess import Popen, DEVNULL
from common.app_config import SLEEP_TIME, TCPDUMP_SHELL_COMMAND, REMOVE_PCAP_FILE


class Command(BaseCommand):
    # python manage.py help control tcpdumpで表示されるメッセージ
    help = 'control tcpdump'

    # コマンドが実行された際に呼ばれるメソッド
    def handle(self, *args, **options):
        """
        tcpdumpの起動と停止をコントロールする。

        :param args:
        :param options:
        """
        # tcpdumpを一般ユーザーで実行する方法
        # https://guyavrah.wordpress.com/2019/07/20/automation-project-considerations-part-7-executing-tcpdump-from-python-script/
        # # 不要ファイルの削除処理
        # pcap_list = []
        # pcap_list.extend(sorted(glob.glob('./' + REMOVE_PCAP_FILE, recursive=True)))
        proc = None
        while True:
            try:
                # 起動状態で起動されていない場合は起動する
                if proc is None:
                    proc = Popen(TCPDUMP_SHELL_COMMAND, stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL)
            except:
                pass
            time.sleep(SLEEP_TIME)


