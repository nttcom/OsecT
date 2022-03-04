import time
from django.core.management import BaseCommand
from subprocess import Popen, DEVNULL
from common.app_config import SLEEP_TIME, TCPDUMP_SHELL_COMMAND


class Command(BaseCommand):
    # python manage.py help control tcpdumpで表示されるメッセージ
    help = "control tcpdump"

    # コマンドが実行された際に呼ばれるメソッド
    def handle(self, *args, **options):
        """
        tcpdumpの起動と停止をコントロールする。
        :param args:
        :param options:
        """
        proc = None
        while True:
            try:
                # 起動状態で起動されていない場合は起動する
                if proc is None:
                    proc = Popen(
                        TCPDUMP_SHELL_COMMAND,
                        stdin=DEVNULL,
                        stdout=DEVNULL,
                        stderr=DEVNULL,
                    )
            except:
                pass
            time.sleep(SLEEP_TIME)
