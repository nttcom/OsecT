import logging
import os
import requests

from django.core.management.base import BaseCommand

from common.common_config import (
    CLIENT_CERTIFICATE_PATH,
    SEND_VERSION_API_URL,
    LABEL_ID,
)

logger = logging.getLogger("edge_send_version")


class Command(BaseCommand):
    help = "send_version function"

    def handle(self, *args, **options):
        """
        Suricataのシグネチャのバージョンをコアに送るコマンド。
        :param args:
        :param options:
        """
        logger.info("start sending signature version")

        suricata = os.environ.get("SURICATA_VERSION", None)
        signature = os.environ.get("SIGNATURE_VERSION", None)
        data = {
            "label_id": LABEL_ID,
            "suricata": suricata,
            "signature": signature,
        }
        resp = requests.post(
            SEND_VERSION_API_URL,
            cert=CLIENT_CERTIFICATE_PATH,
            verify=False,
            data=data,
        )
        if resp.status_code != 200:
            raise Exception(
                "Bad response from application: {!r} / {!r} / {!r}".format(
                    resp.status_code, resp.headers, resp.text
                )
            )
        logger.info(
            "send suricata signature version: {}, {}".format(
                suricata, signature
            )
        )
