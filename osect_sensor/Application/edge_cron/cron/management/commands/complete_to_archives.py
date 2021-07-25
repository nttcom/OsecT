import logging

from django.core.management.base import BaseCommand

from common.common_fonction import exec_complete_to_archives

logger = logging.getLogger('edge_complete_to_archives')


class Command(BaseCommand):
    def handle(self, *args, **options):
        logger.info('complete to archives start')

        try:
            exec_complete_to_archives(logger)
        except Exception as e:
            logger.error('exec_complete_to_archives error: ', exc_info=True)
            exit(1)

        logger.info('complete to archives done')
