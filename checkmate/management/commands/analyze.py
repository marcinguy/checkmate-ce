# -*- coding: utf-8 -*-


from checkmate.lib.models import Snapshot, FileRevision, Issue, IssueOccurrence
from checkmate.lib.code import CodeEnvironment
from .base import BaseCommand

from collections import defaultdict

import sys
import os
import random
import os.path
import copy
import json
import time
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):

    def run(self):

        settings = self.project.settings

        logger.info("Getting file revisions...")
        file_revisions = self.project.get_disk_file_revisions()
        logger.info("%d file revisions" % len(file_revisions))

        snapshot = self.project.GitSnapshot({'created_at': time.time()})

        try:
            code_environment = CodeEnvironment(self.project,
                                               file_revisions,
                                               global_settings=self.settings,
                                               project_settings=settings)
            code_environment.analyze(snapshot=snapshot,
                                     save_if_empty=False)
        except KeyboardInterrupt:
            raise
