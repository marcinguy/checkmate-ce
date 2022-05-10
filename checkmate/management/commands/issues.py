# -*- coding: utf-8 -*-
import pprint

from checkmate.lib.models import Issue
from checkmate.contrib.plugins.git.models import GitSnapshot
from checkmate.management.commands.base import BaseCommand
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):

    """
    Returns a list of issues for the current snapshot or file revision.
    """

    def run(self):
        snapshot_pk = None
        filenames = None
        if self.extra_args:
            if len(self.extra_args) == 1:
                snapshot_pk = self.extra_args[0]
            else:
                snapshot_pk, filenames = self.extra_args[0], self.extra_args[1:]

        if snapshot_pk:
            try:
                snapshot = self.backend.get(GitSnapshot,
                                            {'pk': {'$regex': r'^'+snapshot_pk}})
            except GitSnapshot.DoesNotExist:
                logger.error("Snapshot %s does not exist!" % snapshot_pk)
                return -1
            except GitSnapshot.MultipleDocumentsReturned:
                logger.error("Ambiguous key %s!" % snapshot_pk)
                return -1
        else:
            try:
                snapshot = self.backend.filter(GitSnapshot, {})\
                                       .sort('created_at', -1)[0]
            except IndexError:
                logger.error("No snapshots in this project.")
                return -1

        issues = self.backend.filter(Issue,
                {})\
                             .sort('analyzer',1)

        for issue in issues:
            print(("%(analyzer)s\t%(code)s\t" % {'analyzer': issue['analyzer'],
                                                 'code': issue['code']}))
