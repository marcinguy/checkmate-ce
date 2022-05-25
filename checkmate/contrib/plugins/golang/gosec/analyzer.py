# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import pprint
import subprocess

logger = logging.getLogger(__name__)


class GosecAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(GosecAnalyzer, self).__init__(*args, **kwargs)

    def summarize(self, items):
        pass

    def analyze(self, file_revision):
        issues = []
        tmpdir = "/tmp/"+file_revision.project.pk

        if not os.path.exists(os.path.dirname(tmpdir+"/"+file_revision.path)):
            try:
                os.makedirs(os.path.dirname(tmpdir+"/"+file_revision.path))
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
        f = open(tmpdir+"/"+file_revision.path, "w")

        result = {}
        try:
            with f:
                f.write(file_revision.get_file_content())
            os.chdir(tmpdir)
            try:
                result = subprocess.check_output(["/root/bin/gosec",
                                                  "-fmt", "json",
                                                  "../..."])
            except subprocess.CalledProcessError as e:
                if e.returncode == 2:
                    result = e.output
                elif e.returncode == 1:
                    result = e.output
                    pass
                else:
                    result = []
            try:
                json_result = json.loads(result)
            except ValueError:
                json_result = []
                pass

            for issue in json_result['Issues']:
                try:
                    issue['source_line'] = 1
                except KeyError:
                    issue['source_line'] = 1
                    pass

                location = (((issue['source_line'], None),
                             (issue['source_line'], None)),)

                issues.append({
                    'code': issue['rule_id'],
                    'location': location,
                    'data': issue['details'],
                    'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=issue['details'])
                })

        finally:
            # os.unlink(f.name)
            pass
        return {'issues': issues}
