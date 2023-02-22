# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess

logger = logging.getLogger(__name__)


class Trufflehog3Analyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(Trufflehog3Analyzer, self).__init__(*args, **kwargs)

    def summarize(self, items):
        pass

    def analyze(self, file_revision):
        issues = []
        f = tempfile.NamedTemporaryFile(delete=False)
        try:
            with f:
                try:
                  f.write(file_revision.get_file_content())
                except UnicodeDecodeError:
                  pass
            try:
                result = subprocess.check_output(["/usr/local/bin/trufflehog3",
                                                  "-f", "json",
                                                  "-r", "/srv/scanmycode/rules.json",
                                                  f.name],
                                                  stderr=subprocess.DEVNULL).strip()
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

            for issue in json_result:

                location = (((issue['line'], None),
                             (issue['line'], None)),)

                issues.append({
                    'code': issue['reason'],
                    'location': location,
                    'data': issue['reason'],
                    'file': file_revision.path,
                    'line': issue['line'],
                    'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=issue['reason'])
                })

        return {'issues': issues}
