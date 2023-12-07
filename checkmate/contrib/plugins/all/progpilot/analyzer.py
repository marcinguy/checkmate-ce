# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess

logger = logging.getLogger(__name__)


class ProgpilotAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(ProgpilotAnalyzer, self).__init__(*args, **kwargs)

    def summarize(self, items):
        pass

    def analyze(self, file_revision):
        issues = []
        f = tempfile.NamedTemporaryFile(delete=False)
        try:
            with f:
                f.write(file_revision.get_file_content())
            try:
                result = subprocess.check_output(["/root/phpscan/progpilot.phar",
                                                  f.name])
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
                try:
                    issue['source_line'] = issue['source_line'][0]
                except KeyError:
                    issue['source_line'] = 0
                    pass

                location = (((issue['source_line'], None),
                             (issue['source_line'], None)),)

                issues.append({
                    'code': issue['vuln_name'],
                    'location': location,
                    'data': issue['vuln_name'],
                    'file': file_revision.path,
                    'line': issue['source_line'],
                    'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=issue['vuln_name'])
                })

        finally:
            #os.unlink(f.name)
            pass
        return {'issues': issues}
