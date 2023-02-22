# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess

logger = logging.getLogger(__name__)


class BanditAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(BanditAnalyzer, self).__init__(*args, **kwargs)
        try:
            result = subprocess.check_output(["bandit", "--version"],stderr=subprocess.DEVNULL).strip()
        except subprocess.CalledProcessError:
            logger.error(
                "Cannot initialize Bandit analyzer: Executable is missing, please install it.")
            raise

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
                result = subprocess.check_output(["bandit",
                                                  f.name,
                                                  "-f",
                                                  "json"],
                                                  stderr=subprocess.DEVNULL).strip()
            except subprocess.CalledProcessError as e:
                if e.returncode == 2:
                    result = e.output
                    pass
                elif e.returncode == 1:
                    result = e.output
                    pass
                else:
                    result = []
                    pass

            json_result = json.loads(result)

            for issue in json_result['results']:

                location = (((issue['line_number'], None),
                             (issue['line_number'], None)),)

                if ".py" in file_revision.path:
                    issues.append({
                        'code': issue['test_id'],
                        'location': location,
                        'data': issue['issue_text'],
                        'file': file_revision.path,
                        'line': issue['line_number'],
                        'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=issue['issue_text'])
                    })

        finally:
            os.unlink(f.name)
        return {'issues': issues}
