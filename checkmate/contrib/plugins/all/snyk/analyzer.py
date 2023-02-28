# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess

logger = logging.getLogger(__name__)


class SnykAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(SnykAnalyzer, self).__init__(*args, **kwargs)

    def summarize(self, items):
        pass

    def analyze(self, file_revision):
        issues = []
        result = ""
        f = tempfile.NamedTemporaryFile(delete=False)
        try:
            with f:
                try:
                  f.write(file_revision.get_file_content())
                except UnicodeDecodeError:
                  pass
            try:
                result = subprocess.check_output(["snyk",
                                                  "test",
                                                  "file=",
                                                  f.name],
                                                  stderr=subprocess.DEVNULL).strip()
            except subprocess.CalledProcessError as e:
                pass
            try:
                json_result = json.loads(result)
            except ValueError:
                json_result = {}
                pass

            try:
                for issue in json_result["vulnerabilities"]:
                  line = 1
                  location = (((line, line),
                             (line, None)),)

                  if "package-lock.json" in file_revision.path or "Gemfile.lock" in file_revision or "Pipfile.locl" in file_revision:
                    issues.append({
                      'code': "I001",
                      'location': location,
                      'data': issue["title"],
                      'file': file_revision.path,
                      'line': line,
                      'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=issue["data"])
                    })

            except KeyError:
                pass

        finally:
            os.unlink(f.name)
        return {'issues': issues}

