# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess

logger = logging.getLogger(__name__)


class TrojansourceAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(TrojansourceAnalyzer, self).__init__(*args, **kwargs)

    def summarize(self, items):
        pass

    def analyze(self, file_revision):
        issues = []
        f = tempfile.NamedTemporaryFile(delete=False)
        try:
            with f:
                f.write(file_revision.get_file_content())
            try:
                result = subprocess.check_output(["/usr/local/bin/find_unicode_control2.py",
                                                  "-p",
                                                  "bidi",
                                                  "-d",
                                                  f.name])
            except subprocess.CalledProcessError as e:
                pass
            try:
                json_result = json.loads(result)
            except ValueError:
                json_result = {}
                pass

            try:
                line = json_result["line"]
                line = int(line)
                location = (((line, line),
                             (line, None)),)

                issues.append({
                    'code': "I001",
                    'location': location,
                    'data': json_result["I001"],
                    'file': file_revision.path,
                    'line': line,
                    'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=json_result["I001"])
                })

            except KeyError:
                pass
        except:
            pass

        return {'issues': issues}
