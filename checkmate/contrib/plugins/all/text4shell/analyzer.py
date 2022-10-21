# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess

logger = logging.getLogger(__name__)


class Text4shellAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(Text4shellAnalyzer, self).__init__(*args, **kwargs)

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
                result = subprocess.check_output(["/root/text4shell-ce/scan_commons_text_versions.py",
                                                  f.name,
                                                  "-quiet"],
                                                  stderr=subprocess.DEVNULL).strip()
            except subprocess.CalledProcessError as e:
                pass
            try:
                json_result = json.loads(result)
            except ValueError:
                json_result = {}
                pass

            try:
                line = "1"
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

        finally:
            os.unlink(f.name)
        return {'issues': issues}