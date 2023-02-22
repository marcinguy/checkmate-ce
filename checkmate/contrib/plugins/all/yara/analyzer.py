# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess

logger = logging.getLogger(__name__)


class YaraAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(YaraAnalyzer, self).__init__(*args, **kwargs)

    def summarize(self, items):
        pass

    def analyze(self, file_revision):
        issues = []
        tmpdir = "/tmp/"+file_revision.project.pk
        try:
          f = open(tmpdir+"/"+file_revision.path, "wb")
        except:
          pass
        try:
            f.write(file_revision.get_file_content())
            try:
                result = subprocess.check_output(["scan",
                                                  "-Y",
                                                  "/root/yara",
                                                  "-j",
                                                  f.name]
                                                  )
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
                for item in json_result:
                    issues.append({
                    'code': item["rule"],
                    'location': location,
                    'data': item["rule"],
                    'file': file_revision.path,
                    'line': line,
                    'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=item["rule"])
                })

            except KeyError:
                pass
        except:
            pass

        return {'issues': issues}
