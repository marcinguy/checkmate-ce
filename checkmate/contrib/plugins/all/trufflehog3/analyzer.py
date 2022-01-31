# -*- coding: utf-8 -*-

from __future__ import unicode_literals
from __future__ import absolute_import

from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import pprint
import subprocess

logger = logging.getLogger(__name__)

class Trufflehog3Analyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(Trufflehog3Analyzer, self).__init__(*args, **kwargs)

    def summarize(self,items):
        pass

    def analyze(self,file_revision):
        issues = []
        f = tempfile.NamedTemporaryFile(delete = False)
        try:
            with f:
                f.write(file_revision.get_file_content())
            try:
                result = subprocess.check_output(["/usr/local/bin/trufflehog3",
                                                  "-f","json",
                                                  "-r", "/srv/scanmycode/rules.json",
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
                  issue['source_line'] = 1
                except KeyError:
                  issue['source_line'] = 1
                  pass

                location = (((issue['source_line'],None),
                              (issue['source_line'],None)),)



                issues.append({
                    'code' : issue['reason'],
                    'location' : location,
                    'data' : issue['reason'],
                    'fingerprint' : self.get_fingerprint_from_code(file_revision,location, extra_data=issue['reason'])
                    })

        finally:
            os.unlink(f.name)
        return {'issues' : issues}
