# -*- coding: utf-8 -*-

from __future__ import unicode_literals
from __future__ import absolute_import

from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess

logger = logging.getLogger(__name__)

class ConfusedAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(ConfusedAnalyzer, self).__init__(*args, **kwargs)

    def summarize(self,items):
        pass

    def analyze(self,file_revision):
        issues = []
        f = tempfile.NamedTemporaryFile(delete = False)
        try:
            with f:
                f.write(file_revision.get_file_content())
            try:
                result = subprocess.check_output(["/root/confused/confused",
                                                  "-l",
                                                  "npm",
                                                  f.name])
            except subprocess.CalledProcessError as e:
                pass
            try:
              json_result = json.loads(result)
            except ValueError:
              json_result = []
              pass
            
            location = (((1,None),
                              (1,None)),)
            if len(json_result)==1 and len(json_result["I001"])>0:
              issues.append({
                    'code' : "I001",
                    'location' : location,
                    'data' : json_result["I001"],
                    'fingerprint' : self.get_fingerprint_from_code(file_revision,location,extra_data=json_result["I001"])
                    })

        finally:
            os.unlink(f.name)
        return {'issues' : issues}

