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
        tmpdir = "/tmp/"+file_revision.project.pk
        try:
          os.mkdir(tmpdir)
        except:
          pass
        try:
          f=open("/tmp/"+file_revision.project.pk+"/"+file_revision.path, 'wb')
          f.write(file_revision.get_file_content())
         
          f.close()
        except:
          pass

 
        os.chdir(tmpdir)
        try:
          out = subprocess.check_output(["npm install"],shell=True).strip()
        except:
           pass
        #result = subprocess.check_output(["rsync . "+tmpdir+" --exclude .git"],shell=True).strip()

        try:

            try:
                result = subprocess.check_output(["snyk",
                                                  "test",
                                                  "--file="+tmpdir+"/"+file_revision.path,
                                                  "--json"],
                                                  stderr=subprocess.DEVNULL).strip()

            except subprocess.CalledProcessError as e:
                result = e.output
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

                  issues.append({
                      'code': "I001",
                      'location': location,
                      'data': issue["title"]+" ("+issue["id"]+")",
                      'file': file_revision.path,
                      'line': line,
                      'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=issue["title"])
                  })
            except:
              pass

        finally:
            #os.unlink(f.name)
            pass
        return {'issues': issues}
