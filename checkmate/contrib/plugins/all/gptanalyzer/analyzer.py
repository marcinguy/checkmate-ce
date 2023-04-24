# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess
import re


logger = logging.getLogger(__name__)


class GptAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(GptAnalyzer, self).__init__(*args, **kwargs)

    def summarize(self, items):
        pass


    def analyze(self, file_revision):
        issues = []
        tmpdir = "/tmp/"+file_revision.project.pk

        if not os.path.exists(os.path.dirname(tmpdir+"/"+file_revision.path)):
          os.makedirs(os.path.dirname(tmpdir+"/"+file_revision.path))
        
                                        
        f = open(tmpdir+"/"+file_revision.path, "wb")

        result = {}
        f.write(file_revision.get_file_content())
        f.close()
        os.environ["PATH"] = "/root/.go/bin:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/:/usr/local/go/bin/"

        try:
                myjson = {}
                result = subprocess.check_output(["/root/bin/ptpt",
                                                  "run",
                                                  "scrt",
                                                  tmpdir+"/"+file_revision.path],
                                                  stderr=subprocess.DEVNULL).strip()
                splitstr = result.decode().split(":")


                out = re.findall(r'\d+', splitstr[0])
                try:
                  myjson['line'] = int(out[0])
                except:
                  pass
                
                try:
                  string = splitstr[1][:splitstr[1].rfind('\n')]
                  string = string.replace("'","")
                  string = string.replace("`","")
                  string = string.replace("\"","")
                  string = string.strip()
                  string = re.sub('[^A-Za-z0-9 ]+', '', string)

                  myjson['finding'] = string
                  result = json.dumps(myjson)
                except:
                  pass

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
          value = int(json_result["line"])

          location = (((value,None),
                             (value,None)),)


          issues.append({
                      'code': "C001",
                      'location': location,
                      'data': json_result["finding"],
                      'line': value,
                      'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=json_result["finding"])
                })
        except:
          pass
        return {'issues': issues}

