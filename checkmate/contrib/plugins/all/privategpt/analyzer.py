# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess
import requests


logger = logging.getLogger(__name__)


class PrivateGptAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(PrivateGptAnalyzer, self).__init__(*args, **kwargs)

    def summarize(self, items):
        pass

    def analyze(self, file_revision):
        issues = []
        tmpdir = "/tmp/"+file_revision.project.pk

        if not os.path.exists(os.path.dirname(tmpdir+"/"+file_revision.path)):
            try:
                os.makedirs(os.path.dirname(tmpdir+"/"+file_revision.path))
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
        
        result = subprocess.check_output(["rsync -r . "+tmpdir+" --exclude .git"],shell=True).strip()
                                        
        f = open(tmpdir+"/"+file_revision.path, "wb")

        result = {}
        try:
            with f:
                try:
                  f.write(file_revision.get_file_content())
                except UnicodeDecodeError:
                  pass
            os.chdir(tmpdir)
            os.environ["PATH"] = "/root/.go/bin:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/:/usr/local/go/bin/"

            try:
                url=os.environ["PRIVATEGPT_URL"]

                prompt="I want you to act as a security engineer. Your task is to security review the code and find potential security bugs.\n    Your input would be a git diff, please only give suggestion on only the edited content. Consider the context for better suggestion.\n    Find and fix any bugs and typos. If no bug is found, just output \\\"No obvious bug found.\\\"\n    Do not include any personal opinions or subjective evaluations in your response.\n    Your output should looks like:\n\n      [\n        {\n        \\\"line\\\": 66,\n        \\\"finding\\\":\\\"...(your suggestion)\\\"\n        },\n        {\n        \\\"line\\\": 77,\n        \\\"finding\\\":\\\"...(your suggestion)\\\"\n        }\n\n     ]"
                
                jsondata={}
                #open text file in read mode
                filecode = open(f.name, "r")

                code  = filecode.read()
                filecode.close()
  
                jsondata["question"] = prompt+"\n"+code

                x = requests.post(url, json = jsondata)
                result = x.content

            except:
                pass


            try:
                  json_result = json.loads(result)
            except ValueError:
                  json_result = []
                  pass
            try:
              for issue in json_result:
                  value = issue['line']

                  location = (((value,None),
                             (value,None)),)

                  issues.append({
                            'code': "I001",
                            'location': location,
                            'data': issue['finding'],
                            'file': file_revision.path,
                            'line': value,
                            'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=issue['finding'])
                        })

            except:
                pass

        finally:
            pass
        return {'issues': issues}


