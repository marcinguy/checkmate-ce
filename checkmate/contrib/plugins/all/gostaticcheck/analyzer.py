# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess


logger = logging.getLogger(__name__)


class GostaticcheckAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(GostaticcheckAnalyzer, self).__init__(*args, **kwargs)

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
                result = subprocess.check_output(["/root/bin/staticcheck",
                                                  "-f", "json",
                                                  f.name],
                                                  stderr=subprocess.DEVNULL).strip()
            except subprocess.CalledProcessError as e:
                if e.returncode == 2:
                    result = e.output
                elif e.returncode == 1:
                    result = e.output
                    pass
                else:
                    result = []

            for line in result.splitlines():
              try:
                  json_result = json.loads(line)
              except ValueError:
                  json_result = []
                  pass
              try:
                    issue = json_result
                    value = issue['location']['line']

                    location = (((value,None),
                                  (value,None)),)

                   

                    if ".go" in file_revision.path:
                        issues.append({
                            'code': issue['code'],
                            'location': location,
                            'data': issue['message'],
                            'file': file_revision.path,
                            'line': value,
                            'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=issue['message'])
                        })

              except:
                pass

        finally:
            pass
        return {'issues': issues}

