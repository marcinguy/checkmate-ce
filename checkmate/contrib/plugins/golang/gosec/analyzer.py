# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess


logger = logging.getLogger(__name__)


class GosecAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(GosecAnalyzer, self).__init__(*args, **kwargs)

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
        
        #result = subprocess.check_output(["rsync . "+tmpdir+" --exclude .git"],shell=True).strip()
                                        
        f = open(tmpdir+"/"+file_revision.path, "wb")

        result = {}
        try:
            with f:
                try:
                  f.write(file_revision.get_file_content())
                except UnicodeDecodeError:
                  pass
            os.chdir(tmpdir)
            os.environ["PATH"] = "/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/:/usr/local/go/bin/"

            try:
                result = subprocess.check_output(["/root/bin/gosec",
                                                  "-fmt", "json",
                                                  "./..."],
                                                  stderr=subprocess.DEVNULL).strip()
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

            try:
                for issue in json_result['Issues']:


                    try:
                        value = issue['line'].split("-",1)[1]
                    except IndexError:
                        value = issue['line']
                        pass

                    location = (((value,None),
                                  (value,None)),)

                   

                    if ".go" in file_revision.path and file_revision.path in issue['file']:
                        issues.append({
                            'code': issue['rule_id'],
                            'location': location,
                            'data': issue['details'],
                            'file': file_revision.path,
                            'line': value,
                            'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=issue['details'])
                        })

            except:
                pass

        finally:
            pass
        return {'issues': issues}
