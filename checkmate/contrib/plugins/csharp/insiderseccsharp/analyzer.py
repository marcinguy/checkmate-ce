# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess
from os.path import exists


logger = logging.getLogger(__name__)


class InsiderseccsharpAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(InsiderseccsharpAnalyzer, self).__init__(*args, **kwargs)
        try:
            result = subprocess.check_output(
                ["/root/insider", "--version"],stderr=subprocess.DEVNULL).strip()
        except subprocess.CalledProcessError:
            logger.error(
                "Cannot initialize insidersec analyzer: Executable is missing, please install it.")
            raise

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

        fout = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        result = {}
        try:
            with f:
                try:
                  f.write(file_revision.get_file_content())
                except UnicodeDecodeError:
                  pass
            try:
                result = subprocess.check_output(["/root/insider",
                                                  "-tech",
                                                  "csharp",
                                                  "-target",
                                                  f.name],
                                                  stderr=subprocess.DEVNULL).strip()
                file_exists = exists("report.json")
                if file_exists:     
                    result = subprocess.check_output(["mv",
                                                  "report.json",
                                                  tmpdir],
                                                  stderr=subprocess.DEVNULL).strip()

            except subprocess.CalledProcessError as e:
                if e.returncode == 1:
                    result = e.output
                    pass
                elif e.returncode == 3:
                    result = []
                    pass
                else:
                    #print((e.returncode))
                    result = e.output
                    pass

            with open(tmpdir+"/report.json", "r") as f:
                try:
                    result = json.load(f)
                except ValueError as e:
                    result['warnings'] = []
                    pass
            json_result = result

            try:

                for issue in json_result['vulnerabilities']:
                    line = issue['line']

                    location = (((line, None),
                                 (line, None)),)
                    if ".cs" in file_revision.path:
                      issues.append({
                            'code': issue['cwe'],
                            'location': location,
                            'data': issue['description'],
                            'file': file_revision.path,
                            'line': issue['line'],
                            'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=issue['description'])
                      })
            except:
                pass

        finally:
          try:
            os.remove('report.html')
            os.remove('style.css')
          except FileNotFoundError:
            pass
          return {'issues': issues}
