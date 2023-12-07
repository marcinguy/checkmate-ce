# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess
from os.path import exists


logger = logging.getLogger(__name__)


class InsidersecswiftAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(InsidersecswiftAnalyzer, self).__init__(*args, **kwargs)
        try:
            result = subprocess.check_output(
                ["/root/insider", "--version"])
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
        f = open(tmpdir+"/"+file_revision.path, "w")

        fout = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        result = {}
        try:
            with f:
                f.write(file_revision.get_file_content().decode("utf-8"))
            try:
                result = subprocess.check_output(["/root/insider",
                                                  "-tech",
                                                  "ios",
                                                  "-target",
                                                  f.name])
                file_exists = exists("report.json")
                if file_exists:
                    result = subprocess.check_output(["mv",
                                                  "report.json",
                                                  tmpdir])

            except subprocess.CalledProcessError as e:
                if e.returncode == 1:
                    result = e.output
                    pass
                elif e.returncode == 3:
                    result = []
                    pass
                else:
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

                    if ".swift" in file_revision.path:
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
            return {'issues': issues}
