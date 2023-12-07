# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess

logger = logging.getLogger(__name__)


class CheckovAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(CheckovAnalyzer, self).__init__(*args, **kwargs)
        try:
            result = subprocess.check_output(
                ["checkov", "--version"])
        except subprocess.CalledProcessError:
            logger.error(
                "Cannot initialize checkov analyzer: Executable is missing, please install it.")
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
                result = subprocess.check_output(["checkov",
                                                  "-o",
                                                  "json",
                                                  "--file",
                                                  f.name])
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

            try:
                json_result = json.loads(result)

                for issue in json_result['results']['failed_checks']:
                    
                    line = issue['file_line_range'][0]
                    location = (((line, None),
                                 (line, None)),)

                    issues.append({
                            'code': issue['check_id'],
                            'location': location,
                            'data': issue['check_name'],
                            'file': file_revision.path,
                            'line': line,
                            'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=issue['check_name'])
                    })
            except:
                pass

        finally:
            return {'issues': issues}
