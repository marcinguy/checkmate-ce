# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess

logger = logging.getLogger(__name__)


class TfsecAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(TfsecAnalyzer, self).__init__(*args, **kwargs)
        try:
            result = subprocess.check_output(
                ["tfsec", "--version"],stderr=subprocess.DEVNULL).strip()
        except subprocess.CalledProcessError:
            logger.error(
                "Cannot initialize tfsec analyzer: Executable is missing, please install it.")
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

        result = subprocess.check_output(["rsync -r . "+tmpdir+" --exclude .git"],shell=True).strip()

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
                result = subprocess.check_output(["tfsec",
                                                  "-f",
                                                  "json",
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

            try:
                json_result = json.loads(result)

                for issue in json_result['results']:
                    
                    line = issue['location']['start_line']
                    location = (((line, None),
                                 (line, None)),)

                    issues.append({
                            'code': issue['rule_id'],
                            'location': location,
                            'data': issue['rule_description'],
                            'file': file_revision.path,
                            'line': line,
                            'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=issue['rule_description'])
                    })
            except:
                pass

        finally:
          return {'issues': issues}
