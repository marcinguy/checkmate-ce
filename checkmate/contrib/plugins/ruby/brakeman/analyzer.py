# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess

logger = logging.getLogger(__name__)


class BrakemanAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(BrakemanAnalyzer, self).__init__(*args, **kwargs)
        try:
            result = subprocess.check_output(["brakeman", "--version"],stderr=subprocess.DEVNULL).strip()
        except subprocess.CalledProcessError:
            logger.error(
                "Cannot initialize Brakeman analyzer: Executable is missing, please install it.")
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
                result = subprocess.check_output(["brakeman",
                                                  "-q",
                                                  "--path",
                                                  tmpdir,
                                                  "-o",
                                                  fout.name],
                                                  stderr=subprocess.DEVNULL).strip()
            except subprocess.CalledProcessError as e:
                if e.returncode == 2:
                    result = e.output
                elif e.returncode == 3:
                    pass
                elif e.returncode == 4:
                    pass
                else:
                    raise

            with open(fout.name, "r") as f:
                try:
                    result = json.load(f)
                except ValueError as e:
                    result['warnings'] = []
                    pass
            json_result = result

            for issue in json_result['warnings']:

                location = (((issue['line'], None),
                             (issue['line'], None)),)

                if ".rb" in file_revision.path and file_revision.path in issue['file']:
                    issues.append({
                        'code': issue['check_name'],
                        'warning_type': issue['warning_type'],
                        'location': location,
                        'data': issue['message'],
                        'file': file_revision.path,
                        'line': issue['line'],
                        'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=issue['message'])
                    })

        finally:
            # os.unlink(f.name)
            pass
        return {'issues': issues}
