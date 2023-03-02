# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess

logger = logging.getLogger(__name__)


class PmdapexAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(PmdapexAnalyzer, self).__init__(*args, **kwargs)
        try:
            result = subprocess.check_output(
                ["/root/pmd-bin-6.41.0/bin/run.sh", "pmd", "--version"],stderr=subprocess.DEVNULL).strip()
        except subprocess.CalledProcessError:
            logger.error(
                "Cannot initialize PMD analyzer: Executable is missing, please install it.")
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
                result = subprocess.check_output(["/root/pmd-bin-6.41.0/bin/run.sh",
                                                  "pmd",
                                                  "-d",
                                                  f.name,
                                                  "-f",
                                                  "json",
                                                  "-R",
                                                  "rulesets/apex/quickstart.xml"],
                                                  stderr=subprocess.DEVNULL).strip()
                
            except subprocess.CalledProcessError as e:
                if e.returncode == 4:
                    result = e.output
                elif e.returncode == 3:
                    result = []
                    pass
                else:
                    result = []
                    pass

            
            try:
                json_result = json.loads(result)

                for issue in json_result['files'][0]['violations']:

                    location = (((issue['beginline'], None),
                                 (issue['beginline'], None)),)

                    if ".cls" in file_revision.path:
                        issues.append({
                            'code': issue['rule'],
                            'location': location,
                            'data': issue['description'],
                            'file': file_revision.path,
                            'line': issue['beginline'],
                            'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=issue['description'])
                        })
            except:
                pass

        finally:
          return {'issues': issues}
