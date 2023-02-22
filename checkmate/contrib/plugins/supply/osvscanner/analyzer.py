# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import sys
import tempfile
import json
import subprocess
import pprint

logger = logging.getLogger(__name__)


class OSVscannerAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(OSVscannerAnalyzer, self).__init__(*args, **kwargs)

    def summarize(self, items):
        pass

    def analyze(self, file_revision):
        issues = []
        json_result = ""
        tmpdir = "/tmp/"+file_revision.project.pk

        if not os.path.exists(os.path.dirname(tmpdir+"/"+file_revision.path)):
            try:
                os.makedirs(os.path.dirname(tmpdir+"/"+file_revision.path))
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
        
        f = open(tmpdir+"/"+file_revision.path, "wb")

        result = {}
        try:
            with f:
                try:
                  f.write(file_revision.get_file_content())
                except UnicodeDecodeError:
                  pass
            os.environ["PATH"] = "/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/:/usr/local/go/bin/"

            try:
                result = subprocess.check_output(["/root/bin/osv-scanner",
                                                  "--json",
                                                  tmpdir],
                                                  stderr=subprocess.DEVNULL).strip()
            except subprocess.CalledProcessError as e:
                json_result = e.output

            try:
              json_result = json.loads(json_result)
            except:
              pass

            try:
               if "Cargo.lock" in file_revision.path or "packages.lock.json" in file_revision.path or "package-lock.json" in file_revision.path or  "yarn.lock" in file_revision.path or  "pnpm-lock.yaml" in file_revision.path or  "composer.lock" in file_revision.path or  "Gemfile.lock" in file_revision.path or  "go.mod" in file_revision.path or  "mix.lock" in file_revision.path or  "poetry.lock" in file_revision.path or "pubsepc.lock" in file_revision.path or "pom.xml" in file_revision.path or  "requirements.txt" in file_revision.path or "gradle.lockfile" in file_revision.path or  "buildscript-gradle.lockfile" in file_revision.path:
                  for res in json_result['results']:
                    for pkg in res['packages']:
                      for vuln in pkg['vulnerabilities']:
                        location = (((1,None),
                              (1,None)),)
                        issues.append({
                          'code' : vuln['id'],
                          'location' : location,
                          'data' : vuln['id'],
                          'file': file_revision.path,
                          'line': int(1),
                          'fingerprint' : self.get_fingerprint_from_code(file_revision,location, extra_data=vuln['id'])
                        })
            except:
                pass

        finally:
            pass
        return {'issues': issues}

