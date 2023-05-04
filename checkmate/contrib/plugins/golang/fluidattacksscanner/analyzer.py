# -*- coding: utf-8 -*-


from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import subprocess
import csv

logger = logging.getLogger(__name__)


class FluidAttacksAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(FluidAttacksAnalyzer, self).__init__(*args, **kwargs)

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

        result = ""
        fconf = tempfile.NamedTemporaryFile(delete=False)
        fresults = tempfile.NamedTemporaryFile(delete=False)

        try:
            with f:
                try:
                  f.write(file_revision.get_file_content())
                except UnicodeDecodeError:
                  pass
            f1 = open(fconf.name, "w")
            f1.write("namespace: repository\noutput:\n  file_path: ")
            f1.write(fresults.name+"\n")
            f1.write("  format: CSV\nsast:\n  include:\n    - "+f.name)
            f1.close()
            os.chdir("/tmp")
            os.environ["PATH"] = "/root/.nix-profile/bin:/nix/var/nix/profiles/default/bin:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            try:
                result = subprocess.check_output(["/root/.nix-profile/bin/m",
                                                  "gitlab:fluidattacks/universe@trunk",
                                                  "/skims",
                                                  "scan",
                                                  fconf.name],
                                                  stderr=subprocess.DEVNULL).strip()
            except subprocess.CalledProcessError as e:
                pass
            try:
                json_result = json.loads(result)
            except ValueError:
                json_result = {}
                pass

            my_file = open(fresults.name, 'r')
            reader = csv.reader(my_file)
            try:
              next(reader)
            except:
              logger.error("Fluidattacksscanner error. Continuing ...")
              pass

            outjson = []
            val ={}
            for line in reader:
              val["line"]=line[8]
              val["data"]=line[0]
              outjson.append(val)
              val={}
            try:
                for issue in outjson:
                  line = issue["line"]
                  line = int(line)
                  location = (((line, line),
                             (line, None)),)

                  data = issue["data"]
                  data = data.split(' ', 1)[1]
                  if ".go" in file_revision.path or ".cs" in file_revision.path or ".java" in file_revision.path or ".js" in file_revision.path or ".ts" in file_revision.path:
                    issues.append({
                      'code': "I001",
                      'location': location,
                      'data': data,
                      'file': file_revision.path,
                      'line': line,
                      'fingerprint': self.get_fingerprint_from_code(file_revision, location, extra_data=data)
                    })

            except KeyError:
                pass

        finally:
            os.unlink(f.name)
        return {'issues': issues}

