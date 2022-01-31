# -*- coding: utf-8 -*-

from __future__ import unicode_literals
from __future__ import absolute_import

from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import pprint
import subprocess

logger = logging.getLogger(__name__)

class PmdAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(PmdAnalyzer, self).__init__(*args, **kwargs)
        try:
            result = subprocess.check_output(["/root/pmd-bin-6.41.0/bin/run.sh","pmd","--version"])
        except subprocess.CalledProcessError:
            logger.error("Cannot initialize PMD analyzer: Executable is missing, please install it.")
            raise

    def summarize(self,items):
        pass

    def analyze(self,file_revision):
        issues = []
        tmpdir =  "/tmp/"+file_revision.project.pk
        
        if not os.path.exists(os.path.dirname(tmpdir+"/"+file_revision.path)):
          try:
             os.makedirs(os.path.dirname(tmpdir+"/"+file_revision.path))
          except OSError as exc: # Guard against race condition
             if exc.errno != errno.EEXIST:
               raise
        f = open(tmpdir+"/"+file_revision.path,"w")
        
        fout = tempfile.NamedTemporaryFile(suffix=".json", delete = False)
        result = {}
        try:
            with f:
                f.write(file_revision.get_file_content())
            try:
                result = subprocess.check_output(["/root/pmd-bin-6.41.0/bin/run.sh",
                                                  "pmd",
                                                  "-d",
                                                  f.name,
                                                  "-f",
                                                  "json",
                                                  "-R",
                                                  "rulesets/java/quickstart.xml"])
                #pprint.pprint(result)
            except subprocess.CalledProcessError as e:
                if e.returncode == 4:
                    result = e.output
                elif e.returncode == 3:
                    result = []
                    pass
		else:
                    result = []
                    pass

            #pprint.pprint(result)
            try:
              json_result = json.loads(result)
            
              for issue in json_result['files'][0]['violations']:

                location = (((issue['beginline'],None),
                              (issue['beginline'],None)),)


                if ".java" in file_revision.path or ".jsp" in file_revision.path or ".scala" in file_revision.path:
                  issues.append({
                    'code' : issue['rule'],
                    'location' : location,
                    'data' : issue['description'],
                    'fingerprint' : self.get_fingerprint_from_code(file_revision,location, extra_data=issue['description'])
                    })
            except:
              pass

        finally:
            #os.unlink(f.name)
            print("")
        #pprint.pprint(issues)  
        return {'issues' : issues}
