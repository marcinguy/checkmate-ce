# -*- coding: utf-8 -*-

from __future__ import unicode_literals
from __future__ import absolute_import

import subprocess
import pprint
import json

result = subprocess.check_output(["/usr/local/bin/find_unicode_control2.py",
                                                  "-d",
                                                  "/root/trojan-source/Python/commenting-out.py"])
json_result = json.loads(result)
pprint.pprint(json_result)

print type(json_result)
line = json_result["line"]
print line

