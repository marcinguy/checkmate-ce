# -*- coding: utf-8 -*-


issues_data = {
  "eslintdetectevalwithexpression": {
    "title": "Detected eval(variable), which could allow a malicious actor to run arbitrary code.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected eval(variable), which could allow a malicious actor to run arbitrary code.\n"
  },
  "eslintdetectnonliteralrequire": {
    "title": "Detected the use of require(variable). Calling require with a non-literal argument might\nallow an attacker to load an run arbitrary code, or access arbitrary files.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected the use of require(variable). Calling require with a non-literal argument might\nallow an attacker to load an run arbitrary code, or access arbitrary files.\n"
  },
  "eslintdetectobjectinjection": {
    "title": "Bracket object notation with user input is present, this might allow an attacker to access all properties of the object and even it's prototype, leading to possible code execution.",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Bracket object notation with user input is present, this might allow an attacker to access all properties of the object and even it's prototype, leading to possible code execution."
  },
  "eslintdetectnonliteralregexp": {
    "title": "RegExp() called with a variable, this might allow an attacker to DOS your application with a long-running regular expression.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "RegExp() called with a variable, this might allow an attacker to DOS your application with a long-running regular expression.\n"
  },
  "eslintdetectbuffernoassert": {
    "title": "Detected usage of noassert in Buffer API, which allows the offset the be beyond the\nend of the buffer. This could result in writing or reading beyond the end of the buffer.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected usage of noassert in Buffer API, which allows the offset the be beyond the\nend of the buffer. This could result in writing or reading beyond the end of the buffer.\n"
  },
  "eslintdetectnocsrfbeforemethodoverride": {
    "title": "Detected use of express.csrf() middleware before express.methodOverride(). This can\nallow GET requests (which are not checked by csrf) to turn into POST requests later.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected use of express.csrf() middleware before express.methodOverride(). This can\nallow GET requests (which are not checked by csrf) to turn into POST requests later.\n"
  },
  "eslintdetectpseudoRandomBytes": {
    "title": "Detected usage of crypto.pseudoRandomBytes, which does not produce secure random numbers.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected usage of crypto.pseudoRandomBytes, which does not produce secure random numbers.\n"
  },
  "eslintdetectchildprocess": {
    "title": "Detected non-literal calls to child_process.exec(). This could lead to a command\ninjection vulnerability.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected non-literal calls to child_process.exec(). This could lead to a command\ninjection vulnerability.\n"
  },
  "eslintdetectpossibletimingattacks": {
    "title": "String comparisons using '===', '!==', '!=' and '==' is vulnerable to timing attacks. More info: https://snyk.io/blog/node-js-timing-attack-ccc-ctf/",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "String comparisons using '===', '!==', '!=' and '==' is vulnerable to timing attacks. More info: https://snyk.io/blog/node-js-timing-attack-ccc-ctf/"
  },
  "eslintdetectdisablemustacheescape": {
    "title": "Markup escaping disabled. This can be used with some template engines to escape\ndisabling of HTML entities, which can lead to XSS attacks.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Markup escaping disabled. This can be used with some template engines to escape\ndisabling of HTML entities, which can lead to XSS attacks.\n"
  },
  "eslintdetectnonliteralfsfilename": {
    "title": "A variable is present in the filename argument of fs calls, this might allow an attacker to access anything on your system.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A variable is present in the filename argument of fs calls, this might allow an attacker to access anything on your system.\n"
  }
}





