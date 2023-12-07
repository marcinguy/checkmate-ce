issues_data = {   'eslintdetectbuffernoassert': {   'categories': ['security'],
                                      'description': 'Detected usage of '
                                                     'noassert in Buffer API, '
                                                     'which allows the offset '
                                                     'the be beyond the\n'
                                                     'end of the buffer. This '
                                                     'could result in writing '
                                                     'or reading beyond the '
                                                     'end of the buffer.\n',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'Detected usage of noassert in '
                                               'Buffer API, which allows the '
                                               'offset the be beyond the\n'
                                               'end of the buffer. This could '
                                               'result in writing or reading '
                                               'beyond the end of the '
                                               'buffer.\n'},
    'eslintdetectchildprocess': {   'categories': ['security'],
                                    'description': 'Detected non-literal calls '
                                                   'to child_process.exec(). '
                                                   'This could lead to a '
                                                   'command\n'
                                                   'injection vulnerability.\n',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'Detected non-literal calls to '
                                             'child_process.exec(). This could '
                                             'lead to a command\n'
                                             'injection vulnerability.\n'},
    'eslintdetectdisablemustacheescape': {   'categories': ['security'],
                                             'description': 'Markup escaping '
                                                            'disabled. This '
                                                            'can be used with '
                                                            'some template '
                                                            'engines to '
                                                            'escape\n'
                                                            'disabling of HTML '
                                                            'entities, which '
                                                            'can lead to XSS '
                                                            'attacks.\n',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': 'Markup escaping '
                                                      'disabled. This can be '
                                                      'used with some template '
                                                      'engines to escape\n'
                                                      'disabling of HTML '
                                                      'entities, which can '
                                                      'lead to XSS attacks.\n'},
    'eslintdetectevalwithexpression': {   'categories': ['security'],
                                          'description': 'Detected '
                                                         'eval(variable), '
                                                         'which could allow a '
                                                         'malicious actor to '
                                                         'run arbitrary '
                                                         'code.\n',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'Detected eval(variable), '
                                                   'which could allow a '
                                                   'malicious actor to run '
                                                   'arbitrary code.\n'},
    'eslintdetectnocsrfbeforemethodoverride': {   'categories': ['security'],
                                                  'description': 'Detected use '
                                                                 'of '
                                                                 'express.csrf() '
                                                                 'middleware '
                                                                 'before '
                                                                 'express.methodOverride(). '
                                                                 'This can\n'
                                                                 'allow GET '
                                                                 'requests '
                                                                 '(which are '
                                                                 'not checked '
                                                                 'by csrf) to '
                                                                 'turn into '
                                                                 'POST '
                                                                 'requests '
                                                                 'later.\n',
                                                  'file': '%(issue.file)s',
                                                  'line': '%(issue.line)s',
                                                  'severity': '1',
                                                  'title': 'Detected use of '
                                                           'express.csrf() '
                                                           'middleware before '
                                                           'express.methodOverride(). '
                                                           'This can\n'
                                                           'allow GET requests '
                                                           '(which are not '
                                                           'checked by csrf) '
                                                           'to turn into POST '
                                                           'requests later.\n'},
    'eslintdetectnonliteralfsfilename': {   'categories': ['security'],
                                            'description': 'A variable is '
                                                           'present in the '
                                                           'filename argument '
                                                           'of fs calls, this '
                                                           'might allow an '
                                                           'attacker to access '
                                                           'anything on your '
                                                           'system.\n',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'A variable is present in '
                                                     'the filename argument of '
                                                     'fs calls, this might '
                                                     'allow an attacker to '
                                                     'access anything on your '
                                                     'system.\n'},
    'eslintdetectnonliteralregexp': {   'categories': ['security'],
                                        'description': 'RegExp() called with a '
                                                       'variable, this might '
                                                       'allow an attacker to '
                                                       'DOS your application '
                                                       'with a long-running '
                                                       'regular expression.\n',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'RegExp() called with a '
                                                 'variable, this might allow '
                                                 'an attacker to DOS your '
                                                 'application with a '
                                                 'long-running regular '
                                                 'expression.\n'},
    'eslintdetectnonliteralrequire': {   'categories': ['security'],
                                         'description': 'Detected the use of '
                                                        'require(variable). '
                                                        'Calling require with '
                                                        'a non-literal '
                                                        'argument might\n'
                                                        'allow an attacker to '
                                                        'load an run arbitrary '
                                                        'code, or access '
                                                        'arbitrary files.\n',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'Detected the use of '
                                                  'require(variable). Calling '
                                                  'require with a non-literal '
                                                  'argument might\n'
                                                  'allow an attacker to load '
                                                  'an run arbitrary code, or '
                                                  'access arbitrary files.\n'},
    'eslintdetectobjectinjection': {   'categories': ['security'],
                                       'description': 'Bracket object notation '
                                                      'with user input is '
                                                      'present, this might '
                                                      'allow an attacker to '
                                                      'access all properties '
                                                      'of the object and even '
                                                      "it's prototype, leading "
                                                      'to possible code '
                                                      'execution.',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'Bracket object notation with '
                                                'user input is present, this '
                                                'might allow an attacker to '
                                                'access all properties of the '
                                                "object and even it's "
                                                'prototype, leading to '
                                                'possible code execution.'},
    'eslintdetectpossibletimingattacks': {   'categories': ['security'],
                                             'description': 'String '
                                                            'comparisons using '
                                                            "'===', '!==', "
                                                            "'!=' and '==' is "
                                                            'vulnerable to '
                                                            'timing attacks. '
                                                            'More info: '
                                                            'https://snyk.io/blog/node-js-timing-attack-ccc-ctf/',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': 'String comparisons '
                                                      "using '===', '!==', "
                                                      "'!=' and '==' is "
                                                      'vulnerable to timing '
                                                      'attacks. More info: '
                                                      'https://snyk.io/blog/node-js-timing-attack-ccc-ctf/'},
    'eslintdetectpseudoRandomBytes': {   'categories': ['security'],
                                         'description': 'Detected usage of '
                                                        'crypto.pseudoRandomBytes, '
                                                        'which does not '
                                                        'produce secure random '
                                                        'numbers.\n',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'Detected usage of '
                                                  'crypto.pseudoRandomBytes, '
                                                  'which does not produce '
                                                  'secure random numbers.\n'}}
