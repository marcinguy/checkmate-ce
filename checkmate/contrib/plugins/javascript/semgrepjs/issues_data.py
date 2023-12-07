issues_data = {   'AccessForeignKeys': {   'categories': ['security'],
                             'description': 'You should use ITEM.user_id '
                                            'rather than ITEM.user.id to '
                                            'prevent running an extra query.',
                             'display_name': 'AccessForeignKeys',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'access foreign keys'},
    'AdmzipPathOverwrite': {   'categories': ['security'],
                               'description': 'Insecure ZIP archive extraction '
                                              'using adm-zip can result in '
                                              'arbitrary path over write and '
                                              'can result in code injection.',
                               'display_name': 'AdmzipPathOverwrite',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'admzip path overwrite'},
    'AiopgSqli': {   'categories': ['security'],
                     'description': 'Detected string concatenation with a '
                                    'non-literal variable in an aiopg\n'
                                    'Python SQL statement. This could lead to '
                                    'SQL injection if the variable is '
                                    'user-controlled\n'
                                    'and not properly sanitized. In order to '
                                    'prevent SQL injection,\n'
                                    'use parameterized queries instead.\n'
                                    'You can create parameterized queries like '
                                    'so:\n'
                                    '\'cur.execute("SELECT %s FROM table", '
                                    "(user_value,))'.",
                     'display_name': 'AiopgSqli',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'aiopg sqli'},
    'AliasForHtmlSafe': {   'categories': ['security'],
                            'description': 'The syntax `<%== ... %>` is an '
                                           'alias for `html_safe`. This means '
                                           'the\n'
                                           'content inside these tags will be '
                                           'rendered as raw HTML. This may '
                                           'expose\n'
                                           'your application to cross-site '
                                           'scripting. If you need raw HTML, '
                                           'prefer\n'
                                           'using the more explicit '
                                           '`html_safe` and be sure to '
                                           'correctly sanitize\n'
                                           'variables using a library such as '
                                           'DOMPurify.',
                            'display_name': 'AliasForHtmlSafe',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'alias for html safe'},
    'AliasMustBeUnique': {   'categories': ['security'],
                             'description': 'Image aliases must have a unique '
                                            "name, and '$REF' is used twice. "
                                            "Use another name for '$REF'.\n"
                                            '{"include": ["*dockerfile*", '
                                            '"*Dockerfile*"]}',
                             'display_name': 'AliasMustBeUnique',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'dockerfile: alias must be unique'},
    'AliasPathTraversal': {   'categories': ['security'],
                              'description': 'The alias in this location block '
                                             'is subject to a path traversal '
                                             'because the location path does '
                                             'not end in a path separator '
                                             "(e.g., '/'). To fix, add a path "
                                             'separator to the end of the '
                                             'path.\n'
                                             '{"include": ["*.conf", '
                                             '"*.vhost", "sites-available/*", '
                                             '"sites-enabled/*"]}',
                              'display_name': 'AliasPathTraversal',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'nginx: alias path traversal'},
    'AllowPrivilegeEscalation': {   'categories': ['security'],
                                    'description': 'Container allows for '
                                                   'privilege escalation via '
                                                   'setuid or setgid '
                                                   'binaries.\n'
                                                   'Add '
                                                   "'allowPrivilegeEscalation: "
                                                   "false' in "
                                                   "'securityContext' to "
                                                   'prevent this.',
                                    'display_name': 'AllowPrivilegeEscalation',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'kubernetes: allow privilege '
                                             'escalation'},
    'AngularBypasssecuritytrust': {   'categories': ['security'],
                                      'description': 'Bypassing the built-in '
                                                     'sanitization could '
                                                     'expose the application '
                                                     'to cross-site scripting '
                                                     '(XSS).',
                                      'display_name': 'AngularBypasssecuritytrust',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'angular bypasssecuritytrust'},
    'AngularSanitizeNoneContext': {   'categories': ['security'],
                                      'description': 'The output is not '
                                                     'sanitized when calling '
                                                     'with '
                                                     'SecurityContext.NONE.',
                                      'display_name': 'AngularSanitizeNoneContext',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'angular sanitize none context'},
    'AnonymousLdapBind': {   'categories': ['security'],
                             'description': 'Detected anonymous LDAP bind.\n'
                                            'This permits anonymous users to '
                                            'execute LDAP statements. Consider '
                                            'enforcing\n'
                                            'authentication for LDAP. See '
                                            'https://docs.oracle.com/javase/tutorial/jndi/ldap/auth_mechs.html\n'
                                            'for more information.',
                             'display_name': 'AnonymousLdapBind',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'anonymous ldap bind'},
    'AntiCsrfControl': {   'categories': ['security'],
                           'description': 'This application has anti CSRF '
                                          'protection which prevents cross '
                                          'site request forgery attacks.',
                           'display_name': 'AntiCsrfControl',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'anti csrf control'},
    'ArbitrarySleep': {   'categories': ['security'],
                          'description': 'time.sleep() call; did you mean to '
                                         'leave this in?',
                          'display_name': 'ArbitrarySleep',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'arbitrary sleep'},
    'AssertUse': {   'categories': ['security'],
                     'description': 'Calling assert with user input is '
                                    "equivalent to eval'ing.",
                     'display_name': 'AssertUse',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'assert use'},
    'AssignedUndefined': {   'categories': ['security'],
                             'description': '`undefined` is not a reserved '
                                            'keyword in Javascript, so this is '
                                            '"valid" Javascript but highly '
                                            'confusing and likely to result in '
                                            'bugs.',
                             'display_name': 'AssignedUndefined',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'assigned undefined'},
    'AssignmentComparison': {   'categories': ['security'],
                                'description': 'The value of `$X` is being '
                                               'ignored and will be used in '
                                               'the conditional test',
                                'display_name': 'AssignmentComparison',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'assignment comparison'},
    'AsyncpgSqli': {   'categories': ['security'],
                       'description': 'Detected string concatenation with a '
                                      'non-literal variable in a asyncpg\n'
                                      'Python SQL statement. This could lead '
                                      'to SQL injection if the variable is '
                                      'user-controlled\n'
                                      'and not properly sanitized. In order to '
                                      'prevent SQL injection,\n'
                                      'used parameterized queries or prepared '
                                      'statements instead.\n'
                                      'You can create parameterized queries '
                                      'like so:\n'
                                      '\'conn.fetch("SELECT $1 FROM table", '
                                      "value)'.\n"
                                      'You can also create prepared statements '
                                      "with 'Connection.prepare':\n"
                                      '\'stmt = conn.prepare("SELECT $1 FROM '
                                      'table")\n'
                                      " await stmt.fetch(user_value)'",
                       'display_name': 'AsyncpgSqli',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'asyncpg sqli'},
    'AttrMutableInitializer': {   'categories': ['security'],
                                  'description': 'Unsafe usage of mutable '
                                                 'initializer with attr.s '
                                                 'decorator.\n'
                                                 'Multiple instances of this '
                                                 'class will re-use the same '
                                                 'data structure, which is '
                                                 'likely not the desired '
                                                 'behavior.\n'
                                                 'Consider instead: replace '
                                                 'assignment to mutable '
                                                 'initializer (ex. dict() or '
                                                 '{}) with '
                                                 'attr.ib(factory=type) where '
                                                 'type is dict, set, or list',
                                  'display_name': 'AttrMutableInitializer',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'attr mutable initializer'},
    'AutoescapeDisabled': {   'categories': ['security'],
                              'description': 'Detected an element with '
                                             'disabled HTML escaping. If '
                                             'external\n'
                                             'data can reach this, this is a '
                                             'cross-site scripting (XSS)\n'
                                             'vulnerability. Ensure no '
                                             'external data can reach here, '
                                             'or\n'
                                             "remove 'escape=false' from this "
                                             'element.',
                              'display_name': 'AutoescapeDisabled',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'autoescape disabled'},
    'AvoidAccessingRequestInWrongHandler': {   'categories': ['security'],
                                               'description': 'Accessing '
                                                              'request object '
                                                              'inside a route '
                                                              'handle for HTTP '
                                                              'GET command '
                                                              'will throw due '
                                                              'to missing '
                                                              'request body.',
                                               'display_name': 'AvoidAccessingRequestInWrongHandler',
                                               'file': '%(issue.file)s',
                                               'line': '%(issue.line)s',
                                               'severity': '1',
                                               'title': 'avoid accessing '
                                                        'request in wrong '
                                                        'handler'},
    'AvoidApkUpgrade': {   'categories': ['security'],
                           'description': 'Packages in base images should be '
                                          'up-to-date, removing the need for\n'
                                          "'apk upgrade'. If packages are "
                                          'out-of-date, consider contacting '
                                          'the\n'
                                          'base image maintainer.\n'
                                          '\n'
                                          '{"include": ["*dockerfile*", '
                                          '"*Dockerfile*"]}',
                           'display_name': 'AvoidApkUpgrade',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'dockerfile: avoid apk upgrade'},
    'AvoidAptGetUpgrade': {   'categories': ['security'],
                              'description': 'Packages in base containers '
                                             'should be up-to-date, removing '
                                             'the need to upgrade or '
                                             'dist-upgrade. If a package is '
                                             'out of date, contact the '
                                             'maintainers.\n'
                                             '{"include": ["*dockerfile*", '
                                             '"*Dockerfile*"]}',
                              'display_name': 'AvoidAptGetUpgrade',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'dockerfile: avoid apt get upgrade'},
    'AvoidBindToAllInterfaces': {   'categories': ['security'],
                                    'description': 'Listening on 0.0.0.0 or '
                                                   'empty string could '
                                                   'unexpectedly expose the '
                                                   'server publicly as it '
                                                   'binds to all available '
                                                   'interfaces',
                                    'display_name': 'AvoidBindToAllInterfaces',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'avoid bind to all interfaces'},
    'AvoidContentTag': {   'categories': ['security'],
                           'description': "'content_tag()' bypasses HTML "
                                          'escaping for some portion of the '
                                          'content.\n'
                                          'If external data can reach here, '
                                          'this exposes your application\n'
                                          'to cross-site scripting (XSS) '
                                          'attacks. Ensure no external data '
                                          'reaches here.\n'
                                          'If you must do this, create your '
                                          "HTML manually and use 'html_safe'. "
                                          'Ensure no\n'
                                          'external data enters the HTML-safe '
                                          'string!',
                           'display_name': 'AvoidContentTag',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'avoid content tag'},
    'AvoidCpickle': {   'categories': ['security'],
                        'description': 'Avoid using `cPickle`, which is known '
                                       'to lead to code execution '
                                       'vulnerabilities.\n'
                                       'When unpickling, the serialized data '
                                       'could be manipulated to run arbitrary '
                                       'code.\n'
                                       'Instead, consider serializing the '
                                       'relevant data as JSON or a similar '
                                       'text-based\n'
                                       'serialization format.',
                        'display_name': 'AvoidCpickle',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'avoid cPickle'},
    'AvoidDill': {   'categories': ['security'],
                     'description': 'Avoid using `dill`, which uses `pickle`, '
                                    'which is known to lead to code execution '
                                    'vulnerabilities.\n'
                                    'When unpickling, the serialized data '
                                    'could be manipulated to run arbitrary '
                                    'code.\n'
                                    'Instead, consider serializing the '
                                    'relevant data as JSON or a similar '
                                    'text-based\n'
                                    'serialization format.',
                     'display_name': 'AvoidDill',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'avoid dill'},
    'AvoidDnfUpdate': {   'categories': ['security'],
                          'description': 'Packages in base images should be '
                                         'up-to-date, removing the need for\n'
                                         "'dnf update'. If packages are "
                                         'out-of-date, consider contacting '
                                         'the\n'
                                         'base image maintainer.\n'
                                         '\n'
                                         '{"include": ["*dockerfile*", '
                                         '"*Dockerfile*"]}',
                          'display_name': 'AvoidDnfUpdate',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'dockerfile: avoid dnf update'},
    'AvoidHtmlSafe': {   'categories': ['security'],
                         'description': "'html_safe()' does not make the "
                                        "supplied string safe. 'html_safe()' "
                                        'bypasses\n'
                                        'HTML escaping. If external data can '
                                        'reach here, this exposes your '
                                        'application\n'
                                        'to cross-site scripting (XSS) '
                                        'attacks. Ensure no external data '
                                        'reaches here.',
                         'display_name': 'AvoidHtmlSafe',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'avoid html safe'},
    'AvoidImplementingCustomDigests': {   'categories': ['security'],
                                          'description': 'Cryptographic '
                                                         'algorithms are '
                                                         'notoriously '
                                                         'difficult to get '
                                                         'right. By '
                                                         'implementing\n'
                                                         'a custom message '
                                                         'digest, you risk '
                                                         'introducing security '
                                                         'issues into your '
                                                         'program.\n'
                                                         'Use one of the many '
                                                         'sound message '
                                                         'digests already '
                                                         'available to you:\n'
                                                         'MessageDigest '
                                                         'sha256Digest = '
                                                         'MessageDigest.getInstance("SHA256");',
                                          'display_name': 'AvoidImplementingCustomDigests',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'avoid implementing custom '
                                                   'digests'},
    'AvoidInsecureDeserialization': {   'categories': ['security'],
                                        'description': 'Avoid using insecure '
                                                       'deserialization '
                                                       'library, backed by '
                                                       '`pickle`, `_pickle`, '
                                                       '`cpickle`, `dill`, '
                                                       '`shelve`, or `yaml`, '
                                                       'which are known to '
                                                       'lead to remote code '
                                                       'execution '
                                                       'vulnerabilities.',
                                        'display_name': 'AvoidInsecureDeserialization',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'avoid insecure '
                                                 'deserialization'},
    'AvoidLatestVersion': {   'categories': ['security'],
                              'description': 'Images should be tagged with an '
                                             'explicit version to produce\n'
                                             'deterministic container images. '
                                             "The 'latest' tag may change\n"
                                             'the base container without '
                                             'warning.\n'
                                             '\n'
                                             '{"include": ["*dockerfile*", '
                                             '"*Dockerfile*"]}',
                              'display_name': 'AvoidLatestVersion',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'dockerfile: avoid latest version'},
    'AvoidMarkSafe': {   'categories': ['security'],
                         'description': "'mark_safe()' is used to mark a "
                                        'string as "safe" for HTML output.\n'
                                        'This disables escaping and could '
                                        'therefore subject the content to\n'
                                        'XSS attacks. Use '
                                        "'django.utils.html.format_html()' to "
                                        'build HTML\n'
                                        'for rendering instead.',
                         'display_name': 'AvoidMarkSafe',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'avoid mark safe'},
    'AvoidPickle': {   'categories': ['security'],
                       'description': 'Avoid using `pickle`, which is known to '
                                      'lead to code execution '
                                      'vulnerabilities.\n'
                                      'When unpickling, the serialized data '
                                      'could be manipulated to run arbitrary '
                                      'code.\n'
                                      'Instead, consider serializing the '
                                      'relevant data as JSON or a similar '
                                      'text-based\n'
                                      'serialization format.',
                       'display_name': 'AvoidPickle',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'avoid pickle'},
    'AvoidPlatformWithFrom': {   'categories': ['security'],
                                 'description': "Using '--platform' with FROM "
                                                'restricts the image to build '
                                                'on a single platform. '
                                                'Further, this must be the '
                                                'same as the build platform. '
                                                'If you intended to specify '
                                                'the target platform, use the '
                                                "utility 'docker buildx "
                                                "--platform=' instead.\n"
                                                '{"include": ["*dockerfile*", '
                                                '"*Dockerfile*"]}',
                                 'display_name': 'AvoidPlatformWithFrom',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'dockerfile: avoid platform with '
                                          'from'},
    'AvoidPyyamlLoad': {   'categories': ['security'],
                           'description': 'Avoid using `load()`. `PyYAML.load` '
                                          'can create arbitrary Python\n'
                                          'objects. A malicious actor could '
                                          'exploit this to run arbitrary\n'
                                          'code. Use `safe_load()` instead.',
                           'display_name': 'AvoidPyyamlLoad',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'avoid pyyaml load'},
    'AvoidQuerySetExtra': {   'categories': ['security'],
                              'description': 'This is a last resort. You '
                                             'should be careful when using '
                                             'QuerySet.extra due to SQLi '
                                             'https://docs.djangoproject.com/en/3.0/ref/models/querysets/#django.db.models.query.QuerySet.extra',
                              'display_name': 'AvoidQuerySetExtra',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'avoid query set extra'},
    'AvoidRaw': {   'categories': ['security'],
                    'description': "'raw()' bypasses HTML escaping. If "
                                   'external data can reach here, this exposes '
                                   'your application\n'
                                   'to cross-site scripting (XSS) attacks. If '
                                   'you must do this, construct individual '
                                   'strings\n'
                                   'and mark them as safe for HTML rendering '
                                   'with `html_safe()`.',
                    'display_name': 'AvoidRaw',
                    'file': '%(issue.file)s',
                    'line': '%(issue.line)s',
                    'severity': '1',
                    'title': 'avoid raw'},
    'AvoidRawSql': {   'categories': ['security'],
                       'description': 'You should be very careful whenever you '
                                      'write raw SQL. Consider using Django '
                                      'ORM before raw SQL. See '
                                      'https://docs.djangoproject.com/en/3.0/topics/db/sql/#passing-parameters-into-raw',
                       'display_name': 'AvoidRawSql',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'avoid raw sql'},
    'AvoidRenderInline': {   'categories': ['security'],
                             'description': "'render inline: ...' renders an "
                                            'entire ERB template inline and is '
                                            'dangerous.\n'
                                            'If external data can reach here, '
                                            'this exposes your application\n'
                                            'to server-side template injection '
                                            '(SSTI) or cross-site scripting '
                                            '(XSS) attacks.\n'
                                            'Instead, consider using a partial '
                                            'or another safe rendering method.',
                             'display_name': 'AvoidRenderInline',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'avoid render inline'},
    'AvoidRenderText': {   'categories': ['security'],
                           'description': "'render text: ...' actually sets "
                                          "the content-type to 'text/html'.\n"
                                          'If external data can reach here, '
                                          'this exposes your application\n'
                                          'to cross-site scripting (XSS) '
                                          "attacks. Instead, use 'render "
                                          "plain: ...' to\n"
                                          'render non-HTML text.',
                           'display_name': 'AvoidRenderText',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'avoid render text'},
    'AvoidShelve': {   'categories': ['security'],
                       'description': 'Avoid using `shelve`, which uses '
                                      '`pickle`, which is known to lead to '
                                      'code execution vulnerabilities.\n'
                                      'When unpickling, the serialized data '
                                      'could be manipulated to run arbitrary '
                                      'code.\n'
                                      'Instead, consider serializing the '
                                      'relevant data as JSON or a similar '
                                      'text-based\n'
                                      'serialization format.',
                       'display_name': 'AvoidShelve',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'avoid shelve'},
    'AvoidSshInsecureIgnoreHostKey': {   'categories': ['security'],
                                         'description': 'Disabled host key '
                                                        'verification '
                                                        'detected. This allows '
                                                        'man-in-the-middle\n'
                                                        'attacks. Use the '
                                                        "'golang.org/x/crypto/ssh/knownhosts' "
                                                        'package to do\n'
                                                        'host key '
                                                        'verification.\n'
                                                        'See '
                                                        'https://skarlso.github.io/2019/02/17/go-ssh-with-host-key-verification/\n'
                                                        'to learn more about '
                                                        'the problem and how '
                                                        'to fix it.',
                                         'display_name': 'AvoidSshInsecureIgnoreHostKey',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'avoid ssh insecure ignore '
                                                  'host key'},
    'AvoidUnsafeRuamel': {   'categories': ['security'],
                             'description': 'Avoid using unsafe '
                                            '`ruamel.yaml.YAML()`. '
                                            '`ruamel.yaml.YAML` can\n'
                                            'create arbitrary Python objects. '
                                            'A malicious actor could exploit\n'
                                            'this to run arbitrary code. Use '
                                            "`YAML(typ='rt')` or\n"
                                            "`YAML(typ='safe')` instead.",
                             'display_name': 'AvoidUnsafeRuamel',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'avoid unsafe ruamel'},
    'AvoidVHtml': {   'categories': ['security'],
                      'description': 'Dynamically rendering arbitrary HTML on '
                                     'your website can be very dangerous '
                                     'because it can easily lead to XSS '
                                     'vulnerabilities. Only use HTML '
                                     'interpolation on trusted content and '
                                     'never on user-provided content.',
                      'display_name': 'AvoidVHtml',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'avoid v html'},
    'AvoidYumUpdate': {   'categories': ['security'],
                          'description': 'Packages in base images should be '
                                         'up-to-date, removing the need for\n'
                                         "'yum update'. If packages are "
                                         'out-of-date, consider contacting '
                                         'the\n'
                                         'base image maintainer.\n'
                                         '\n'
                                         '{"include": ["*dockerfile*", '
                                         '"*Dockerfile*"]}',
                          'display_name': 'AvoidYumUpdate',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'dockerfile: avoid yum update'},
    'AvoidZypperUpdate': {   'categories': ['security'],
                             'description': 'Packages in base images should be '
                                            'up-to-date, removing the need '
                                            'for\n'
                                            "'zypper update'. If packages are "
                                            'out-of-date, consider contacting '
                                            'the\n'
                                            'base image maintainer.\n'
                                            '\n'
                                            '{"include": ["*dockerfile*", '
                                            '"*Dockerfile*"]}',
                             'display_name': 'AvoidZypperUpdate',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'dockerfile: avoid zypper update'},
    'Avoid_app_run_with_bad_host': {   'categories': ['security'],
                                       'description': 'Running flask app with '
                                                      'host 0.0.0.0 could '
                                                      'expose the server '
                                                      'publicly.',
                                       'display_name': 'Avoid_app_run_with_bad_host',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'avoid_app_run_with_bad_host'},
    'Avoid_hardcoded_config_debug': {   'categories': ['security'],
                                        'description': 'Hardcoded variable '
                                                       '`DEBUG` detected. Set '
                                                       'this by using '
                                                       'FLASK_DEBUG '
                                                       'environment variable',
                                        'display_name': 'Avoid_hardcoded_config_debug',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'avoid_hardcoded_config_DEBUG'},
    'Avoid_hardcoded_config_env': {   'categories': ['security'],
                                      'description': 'Hardcoded variable `ENV` '
                                                     'detected. Set this by '
                                                     'using FLASK_ENV '
                                                     'environment variable',
                                      'display_name': 'Avoid_hardcoded_config_env',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'avoid_hardcoded_config_ENV'},
    'Avoid_hardcoded_config_secret_key': {   'categories': ['security'],
                                             'description': 'Hardcoded '
                                                            'variable '
                                                            '`SECRET_KEY` '
                                                            'detected. Use '
                                                            'environment '
                                                            'variables or '
                                                            'config files '
                                                            'instead',
                                             'display_name': 'Avoid_hardcoded_config_secret_key',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': 'avoid_hardcoded_config_SECRET_KEY'},
    'Avoid_hardcoded_config_testing': {   'categories': ['security'],
                                          'description': 'Hardcoded variable '
                                                         '`TESTING` detected. '
                                                         'Use environment '
                                                         'variables or config '
                                                         'files instead',
                                          'display_name': 'Avoid_hardcoded_config_testing',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'avoid_hardcoded_config_TESTING'},
    'Avoid_send_file_without_path_sanitization': {   'categories': ['security'],
                                                     'description': 'Looks '
                                                                    'like '
                                                                    '`filename` '
                                                                    'could '
                                                                    'flow to '
                                                                    '`flask.send_file()` '
                                                                    'function. '
                                                                    'Make sure '
                                                                    'to '
                                                                    'properly '
                                                                    'sanitize '
                                                                    'filename '
                                                                    'or use '
                                                                    '`flask.send_from_directory`',
                                                     'display_name': 'Avoid_send_file_without_path_sanitization',
                                                     'file': '%(issue.file)s',
                                                     'line': '%(issue.line)s',
                                                     'severity': '1',
                                                     'title': 'avoid_send_file_without_path_sanitization'},
    'Avoid_using_app_run_directly': {   'categories': ['security'],
                                        'description': 'top-level app.run(...) '
                                                       'is ignored by flask. '
                                                       'Consider putting '
                                                       'app.run(...) behind a '
                                                       'guard, like inside a '
                                                       'function',
                                        'display_name': 'Avoid_using_app_run_directly',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'avoid_using_app_run_directly'},
    'BackticksUse': {   'categories': ['security'],
                        'description': 'Backticks use may lead to command '
                                       'injection vulnerabilities.',
                        'display_name': 'BackticksUse',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'backticks use'},
    'BadDeserialization': {   'categories': ['security'],
                              'description': 'Checks for unsafe '
                                             'deserialization. Objects in Ruby '
                                             'can be serialized into strings,\n'
                                             'then later loaded from strings. '
                                             'However, uses of load and '
                                             'object_load can cause remote '
                                             'code execution.\n'
                                             'Loading user input with YAML, '
                                             'MARSHAL, or CSV can potentially '
                                             'be dangerous. Use JSON securely '
                                             'instead.',
                              'display_name': 'BadDeserialization',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'bad deserialization'},
    'BadHexaConversion': {   'categories': ['security'],
                             'description': "'Integer.toHexString()' strips "
                                            'leading zeroes from each byte if '
                                            'read byte-by-byte.\n'
                                            'This mistake weakens the hash '
                                            'value computed since it '
                                            'introduces more collisions.\n'
                                            'Use \'String.format("%02X", '
                                            "...)' instead.",
                             'display_name': 'BadHexaConversion',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'bad hexa conversion'},
    'BadOperatorInFilter': {   'categories': ['security'],
                               'description': 'Only comparison operators '
                                              'should be used inside '
                                              'SQLAlchemy filter expressions. '
                                              'Use `==` instead of `is`,\n'
                                              '`!=` instead of `is not`, '
                                              '`sqlalchemy.and_` instead of '
                                              '`and`, `sqlalchemy.or_` instead '
                                              'of `or`,\n'
                                              '`sqlalchemy.not_` instead of '
                                              '`not`, and `sqlalchemy.in_` '
                                              'instead of `in_`.',
                               'display_name': 'BadOperatorInFilter',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'bad operator in filter'},
    'BadSend': {   'categories': ['security'],
                   'description': 'Checks for unsafe use of Object#send, try, '
                                  '__send__, and public_send. These only '
                                  'account for unsafe\n'
                                  'use of a method, not target. This can lead '
                                  'to arbitrary calling of exit, along with '
                                  'arbitrary code     execution.\n'
                                  'Please be sure to sanitize input in order '
                                  'to avoid this.',
                   'display_name': 'BadSend',
                   'file': '%(issue.file)s',
                   'line': '%(issue.line)s',
                   'severity': '1',
                   'title': 'bad send'},
    'BadTmpFileCreation': {   'categories': ['security'],
                              'description': 'File creation in shared tmp '
                                             'directory without using '
                                             'ioutil.Tempfile',
                              'display_name': 'BadTmpFileCreation',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'bad tmp file creation'},
    'BaseclassAttributeOverride': {   'categories': ['security'],
                                      'description': 'Class $C inherits from '
                                                     'both `$A` and `$B` which '
                                                     'both have a method '
                                                     'named\n'
                                                     '`$F`; one of these '
                                                     'methods will be '
                                                     'overwritten.',
                                      'display_name': 'BaseclassAttributeOverride',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'baseclass attribute override'},
    'Bash_reverse_shell': {   'categories': ['security'],
                              'description': 'Semgrep found a bash reverse '
                                             'shell',
                              'display_name': 'Bash_reverse_shell',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'ci: bash_reverse_shell'},
    'BatchImport': {   'categories': ['security'],
                       'description': 'Rather than adding one element at a '
                                      'time, consider batch loading to improve '
                                      'performance.',
                       'display_name': 'BatchImport',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'batch import'},
    'BlowfishInsufficientKeySize': {   'categories': ['security'],
                                       'description': 'Using less than 128 '
                                                      'bits for Blowfish is '
                                                      'considered insecure. '
                                                      'Use 128 bits\n'
                                                      'or more, or switch to '
                                                      'use AES instead.',
                                       'display_name': 'BlowfishInsufficientKeySize',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'blowfish insufficient key '
                                                'size'},
    'BokehDeprecatedApis': {   'categories': ['security'],
                               'description': 'These APIs are deprecated in '
                                              'Bokeh see '
                                              'https://docs.bokeh.org/en/latest/docs/releases.html#api-deprecations',
                               'display_name': 'BokehDeprecatedApis',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'bokeh deprecated apis'},
    'BufferNoassert': {   'categories': ['security'],
                          'description': 'Detected usage of noassert in Buffer '
                                         'API, which allows the offset the be '
                                         'beyond the end of the buffer. This '
                                         'could result in writing or reading '
                                         'beyond the end of the buffer.',
                          'display_name': 'BufferNoassert',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'buffer noassert'},
    'CStringEquality': {   'categories': ['security'],
                           'description': 'Using == on char* performs pointer '
                                          'comparison, use strcmp instead',
                           'display_name': 'CStringEquality',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'c string equality'},
    'CbcPaddingOracle': {   'categories': ['security'],
                            'description': 'Using CBC with PKCS5Padding is '
                                           'susceptible to padding orcale '
                                           'attacks. A malicious actor\n'
                                           'could discern the difference '
                                           'between plaintext with valid or '
                                           'invalid padding. Further,\n'
                                           'CBC mode does not include any '
                                           'integrity checks. See '
                                           'https://find-sec-bugs.github.io/bugs.htm#CIPHER_INTEGRITY.\n'
                                           "Use 'AES/GCM/NoPadding' instead.",
                            'display_name': 'CbcPaddingOracle',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'cbc padding oracle'},
    'ChannelGuardedWithMutex': {   'categories': ['security'],
                                   'description': 'Detected a channel guarded '
                                                  'with a mutex. Channels '
                                                  'already have\n'
                                                  'an internal mutex, so this '
                                                  'is unnecessary. Remove the '
                                                  'mutex.\n'
                                                  'See '
                                                  'https://hackmongo.com/page/golang-antipatterns/#guarded-channel\n'
                                                  'for more information.',
                                   'display_name': 'ChannelGuardedWithMutex',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'channel guarded with mutex'},
    'ChromeRemoteInterfaceCompilescriptInjection': {   'categories': [   'security'],
                                                       'description': 'If '
                                                                      'unverified '
                                                                      'user '
                                                                      'data '
                                                                      'can '
                                                                      'reach '
                                                                      'the '
                                                                      '`compileScript` '
                                                                      'method '
                                                                      'it can '
                                                                      'result '
                                                                      'in '
                                                                      'Server-Side '
                                                                      'Request '
                                                                      'Forgery '
                                                                      'vulnerabilities',
                                                       'display_name': 'ChromeRemoteInterfaceCompilescriptInjection',
                                                       'file': '%(issue.file)s',
                                                       'line': '%(issue.line)s',
                                                       'severity': '1',
                                                       'title': 'chrome remote '
                                                                'interface '
                                                                'compilescript '
                                                                'injection'},
    'ChromeRemoteInterfaceEvaluateInjection': {   'categories': ['security'],
                                                  'description': 'If '
                                                                 'unverified '
                                                                 'user data '
                                                                 'can reach '
                                                                 'the '
                                                                 '`evaluate` '
                                                                 'method it '
                                                                 'can result '
                                                                 'in '
                                                                 'Server-Side '
                                                                 'Request '
                                                                 'Forgery '
                                                                 'vulnerabilities',
                                                  'display_name': 'ChromeRemoteInterfaceEvaluateInjection',
                                                  'file': '%(issue.file)s',
                                                  'line': '%(issue.line)s',
                                                  'severity': '1',
                                                  'title': 'chrome remote '
                                                           'interface evaluate '
                                                           'injection'},
    'ChromeRemoteInterfaceNavigateInjection': {   'categories': ['security'],
                                                  'description': 'If '
                                                                 'unverified '
                                                                 'user data '
                                                                 'can reach '
                                                                 'the '
                                                                 '`navigate` '
                                                                 'method it '
                                                                 'can result '
                                                                 'in '
                                                                 'Server-Side '
                                                                 'Request '
                                                                 'Forgery '
                                                                 'vulnerabilities',
                                                  'display_name': 'ChromeRemoteInterfaceNavigateInjection',
                                                  'file': '%(issue.file)s',
                                                  'line': '%(issue.line)s',
                                                  'severity': '1',
                                                  'title': 'chrome remote '
                                                           'interface navigate '
                                                           'injection'},
    'ChromeRemoteInterfacePrinttopdfInjection': {   'categories': ['security'],
                                                    'description': 'If '
                                                                   'unverified '
                                                                   'user data '
                                                                   'can reach '
                                                                   'the '
                                                                   '`printToPDF` '
                                                                   'method it '
                                                                   'can result '
                                                                   'in '
                                                                   'Server-Side '
                                                                   'Request '
                                                                   'Forgery '
                                                                   'vulnerabilities',
                                                    'display_name': 'ChromeRemoteInterfacePrinttopdfInjection',
                                                    'file': '%(issue.file)s',
                                                    'line': '%(issue.line)s',
                                                    'severity': '1',
                                                    'title': 'chrome remote '
                                                             'interface '
                                                             'printtopdf '
                                                             'injection'},
    'ChromeRemoteInterfaceSetdocumentcontentInjection': {   'categories': [   'security'],
                                                            'description': 'If '
                                                                           'unverified '
                                                                           'user '
                                                                           'data '
                                                                           'can '
                                                                           'reach '
                                                                           'the '
                                                                           '`setDocumentContent` '
                                                                           'method '
                                                                           'it '
                                                                           'can '
                                                                           'result '
                                                                           'in '
                                                                           'Server-Side '
                                                                           'Request '
                                                                           'Forgery '
                                                                           'vulnerabilities',
                                                            'display_name': 'ChromeRemoteInterfaceSetdocumentcontentInjection',
                                                            'file': '%(issue.file)s',
                                                            'line': '%(issue.line)s',
                                                            'severity': '1',
                                                            'title': 'chrome '
                                                                     'remote '
                                                                     'interface '
                                                                     'setdocumentcontent '
                                                                     'injection'},
    'ClassExtendsSafestring': {   'categories': ['security'],
                                  'description': 'Found a class extending '
                                                 "'SafeString', 'SafeText' or "
                                                 "'SafeData'. These classes "
                                                 'are\n'
                                                 'for bypassing the escaping '
                                                 'enging built in to Django '
                                                 'and should not be\n'
                                                 'used directly. Improper use '
                                                 'of this class exposes your '
                                                 'application to\n'
                                                 'cross-site scripting (XSS) '
                                                 'vulnerabilities. If you need '
                                                 'this functionality,\n'
                                                 "use 'mark_safe' instead and "
                                                 'ensure no user data can '
                                                 'reach it.',
                                  'display_name': 'ClassExtendsSafestring',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'class extends safestring'},
    'CodeAfterUnconditionalReturn': {   'categories': ['security'],
                                        'description': 'code after return '
                                                       'statement will not be '
                                                       'executed',
                                        'display_name': 'CodeAfterUnconditionalReturn',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'code after unconditional '
                                                 'return'},
    'CommandInjectionFormattedRuntimeCall': {   'categories': ['security'],
                                                'description': 'A formatted or '
                                                               'concatenated '
                                                               'string was '
                                                               'detected as '
                                                               'input to a '
                                                               'java.lang.Runtime '
                                                               'call.\n'
                                                               'This is '
                                                               'dangerous if a '
                                                               'variable is '
                                                               'controlled by '
                                                               'user input and '
                                                               'could result '
                                                               'in a\n'
                                                               'command '
                                                               'injection. '
                                                               'Ensure your '
                                                               'variables are '
                                                               'not controlled '
                                                               'by users or '
                                                               'sufficiently '
                                                               'sanitized.',
                                                'display_name': 'CommandInjectionFormattedRuntimeCall',
                                                'file': '%(issue.file)s',
                                                'line': '%(issue.line)s',
                                                'severity': '1',
                                                'title': 'command injection '
                                                         'formatted runtime '
                                                         'call'},
    'CommandInjectionOsSystem': {   'categories': ['security'],
                                    'description': 'Request data detected in '
                                                   'os.system. This could be '
                                                   'vulnerable to a command '
                                                   'injection and should be '
                                                   'avoided. If this must be '
                                                   "done, use the 'subprocess' "
                                                   'module instead and pass '
                                                   'the arguments as a list. '
                                                   'See '
                                                   'https://owasp.org/www-community/attacks/Command_Injection '
                                                   'for more information.',
                                    'display_name': 'CommandInjectionOsSystem',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'command injection os system'},
    'CommandInjectionProcessBuilder': {   'categories': ['security'],
                                          'description': 'A formatted or '
                                                         'concatenated string '
                                                         'was detected as '
                                                         'input to a '
                                                         'ProcessBuilder '
                                                         'call.\n'
                                                         'This is dangerous if '
                                                         'a variable is '
                                                         'controlled by user '
                                                         'input and could '
                                                         'result in a\n'
                                                         'command injection. '
                                                         'Ensure your '
                                                         'variables are not '
                                                         'controlled by users '
                                                         'or sufficiently '
                                                         'sanitized.',
                                          'display_name': 'CommandInjectionProcessBuilder',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'command injection process '
                                                   'builder'},
    'ContextAutoescapeOff': {   'categories': ['security'],
                                'description': 'Detected a Context with '
                                               'autoescape diabled. If you '
                                               'are\n'
                                               'rendering any web pages, this '
                                               'exposes your application to '
                                               'cross-site\n'
                                               'scripting (XSS) '
                                               'vulnerabilities. Remove '
                                               "'autoescape: False' or set it\n"
                                               "to 'True'.",
                                'display_name': 'ContextAutoescapeOff',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'context autoescape off'},
    'CookieIssecureFalse': {   'categories': ['security'],
                               'description': 'Default session middleware '
                                              'settings: `setSecure` not set '
                                              'to true.\n'
                                              'This ensures that the cookie is '
                                              'sent only over HTTPS to prevent '
                                              'cross-site scripting attacks.',
                               'display_name': 'CookieIssecureFalse',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'cookie issecure false'},
    'CookieMissingHttponly': {   'categories': ['security'],
                                 'description': 'A session cookie was detected '
                                                'without setting the '
                                                "'HttpOnly' flag.\n"
                                                "The 'HttpOnly' flag for "
                                                'cookies instructs the browser '
                                                'to forbid\n'
                                                'client-side scripts from '
                                                'reading the cookie which '
                                                'mitigates XSS\n'
                                                "attacks. Set the 'HttpOnly' "
                                                "flag by setting 'HttpOnly' to "
                                                "'true'\n"
                                                'in the Cookie.',
                                 'display_name': 'CookieMissingHttponly',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'cookie missing httponly'},
    'CookieMissingSamesite': {   'categories': ['security'],
                                 'description': 'Detected cookie without the '
                                                'SameSite attribute.',
                                 'display_name': 'CookieMissingSamesite',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'cookie missing samesite'},
    'CookieMissingSecure': {   'categories': ['security'],
                               'description': 'A session cookie was detected '
                                              "without setting the 'Secure' "
                                              'flag.\n'
                                              "The 'secure' flag for cookies "
                                              'prevents the client from '
                                              'transmitting\n'
                                              'the cookie over insecure '
                                              'channels such as HTTP.  Set the '
                                              "'Secure'\n"
                                              "flag by setting 'Secure' to "
                                              "'true' in the Options struct.",
                               'display_name': 'CookieMissingSecure',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'cookie missing secure'},
    'CookieMissingSecureFlag': {   'categories': ['security'],
                                   'description': 'A cookie was detected '
                                                  'without setting the '
                                                  "'secure' flag. The 'secure' "
                                                  'flag\n'
                                                  'for cookies prevents the '
                                                  'client from transmitting '
                                                  'the cookie over insecure\n'
                                                  'channels such as HTTP. Set '
                                                  "the 'secure' flag by "
                                                  'calling '
                                                  "'$COOKIE.setSecure(true);'",
                                   'display_name': 'CookieMissingSecureFlag',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'cookie missing secure flag'},
    'CookieSerialization': {   'categories': ['security'],
                               'description': 'Checks if code allows cookies '
                                              'to be deserialized using '
                                              'Marshal. If the attacker can '
                                              'craft a valid cookie, this '
                                              'could lead to\n'
                                              'remote code execution. The '
                                              'hybrid check is just to warn '
                                              'users to migrate to :json for '
                                              'best practice.',
                               'display_name': 'CookieSerialization',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'cookie serialization'},
    'CookieSessionDefault': {   'categories': ['security'],
                                'description': 'Consider changing the default '
                                               'session cookie name. An '
                                               'attacker can use it to '
                                               'fingerprint the server and '
                                               'target attacks accordingly.',
                                'display_name': 'CookieSessionDefault',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'cookie session default'},
    'CookieSessionNoDomain': {   'categories': ['security'],
                                 'description': 'Default session middleware '
                                                'settings: `domain` not set. '
                                                'It indicates the domain of '
                                                'the cookie; use it to compare '
                                                'against the domain of the '
                                                'server in which the URL is '
                                                'being requested. If they '
                                                'match, then check the path '
                                                'attribute next.',
                                 'display_name': 'CookieSessionNoDomain',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'cookie session no domain'},
    'CookieSessionNoHttponly': {   'categories': ['security'],
                                   'description': 'Session middleware '
                                                  'settings: `httpOnly` is '
                                                  'explicitly set to false.  '
                                                  'It ensures that sensitive '
                                                  'cookies cannot be accessed '
                                                  'by client side  JavaScript '
                                                  'and helps to protect '
                                                  'against cross-site '
                                                  'scripting attacks.',
                                   'display_name': 'CookieSessionNoHttponly',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'cookie session no httponly'},
    'CookieSessionNoMaxage': {   'categories': ['security'],
                                 'description': 'Session middleware settings: '
                                                '`maxAge` not set. Use it to '
                                                'set expiration date for '
                                                'cookies.',
                                 'display_name': 'CookieSessionNoMaxage',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'cookie session no maxage'},
    'CookieSessionNoPath': {   'categories': ['security'],
                               'description': 'Default session middleware '
                                              'settings: `path` not set. It '
                                              'indicates the path of the '
                                              'cookie; use it to compare '
                                              'against the request path. If '
                                              'this and domain match, then '
                                              'send the cookie in the request.',
                               'display_name': 'CookieSessionNoPath',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'cookie session no path'},
    'CookieSessionNoSamesite': {   'categories': ['security'],
                                   'description': 'Default session middleware '
                                                  'settings: `sameSite` '
                                                  'attribute is not configured '
                                                  'to strict or lax. These '
                                                  'configurations provides '
                                                  'protection against Cross '
                                                  'Site Request Forgery '
                                                  'attacks.',
                                   'display_name': 'CookieSessionNoSamesite',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'cookie session no samesite'},
    'CookieSessionNoSecure': {   'categories': ['security'],
                                 'description': 'Default session middleware '
                                                'settings: `secure` not set. '
                                                'It ensures the browser only '
                                                'sends the cookie over HTTPS.',
                                 'display_name': 'CookieSessionNoSecure',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'cookie session no secure'},
    'CopyFromOwnAlias': {   'categories': ['security'],
                            'description': 'COPY instructions cannot copy from '
                                           "its own alias. The '$REF' alias is "
                                           'used before switching to a new '
                                           'image. If you meant to switch to a '
                                           "new image, include a new 'FROM' "
                                           'statement. Otherwise, remove the '
                                           "'--from=$REF' from the COPY "
                                           'statement.\n'
                                           '{"include": ["*dockerfile*", '
                                           '"*Dockerfile*"]}',
                            'display_name': 'CopyFromOwnAlias',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'dockerfile: copy from own alias'},
    'CreateWith': {   'categories': ['security'],
                      'description': 'Checks for strong parameter bypass '
                                     'through usage of create_with. '
                                     'Create_with bypasses strong parameter '
                                     'protection, which\n'
                                     'could allow attackers to set arbitrary '
                                     'attributes on models. To fix this '
                                     'vulnerability, either remove all '
                                     'create_with calls\n'
                                     'or use the permit function to specify '
                                     'tags that are allowed to be set.',
                      'display_name': 'CreateWith',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'create with'},
    'CrlfInjectionLogs': {   'categories': ['security'],
                             'description': 'When data from an untrusted '
                                            'source is put into a logger and '
                                            'not neutralized correctly,\n'
                                            'an attacker could forge log '
                                            'entries or include malicious '
                                            'content.',
                             'display_name': 'CrlfInjectionLogs',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'crlf injection logs'},
    'CurlSslVerifypeerOff': {   'categories': ['security'],
                                'description': 'SSL verification is disabled '
                                               'but should not be (currently '
                                               'CURLOPT_SSL_VERIFYPEER= '
                                               '$IS_VERIFIED)',
                                'display_name': 'CurlSslVerifypeerOff',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'curl ssl verifypeer off'},
    'CustomExpressionAsSql': {   'categories': ['security'],
                                 'description': 'Detected a Custom Expression '
                                                "''$EXPRESSION'' calling "
                                                "''as_sql(...).'' Ensure no "
                                                'user input enters this '
                                                'function because it is '
                                                'susceptible to SQL injection. '
                                                'See '
                                                'https://docs.djangoproject.com/en/3.0/ref/models/expressions/#django.db.models.Func.as_sql '
                                                'for more information.',
                                 'display_name': 'CustomExpressionAsSql',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'custom expression as sql'},
    'DangerousCommandWrite': {   'categories': ['security'],
                                 'description': 'Detected non-static command '
                                                'inside Write. Audit the input '
                                                "to '$CW.Write'.\n"
                                                'If unverified user data can '
                                                'reach this call site, this is '
                                                'a code injection\n'
                                                'vulnerability. A malicious '
                                                'actor can inject a malicious '
                                                'script to execute\n'
                                                'arbitrary code.',
                                 'display_name': 'DangerousCommandWrite',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'dangerous command write'},
    'DangerousExec': {   'categories': ['security'],
                         'description': 'Detected non-static command inside '
                                        "$EXEC. Audit the input to '$EXEC'.\n"
                                        'If unverified user data can reach '
                                        'this call site, this is a code '
                                        'injection\n'
                                        'vulnerability. A malicious actor can '
                                        'inject a malicious script to execute\n'
                                        'arbitrary code.',
                         'display_name': 'DangerousExec',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'dangerous exec'},
    'DangerousExecCmd': {   'categories': ['security'],
                            'description': 'Detected non-static command inside '
                                           'exec.Cmd. Audit the input to '
                                           "'exec.Cmd'.\n"
                                           'If unverified user data can reach '
                                           'this call site, this is a code '
                                           'injection\n'
                                           'vulnerability. A malicious actor '
                                           'can inject a malicious script to '
                                           'execute\n'
                                           'arbitrary code.',
                            'display_name': 'DangerousExecCmd',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'dangerous exec cmd'},
    'DangerousExecCommand': {   'categories': ['security'],
                                'description': 'Detected non-static command '
                                               'inside Command. Audit the '
                                               "input to 'exec.Command'.\n"
                                               'If unverified user data can '
                                               'reach this call site, this is '
                                               'a code injection\n'
                                               'vulnerability. A malicious '
                                               'actor can inject a malicious '
                                               'script to execute\n'
                                               'arbitrary code.',
                                'display_name': 'DangerousExecCommand',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'dangerous exec command'},
    'DangerousExecution': {   'categories': ['security'],
                              'description': 'Detected non-static script '
                                             'inside otto VM. Audit the input '
                                             "to 'VM.Run'.\n"
                                             'If unverified user data can '
                                             'reach this call site, this is a '
                                             'code injection\n'
                                             'vulnerability. A malicious actor '
                                             'can inject a malicious script to '
                                             'execute\n'
                                             'arbitrary code.',
                              'display_name': 'DangerousExecution',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'dangerous execution'},
    'DangerousGlobalsUse': {   'categories': ['security'],
                               'description': 'Found non static data as an '
                                              "index to 'globals()'. This is "
                                              'extremely\n'
                                              'dangerous because it allows an '
                                              'attacker to execute arbitrary '
                                              'code\n'
                                              'on the system. Refactor your '
                                              "code not to use 'globals()'.",
                               'display_name': 'DangerousGlobalsUse',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'dangerous globals use'},
    'DangerousGroovyShell': {   'categories': ['security'],
                                'description': 'A expression is built with a '
                                               'dynamic value. The source of '
                                               'the value(s) should be '
                                               'verified to avoid that '
                                               'unfiltered values fall into '
                                               'this risky code evaluation.',
                                'display_name': 'DangerousGroovyShell',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'dangerous groovy shell'},
    'DangerousLinkTo': {   'categories': ['security'],
                           'description': 'Detected a template variable used '
                                          "in 'link_to'. This will\n"
                                          "generate dynamic data in the 'href' "
                                          'attribute.\n'
                                          'This allows a malicious actor to\n'
                                          "input the 'javascript:' URI and is "
                                          'subject to cross-\n'
                                          'site scripting (XSS) attacks. If '
                                          'using a relative URL,\n'
                                          'start with a literal forward slash '
                                          'and concatenate the URL,\n'
                                          'like this: \'link_to "Here", '
                                          '"/"+@link\'. You may also consider\n'
                                          'setting the Content Security Policy '
                                          '(CSP) header.',
                           'display_name': 'DangerousLinkTo',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'dangerous link to'},
    'DangerousOpen': {   'categories': ['security'],
                         'description': 'Detected non-static command inside '
                                        "'open'. Audit the input to 'open'.\n"
                                        'If unverified user data can reach '
                                        'this call site, this is a code '
                                        'injection\n'
                                        'vulnerability. A malicious actor can '
                                        'inject a malicious script to execute\n'
                                        'arbitrary code.',
                         'display_name': 'DangerousOpen',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'dangerous open'},
    'DangerousOpen3Pipeline': {   'categories': ['security'],
                                  'description': 'Detected non-static command '
                                                 'inside $PIPE. Audit the '
                                                 "input to '$PIPE'.\n"
                                                 'If unverified user data can '
                                                 'reach this call site, this '
                                                 'is a code injection\n'
                                                 'vulnerability. A malicious '
                                                 'actor can inject a malicious '
                                                 'script to execute\n'
                                                 'arbitrary code.',
                                  'display_name': 'DangerousOpen3Pipeline',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'dangerous open3 pipeline'},
    'DangerousSpawnProcess': {   'categories': ['security'],
                                 'description': 'Found dynamic content when '
                                                'spawning a process. This is '
                                                'dangerous if external\n'
                                                'data can reach this function '
                                                'call because it allows a '
                                                'malicious actor to\n'
                                                'execute commands. Ensure no '
                                                'external data reaches here.',
                                 'display_name': 'DangerousSpawnProcess',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'dangerous spawn process'},
    'DangerousSpawnShell': {   'categories': ['security'],
                               'description': 'Detected non-literal calls to '
                                              '$EXEC(). This could lead to a '
                                              'command\n'
                                              'injection vulnerability.',
                               'display_name': 'DangerousSpawnShell',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'dangerous spawn shell'},
    'DangerousSubprocessUse': {   'categories': ['security'],
                                  'description': 'Detected subprocess function '
                                                 "'$FUNC' without a static "
                                                 'string. If this data can be\n'
                                                 'controlled by a malicious '
                                                 'actor, it may be an instance '
                                                 'of command injection.\n'
                                                 'Audit the use of this call '
                                                 'to ensure it is not '
                                                 'controllable by an external '
                                                 'resource.\n'
                                                 'You may consider using '
                                                 "'shlex.escape()'.",
                                  'display_name': 'DangerousSubprocessUse',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'dangerous subprocess use'},
    'DangerousSubshell': {   'categories': ['security'],
                             'description': 'Detected non-static command '
                                            'inside `...`.\n'
                                            'If unverified user data can reach '
                                            'this call site, this is a code '
                                            'injection\n'
                                            'vulnerability. A malicious actor '
                                            'can inject a malicious script to '
                                            'execute\n'
                                            'arbitrary code.',
                             'display_name': 'DangerousSubshell',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'dangerous subshell'},
    'DangerousSyscall': {   'categories': ['security'],
                            'description': "'syscall' is essentially unsafe "
                                           'and unportable. The DL '
                                           '(https://apidock.com/ruby/Fiddle) '
                                           'library is preferred for safer and '
                                           'a bit more portable programming.',
                            'display_name': 'DangerousSyscall',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'dangerous syscall'},
    'DangerousSyscallExec': {   'categories': ['security'],
                                'description': 'Detected non-static command '
                                               'inside Exec. Audit the input '
                                               "to 'syscall.Exec'.\n"
                                               'If unverified user data can '
                                               'reach this call site, this is '
                                               'a code injection\n'
                                               'vulnerability. A malicious '
                                               'actor can inject a malicious '
                                               'script to execute\n'
                                               'arbitrary code.',
                                'display_name': 'DangerousSyscallExec',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'dangerous syscall exec'},
    'DangerousSystemCall': {   'categories': ['security'],
                               'description': 'Found dynamic content used in a '
                                              'system call. This is dangerous '
                                              'if external data can reach this '
                                              'function call because it allows '
                                              'a malicious actor to execute '
                                              "commands. Use the 'subprocess' "
                                              'module instead, which is easier '
                                              'to use without accidentally '
                                              'exposing a command injection '
                                              'vulnerability.',
                               'display_name': 'DangerousSystemCall',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'dangerous system call'},
    'DangerousTemplateString': {   'categories': ['security'],
                                   'description': 'Found a template created '
                                                  'with string formatting.\n'
                                                  'This is susceptible to '
                                                  'server-side template '
                                                  'injection\n'
                                                  'and cross-site scripting '
                                                  'attacks.',
                                   'display_name': 'DangerousTemplateString',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'dangerous template string'},
    'DebugEnabled': {   'categories': ['security'],
                        'description': 'Detected Flask app with debug=True. Do '
                                       'not deploy to production with this '
                                       'flag enabled\n'
                                       'as it will leak sensitive information. '
                                       'Instead, consider using Flask '
                                       'configuration\n'
                                       "variables or setting 'debug' using "
                                       'system environment variables.',
                        'display_name': 'DebugEnabled',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'debug enabled'},
    'DebugTemplateTag': {   'categories': ['security'],
                            'description': 'Detected a debug template tag in a '
                                           'Django template. This dumps\n'
                                           'debugging information to the page '
                                           'when debug mode is enabled.\n'
                                           'Showing debug information to users '
                                           'is dangerous because it may\n'
                                           'reveal information about your '
                                           'environment that malicious actors\n'
                                           'can use to gain access to the '
                                           'system. Remove the debug tag.',
                            'display_name': 'DebugTemplateTag',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'debug template tag'},
    'DefaultMutableDict': {   'categories': ['security'],
                              'description': 'Function $F mutates default dict '
                                             '$D. Python only instantiates '
                                             'default function arguments once '
                                             'and shares the instance across '
                                             'the function calls. If the '
                                             'default function argument is '
                                             'mutated, that will modify the '
                                             'instance used by all future '
                                             'function calls. This can cause '
                                             'unexpected results, or lead to '
                                             'security vulnerabilities whereby '
                                             'one function consumer can view '
                                             'or modify the data of another '
                                             'function consumer. Instead, use '
                                             'a default argument (like None) '
                                             'to indicate that no argument was '
                                             'provided and instantiate a new '
                                             'dictionary at that time. For '
                                             'example: `if $D is None: $D = '
                                             '{}`.',
                              'display_name': 'DefaultMutableDict',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'default mutable dict'},
    'DefaultMutableList': {   'categories': ['security'],
                              'description': 'Function $F mutates default list '
                                             '$D. Python only instantiates '
                                             'default function arguments once '
                                             'and shares the instance across '
                                             'the function calls. If the '
                                             'default function argument is '
                                             'mutated, that will modify the '
                                             'instance used by all future '
                                             'function calls. This can cause '
                                             'unexpected results, or lead to '
                                             'security vulnerabilities whereby '
                                             'one function consumer can view '
                                             'or modify the data of another '
                                             'function consumer. Instead, use '
                                             'a default argument (like None) '
                                             'to indicate that no argument was '
                                             'provided and instantiate a new '
                                             'list at that time. For example: '
                                             '`if $D is None: $D = []`.',
                              'display_name': 'DefaultMutableList',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'default mutable list'},
    'DefaultResteasyProviderAbuse': {   'categories': ['security'],
                                        'description': 'When a Restful '
                                                       'webservice endpoint '
                                                       "isn't configured with "
                                                       'a @Consumes '
                                                       'annotation, an '
                                                       'attacker could abuse '
                                                       'the '
                                                       'SerializableProvider '
                                                       'by sending a HTTP '
                                                       'Request with a '
                                                       'Content-Type of '
                                                       'application/x-java-serialized-object. '
                                                       'The body of that '
                                                       'request would be '
                                                       'processed by the '
                                                       'SerializationProvider '
                                                       'and could contain a '
                                                       'malicious payload, '
                                                       'which may lead to '
                                                       'arbitrary code '
                                                       'execution.',
                                        'display_name': 'DefaultResteasyProviderAbuse',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'default resteasy provider '
                                                 'abuse'},
    'DefaulthttpclientIsDeprecated': {   'categories': ['security'],
                                         'description': 'DefaultHttpClient is '
                                                        'deprecated. Further, '
                                                        'it does not support '
                                                        'connections\n'
                                                        'using TLS1.2, which '
                                                        'makes using '
                                                        'DefaultHttpClient a '
                                                        'security hazard.\n'
                                                        'Use '
                                                        'SystemDefaultHttpClient '
                                                        'instead, which '
                                                        'supports TLS1.2.',
                                         'display_name': 'DefaulthttpclientIsDeprecated',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'defaulthttpclient is '
                                                  'deprecated'},
    'DefineStyledComponentsOnModuleLevel': {   'categories': ['security'],
                                               'description': 'By declaring a '
                                                              'styled '
                                                              'component '
                                                              'inside the '
                                                              'render method '
                                                              'of a react '
                                                              'component, you '
                                                              'are dynamically '
                                                              'creating a new '
                                                              'component on '
                                                              'every render. '
                                                              'This means that '
                                                              'React will have '
                                                              'to discard and '
                                                              're-calculate '
                                                              'that part of '
                                                              'the DOM subtree '
                                                              'on each '
                                                              'subsequent '
                                                              'render, instead '
                                                              'of just '
                                                              'calculating the '
                                                              'difference of '
                                                              'what changed '
                                                              'between them. '
                                                              'This leads to '
                                                              'performance '
                                                              'bottlenecks and '
                                                              'unpredictable '
                                                              'behavior.',
                                               'display_name': 'DefineStyledComponentsOnModuleLevel',
                                               'file': '%(issue.file)s',
                                               'line': '%(issue.line)s',
                                               'severity': '1',
                                               'title': 'define styled '
                                                        'components on module '
                                                        'level'},
    'DeleteWhereNoExecute': {   'categories': ['security'],
                                'description': '.delete().where(...) results '
                                               'in a no-op in SQLAlchemy '
                                               'unless the command is '
                                               'executed, use '
                                               '.filter(...).delete() instead.',
                                'display_name': 'DeleteWhereNoExecute',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'delete where no execute'},
    'DenoDangerousRun': {   'categories': ['security'],
                            'description': 'Detected non-literal calls to '
                                           'Deno.run(). This could lead to a '
                                           'command\n'
                                           'injection vulnerability.',
                            'display_name': 'DenoDangerousRun',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'deno dangerous run'},
    'DesIsDeprecated': {   'categories': ['security'],
                           'description': 'DES is considered deprecated. AES '
                                          'is the recommended cipher.\n'
                                          'Upgrade to use AES.\n'
                                          'See '
                                          'https://www.nist.gov/news-events/news/2005/06/nist-withdraws-outdated-data-encryption-standard '
                                          'for more information.',
                           'display_name': 'DesIsDeprecated',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'des is deprecated'},
    'DesedeIsDeprecated': {   'categories': ['security'],
                              'description': 'Triple DES (3DES or DESede) is '
                                             'considered deprecated. AES is '
                                             'the recommended cipher.\n'
                                             'Upgrade to use AES.\n'
                                             'See '
                                             'https://csrc.nist.gov/News/2017/Update-to-Current-Use-and-Deprecation-of-TDEA '
                                             'for more information.',
                              'display_name': 'DesedeIsDeprecated',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'desede is deprecated'},
    'DetectAngularElementMethods': {   'categories': ['security'],
                                       'description': 'Use of angular.element '
                                                      'can lead to XSS if '
                                                      'after,append,html,prepend,replaceWith,wrap '
                                                      'are used with '
                                                      'user-input.',
                                       'display_name': 'DetectAngularElementMethods',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'detect angular element '
                                                'methods'},
    'DetectAngularOpenRedirect': {   'categories': ['security'],
                                     'description': 'Use of '
                                                    '$window.location.href can '
                                                    'lead to open-redirect if '
                                                    'user input is used for '
                                                    'redirection.',
                                     'display_name': 'DetectAngularOpenRedirect',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'detect angular open redirect'},
    'DetectAngularResourceLoading': {   'categories': ['security'],
                                        'description': '$sceDelegateProvider '
                                                       'allowlisting can be '
                                                       'introduce security '
                                                       'issues if wildcards '
                                                       'are used.',
                                        'display_name': 'DetectAngularResourceLoading',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'detect angular resource '
                                                 'loading'},
    'DetectAngularSceDisabled': {   'categories': ['security'],
                                    'description': '$sceProvider is set to '
                                                   'false. Disabling Strict '
                                                   'Contextual escaping (SCE) '
                                                   'in an AngularJS '
                                                   'application could provide '
                                                   'additional attack surface '
                                                   'for XSS vulnerabilities.',
                                    'display_name': 'DetectAngularSceDisabled',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'detect angular sce disabled'},
    'DetectAngularTranslateproviderTranslationsMethod': {   'categories': [   'security'],
                                                            'description': 'The '
                                                                           'use '
                                                                           'of '
                                                                           '$translateProvider.translations '
                                                                           'method '
                                                                           'can '
                                                                           'be '
                                                                           'dangerous '
                                                                           'if '
                                                                           'user '
                                                                           'input '
                                                                           'is '
                                                                           'provided '
                                                                           'to '
                                                                           'this '
                                                                           'API.',
                                                            'display_name': 'DetectAngularTranslateproviderTranslationsMethod',
                                                            'file': '%(issue.file)s',
                                                            'line': '%(issue.line)s',
                                                            'severity': '1',
                                                            'title': 'detect '
                                                                     'angular '
                                                                     'translateprovider '
                                                                     'translations '
                                                                     'method'},
    'DetectAngularTranslateproviderUsestrategyMethod': {   'categories': [   'security'],
                                                           'description': 'If '
                                                                          'the '
                                                                          '$translateSanitization.useStrategy '
                                                                          'is '
                                                                          'set '
                                                                          'to '
                                                                          'null '
                                                                          'or '
                                                                          'blank '
                                                                          'this '
                                                                          'can '
                                                                          'be '
                                                                          'dangerous.',
                                                           'display_name': 'DetectAngularTranslateproviderUsestrategyMethod',
                                                           'file': '%(issue.file)s',
                                                           'line': '%(issue.line)s',
                                                           'severity': '1',
                                                           'title': 'detect '
                                                                    'angular '
                                                                    'translateprovider '
                                                                    'useStrategy '
                                                                    'method'},
    'DetectAngularTrustAsCssMethod': {   'categories': ['security'],
                                         'description': 'The use of '
                                                        '$sce.trustAsCss can '
                                                        'be dangerous if '
                                                        'unsantiized user '
                                                        'input flows through '
                                                        'this API.',
                                         'display_name': 'DetectAngularTrustAsCssMethod',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'detect angular trust as css '
                                                  'method'},
    'DetectAngularTrustAsHtmlMethod': {   'categories': ['security'],
                                          'description': 'The use of '
                                                         '$sce.trustAsHtml can '
                                                         'be dangerous if '
                                                         'unsantiized user '
                                                         'input flows through '
                                                         'this API.',
                                          'display_name': 'DetectAngularTrustAsHtmlMethod',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'detect angular trust as '
                                                   'html method'},
    'DetectAngularTrustAsJsMethod': {   'categories': ['security'],
                                        'description': 'The use of '
                                                       '$sce.trustAsJs can be '
                                                       'dangerous if '
                                                       'unsantiized user input '
                                                       'flows through this '
                                                       'API.',
                                        'display_name': 'DetectAngularTrustAsJsMethod',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'detect angular trust as js '
                                                 'method'},
    'DetectAngularTrustAsMethod': {   'categories': ['security'],
                                      'description': 'The use of $sce.trustAs '
                                                     'can be dangerous if '
                                                     'unsantiized user input '
                                                     'flows through this API.',
                                      'display_name': 'DetectAngularTrustAsMethod',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'detect angular trust as '
                                               'method'},
    'DetectAngularTrustAsResourceurlMethod': {   'categories': ['security'],
                                                 'description': 'The use of '
                                                                '$sce.trustAsResourceUrl '
                                                                'can be '
                                                                'dangerous if '
                                                                'unsantiized '
                                                                'user input '
                                                                'flows through '
                                                                'this API.',
                                                 'display_name': 'DetectAngularTrustAsResourceurlMethod',
                                                 'file': '%(issue.file)s',
                                                 'line': '%(issue.line)s',
                                                 'severity': '1',
                                                 'title': 'detect angular '
                                                          'trust as '
                                                          'resourceurl method'},
    'DetectAngularTrustAsUrlMethod': {   'categories': ['security'],
                                         'description': 'The use of '
                                                        '$sce.trustAsUrl can '
                                                        'be dangerous if '
                                                        'unsantiized user '
                                                        'input flows through '
                                                        'this API.',
                                         'display_name': 'DetectAngularTrustAsUrlMethod',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'detect angular trust as url '
                                                  'method'},
    'DetectBracketObjectInjection': {   'categories': ['security'],
                                        'description': 'Object injection via '
                                                       'bracket notation via '
                                                       '$FIELD',
                                        'display_name': 'DetectBracketObjectInjection',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'detect bracket object '
                                                 'injection'},
    'DetectBufferNoassert': {   'categories': ['security'],
                                'description': 'Detected usage of noassert in '
                                               'Buffer API, which allows the '
                                               'offset the be beyond the\n'
                                               'end of the buffer. This could '
                                               'result in writing or reading '
                                               'beyond the end of the buffer.',
                                'display_name': 'DetectBufferNoassert',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'detect buffer noassert'},
    'DetectChildProcess': {   'categories': ['security'],
                              'description': 'Detected non-literal calls to '
                                             '$EXEC(). This could lead to a '
                                             'command\n'
                                             'injection vulnerability.',
                              'display_name': 'DetectChildProcess',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'detect child process'},
    'DetectDisableMustacheEscape': {   'categories': ['security'],
                                       'description': 'Markup escaping '
                                                      'disabled. This can be '
                                                      'used with some template '
                                                      'engines to escape\n'
                                                      'disabling of HTML '
                                                      'entities, which can '
                                                      'lead to XSS attacks.',
                                       'display_name': 'DetectDisableMustacheEscape',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'detect disable mustache '
                                                'escape'},
    'DetectEvalWithExpression': {   'categories': ['security'],
                                    'description': 'Detected eval(variable), '
                                                   'which could allow a '
                                                   'malicious actor to run '
                                                   'arbitrary code.',
                                    'display_name': 'DetectEvalWithExpression',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'detect eval with expression'},
    'DetectInsecureWebsocket': {   'categories': ['security'],
                                   'description': 'Insecure WebSocket '
                                                  'Detected. WebSocket Secure '
                                                  '(wss) should be used for '
                                                  'all WebSocket connections.',
                                   'display_name': 'DetectInsecureWebsocket',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'detect insecure websocket'},
    'DetectNoCsrfBeforeMethodOverride': {   'categories': ['security'],
                                            'description': 'Detected use of '
                                                           'express.csrf() '
                                                           'middleware before '
                                                           'express.methodOverride(). '
                                                           'This can\n'
                                                           'allow GET requests '
                                                           '(which are not '
                                                           'checked by csrf) '
                                                           'to turn into POST '
                                                           'requests later.',
                                            'display_name': 'DetectNoCsrfBeforeMethodOverride',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'detect no csrf before '
                                                     'method override'},
    'DetectNonLiteralRequire': {   'categories': ['security'],
                                   'description': 'Detected the use of '
                                                  'require(variable). Calling '
                                                  'require with a non-literal '
                                                  'argument might\n'
                                                  'allow an attacker to load '
                                                  'an run arbitrary code, or '
                                                  'access arbitrary files.',
                                   'display_name': 'DetectNonLiteralRequire',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'detect non literal require'},
    'DetectPseudorandombytes': {   'categories': ['security'],
                                   'description': 'Detected usage of '
                                                  'crypto.pseudoRandomBytes, '
                                                  'which does not produce '
                                                  'secure random numbers.',
                                   'display_name': 'DetectPseudorandombytes',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'detect pseudoRandomBytes'},
    'DetectedAmazonMwsAuthToken': {   'categories': ['security'],
                                      'description': 'Amazon MWS Auth Token '
                                                     'detected',
                                      'display_name': 'DetectedAmazonMwsAuthToken',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'secrets: detected amazon mws '
                                               'auth token'},
    'DetectedArtifactoryPassword': {   'categories': ['security'],
                                       'description': 'Artifactory token '
                                                      'detected',
                                       'display_name': 'DetectedArtifactoryPassword',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'secrets: detected artifactory '
                                                'password'},
    'DetectedArtifactoryToken': {   'categories': ['security'],
                                    'description': 'Artifactory token detected',
                                    'display_name': 'DetectedArtifactoryToken',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'secrets: detected artifactory '
                                             'token'},
    'DetectedAwsAccessKeyIdValue': {   'categories': ['security'],
                                       'description': 'AWS Access Key ID Value '
                                                      'detected',
                                       'display_name': 'DetectedAwsAccessKeyIdValue',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'secrets: detected aws access '
                                                'key id value'},
    'DetectedAwsAccountId': {   'categories': ['security'],
                                'description': 'AWS Account ID detected',
                                'display_name': 'DetectedAwsAccountId',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'secrets: detected aws account id'},
    'DetectedAwsAppsyncGraphqlKey': {   'categories': ['security'],
                                        'description': 'AWS AppSync GraphQL '
                                                       'Key detected',
                                        'display_name': 'DetectedAwsAppsyncGraphqlKey',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'secrets: detected aws '
                                                 'appsync graphql key'},
    'DetectedAwsSecretAccessKey': {   'categories': ['security'],
                                      'description': 'AWS Secret Access Key '
                                                     'detected',
                                      'display_name': 'DetectedAwsSecretAccessKey',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'secrets: detected aws secret '
                                               'access key'},
    'DetectedAwsSessionToken': {   'categories': ['security'],
                                   'description': 'AWS Session Token detected',
                                   'display_name': 'DetectedAwsSessionToken',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'secrets: detected aws session '
                                            'token'},
    'DetectedBcryptHash': {   'categories': ['security'],
                              'description': 'bcrypt hash detected',
                              'display_name': 'DetectedBcryptHash',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'secrets: detected bcrypt hash'},
    'DetectedCodeclimate': {   'categories': ['security'],
                               'description': 'CodeClimate detected',
                               'display_name': 'DetectedCodeclimate',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'secrets: detected codeclimate'},
    'DetectedEtcShadow': {   'categories': ['security'],
                             'description': 'linux shadow file detected',
                             'display_name': 'DetectedEtcShadow',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'secrets: detected etc shadow'},
    'DetectedFacebookAccessToken': {   'categories': ['security'],
                                       'description': 'Facebook Access Token '
                                                      'detected',
                                       'display_name': 'DetectedFacebookAccessToken',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'secrets: detected facebook '
                                                'access token'},
    'DetectedFacebookOauth': {   'categories': ['security'],
                                 'description': 'Facebook OAuth detected',
                                 'display_name': 'DetectedFacebookOauth',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'secrets: detected facebook oauth'},
    'DetectedGenericApiKey': {   'categories': ['security'],
                                 'description': 'Generic API Key detected',
                                 'display_name': 'DetectedGenericApiKey',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'secrets: detected generic api key'},
    'DetectedGenericSecret': {   'categories': ['security'],
                                 'description': 'Generic Secret detected',
                                 'display_name': 'DetectedGenericSecret',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'secrets: detected generic secret'},
    'DetectedGoogleCloudApiKey': {   'categories': ['security'],
                                     'description': 'Google Cloud API Key '
                                                    'detected',
                                     'display_name': 'DetectedGoogleCloudApiKey',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'secrets: detected google cloud '
                                              'api key'},
    'DetectedGoogleGcmServiceAccount': {   'categories': ['security'],
                                           'description': 'Google (GCM) '
                                                          'Service account '
                                                          'detected',
                                           'display_name': 'DetectedGoogleGcmServiceAccount',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'secrets: detected google '
                                                    'gcm service account'},
    'DetectedGoogleOauthAccessToken': {   'categories': ['security'],
                                          'description': 'Google OAuth Access '
                                                         'Token detected',
                                          'display_name': 'DetectedGoogleOauthAccessToken',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'secrets: detected google '
                                                   'oauth access token'},
    'DetectedGoogleOauthUrl': {   'categories': ['security'],
                                  'description': 'Google OAuth url detected',
                                  'display_name': 'DetectedGoogleOauthUrl',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'secrets: detected google oauth '
                                           'url'},
    'DetectedHerokuApiKey': {   'categories': ['security'],
                                'description': 'Heroku API Key detected',
                                'display_name': 'DetectedHerokuApiKey',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'secrets: detected heroku api key'},
    'DetectedHockeyapp': {   'categories': ['security'],
                             'description': 'HockeyApp detected',
                             'display_name': 'DetectedHockeyapp',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'secrets: detected hockeyapp'},
    'DetectedLog4jCore': {   'categories': ['security'],
                             'description': '检查maven，gradle等配置文件中使用的log4j-core版本',
                             'display_name': 'DetectedLog4jCore',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'detected log4j core'},
    'DetectedLogbackCore': {   'categories': ['security'],
                               'description': '检查maven，gradle等配置文件中使用的logback-core版本\n'
                                              'logback version < 1.2.9\n'
                                              'logback version < '
                                              '1.3.0-alpha11\n'
                                              '请升级到1.2.9及以上版本。\n'
                                              '漏洞详情可以看：https://logback.qos.ch/news.html\n'
                                              'CVE详情：https://cve.report/CVE-2021-42550',
                               'display_name': 'DetectedLogbackCore',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'detected logback core'},
    'DetectedMailchimpApiKey': {   'categories': ['security'],
                                   'description': 'MailChimp API Key detected',
                                   'display_name': 'DetectedMailchimpApiKey',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'secrets: detected mailchimp api '
                                            'key'},
    'DetectedMailgunApiKey': {   'categories': ['security'],
                                 'description': 'Mailgun API Key detected',
                                 'display_name': 'DetectedMailgunApiKey',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'secrets: detected mailgun api key'},
    'DetectedNpmRegistryAuthToken': {   'categories': ['security'],
                                        'description': 'NPM registry '
                                                       'authentication token '
                                                       'detected\n'
                                                       '{"include": '
                                                       '["*npmrc*"]}',
                                        'display_name': 'DetectedNpmRegistryAuthToken',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'secrets: detected npm '
                                                 'registry auth token'},
    'DetectedOutlookTeam': {   'categories': ['security'],
                               'description': 'Outlook Team detected',
                               'display_name': 'DetectedOutlookTeam',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'secrets: detected outlook team'},
    'DetectedPaypalBraintreeAccessToken': {   'categories': ['security'],
                                              'description': 'PayPal Braintree '
                                                             'Access Token '
                                                             'detected',
                                              'display_name': 'DetectedPaypalBraintreeAccessToken',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '1',
                                              'title': 'secrets: detected '
                                                       'paypal braintree '
                                                       'access token'},
    'DetectedPgpPrivateKeyBlock': {   'categories': ['security'],
                                      'description': 'PGP private key block '
                                                     'detected',
                                      'display_name': 'DetectedPgpPrivateKeyBlock',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'secrets: detected pgp private '
                                               'key block'},
    'DetectedPicaticApiKey': {   'categories': ['security'],
                                 'description': 'Picatic API Key detected',
                                 'display_name': 'DetectedPicaticApiKey',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'secrets: detected picatic api key'},
    'DetectedPrivateKey': {   'categories': ['security'],
                              'description': 'Private Key detected',
                              'display_name': 'DetectedPrivateKey',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'secrets: detected private key'},
    'DetectedSauceToken': {   'categories': ['security'],
                              'description': 'Sauce Token detected',
                              'display_name': 'DetectedSauceToken',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'secrets: detected sauce token'},
    'DetectedSlackToken': {   'categories': ['security'],
                              'description': 'Slack Token detected',
                              'display_name': 'DetectedSlackToken',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'secrets: detected slack token'},
    'DetectedSlackWebhook': {   'categories': ['security'],
                                'description': 'Slack Webhook detected',
                                'display_name': 'DetectedSlackWebhook',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'secrets: detected slack webhook'},
    'DetectedSonarqubeDocsApiKey': {   'categories': ['security'],
                                       'description': 'SonarQube Docs API Key '
                                                      'detected',
                                       'display_name': 'DetectedSonarqubeDocsApiKey',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'secrets: detected sonarqube '
                                                'docs api key'},
    'DetectedSqlDump': {   'categories': ['security'],
                           'description': 'SQL dump detected',
                           'display_name': 'DetectedSqlDump',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'secrets: detected sql dump'},
    'DetectedSquareAccessToken': {   'categories': ['security'],
                                     'description': 'Square Access Token '
                                                    'detected',
                                     'display_name': 'DetectedSquareAccessToken',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'secrets: detected square access '
                                              'token'},
    'DetectedSquareOauthSecret': {   'categories': ['security'],
                                     'description': 'Square OAuth Secret '
                                                    'detected',
                                     'display_name': 'DetectedSquareOauthSecret',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'secrets: detected square oauth '
                                              'secret'},
    'DetectedSshPassword': {   'categories': ['security'],
                               'description': 'SSH Password detected',
                               'display_name': 'DetectedSshPassword',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'secrets: detected ssh password'},
    'DetectedStripeApiKey': {   'categories': ['security'],
                                'description': 'Stripe API Key detected',
                                'display_name': 'DetectedStripeApiKey',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'secrets: detected stripe api key'},
    'DetectedStripeRestrictedApiKey': {   'categories': ['security'],
                                          'description': 'Stripe Restricted '
                                                         'API Key detected',
                                          'display_name': 'DetectedStripeRestrictedApiKey',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'secrets: detected stripe '
                                                   'restricted api key'},
    'DetectedTelegramBotApiKey': {   'categories': ['security'],
                                     'description': 'Telegram Bot API Key '
                                                    'detected',
                                     'display_name': 'DetectedTelegramBotApiKey',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'secrets: detected telegram bot '
                                              'api key'},
    'DetectedTwilioApiKey': {   'categories': ['security'],
                                'description': 'Twilio API Key detected',
                                'display_name': 'DetectedTwilioApiKey',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'secrets: detected twilio api key'},
    'DetectedTwitterAccessToken': {   'categories': ['security'],
                                      'description': 'Twitter Access Token '
                                                     'detected',
                                      'display_name': 'DetectedTwitterAccessToken',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'secrets: detected twitter '
                                               'access token'},
    'DetectedTwitterOauth': {   'categories': ['security'],
                                'description': 'Twitter OAuth detected',
                                'display_name': 'DetectedTwitterOauth',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'secrets: detected twitter oauth'},
    'DetectedUsernameAndPasswordInUri': {   'categories': ['security'],
                                            'description': 'Username and '
                                                           'password in URI '
                                                           'detected',
                                            'display_name': 'DetectedUsernameAndPasswordInUri',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'secrets: detected '
                                                     'username and password in '
                                                     'uri'},
    'DictDelWhileIterate': {   'categories': ['security'],
                               'description': 'It appears that `$DICT[$KEY]` '
                                              'is a dict with items being '
                                              'deleted while in a for loop. '
                                              'This is usually a bad idea and '
                                              'will likely lead to a '
                                              'RuntimeError: dictionary '
                                              'changed size during iteration',
                               'display_name': 'DictDelWhileIterate',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'dict del while iterate'},
    'DirectResponseWrite': {   'categories': ['security'],
                               'description': 'Detected direclty writing to a '
                                              'Response object. This bypasses '
                                              'any HTML escaping and may '
                                              'expose your app to a cross-site '
                                              'scripting (XSS) vulnerability. '
                                              "Instead, use 'resp.render()' to "
                                              'render safely escaped HTML.',
                               'display_name': 'DirectResponseWrite',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'direct response write'},
    'DirectUseOfHttpresponse': {   'categories': ['security'],
                                   'description': 'Detected data rendered '
                                                  'directly to the end user '
                                                  "via 'HttpResponse'\n"
                                                  'or a similar object. This '
                                                  "bypasses Django's built-in "
                                                  'cross-site scripting\n'
                                                  '(XSS) defenses and could '
                                                  'result in an XSS '
                                                  'vulnerability. Use '
                                                  "Django's\n"
                                                  'template engine to safely '
                                                  'render HTML.',
                                   'display_name': 'DirectUseOfHttpresponse',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'direct use of httpresponse'},
    'DirectUseOfJinja2': {   'categories': ['security'],
                             'description': 'Detected direct use of jinja2. If '
                                            'not done properly,\n'
                                            'this may bypass HTML escaping '
                                            'which opens up the application '
                                            'to\n'
                                            'cross-site scripting (XSS) '
                                            'vulnerabilities. Prefer using the '
                                            'Flask\n'
                                            "method 'render_template()' and "
                                            "templates with a '.html' "
                                            'extension\n'
                                            'in order to prevent XSS.',
                             'display_name': 'DirectUseOfJinja2',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'direct use of jinja2'},
    'DirectlyReturnedFormatString': {   'categories': ['security'],
                                        'description': 'Detected Flask route '
                                                       'directly returning a '
                                                       'formatted string. '
                                                       'This\n'
                                                       'is subject to '
                                                       'cross-site scripting '
                                                       'if user input can '
                                                       'reach the string.\n'
                                                       'Consider using the '
                                                       'template engine '
                                                       'instead and rendering '
                                                       'pages with\n'
                                                       "'render_template()'.",
                                        'display_name': 'DirectlyReturnedFormatString',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'directly returned format '
                                                 'string'},
    'DisabledCertValidation': {   'categories': ['security'],
                                  'description': 'Certificate verification has '
                                                 'been explicitly disabled. '
                                                 'This\n'
                                                 'permits insecure connections '
                                                 'to insecure servers. '
                                                 'Re-enable\n'
                                                 'certification validation.',
                                  'display_name': 'DisabledCertValidation',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'disabled cert validation'},
    'DivideByZero': {   'categories': ['security'],
                        'description': 'Checks for divide by zero. Best '
                                       'practice involves not dividing a '
                                       'variable by zero, as this leads to a '
                                       'Ruby\n'
                                       'ZeroDivisionError.',
                        'display_name': 'DivideByZero',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'divide by zero'},
    'DjangoCompat2_0AssertRedirectsHelper': {   'categories': ['security'],
                                                'description': 'The host '
                                                               'argument to '
                                                               'assertRedirects '
                                                               'is removed in '
                                                               'Django 2.0.',
                                                'display_name': 'DjangoCompat2_0AssertRedirectsHelper',
                                                'file': '%(issue.file)s',
                                                'line': '%(issue.line)s',
                                                'severity': '1',
                                                'title': 'django compat 2_0 '
                                                         'assert redirects '
                                                         'helper'},
    'DjangoCompat2_0AssignmentTag': {   'categories': ['security'],
                                        'description': 'The assignment_tag '
                                                       'helper is removed in '
                                                       'Django 2.0.',
                                        'display_name': 'DjangoCompat2_0AssignmentTag',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'django compat 2_0 assignment '
                                                 'tag'},
    'DjangoCompat2_0CheckAggregateSupport': {   'categories': ['security'],
                                                'description': 'django.db.backends.base.BaseDatabaseOperations.check_aggregate_support() '
                                                               'is removed in '
                                                               'Django 2.0.',
                                                'display_name': 'DjangoCompat2_0CheckAggregateSupport',
                                                'file': '%(issue.file)s',
                                                'line': '%(issue.line)s',
                                                'severity': '1',
                                                'title': 'django compat 2_0 '
                                                         'check aggregate '
                                                         'support'},
    'DjangoCompat2_0ExtraForms': {   'categories': ['security'],
                                     'description': 'The django.forms.extras '
                                                    'package is removed in '
                                                    'Django 2.0.',
                                     'display_name': 'DjangoCompat2_0ExtraForms',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'django compat 2_0 extra forms'},
    'DjangoCompat2_0SignalsWeak': {   'categories': ['security'],
                                      'description': 'The weak argument to '
                                                     'django.dispatch.signals.Signal.disconnect() '
                                                     'is removed in Django '
                                                     '2.0.',
                                      'display_name': 'DjangoCompat2_0SignalsWeak',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'django compat 2_0 signals '
                                               'weak'},
    'DjangoDbModelSaveSuper': {   'categories': ['security'],
                                  'description': 'Detected a django model '
                                                 '`$MODEL` is not calling '
                                                 'super().save() inside of the '
                                                 'save method.',
                                  'display_name': 'DjangoDbModelSaveSuper',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'django db model save super'},
    'DjangoSecureSetCookie': {   'categories': ['security'],
                                 'description': 'Django cookies should be '
                                                'handled securely by setting '
                                                'secure=True, httponly=True, '
                                                "and samesite='Lax' in\n"
                                                'response.set_cookie(...). If '
                                                'your situation calls for '
                                                'different settings, '
                                                'explicitly disable the '
                                                'setting.\n'
                                                'If you want to send the '
                                                'cookie over http, set '
                                                'secure=False.  If you want to '
                                                'let client-side JavaScript\n'
                                                'read the cookie, set '
                                                'httponly=False. If you want '
                                                'to attach cookies to requests '
                                                'for external sites,\n'
                                                'set samesite=None.',
                                 'display_name': 'DjangoSecureSetCookie',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'django secure set cookie'},
    'DoPrivilegedUse': {   'categories': ['security'],
                           'description': 'Marking code as privileged enables '
                                          'a piece of trusted code to '
                                          'temporarily\n'
                                          'enable access to more resources '
                                          'than are available directly to the '
                                          'code\n'
                                          'that called it. Be very careful in '
                                          'your use of the privileged '
                                          'construct,\n'
                                          'and always remember to make the '
                                          'privileged code section as small as '
                                          'possible.',
                           'display_name': 'DoPrivilegedUse',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'do privileged use'},
    'DockerArbitraryContainerRun': {   'categories': ['security'],
                                       'description': 'If unverified user data '
                                                      'can reach the `run` or '
                                                      '`create` method it can '
                                                      'result in runing '
                                                      'arbitrary container.',
                                       'display_name': 'DockerArbitraryContainerRun',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'docker arbitrary container '
                                                'run'},
    'DomBasedXss': {   'categories': ['security'],
                       'description': 'Detected possible DOM-based XSS. This '
                                      'occurs because a portion of the URL is '
                                      'being used\n'
                                      'to construct an element added directly '
                                      'to the page. For example, a malicious '
                                      'actor could\n'
                                      'send someone a link like this: '
                                      'http://www.some.site/page.html?default=<script>alert(document.cookie)</script>\n'
                                      'which would add the script to the '
                                      'page.\n'
                                      'Consider allowlisting appropriate '
                                      'values or using an approach which does '
                                      'not involve the URL.',
                       'display_name': 'DomBasedXss',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'dom based xss'},
    'DoubleFree': {   'categories': ['security'],
                      'description': "Variable '$VAR' was freed twice. This "
                                     'can lead to undefined behavior.',
                      'display_name': 'DoubleFree',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'double free'},
    'Double_goto': {   'categories': ['security'],
                       'description': 'The second goto statement will always '
                                      'be executed.',
                       'display_name': 'Double_goto',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'double_goto'},
    'DynamicHttptraceClienttrace': {   'categories': ['security'],
                                       'description': 'Detected a potentially '
                                                      'dynamic ClientTrace. '
                                                      'This occurred because '
                                                      'semgrep could not\n'
                                                      'find a static '
                                                      'definition for '
                                                      "'$TRACE'. Dynamic "
                                                      'ClientTraces are '
                                                      'dangerous because\n'
                                                      'they deserialize '
                                                      'function code to run '
                                                      'when certain Request '
                                                      'events occur, which '
                                                      'could lead\n'
                                                      'to code being run '
                                                      'without your knowledge. '
                                                      'Ensure that your '
                                                      'ClientTrace is '
                                                      'statically defined.',
                                       'display_name': 'DynamicHttptraceClienttrace',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'dynamic httptrace '
                                                'clienttrace'},
    'DynamicProxyHost': {   'categories': ['security'],
                            'description': 'The host for this proxy URL is '
                                           'dynamically determined. This can '
                                           'be dangerous if the host can be '
                                           'injected by an attacker because it '
                                           'may forcibly alter destination of '
                                           'the proxy. Consider hardcoding '
                                           'acceptable destinations and '
                                           "retrieving them with 'map' or "
                                           'something similar.\n'
                                           '{"include": ["*.conf", "*.vhost", '
                                           '"sites-available/*", '
                                           '"sites-enabled/*"]}',
                            'display_name': 'DynamicProxyHost',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'nginx: dynamic proxy host'},
    'DynamicProxyScheme': {   'categories': ['security'],
                              'description': 'The protocol scheme for this '
                                             'proxy is dynamically '
                                             'determined.\n'
                                             'This can be dangerous if the '
                                             'scheme can be injected by an\n'
                                             'attacker because it may forcibly '
                                             'alter the connection scheme.\n'
                                             'Consider hardcoding a scheme for '
                                             'this proxy.\n'
                                             '\n'
                                             '{"include": ["*.conf", '
                                             '"*.vhost", "sites-available/*", '
                                             '"sites-enabled/*"]}',
                              'display_name': 'DynamicProxyScheme',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'nginx: dynamic proxy scheme'},
    'DynamicUrllibUseDetected': {   'categories': ['security'],
                                    'description': 'Detected a dynamic value '
                                                   'being used with urllib. '
                                                   "urllib supports 'file://' "
                                                   'schemes, so a dynamic '
                                                   'value controlled by a '
                                                   'malicious actor may allow '
                                                   'them to read arbitrary '
                                                   'files. Audit uses of '
                                                   'urllib calls to ensure '
                                                   'user data cannot control '
                                                   'the URLs, or consider '
                                                   "using the 'requests' "
                                                   'library instead.',
                                    'display_name': 'DynamicUrllibUseDetected',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'dynamic urllib use detected'},
    'EcbCipher': {   'categories': ['security'],
                     'description': 'Cipher in ECB mode is detected. ECB mode '
                                    'produces the same output for the same '
                                    'input each time\n'
                                    'which allows an attacker to intercept and '
                                    'replay the data. Further, ECB mode does '
                                    'not provide\n'
                                    'any integrity checking. See '
                                    'https://find-sec-bugs.github.io/bugs.htm#CIPHER_INTEGRITY.',
                     'display_name': 'EcbCipher',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'ecb cipher'},
    'ElInjection': {   'categories': ['security'],
                       'description': 'An expression is built with a dynamic '
                                      'value. The source of the value(s) '
                                      'should be verified to avoid that '
                                      'unfiltered values fall into this risky '
                                      'code evaluation.',
                       'display_name': 'ElInjection',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'el injection'},
    'ElectronAllowHttp': {   'categories': ['security'],
                             'description': 'Application can load content over '
                                            'HTTP and that makes the app '
                                            'vulnerable to Man in the middle '
                                            'attacks.',
                             'display_name': 'ElectronAllowHttp',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'electron allow http'},
    'ElectronBlinkIntegration': {   'categories': ['security'],
                                    'description': "Blink's expirimental "
                                                   'features are enabled in '
                                                   'this application. Some of '
                                                   'the features may affect '
                                                   'the security of the '
                                                   'application.',
                                    'display_name': 'ElectronBlinkIntegration',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'electron blink integration'},
    'ElectronContextIsolation': {   'categories': ['security'],
                                    'description': 'Disabling context '
                                                   'isolation can introduce '
                                                   'Prototype Pollution '
                                                   'vulnerabilities.',
                                    'display_name': 'ElectronContextIsolation',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'electron context isolation'},
    'ElectronDisableWebsecurity': {   'categories': ['security'],
                                      'description': 'Disabling webSecurity '
                                                     'will disable the '
                                                     'same-origin policy and '
                                                     'allows the execution of '
                                                     'insecure code from any '
                                                     'domain.',
                                      'display_name': 'ElectronDisableWebsecurity',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'electron disable websecurity'},
    'ElectronExperimentalFeatures': {   'categories': ['security'],
                                        'description': 'Experimental features '
                                                       'are not expected to be '
                                                       'in production ready '
                                                       'applications.',
                                        'display_name': 'ElectronExperimentalFeatures',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'electron experimental '
                                                 'features'},
    'ElectronNodejsIntegration': {   'categories': ['security'],
                                     'description': 'Node integration exposes '
                                                    'node.js APIs to the '
                                                    'electron app and this can '
                                                    'introduce remote code '
                                                    'execution vulnerabilities '
                                                    'to the application if the '
                                                    'app is vulnerable to '
                                                    'Cross Site Scripting '
                                                    '(XSS).',
                                     'display_name': 'ElectronNodejsIntegration',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'electron nodejs integration'},
    'Eqeq': {   'categories': ['security'],
                'description': '`$X == $X` or `$X != $X` is always true. '
                               '(Unless the value compared is a float or '
                               'double).\n'
                               'To test if `$X` is not-a-number, use '
                               '`Double.isNaN($X)`.',
                'display_name': 'Eqeq',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'eqeq'},
    'EqeqIsBad': {   'categories': ['security'],
                     'description': 'useless comparison operation `$X == $X` '
                                    'or `$X != $X`',
                     'display_name': 'EqeqIsBad',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'eqeq is bad'},
    'EscapeFunctionOverwrite': {   'categories': ['security'],
                                   'description': 'The Mustache escape '
                                                  'function is being '
                                                  'overwritten. This could '
                                                  'bypass\n'
                                                  'HTML escaping safety '
                                                  'measures built into the '
                                                  'rendering engine, exposing\n'
                                                  'your application to '
                                                  'cross-site scripting (XSS) '
                                                  'vulnerabilities. If you\n'
                                                  'need unescaped HTML, use '
                                                  'the triple brace operator '
                                                  'in your template:\n'
                                                  "'{{{ ... }}}'.",
                                   'display_name': 'EscapeFunctionOverwrite',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'escape function overwrite'},
    'EvalDetected': {   'categories': ['security'],
                        'description': 'Detected the use of eval(). eval() can '
                                       'be dangerous if used to evaluate\n'
                                       'dynamic content. If this content can '
                                       'be input from outside the program, '
                                       'this\n'
                                       'may be a code injection vulnerability. '
                                       'Ensure evaluated content is not '
                                       'definable\n'
                                       'by external sources.',
                        'display_name': 'EvalDetected',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'eval detected'},
    'EvalInjection': {   'categories': ['security'],
                         'description': 'Detected user data flowing into eval. '
                                        'This is code injection and should be '
                                        'avoided.',
                         'display_name': 'EvalInjection',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'eval injection'},
    'EvalNodejs': {   'categories': ['security'],
                      'description': 'User controlled data in eval() or '
                                     'similar functions may result in Server '
                                     'Side Injection or Remote Code Injection',
                      'display_name': 'EvalNodejs',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'eval nodejs'},
    'EvalRequire': {   'categories': ['security'],
                       'description': 'Untrusted user input in `require()` '
                                      'function allows an attacker to load '
                                      'arbitrary code.',
                       'display_name': 'EvalRequire',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'eval require'},
    'EvalUse': {   'categories': ['security'],
                   'description': 'Evaluating non-constant commands. This can '
                                  'lead to command injection.',
                   'display_name': 'EvalUse',
                   'file': '%(issue.file)s',
                   'line': '%(issue.line)s',
                   'severity': '1',
                   'title': 'eval use'},
    'ExecDetected': {   'categories': ['security'],
                        'description': 'Detected the use of exec(). exec() can '
                                       'be dangerous if used to evaluate\n'
                                       'dynamic content. If this content can '
                                       'be input from outside the program, '
                                       'this\n'
                                       'may be a code injection vulnerability. '
                                       'Ensure evaluated content is not '
                                       'definable\n'
                                       'by external sources.',
                        'display_name': 'ExecDetected',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'exec detected'},
    'ExecInjection': {   'categories': ['security'],
                         'description': 'Detected user data flowing into exec. '
                                        'This is code injection and should be '
                                        'avoided.',
                         'display_name': 'ExecInjection',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'exec injection'},
    'ExecUse': {   'categories': ['security'],
                   'description': 'Executing non-constant commands. This can '
                                  'lead to command injection.',
                   'display_name': 'ExecUse',
                   'file': '%(issue.file)s',
                   'line': '%(issue.line)s',
                   'severity': '1',
                   'title': 'exec use'},
    'ExpatXxe': {   'categories': ['security'],
                    'description': 'If unverified user data can reach the XML '
                                   'Parser it can result in XML External or\n'
                                   'Internal Entity (XXE) Processing '
                                   'vulnerabilities',
                    'display_name': 'ExpatXxe',
                    'file': '%(issue.file)s',
                    'line': '%(issue.line)s',
                    'severity': '1',
                    'title': 'expat xxe'},
    'ExplicitUnescapeWithMarkup': {   'categories': ['security'],
                                      'description': 'Detected explicitly '
                                                     'unescaped content using '
                                                     "'Markup()'. This "
                                                     'permits\n'
                                                     'the unescaped data to '
                                                     'include unescaped HTML '
                                                     'which could result in\n'
                                                     'cross-site scripting. '
                                                     'Ensure this data is not '
                                                     'externally controlled,\n'
                                                     'or consider rewriting to '
                                                     "not use 'Markup()'.",
                                      'display_name': 'ExplicitUnescapeWithMarkup',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'explicit unescape with markup'},
    'Exported_loop_pointer': {   'categories': ['security'],
                                 'description': '`$VALUE` is a loop pointer '
                                                'that may be exported from the '
                                                'loop. This pointer is shared '
                                                'between loop iterations, so '
                                                'the exported reference will '
                                                'always point to the last loop '
                                                'value, which is likely '
                                                'unintentional. To fix, copy '
                                                'the pointer to a new pointer '
                                                'within the loop.',
                                 'display_name': 'Exported_loop_pointer',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'exported_loop_pointer'},
    'ExposingDockerSocketHostpath': {   'categories': ['security'],
                                        'description': "Exposing host's Docker "
                                                       'socket to containers '
                                                       'via a volume. The '
                                                       'owner of this\n'
                                                       'socket is root. Giving '
                                                       'someone access to it '
                                                       'is equivalent to '
                                                       'giving\n'
                                                       'unrestricted root '
                                                       'access to your host. '
                                                       "Remove 'docker.sock' "
                                                       'from hostpath to\n'
                                                       'prevent this.',
                                        'display_name': 'ExposingDockerSocketHostpath',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'kubernetes: exposing docker '
                                                 'socket hostpath'},
    'ExpressBodyparser': {   'categories': ['security'],
                             'description': 'POST Request to Express Body '
                                            "Parser 'bodyParser()' can create "
                                            'Temporary files and consume '
                                            'space.',
                             'display_name': 'ExpressBodyparser',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'express bodyparser'},
    'ExpressCookieSessionDefaultName': {   'categories': ['security'],
                                           'description': 'Don’t use the '
                                                          'default session '
                                                          'cookie name\n'
                                                          'Using the default '
                                                          'session cookie name '
                                                          'can open your app '
                                                          'to attacks.\n'
                                                          'The security issue '
                                                          'posed is similar to '
                                                          'X-Powered-By: a '
                                                          'potential attacker '
                                                          'can use it to '
                                                          'fingerprint the '
                                                          'server and target '
                                                          'attacks '
                                                          'accordingly.',
                                           'display_name': 'ExpressCookieSessionDefaultName',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'express cookie session '
                                                    'default name'},
    'ExpressCookieSessionNoDomain': {   'categories': ['security'],
                                        'description': 'Default session '
                                                       'middleware settings: '
                                                       '`domain` not set.\n'
                                                       'It indicates the '
                                                       'domain of the cookie; '
                                                       'use it to compare '
                                                       'against the domain of '
                                                       'the server in which '
                                                       'the URL is being '
                                                       'requested.\n'
                                                       'If they match, then '
                                                       'check the path '
                                                       'attribute next.',
                                        'display_name': 'ExpressCookieSessionNoDomain',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'express cookie session no '
                                                 'domain'},
    'ExpressCookieSessionNoExpires': {   'categories': ['security'],
                                         'description': 'Default session '
                                                        'middleware settings: '
                                                        '`expires` not set.\n'
                                                        'Use it to set '
                                                        'expiration date for '
                                                        'persistent cookies.',
                                         'display_name': 'ExpressCookieSessionNoExpires',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'express cookie session no '
                                                  'expires'},
    'ExpressCookieSessionNoHttponly': {   'categories': ['security'],
                                          'description': 'Default session '
                                                         'middleware settings: '
                                                         '`httpOnly` not set.\n'
                                                         'It ensures the '
                                                         'cookie is sent only '
                                                         'over HTTP(S), not '
                                                         'client JavaScript, '
                                                         'helping to protect '
                                                         'against cross-site '
                                                         'scripting attacks.',
                                          'display_name': 'ExpressCookieSessionNoHttponly',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'express cookie session no '
                                                   'httponly'},
    'ExpressCookieSessionNoPath': {   'categories': ['security'],
                                      'description': 'Default session '
                                                     'middleware settings: '
                                                     '`path` not set.\n'
                                                     'It indicates the path of '
                                                     'the cookie; use it to '
                                                     'compare against the '
                                                     'request path. If this '
                                                     'and domain match, then '
                                                     'send the cookie in the '
                                                     'request.',
                                      'display_name': 'ExpressCookieSessionNoPath',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'express cookie session no '
                                               'path'},
    'ExpressCookieSessionNoSecure': {   'categories': ['security'],
                                        'description': 'Default session '
                                                       'middleware settings: '
                                                       '`secure` not set.\n'
                                                       'It ensures the browser '
                                                       'only sends the cookie '
                                                       'over HTTPS.',
                                        'display_name': 'ExpressCookieSessionNoSecure',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'express cookie session no '
                                                 'secure'},
    'ExpressCors': {   'categories': ['security'],
                       'description': 'Access-Control-Allow-Origin response '
                                      'header is set to "*". This will disable '
                                      'CORS Same Origin Policy restrictions.',
                       'display_name': 'ExpressCors',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'express cors'},
    'ExpressExpatXxe': {   'categories': ['security'],
                           'description': 'Make sure that unverified user data '
                                          'can not reach the XML Parser,\n'
                                          'as it can result in XML External or '
                                          'Internal Entity (XXE) Processing '
                                          'vulnerabilities',
                           'display_name': 'ExpressExpatXxe',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'express expat xxe'},
    'ExpressJwtHardcodedSecret': {   'categories': ['security'],
                                     'description': 'Hardcoded JWT secret or '
                                                    'private key is used.\n'
                                                    'This is a Insufficiently '
                                                    'Protected Credentials '
                                                    'weakness: '
                                                    'https://cwe.mitre.org/data/definitions/522.html\n'
                                                    'Consider using an '
                                                    'appropriate security '
                                                    'mechanism to protect the '
                                                    'credentials (e.g. keeping '
                                                    'secrets in environment '
                                                    'variables: '
                                                    'process.env.SECRET)',
                                     'display_name': 'ExpressJwtHardcodedSecret',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'express jwt hardcoded secret'},
    'ExpressJwtNotRevoked': {   'categories': ['security'],
                                'description': 'No token revoking configured '
                                               'for `express-jwt`. A leaked '
                                               'token could still be used and '
                                               'unable to be revoked.\n'
                                               'Consider using function as the '
                                               '`isRevoked` option.',
                                'display_name': 'ExpressJwtNotRevoked',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'express jwt not revoked'},
    'ExpressLfr': {   'categories': ['security'],
                      'description': 'Untrusted user input in express render() '
                                     'function can result in arbitrary file '
                                     'read when hbs templating is used.',
                      'display_name': 'ExpressLfr',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'express lfr'},
    'ExpressLfrWarning': {   'categories': ['security'],
                             'description': 'Untrusted user input in express '
                                            'render() function can result in '
                                            'arbitrary file read if hbs '
                                            'templating is used.',
                             'display_name': 'ExpressLfrWarning',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'express lfr warning'},
    'ExpressOpenRedirect': {   'categories': ['security'],
                               'description': 'Untrusted user input in '
                                              'redirect() can result in Open '
                                              'Redirect vulnerability.',
                               'display_name': 'ExpressOpenRedirect',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'express open redirect'},
    'ExpressOpenRedirect2': {   'categories': ['security'],
                                'description': 'Untrusted user input in '
                                               "response header('Location') "
                                               'can result in Open Redirect '
                                               'vulnerability.',
                                'display_name': 'ExpressOpenRedirect2',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'express open redirect2'},
    'ExpressPathJoinResolveTraversal': {   'categories': ['security'],
                                           'description': 'Possible writing '
                                                          'outside of the '
                                                          'destination,\n'
                                                          'make sure that the '
                                                          'target path is '
                                                          'nested in the '
                                                          'intended '
                                                          'destination',
                                           'display_name': 'ExpressPathJoinResolveTraversal',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'express path join resolve '
                                                    'traversal'},
    'ExpressPhantomInjection': {   'categories': ['security'],
                                   'description': 'If unverified user data can '
                                                  'reach the `phantom` methods '
                                                  'it can result in '
                                                  'Server-Side Request Forgery '
                                                  'vulnerabilities',
                                   'display_name': 'ExpressPhantomInjection',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'express phantom injection'},
    'ExpressPuppeteerInjection': {   'categories': ['security'],
                                     'description': 'If unverified user data '
                                                    'can reach the `puppeteer` '
                                                    'methods it can result in '
                                                    'Server-Side Request '
                                                    'Forgery vulnerabilities',
                                     'display_name': 'ExpressPuppeteerInjection',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'express puppeteer injection'},
    'ExpressSandboxCodeInjection': {   'categories': ['security'],
                                       'description': 'Make sure that '
                                                      'unverified user data '
                                                      'can not reach '
                                                      '`sandbox`.',
                                       'display_name': 'ExpressSandboxCodeInjection',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'express sandbox code '
                                                'injection'},
    'ExpressVm2CodeInjection': {   'categories': ['security'],
                                   'description': 'Make sure that unverified '
                                                  'user data can not reach '
                                                  '`vm2`.',
                                   'display_name': 'ExpressVm2CodeInjection',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'express vm2 code injection'},
    'ExpressVm2ContextInjection': {   'categories': ['security'],
                                      'description': 'Make sure that '
                                                     'unverified user data can '
                                                     'not reach `vm2`.',
                                      'display_name': 'ExpressVm2ContextInjection',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'express vm2 context injection'},
    'ExpressVmCodeInjection': {   'categories': ['security'],
                                  'description': 'Make sure that unverified '
                                                 'user data can not reach vm '
                                                 'instance.',
                                  'display_name': 'ExpressVmCodeInjection',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'express vm code injection'},
    'ExpressVmCompilefunctionContextInjection': {   'categories': ['security'],
                                                    'description': 'Make sure '
                                                                   'that '
                                                                   'unverified '
                                                                   'user data '
                                                                   'can not '
                                                                   'reach '
                                                                   'vm.compileFunction.',
                                                    'display_name': 'ExpressVmCompilefunctionContextInjection',
                                                    'file': '%(issue.file)s',
                                                    'line': '%(issue.line)s',
                                                    'severity': '1',
                                                    'title': 'express vm '
                                                             'compilefunction '
                                                             'context '
                                                             'injection'},
    'ExpressVmRunincontextContextInjection': {   'categories': ['security'],
                                                 'description': 'Make sure '
                                                                'that '
                                                                'unverified '
                                                                'user data can '
                                                                'not reach '
                                                                'vm.runInContext.',
                                                 'display_name': 'ExpressVmRunincontextContextInjection',
                                                 'file': '%(issue.file)s',
                                                 'line': '%(issue.line)s',
                                                 'severity': '1',
                                                 'title': 'express vm '
                                                          'runincontext '
                                                          'context injection'},
    'ExpressVmRuninnewcontextContextInjection': {   'categories': ['security'],
                                                    'description': 'Make sure '
                                                                   'that '
                                                                   'unverified '
                                                                   'user data '
                                                                   'can not '
                                                                   'reach '
                                                                   'vm.runInNewContext.',
                                                    'display_name': 'ExpressVmRuninnewcontextContextInjection',
                                                    'file': '%(issue.file)s',
                                                    'line': '%(issue.line)s',
                                                    'severity': '1',
                                                    'title': 'express vm '
                                                             'runinnewcontext '
                                                             'context '
                                                             'injection'},
    'ExpressWkhtmltoimageInjection': {   'categories': ['security'],
                                         'description': 'If unverified user '
                                                        'data can reach the '
                                                        '`phantom` methods it '
                                                        'can result in '
                                                        'Server-Side Request '
                                                        'Forgery '
                                                        'vulnerabilities',
                                         'display_name': 'ExpressWkhtmltoimageInjection',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'express wkhtmltoimage '
                                                  'injection'},
    'ExpressWkhtmltopdfInjection': {   'categories': ['security'],
                                       'description': 'If unverified user data '
                                                      'can reach the `phantom` '
                                                      'methods it can result '
                                                      'in Server-Side Request '
                                                      'Forgery vulnerabilities',
                                       'display_name': 'ExpressWkhtmltopdfInjection',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'express wkhtmltopdf '
                                                'injection'},
    'ExpressXml2jsonXxe': {   'categories': ['security'],
                              'description': 'Make sure that unverified user '
                                             'data can not reach the XML '
                                             'Parser,\n'
                                             'as it can result in XML External '
                                             'or Internal Entity (XXE) '
                                             'Processing vulnerabilities',
                              'display_name': 'ExpressXml2jsonXxe',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'express xml2json xxe'},
    'ExpressXml2jsonXxeEvent': {   'categories': ['security'],
                                   'description': 'Xml Parser is used inside '
                                                  'Request Event.\n'
                                                  'Make sure that unverified '
                                                  'user data can not reach the '
                                                  'XML Parser,\n'
                                                  'as it can result in XML '
                                                  'External or Internal Entity '
                                                  '(XXE) Processing '
                                                  'vulnerabilities',
                                   'display_name': 'ExpressXml2jsonXxeEvent',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'express xml2json xxe event'},
    'ExpressXss': {   'categories': ['security'],
                      'description': 'Untrusted User Input in Response will '
                                     'result in Reflected Cross Site Scripting '
                                     'Vulnerability.',
                      'display_name': 'ExpressXss',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'express xss'},
    'ExtendsCustomExpression': {   'categories': ['security'],
                                   'description': 'Found extension of custom '
                                                  'expression: $CLASS. '
                                                  'Extending expressions\n'
                                                  'in this way could '
                                                  'inadvertently expose a SQL '
                                                  'injection vulnerability.\n'
                                                  'See '
                                                  'https://docs.djangoproject.com/en/3.0/ref/models/expressions/#avoiding-sql-injection\n'
                                                  'for more information.',
                                   'display_name': 'ExtendsCustomExpression',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'extends custom expression'},
    'FileDisclosure': {   'categories': ['security'],
                          'description': 'Special requests can determine '
                                         'whether a file exists on a '
                                         "filesystem that's outside the Ruby "
                                         "app's\n"
                                         'root directory. To fix this, set '
                                         'config.serve_static_assets = false.',
                          'display_name': 'FileDisclosure',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'file disclosure'},
    'FileInclusion': {   'categories': ['security'],
                         'description': 'Non-constant file inclusion. This can '
                                        'lead to LFI or RFI if user\n'
                                        'input reaches this statement.',
                         'display_name': 'FileInclusion',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'file inclusion'},
    'FileObjectRedefinedBeforeClose': {   'categories': ['security'],
                                          'description': 'Detected a file '
                                                         'object that is '
                                                         'redefined and never '
                                                         'closed. This\n'
                                                         'could leak file '
                                                         'descriptors and '
                                                         'unnecessarily '
                                                         'consume system '
                                                         'resources.',
                                          'display_name': 'FileObjectRedefinedBeforeClose',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'file object redefined '
                                                   'before close'},
    'FilterSkipping': {   'categories': ['security'],
                          'description': 'Checks for use of action in Ruby '
                                         'routes. This can cause Rails to '
                                         'render an arbitrary view if an\n'
                                         'attacker creates an URL accurately. '
                                         'Affects 3.0 applications. Can avoid '
                                         'the vulnerability by providing\n'
                                         'additional constraints.',
                          'display_name': 'FilterSkipping',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'filter skipping'},
    'FilterWithIsSafe': {   'categories': ['security'],
                            'description': 'Detected Django filters flagged '
                                           "with 'is_safe'. 'is_safe' tells "
                                           'Django\n'
                                           'not to apply escaping on the value '
                                           'returned by this filter (although '
                                           'the\n'
                                           'input is escaped). Used '
                                           "improperly, 'is_safe' could expose "
                                           'your application\n'
                                           'to cross-site scripting (XSS) '
                                           'vulnerabilities. Ensure this '
                                           'filter does not\n'
                                           '1) add HTML characters, 2) remove '
                                           'characters, or 3) use external '
                                           'data in\n'
                                           'any way. Consider instead removing '
                                           "'is_safe' and explicitly marking "
                                           'safe\n'
                                           "content with 'mark_safe()'.",
                            'display_name': 'FilterWithIsSafe',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'filter with is safe'},
    'FindSqlStringConcatenation': {   'categories': ['security'],
                                      'description': 'In $METHOD, $X is used '
                                                     'to construct a SQL query '
                                                     'via string '
                                                     'concatenation.',
                                      'display_name': 'FindSqlStringConcatenation',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'find sql string concatenation'},
    'FlaskApiMethodStringFormat': {   'categories': ['security'],
                                      'description': 'Method $METHOD in API '
                                                     'controller $CLASS '
                                                     'provides user arg $ARG '
                                                     'to requests method '
                                                     '$REQMETHOD',
                                      'display_name': 'FlaskApiMethodStringFormat',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'flask api method string '
                                               'format'},
    'FlaskCacheQueryString': {   'categories': ['security'],
                                 'description': "Flask-caching doesn't cache "
                                                'query strings by default. You '
                                                'have to use '
                                                '`query_string=True`. Also you '
                                                "shouldn't cache verbs that "
                                                'can mutate state.',
                                 'display_name': 'FlaskCacheQueryString',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'flask cache query string'},
    'FlaskClassMethodGetSideEffects': {   'categories': ['security'],
                                          'description': 'Flask class method '
                                                         'GET with side '
                                                         'effects',
                                          'display_name': 'FlaskClassMethodGetSideEffects',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'flask class method get '
                                                   'side effects'},
    'FlaskDeprecatedApis': {   'categories': ['security'],
                               'description': 'deprecated Flask API',
                               'display_name': 'FlaskDeprecatedApis',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'flask deprecated apis'},
    'FlaskDuplicateHandlerName': {   'categories': ['security'],
                                     'description': 'Looks like `$R` is a '
                                                    'flask function handler '
                                                    'that registered to two '
                                                    'different routes. This '
                                                    'will cause a runtime '
                                                    'error',
                                     'display_name': 'FlaskDuplicateHandlerName',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'flask duplicate handler name'},
    'FlaskViewFuncMatchRouteParams': {   'categories': ['security'],
                                         'description': 'The view function '
                                                        'arguments `$PATH` to '
                                                        "`$R` don't match the "
                                                        'path defined in '
                                                        '@app.route($PATH)',
                                         'display_name': 'FlaskViewFuncMatchRouteParams',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'flask view func match route '
                                                  'params'},
    'FlaskWtfCsrfDisabled': {   'categories': ['security'],
                                'description': "Setting 'WTF_CSRF_ENABLED' to "
                                               "'False' explicitly disables "
                                               'CSRF protection.',
                                'display_name': 'FlaskWtfCsrfDisabled',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'flask wtf csrf disabled'},
    'ForceSslFalse': {   'categories': ['security'],
                         'description': 'Checks for configuration setting of '
                                        'force_ssl to false. Force_ssl forces '
                                        'usage of HTTPS, which\n'
                                        'could lead to network interception of '
                                        'unencrypted application traffic. To '
                                        'fix, set config.force_ssl = true.',
                         'display_name': 'ForceSslFalse',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'force ssl false'},
    'FormattedSqlQuery': {   'categories': ['security'],
                             'description': 'Detected possible formatted SQL '
                                            'query. Use parameterized queries '
                                            'instead.',
                             'display_name': 'FormattedSqlQuery',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'formatted sql query'},
    'FormattedSqlString': {   'categories': ['security'],
                              'description': 'Detected a formatted string in a '
                                             'SQL statement. This could lead '
                                             'to SQL\n'
                                             'injection if variables in the '
                                             'SQL statement are not properly '
                                             'sanitized.\n'
                                             'Use a prepared statements '
                                             '(java.sql.PreparedStatement) '
                                             'instead. You\n'
                                             'can obtain a PreparedStatement '
                                             'using '
                                             "'connection.prepareStatement'.",
                              'display_name': 'FormattedSqlString',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'formatted sql string'},
    'FormattedStringBashoperator': {   'categories': ['security'],
                                       'description': 'Found a formatted '
                                                      'string in BashOperator: '
                                                      '$CMD.\n'
                                                      'This could be '
                                                      'vulnerable to '
                                                      'injection.\n'
                                                      'Be extra sure your '
                                                      'variables are not '
                                                      'controllable by '
                                                      'external sources.',
                                       'display_name': 'FormattedStringBashoperator',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'formatted string '
                                                'bashoperator'},
    'FormattedTemplateString': {   'categories': ['security'],
                                   'description': 'Found a formatted template '
                                                  'string passed to '
                                                  "'template.HTML()'.\n"
                                                  "'template.HTML()' does not "
                                                  'escape contents. Be '
                                                  'absolutely sure\n'
                                                  'there is no user-controlled '
                                                  'data in this template. If '
                                                  'user data\n'
                                                  'can reach this template, '
                                                  'you may have a XSS '
                                                  'vulnerability.',
                                   'display_name': 'FormattedTemplateString',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'formatted template string'},
    'FtpUse': {   'categories': ['security'],
                  'description': 'FTP allows for unencrypted file transfers. '
                                 'Consider using an encrypted alternative.',
                  'display_name': 'FtpUse',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'ftp use'},
    'Ftplib': {   'categories': ['security'],
                  'description': 'FTP does not encrypt communications by '
                                 'default. This can lead to sensitive\n'
                                 'data being exposed. Ensure use of FTP here '
                                 'does not expose sensitive data.',
                  'display_name': 'Ftplib',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'ftplib'},
    'GenericCors': {   'categories': ['security'],
                       'description': 'Access-Control-Allow-Origin response '
                                      'header is set to "*". This will disable '
                                      'CORS Same Origin Policy restrictions.',
                       'display_name': 'GenericCors',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'generic cors'},
    'GenericErrorDisclosure': {   'categories': ['security'],
                                  'description': 'Error messages with stack '
                                                 'traces may expose sensitive '
                                                 'information about the '
                                                 'application.',
                                  'display_name': 'GenericErrorDisclosure',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'generic error disclosure'},
    'GenericHeaderInjection': {   'categories': ['security'],
                                  'description': 'Untrusted user input in '
                                                 'response header will result '
                                                 'in HTTP Header Injection or '
                                                 'Response Splitting Attacks.',
                                  'display_name': 'GenericHeaderInjection',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'generic header injection'},
    'GenericOsCommandExec': {   'categories': ['security'],
                                'description': 'User controlled data in '
                                               "'child_process.exec()' can "
                                               'result in Remote OS Command '
                                               'Execution.',
                                'display_name': 'GenericOsCommandExec',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'generic os command exec'},
    'GenericPathTraversal': {   'categories': ['security'],
                                'description': 'Untrusted user input in '
                                               'readFile()/readFileSync() can '
                                               'endup in Directory Traversal '
                                               'Attacks.',
                                'display_name': 'GenericPathTraversal',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'generic path traversal'},
    'GlobalAutoescapeOff': {   'categories': ['security'],
                               'description': 'Autoescape is globally disbaled '
                                              'for this Django application. If '
                                              'you are\n'
                                              'rendering any web pages, this '
                                              'exposes your application to '
                                              'cross-site\n'
                                              'scripting (XSS) '
                                              'vulnerabilities. Remove '
                                              "'autoescape: False' or set it\n"
                                              "to 'True'.",
                               'display_name': 'GlobalAutoescapeOff',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'global autoescape off'},
    'GlobalsMisuseCodeExecution': {   'categories': ['security'],
                                      'description': 'Found request data as an '
                                                     "index to 'globals()'. "
                                                     'This is extremely\n'
                                                     'dangerous because it '
                                                     'allows an attacker to '
                                                     'execute arbitrary code\n'
                                                     'on the system. Refactor '
                                                     'your code not to use '
                                                     "'globals()'.",
                                      'display_name': 'GlobalsMisuseCodeExecution',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'globals misuse code execution'},
    'GoInsecureTemplates': {   'categories': ['security'],
                               'description': 'usage of insecure template '
                                              'types. They are documented as a '
                                              'security risk. See '
                                              'https://golang.org/pkg/html/template/#HTML.',
                               'display_name': 'GoInsecureTemplates',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'go insecure templates'},
    'GosqlSqli': {   'categories': ['security'],
                     'description': 'Detected string concatenation with a '
                                    'non-literal variable in a "database/sql"\n'
                                    'Go SQL statement. This could lead to SQL '
                                    'injection if the variable is '
                                    'user-controlled\n'
                                    'and not properly sanitized. In order to '
                                    'prevent SQL injection,\n'
                                    'used parameterized queries or prepared '
                                    'statements instead.\n'
                                    'You can use prepared statements with the '
                                    "'Prepare' and 'PrepareContext' calls.",
                     'display_name': 'GosqlSqli',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'gosql sqli'},
    'GrpcClientInsecureConnection': {   'categories': ['security'],
                                        'description': 'Found an insecure gRPC '
                                                       'connection using '
                                                       "'grpc.WithInsecure()'. "
                                                       'This creates a '
                                                       'connection without '
                                                       'encryption to a gRPC '
                                                       'server. A malicious '
                                                       'attacker could tamper '
                                                       'with the gRPC message, '
                                                       'which could compromise '
                                                       'the machine. Instead, '
                                                       'establish a secure '
                                                       'connection with an SSL '
                                                       'certificate using the '
                                                       "'grpc.WithTransportCredentials()' "
                                                       'function. You can '
                                                       'create a create '
                                                       'credentials using a '
                                                       "'tls.Config{}' struct "
                                                       'with '
                                                       "'credentials.NewTLS()'. "
                                                       'The final fix looks '
                                                       'like this: '
                                                       "'grpc.WithTransportCredentials(credentials.NewTLS(<config>))'.",
                                        'display_name': 'GrpcClientInsecureConnection',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'grpc client insecure '
                                                 'connection'},
    'GrpcInsecureConnection': {   'categories': ['security'],
                                  'description': 'Found an insecure gRPC '
                                                 'connection. This creates a '
                                                 'connection without '
                                                 'encryption to a gRPC '
                                                 'client/server. A malicious '
                                                 'attacker could  tamper with '
                                                 'the gRPC message, which '
                                                 'could compromise the '
                                                 'machine.',
                                  'display_name': 'GrpcInsecureConnection',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'grpc insecure connection'},
    'GrpcNodejsInsecureConnection': {   'categories': ['security'],
                                        'description': 'Found an insecure gRPC '
                                                       'connection. This '
                                                       'creates a connection '
                                                       'without encryption to '
                                                       'a gRPC client/server. '
                                                       'A malicious attacker\n'
                                                       'could tamper with the '
                                                       'gRPC message, which '
                                                       'could compromise the '
                                                       'machine.',
                                        'display_name': 'GrpcNodejsInsecureConnection',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'grpc nodejs insecure '
                                                 'connection'},
    'GrpcServerInsecureConnection': {   'categories': ['security'],
                                        'description': 'Found an insecure gRPC '
                                                       'server without '
                                                       "'grpc.Creds()' or "
                                                       'options with '
                                                       'credentials. This '
                                                       'allows for a '
                                                       'connection without '
                                                       'encryption to this '
                                                       'server. A malicious '
                                                       'attacker could tamper '
                                                       'with the gRPC message, '
                                                       'which could compromise '
                                                       'the machine. Include '
                                                       'credentials derived '
                                                       'from an SSL '
                                                       'certificate in order '
                                                       'to create a secure '
                                                       'gRPC connection. You '
                                                       'can create credentials '
                                                       'using '
                                                       '\'credentials.NewServerTLSFromFile("cert.pem", '
                                                       '"cert.key")\'.',
                                        'display_name': 'GrpcServerInsecureConnection',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'grpc server insecure '
                                                 'connection'},
    'HandlebarsNoescape': {   'categories': ['security'],
                              'description': 'Disabling Escaping in Handlebars '
                                             'is not a secure behaviour. This '
                                             'can introduce XSS '
                                             'vulnerabilties.',
                              'display_name': 'HandlebarsNoescape',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'handlebars noescape'},
    'HandlebarsSafestring': {   'categories': ['security'],
                                'description': 'Handlebars SafeString will not '
                                               'escape the data passed through '
                                               'it. Untrusted user input '
                                               'passing through SafeString can '
                                               'cause XSS.',
                                'display_name': 'HandlebarsSafestring',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'handlebars safestring'},
    'HandlerAssignmentFromMultipleSources': {   'categories': ['security'],
                                                'description': 'Variable $VAR '
                                                               'is assigned '
                                                               'from two '
                                                               'different '
                                                               "sources: '$X' "
                                                               "and '$Y'. Make "
                                                               'sure this is '
                                                               'intended, as '
                                                               'this could '
                                                               'cause logic '
                                                               'bugs if they '
                                                               'are treated as '
                                                               'they are the '
                                                               'same object.',
                                                'display_name': 'HandlerAssignmentFromMultipleSources',
                                                'file': '%(issue.file)s',
                                                'line': '%(issue.line)s',
                                                'severity': '1',
                                                'title': 'handler assignment '
                                                         'from multiple '
                                                         'sources'},
    'HandlerAttributeReadFromMultipleSources': {   'categories': ['security'],
                                                   'description': 'Attribute '
                                                                  '$ATT is '
                                                                  'read from '
                                                                  'two '
                                                                  'different '
                                                                  'sources: '
                                                                  "'$X.$ATT' "
                                                                  'and '
                                                                  "'$Y.$ATT'. "
                                                                  'Make sure '
                                                                  'this is '
                                                                  'intended, '
                                                                  'as this '
                                                                  'could cause '
                                                                  'logic bugs '
                                                                  'if they are '
                                                                  'treated as '
                                                                  'if they are '
                                                                  'the same '
                                                                  'object.',
                                                   'display_name': 'HandlerAttributeReadFromMultipleSources',
                                                   'file': '%(issue.file)s',
                                                   'line': '%(issue.line)s',
                                                   'severity': '1',
                                                   'title': 'handler attribute '
                                                            'read from '
                                                            'multiple sources'},
    'HandlerAttributeReadFromMultipleSourcesDict': {   'categories': [   'security'],
                                                       'description': 'Attribute '
                                                                      '$ATT is '
                                                                      'read '
                                                                      'from '
                                                                      'two '
                                                                      'different '
                                                                      'sources: '
                                                                      "'$X[$KEY]' "
                                                                      'and '
                                                                      "'$Y.$ATT'. "
                                                                      'Make '
                                                                      'sure '
                                                                      'this is '
                                                                      'intended, '
                                                                      'as this '
                                                                      'could '
                                                                      'cause '
                                                                      'logic '
                                                                      'bugs if '
                                                                      'they '
                                                                      'are '
                                                                      'treated '
                                                                      'as if '
                                                                      'they '
                                                                      'are the '
                                                                      'same '
                                                                      'object.',
                                                       'display_name': 'HandlerAttributeReadFromMultipleSourcesDict',
                                                       'file': '%(issue.file)s',
                                                       'line': '%(issue.line)s',
                                                       'severity': '1',
                                                       'title': 'handler '
                                                                'attribute '
                                                                'read from '
                                                                'multiple '
                                                                'sources dict'},
    'HardcodedConditional': {   'categories': ['security'],
                                'description': 'useless if statement, always '
                                               'the same behavior',
                                'display_name': 'HardcodedConditional',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'hardcoded conditional'},
    'HardcodedEqTrueOrFalse': {   'categories': ['security'],
                                  'description': 'useless if statement, always '
                                                 'the same behavior',
                                  'display_name': 'HardcodedEqTrueOrFalse',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'hardcoded eq true or false'},
    'HardcodedHttpAuthInController': {   'categories': ['security'],
                                         'description': 'Detected hardcoded '
                                                        'password used in '
                                                        'basic authentication '
                                                        'in a controller\n'
                                                        'class. Including this '
                                                        'password in version '
                                                        'control could expose '
                                                        'this\n'
                                                        'credential. Consider '
                                                        'refactoring to use '
                                                        'environment variables '
                                                        'or\n'
                                                        'configuration files.',
                                         'display_name': 'HardcodedHttpAuthInController',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'hardcoded http auth in '
                                                  'controller'},
    'HardcodedJwtKey': {   'categories': ['security'],
                           'description': 'JWT token is hardcoded',
                           'display_name': 'HardcodedJwtKey',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'hardcoded jwt key'},
    'HardcodedJwtSecret': {   'categories': ['security'],
                              'description': 'Hardcoded JWT secret was found. '
                                             'Store it properly in an '
                                             'environment variable.',
                              'display_name': 'HardcodedJwtSecret',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'hardcoded jwt secret'},
    'HardcodedPassportSecret': {   'categories': ['security'],
                                   'description': 'Hardcoded plain text secret '
                                                  'used for Passport Strategy. '
                                                  'Store it properly in an '
                                                  'environment variable.',
                                   'display_name': 'HardcodedPassportSecret',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'hardcoded passport secret'},
    'HardcodedPasswordDefaultArgument': {   'categories': ['security'],
                                            'description': 'Hardcoded password '
                                                           'is used as a '
                                                           'default argument '
                                                           "to '$FUNC'. This "
                                                           'could be dangerous '
                                                           'if\n'
                                                           'a real password is '
                                                           'not supplied.',
                                            'display_name': 'HardcodedPasswordDefaultArgument',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'hardcoded password '
                                                     'default argument'},
    'HardcodedTmpPath': {   'categories': ['security'],
                            'description': 'Detected hardcoded temp directory. '
                                           'Consider using '
                                           "'tempfile.TemporaryFile' instead.",
                            'display_name': 'HardcodedTmpPath',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'hardcoded tmp path'},
    'HardcodedToken': {   'categories': ['security'],
                          'description': 'Hardcoded AWS access token detected. '
                                         'Use environment variables\n'
                                         'to access tokens (e.g., '
                                         'os.environ.get(...)) or use non '
                                         'version-controlled\n'
                                         'configuration files.',
                          'display_name': 'HardcodedToken',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'hardcoded token'},
    'HeaderInjection': {   'categories': ['security'],
                           'description': 'The $$VARIABLE path parameter is '
                                          'added as a header in the response. '
                                          'This could allow an attacker to '
                                          'inject a newline and add a new '
                                          'header into the response. This is '
                                          'called HTTP response splitting. To '
                                          'fix, do not allow whitespace in the '
                                          "path parameter: '[^\\s]+'.\n"
                                          '{"include": ["*.conf", "*.vhost", '
                                          '"sites-available/*", '
                                          '"sites-enabled/*"]}',
                           'display_name': 'HeaderInjection',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'nginx: header injection'},
    'HeaderRedefinition': {   'categories': ['security'],
                              'description': "The 'add_header' directive is "
                                             "called in a 'location' block "
                                             'after headers have been set at '
                                             'the server block. Calling '
                                             "'add_header' in the location "
                                             'block will actually overwrite '
                                             'the headers defined in the '
                                             'server block, no matter which '
                                             'headers are set. To fix this, '
                                             'explicitly set all headers or '
                                             'set all headers in the server '
                                             'block.\n'
                                             '{"include": ["*.conf", '
                                             '"*.vhost", "sites-available/*", '
                                             '"sites-enabled/*"]}',
                              'display_name': 'HeaderRedefinition',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'nginx: header redefinition'},
    'HeaderXssGeneric': {   'categories': ['security'],
                            'description': 'X-XSS-Protection header is set to '
                                           "0. This will disable the browser's "
                                           'XSS Filter.',
                            'display_name': 'HeaderXssGeneric',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'header xss generic'},
    'HeaderXssLusca': {   'categories': ['security'],
                          'description': 'X-XSS-Protection header is set to 0. '
                                         "This will disable the browser's XSS "
                                         'Filter.',
                          'display_name': 'HeaderXssLusca',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'header xss lusca'},
    'HelmetFeatureDisabled': {   'categories': ['security'],
                                 'description': 'One or more Security Response '
                                                'header is explicitly disabled '
                                                'in Helmet.',
                                 'display_name': 'HelmetFeatureDisabled',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'helmet feature disabled'},
    'HelmetHeaderCheckCrossdomain': {   'categories': ['security'],
                                        'description': 'X-Permitted-Cross-Domain-Policies '
                                                       'header set to off. '
                                                       'More information: '
                                                       'https://helmetjs.github.io/docs/crossdomain/',
                                        'display_name': 'HelmetHeaderCheckCrossdomain',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'helmet header check '
                                                 'crossdomain'},
    'HelmetHeaderCheckCsp': {   'categories': ['security'],
                                'description': 'Content Security Policy header '
                                               'is present. More Information: '
                                               'https://helmetjs.github.io/docs/csp/',
                                'display_name': 'HelmetHeaderCheckCsp',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'helmet header check csp'},
    'HelmetHeaderCheckExpectCt': {   'categories': ['security'],
                                     'description': 'Expect-CT header is '
                                                    'present. More '
                                                    'information: '
                                                    'https://helmetjs.github.io/docs/expect-ct/',
                                     'display_name': 'HelmetHeaderCheckExpectCt',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'helmet header check expect ct'},
    'HelmetHeaderDnsPrefetch': {   'categories': ['security'],
                                   'description': 'X-DNS-Prefetch-Control '
                                                  'header is present and DNS '
                                                  'Prefetch Control is '
                                                  'enabled. More information: '
                                                  'https://helmetjs.github.io/docs/dns-prefetch-control/',
                                   'display_name': 'HelmetHeaderDnsPrefetch',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'helmet header dns prefetch'},
    'HelmetHeaderFeaturePolicy': {   'categories': ['security'],
                                     'description': 'Feature-Policy header is '
                                                    'present. More '
                                                    'information: '
                                                    'https://helmetjs.github.io/docs/feature-policy/',
                                     'display_name': 'HelmetHeaderFeaturePolicy',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'helmet header feature policy'},
    'HelmetHeaderFrameGuard': {   'categories': ['security'],
                                  'description': 'X-Frame-Options header is '
                                                 'present. More information: '
                                                 'https://helmetjs.github.io/docs/frameguard/',
                                  'display_name': 'HelmetHeaderFrameGuard',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'helmet header frame guard'},
    'HelmetHeaderHsts': {   'categories': ['security'],
                            'description': 'HSTS header is present. More '
                                           'information: '
                                           'https://helmetjs.github.io/docs/hsts/',
                            'display_name': 'HelmetHeaderHsts',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'helmet header hsts'},
    'HelmetHeaderIenoopen': {   'categories': ['security'],
                                'description': 'X-Download-Options header is '
                                               'present. More information: '
                                               'https://helmetjs.github.io/docs/ienoopen/',
                                'display_name': 'HelmetHeaderIenoopen',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'helmet header ienoopen'},
    'HelmetHeaderNosniff': {   'categories': ['security'],
                               'description': 'Content-Type-Options header is '
                                              'present. More information: '
                                              'https://helmetjs.github.io/docs/dont-sniff-mimetype/',
                               'display_name': 'HelmetHeaderNosniff',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'helmet header nosniff'},
    'HelmetHeaderReferrerPolicy': {   'categories': ['security'],
                                      'description': 'Referrer-Policy header '
                                                     'is present. More '
                                                     'information: '
                                                     'https://helmetjs.github.io/docs/referrer-policy/',
                                      'display_name': 'HelmetHeaderReferrerPolicy',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'helmet header referrer policy'},
    'HelmetHeaderXPoweredBy': {   'categories': ['security'],
                                  'description': 'Default X-Powered-By is '
                                                 'removed or modified. More '
                                                 'information: '
                                                 'https://helmetjs.github.io/docs/hide-powered-by/',
                                  'display_name': 'HelmetHeaderXPoweredBy',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'helmet header x powered by'},
    'HelmetHeaderXssFilter': {   'categories': ['security'],
                                 'description': 'X-XSS-Protection header is '
                                                'present. More information: '
                                                'https://helmetjs.github.io/docs/xss-filter/',
                                 'display_name': 'HelmetHeaderXssFilter',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'helmet header xss filter'},
    'HibernateSqli': {   'categories': ['security'],
                         'description': 'Detected a formatted string in a SQL '
                                        'statement. This could lead to SQL\n'
                                        'injection if variables in the SQL '
                                        'statement are not properly '
                                        'sanitized.\n'
                                        'Use a prepared statements '
                                        '(java.sql.PreparedStatement) instead. '
                                        'You\n'
                                        'can obtain a PreparedStatement using '
                                        "'connection.prepareStatement'.",
                         'display_name': 'HibernateSqli',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'hibernate sqli'},
    'HiddenGoroutine': {   'categories': ['security'],
                           'description': 'Detected a hidden goroutine. '
                                          'Function invocations are expected '
                                          'to synchronous,\n'
                                          'and this function will execute '
                                          'asynchronously because all it does '
                                          'is call a\n'
                                          'goroutine. Instead, remove the '
                                          'internal goroutine and call the '
                                          "function using 'go'.",
                           'display_name': 'HiddenGoroutine',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'hidden goroutine'},
    'HostHeaderInjection': {   'categories': ['security'],
                               'description': 'Using untrusted Host header for '
                                              'generating dynamic URLs can '
                                              'result in web cache and or '
                                              'password reset poisoning.',
                               'display_name': 'HostHeaderInjection',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'host header injection'},
    'HostipcPod': {   'categories': ['security'],
                      'description': 'Pod is sharing the host IPC namespace. '
                                     'This allows container processes\n'
                                     'to communicate with processes on the '
                                     'host which reduces isolation and\n'
                                     'bypasses container protection models. '
                                     "Remove the 'hostIPC' key to disable\n"
                                     'this functionality.',
                      'display_name': 'HostipcPod',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'kubernetes: hostipc pod'},
    'HostnetworkPod': {   'categories': ['security'],
                          'description': 'Pod may use the node network '
                                         'namespace. This gives the pod access '
                                         'to the\n'
                                         'loopback device, services listening '
                                         'on localhost, and could be used to\n'
                                         'snoop on network activity of other '
                                         'pods on the same node. Remove the\n'
                                         "'hostNetwork' key to disable this "
                                         'functionality.',
                          'display_name': 'HostnetworkPod',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'kubernetes: hostnetwork pod'},
    'HostpidPod': {   'categories': ['security'],
                      'description': 'Pod is sharing the host process ID '
                                     'namespace. When paired with ptrace\n'
                                     'this can be used to escalate privileges '
                                     'outside of the container. Remove\n'
                                     "the 'hostPID' key to disable this "
                                     'functionality.',
                      'display_name': 'HostpidPod',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'kubernetes: hostpid pod'},
    'HtmlMagicMethod': {   'categories': ['security'],
                           'description': 'The `__html__` method indicates to '
                                          'the Django template engine that '
                                          'the\n'
                                          "value is 'safe' for rendering. This "
                                          'means that normal HTML escaping '
                                          'will\n'
                                          'not be applied to the return value. '
                                          'This exposes your application to\n'
                                          'cross-site scripting (XSS) '
                                          'vulnerabilities. If you need to '
                                          'render raw HTML,\n'
                                          'consider instead using '
                                          '`mark_safe()` which more clearly '
                                          'marks the intent\n'
                                          'to render raw HTML than a class '
                                          'with a magic method.',
                           'display_name': 'HtmlMagicMethod',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'html magic method'},
    'HtmlSafe': {   'categories': ['security'],
                    'description': '`html_safe()` add the `__html__` magic '
                                   'method to the provided class.\n'
                                   'The `__html__` method indicates to the '
                                   'Django template engine that the\n'
                                   "value is 'safe' for rendering. This means "
                                   'that normal HTML escaping will\n'
                                   'not be applied to the return value. This '
                                   'exposes your application to\n'
                                   'cross-site scripting (XSS) '
                                   'vulnerabilities. If you need to render raw '
                                   'HTML,\n'
                                   'consider instead using `mark_safe()` which '
                                   'more clearly marks the intent\n'
                                   'to render raw HTML than a class with a '
                                   'magic method.',
                    'display_name': 'HtmlSafe',
                    'file': '%(issue.file)s',
                    'line': '%(issue.line)s',
                    'severity': '1',
                    'title': 'html safe'},
    'HttpNotHttpsConnection': {   'categories': ['security'],
                                  'description': 'Detected HTTPConnectionPool. '
                                                 'This will transmit data in '
                                                 'cleartext.\n'
                                                 'It is recommended to use '
                                                 'HTTPSConnectionPool instead '
                                                 'for to encrypt\n'
                                                 'communications.',
                                  'display_name': 'HttpNotHttpsConnection',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'http not https connection'},
    'HttpResponseSplitting': {   'categories': ['security'],
                                 'description': 'Older Java application '
                                                'servers are vulnreable to '
                                                'HTTP response splitting, '
                                                'which may occur if an HTTP\n'
                                                'request can be injected with '
                                                'CRLF characters. This finding '
                                                'is reported for completeness; '
                                                'it is recommended\n'
                                                'to ensure your environment is '
                                                'not affected by testing this '
                                                'yourself.',
                                 'display_name': 'HttpResponseSplitting',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'http response splitting'},
    'HttpsconnectionDetected': {   'categories': ['security'],
                                   'description': 'The HTTPSConnection API has '
                                                  'changed frequently with '
                                                  'minor releases of Python.\n'
                                                  'Ensure you are using the '
                                                  'API for your version of '
                                                  'Python securely.\n'
                                                  'For example, Python 3 '
                                                  'versions prior to 3.4.3 '
                                                  'will not verify SSL '
                                                  'certificates by default.\n'
                                                  'See '
                                                  'https://docs.python.org/3/library/http.client.html#http.client.HTTPSConnection\n'
                                                  'for more information.',
                                   'display_name': 'HttpsconnectionDetected',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'httpsconnection detected'},
    'HttpservletPathTraversal': {   'categories': ['security'],
                                    'description': 'Detected a potential path '
                                                   'traversal. A malicious '
                                                   'actor\n'
                                                   'could control the location '
                                                   'of this file, to include '
                                                   'going backwards\n'
                                                   'in the directory with '
                                                   "'../'. To address this, "
                                                   'ensure that '
                                                   'user-controlled\n'
                                                   'variables in file paths '
                                                   'are sanitized. You may '
                                                   'aslso consider using a '
                                                   'utility\n'
                                                   'method such as '
                                                   'org.apache.commons.io.FilenameUtils.getName(...) '
                                                   'to only\n'
                                                   'retrieve the file name '
                                                   'from the path.',
                                    'display_name': 'HttpservletPathTraversal',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'httpservlet path traversal'},
    'IdenticalIsComparison': {   'categories': ['security'],
                                 'description': 'Found identical comparison '
                                                'using is. Ensure this is what '
                                                'you intended.',
                                 'display_name': 'IdenticalIsComparison',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'identical is comparison'},
    'ImportTextTemplate': {   'categories': ['security'],
                              'description': "'text/template' does not escape "
                                             'HTML content. If you need\n'
                                             'to escape HTML content, use '
                                             "'html/template' instead.",
                              'display_name': 'ImportTextTemplate',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'import text template'},
    'IncorrectDefaultPermission': {   'categories': ['security'],
                                      'description': 'Expect permissions to be '
                                                     '`0600` or less for '
                                                     'os.Chmod, os.Mkdir, '
                                                     'os.OpenFile, '
                                                     'os.MkdirAll, and '
                                                     'ioutil.WriteFile',
                                      'display_name': 'IncorrectDefaultPermission',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'incorrect default permission'},
    'IncorrectUseAtoFn': {   'categories': ['security'],
                             'description': "Avoid the 'ato*()' family of "
                                            'functions. Their use can lead to '
                                            'undefined\n'
                                            'behavior, integer overflows, and '
                                            'lack of appropriate error '
                                            'handling. Instead\n'
                                            "prefer the 'strtol*()' family of "
                                            'functions.',
                             'display_name': 'IncorrectUseAtoFn',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'incorrect use ato fn'},
    'IncorrectUseSscanfFn': {   'categories': ['security'],
                                'description': "Avoid 'sscanf()' for number "
                                               'conversions. Its use can lead '
                                               'to undefined\n'
                                               'behavior, slow processing, and '
                                               'integer overflows. Instead '
                                               'prefer the\n'
                                               "'strto*()' family of "
                                               'functions.',
                                'display_name': 'IncorrectUseSscanfFn',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'incorrect use sscanf fn'},
    'InfoLeakOnNonFormatedString': {   'categories': ['security'],
                                       'description': 'Use %s, %d, %c... to '
                                                      'format your variables, '
                                                      'otherwise this could '
                                                      'leak information.',
                                       'display_name': 'InfoLeakOnNonFormatedString',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'info leak on non formated '
                                                'string'},
    'InsecureCipherAlgorithmBlowfish': {   'categories': ['security'],
                                           'description': 'Detected Blowfish '
                                                          'cipher algorithm '
                                                          'which is considered '
                                                          'insecure. The '
                                                          'algorithm has many\n'
                                                          'known '
                                                          'vulnerabilities. '
                                                          'Use AES instead.',
                                           'display_name': 'InsecureCipherAlgorithmBlowfish',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'insecure cipher algorithm '
                                                    'blowfish'},
    'InsecureCipherAlgorithmDes': {   'categories': ['security'],
                                      'description': 'Detected DES cipher '
                                                     'algorithm which is '
                                                     'considered insecure. The '
                                                     'algorithm is\n'
                                                     'considered weak and has '
                                                     'been deprecated. Use AES '
                                                     'instead.',
                                      'display_name': 'InsecureCipherAlgorithmDes',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'insecure cipher algorithm des'},
    'InsecureCipherAlgorithmIdea': {   'categories': ['security'],
                                       'description': 'Detected IDEA cipher '
                                                      'algorithm which is '
                                                      'considered insecure. '
                                                      'The algorithm is\n'
                                                      'considered weak and has '
                                                      'been deprecated. Use '
                                                      'AES instead.',
                                       'display_name': 'InsecureCipherAlgorithmIdea',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'insecure cipher algorithm '
                                                'idea'},
    'InsecureCipherAlgorithmRc2': {   'categories': ['security'],
                                      'description': 'Detected RC2 cipher '
                                                     'algorithm which is '
                                                     'considered insecure. The '
                                                     'algorithm has known '
                                                     'vulnerabilities and is '
                                                     'difficult to use '
                                                     'securely. Use AES '
                                                     'instead.',
                                      'display_name': 'InsecureCipherAlgorithmRc2',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'insecure cipher algorithm rc2'},
    'InsecureCipherAlgorithmRc4': {   'categories': ['security'],
                                      'description': 'Detected RC4 cipher '
                                                     'algorithm which is '
                                                     'considered insecure. The '
                                                     'algorithm has many\n'
                                                     'known vulnerabilities. '
                                                     'Use AES instead.',
                                      'display_name': 'InsecureCipherAlgorithmRc4',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'insecure cipher algorithm rc4'},
    'InsecureCipherAlgorithmXor': {   'categories': ['security'],
                                      'description': 'Detected XOR cipher '
                                                     'algorithm which is '
                                                     'considered insecure. '
                                                     'This algorithm\n'
                                                     'is not cryptographically '
                                                     'secure and can be '
                                                     'reversed easily. Use AES '
                                                     'instead.',
                                      'display_name': 'InsecureCipherAlgorithmXor',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'insecure cipher algorithm xor'},
    'InsecureCipherModeEcb': {   'categories': ['security'],
                                 'description': 'Detected ECB cipher mode '
                                                'which is considered insecure. '
                                                'The algorithm can\n'
                                                'potentially leak information '
                                                'about the plaintext. Use CBC '
                                                'mode instead.',
                                 'display_name': 'InsecureCipherModeEcb',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'insecure cipher mode ecb'},
    'InsecureCreatenodesfrommarkup': {   'categories': ['security'],
                                         'description': 'User controlled data '
                                                        'in a '
                                                        '`createNodesFromMarkup` '
                                                        'is an anti-pattern '
                                                        'that can lead to XSS '
                                                        'vulnerabilities',
                                         'display_name': 'InsecureCreatenodesfrommarkup',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'insecure '
                                                  'createnodesfrommarkup'},
    'InsecureDeserialization': {   'categories': ['security'],
                                   'description': 'Detected the use of an '
                                                  'insecure deserizliation '
                                                  'library in a Flask route. '
                                                  'These libraries\n'
                                                  'are prone to code execution '
                                                  'vulnerabilities. Ensure '
                                                  'user data does not enter '
                                                  'this function.\n'
                                                  'To fix this, try to avoid '
                                                  'serializing whole objects. '
                                                  'Consider instead using a '
                                                  'serializer\n'
                                                  'such as JSON.',
                                   'display_name': 'InsecureDeserialization',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'insecure deserialization'},
    'InsecureDocumentMethod': {   'categories': ['security'],
                                  'description': 'User controlled data in '
                                                 'methods like `innerHTML`, '
                                                 '`outerHTML` or '
                                                 '`document.write` is an '
                                                 'anti-pattern that can lead '
                                                 'to XSS vulnerabilities',
                                  'display_name': 'InsecureDocumentMethod',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'insecure document method'},
    'InsecureFilePermissions': {   'categories': ['security'],
                                   'description': 'Insecure file permissions '
                                                  'detected.',
                                   'display_name': 'InsecureFilePermissions',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'insecure file permissions'},
    'InsecureHashAlgorithmMd2': {   'categories': ['security'],
                                    'description': 'Detected MD2 hash '
                                                   'algorithm which is '
                                                   'considered insecure. This '
                                                   'algorithm\n'
                                                   'has many known '
                                                   'vulnerabilities and has '
                                                   'been deprecated. Use '
                                                   'SHA256 or SHA3 instead.',
                                    'display_name': 'InsecureHashAlgorithmMd2',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'insecure hash algorithm md2'},
    'InsecureHashAlgorithmMd4': {   'categories': ['security'],
                                    'description': 'Detected MD4 hash '
                                                   'algorithm which is '
                                                   'considered insecure. This '
                                                   'algorithm\n'
                                                   'has many known '
                                                   'vulnerabilities and has '
                                                   'been deprecated. Use '
                                                   'SHA256 or SHA3 instead.',
                                    'display_name': 'InsecureHashAlgorithmMd4',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'insecure hash algorithm md4'},
    'InsecureHashAlgorithmMd5': {   'categories': ['security'],
                                    'description': 'Detected MD5 hash '
                                                   'algorithm which is '
                                                   'considered insecure. MD5 '
                                                   'is not\n'
                                                   'collision resistant and is '
                                                   'therefore not suitable as '
                                                   'a cryptographic\n'
                                                   'signature. Use SHA256 or '
                                                   'SHA3 instead.',
                                    'display_name': 'InsecureHashAlgorithmMd5',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'insecure hash algorithm md5'},
    'InsecureHashAlgorithmSha1': {   'categories': ['security'],
                                     'description': 'Detected SHA1 hash '
                                                    'algorithm which is '
                                                    'considered insecure. SHA1 '
                                                    'is not\n'
                                                    'collision resistant and '
                                                    'is therefore not suitable '
                                                    'as a cryptographic\n'
                                                    'signature. Use SHA256 or '
                                                    'SHA3 instead.',
                                     'display_name': 'InsecureHashAlgorithmSha1',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'insecure hash algorithm sha1'},
    'InsecureHashFunction': {   'categories': ['security'],
                                'description': 'Detected use of an insecure '
                                               'MD4 or MD5 hash function.\n'
                                               'These functions have known '
                                               'vulnerabilities and are '
                                               'considered deprecated.\n'
                                               "Consider using 'SHA256' or a "
                                               'similar function instead.',
                                'display_name': 'InsecureHashFunction',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'insecure hash function'},
    'InsecureHostnameVerifier': {   'categories': ['security'],
                                    'description': 'Insecure HostnameVerifier '
                                                   'implementation detected. '
                                                   'This will accept\n'
                                                   'any SSL certificate with '
                                                   'any hostname, which '
                                                   'creates the possibility\n'
                                                   'for man-in-the-middle '
                                                   'attacks.',
                                    'display_name': 'InsecureHostnameVerifier',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'insecure hostname verifier'},
    'InsecureInnerhtml': {   'categories': ['security'],
                             'description': 'User controlled data in a '
                                            '`$EL.innerHTML` is an '
                                            'anti-pattern that can lead to XSS '
                                            'vulnerabilities',
                             'display_name': 'InsecureInnerhtml',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'insecure innerhtml'},
    'InsecureJmsDeserialization': {   'categories': ['security'],
                                      'description': 'JMS Object messages '
                                                     'depend on Java '
                                                     'Serialization for '
                                                     'marshalling/unmarshalling '
                                                     'of the message payload '
                                                     'when '
                                                     'ObjectMessage.getObject() '
                                                     'is called.\n'
                                                     'Deserialization of '
                                                     'untrusted data can lead '
                                                     'to security flaws; a '
                                                     'remote attacker could '
                                                     'via a crafted JMS '
                                                     'ObjectMessage to '
                                                     'execute\n'
                                                     'arbitrary code with the '
                                                     'permissions of the '
                                                     'application '
                                                     'listening/consuming JMS '
                                                     'Messages.\n'
                                                     'In this case, the JMS '
                                                     'MessageListener consume '
                                                     'an ObjectMessage type '
                                                     'recieved inside\n'
                                                     'the onMessage method, '
                                                     'which may lead to '
                                                     'arbitrary code execution '
                                                     'when calling the '
                                                     '$Y.getObject method.',
                                      'display_name': 'InsecureJmsDeserialization',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'insecure jms deserialization'},
    'InsecureModuleUsed': {   'categories': ['security'],
                              'description': 'Detected use of an insecure '
                                             'cryptographic hashing method. '
                                             'This method is known to be '
                                             'broken and easily compromised. '
                                             'Use SHA256 or SHA3 instead.',
                              'display_name': 'InsecureModuleUsed',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'insecure module used'},
    'InsecureOpenerdirectorOpen': {   'categories': ['security'],
                                      'description': 'Detected an unsecured '
                                                     'transmission channel. '
                                                     "'OpenerDirector.open(...)' "
                                                     'is\n'
                                                     'being used with '
                                                     "'http://'. Use "
                                                     "'https://' instead to "
                                                     'secure the channel.',
                                      'display_name': 'InsecureOpenerdirectorOpen',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'insecure openerdirector open'},
    'InsecureOpenerdirectorOpenFtp': {   'categories': ['security'],
                                         'description': 'Detected an unsecured '
                                                        'transmission channel. '
                                                        "'OpenerDirector.open(...)' "
                                                        'is\n'
                                                        'being used with '
                                                        "'ftp://'. Information "
                                                        'sent over this '
                                                        'connection will be\n'
                                                        'unencrypted. Consider '
                                                        'using SFTP instead. '
                                                        'urllib does not '
                                                        'support SFTP,\n'
                                                        'so consider a library '
                                                        'which supports SFTP.',
                                         'display_name': 'InsecureOpenerdirectorOpenFtp',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'insecure openerdirector '
                                                  'open ftp'},
    'InsecureRedirect': {   'categories': ['security'],
                            'description': 'Detected an insecure redirect in '
                                           'this nginx configuration.\n'
                                           'If no scheme is specified, nginx '
                                           'will forward the request with the\n'
                                           'incoming scheme. This could result '
                                           'in unencrypted communications.\n'
                                           "To fix this, include the 'https' "
                                           'scheme.\n'
                                           '\n'
                                           '{"include": ["*.conf", "*.vhost", '
                                           '"sites-available/*", '
                                           '"sites-enabled/*"]}',
                            'display_name': 'InsecureRedirect',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'nginx: insecure redirect'},
    'InsecureRequestObject': {   'categories': ['security'],
                                 'description': 'Detected a '
                                                "'urllib.request.Request()' "
                                                'object using an insecure '
                                                'transport\n'
                                                "protocol, 'http://'. This "
                                                'connection will not be '
                                                'encrypted. Use\n'
                                                "'https://' instead.",
                                 'display_name': 'InsecureRequestObject',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'insecure request object'},
    'InsecureRequestObjectFtp': {   'categories': ['security'],
                                    'description': 'Detected a '
                                                   "'urllib.request.Request()' "
                                                   'object using an insecure '
                                                   'transport\n'
                                                   "protocol, 'ftp://'. This "
                                                   'connection will not be '
                                                   'encrypted. Consider using\n'
                                                   'SFTP instead. urllib does '
                                                   'not support SFTP natively, '
                                                   'so consider using\n'
                                                   'a library which supports '
                                                   'SFTP.',
                                    'display_name': 'InsecureRequestObjectFtp',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'insecure request object ftp'},
    'InsecureResteasyDeserialization': {   'categories': ['security'],
                                           'description': 'When a Restful '
                                                          'webservice endpoint '
                                                          'is configured to '
                                                          'use wildcard '
                                                          'mediaType {*/*} as '
                                                          'a value for the '
                                                          '@Consumes '
                                                          'annotation, an '
                                                          'attacker could '
                                                          'abuse the '
                                                          'SerializableProvider '
                                                          'by sending a HTTP '
                                                          'Request with a '
                                                          'Content-Type of '
                                                          'application/x-java-serialized-object. '
                                                          'The body of that '
                                                          'request would be '
                                                          'processed by the '
                                                          'SerializationProvider '
                                                          'and could contain a '
                                                          'malicious payload, '
                                                          'which may lead to '
                                                          'arbitrary code '
                                                          'execution when '
                                                          'calling the '
                                                          '$Y.getObject '
                                                          'method.',
                                           'display_name': 'InsecureResteasyDeserialization',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'insecure resteasy '
                                                    'deserialization'},
    'InsecureSmtpConnection': {   'categories': ['security'],
                                  'description': 'Insecure SMTP connection '
                                                 'detected. This connection '
                                                 'will trust any SSL '
                                                 'certificate.\n'
                                                 'Enable certificate '
                                                 'verification by setting '
                                                 "'email.setSSLCheckServerIdentity(true)'.",
                                  'display_name': 'InsecureSmtpConnection',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'insecure smtp connection'},
    'InsecureSslVersion': {   'categories': ['security'],
                              'description': 'Detected use of an insecure SSL '
                                             'version. Secure SSL versions are '
                                             'TLSv1.2 and TLS1.3; older '
                                             'versions are known to be broken '
                                             'and are susceptible to attacks. '
                                             'Prefer use of TLSv1.2 or later.\n'
                                             '{"include": ["*.conf", '
                                             '"*.vhost", "sites-available/*", '
                                             '"sites-enabled/*"]}',
                              'display_name': 'InsecureSslVersion',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'nginx: insecure ssl version'},
    'InsecureTrustManager': {   'categories': ['security'],
                                'description': 'Detected empty trust manager '
                                               'implementations. This is '
                                               'dangerous because it accepts '
                                               'any\n'
                                               'certificate, enabling '
                                               'man-in-the-middle attacks. '
                                               'Consider using a KeyStore\n'
                                               'and TrustManagerFactory '
                                               'isntead.\n'
                                               'See '
                                               'https://stackoverflow.com/questions/2642777/trusting-all-certificates-using-httpclient-over-https\n'
                                               'for more information.',
                                'display_name': 'InsecureTrustManager',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'insecure trust manager'},
    'InsecureUrlopen': {   'categories': ['security'],
                           'description': "Detected 'urllib.urlopen()' using "
                                          "'http://'. This request will not "
                                          'be\n'
                                          "encrypted. Use 'https://' instead.",
                           'display_name': 'InsecureUrlopen',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'insecure urlopen'},
    'InsecureUrlopenFtp': {   'categories': ['security'],
                              'description': "Detected 'urllib.urlopen()' "
                                             "using 'ftp://'. This request "
                                             'will not be\n'
                                             'encrypted. Consider using SFTP '
                                             'instead. urllib does not support '
                                             'SFTP,\n'
                                             'so consider switching to a '
                                             'library which supports SFTP.',
                              'display_name': 'InsecureUrlopenFtp',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'insecure urlopen ftp'},
    'InsecureUrlopenerOpen': {   'categories': ['security'],
                                 'description': 'Detected an unsecured '
                                                'transmission channel. '
                                                "'URLopener.open(...)' is\n"
                                                "being used with 'http://'. "
                                                "Use 'https://' instead to "
                                                'secure the channel.',
                                 'display_name': 'InsecureUrlopenerOpen',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'insecure urlopener open'},
    'InsecureUrlopenerOpenFtp': {   'categories': ['security'],
                                    'description': 'Detected an insecure '
                                                   'transmission channel. '
                                                   "'URLopener.open(...)' is\n"
                                                   "being used with 'ftp://'. "
                                                   'Use SFTP instead. urllib '
                                                   'does not support\n'
                                                   'SFTP, so consider using a '
                                                   'library which supports '
                                                   'SFTP.',
                                    'display_name': 'InsecureUrlopenerOpenFtp',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'insecure urlopener open ftp'},
    'InsecureUrlopenerRetrieve': {   'categories': ['security'],
                                     'description': 'Detected an unsecured '
                                                    'transmission channel. '
                                                    "'URLopener.retrieve(...)' "
                                                    'is\n'
                                                    'being used with '
                                                    "'http://'. Use 'https://' "
                                                    'instead to secure the '
                                                    'channel.',
                                     'display_name': 'InsecureUrlopenerRetrieve',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'insecure urlopener retrieve'},
    'InsecureUrlopenerRetrieveFtp': {   'categories': ['security'],
                                        'description': 'Detected an insecure '
                                                       'transmission channel. '
                                                       "'URLopener.retrieve(...)' "
                                                       'is\n'
                                                       'being used with '
                                                       "'ftp://'. Use SFTP "
                                                       'instead. urllib does '
                                                       'not support\n'
                                                       'SFTP, so consider '
                                                       'using a library which '
                                                       'supports SFTP.',
                                        'display_name': 'InsecureUrlopenerRetrieveFtp',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'insecure urlopener retrieve '
                                                 'ftp'},
    'InsecureUrlretrieve': {   'categories': ['security'],
                               'description': "Detected 'urllib.urlretrieve()' "
                                              "using 'http://'. This request "
                                              'will not be\n'
                                              "encrypted. Use 'https://' "
                                              'instead.',
                               'display_name': 'InsecureUrlretrieve',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'insecure urlretrieve'},
    'InsecureUrlretrieveFtp': {   'categories': ['security'],
                                  'description': 'Detected '
                                                 "'urllib.urlretrieve()' using "
                                                 "'ftp://'. This request will "
                                                 'not be\n'
                                                 'encrypted. Use SFTP instead. '
                                                 'urllib does not support '
                                                 'SFTP, so consider\n'
                                                 'switching to a library which '
                                                 'supports SFTP.',
                                  'display_name': 'InsecureUrlretrieveFtp',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'insecure urlretrieve ftp'},
    'InsecureUseGetsFn': {   'categories': ['security'],
                             'description': "Avoid 'gets()'. This function "
                                            'does not consider buffer '
                                            'boundaries and can lead\n'
                                            'to buffer overflows. Use '
                                            "'fgets()' or 'gets_s()' instead.",
                             'display_name': 'InsecureUseGetsFn',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'insecure use gets fn'},
    'InsecureUsePrintfFn': {   'categories': ['security'],
                               'description': 'Avoid using user-controlled '
                                              'format strings passed into '
                                              "'sprintf', 'printf' and "
                                              "'vsprintf'.\n"
                                              'These functions put you at risk '
                                              'of buffer overflow '
                                              'vulnerabilities through the use '
                                              'of format string exploits.\n'
                                              "Instead, use 'snprintf' and "
                                              "'vsnprintf'.",
                               'display_name': 'InsecureUsePrintfFn',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'insecure use printf fn'},
    'InsecureUseScanfFn': {   'categories': ['security'],
                              'description': "Avoid using 'scanf()'. This "
                                             'function, when used improperly, '
                                             'does not consider\n'
                                             'buffer boundaries and can lead '
                                             'to buffer overflows. Use '
                                             "'fgets()' instead\n"
                                             'for reading input.',
                              'display_name': 'InsecureUseScanfFn',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'insecure use scanf fn'},
    'InsecureUseStrcatFn': {   'categories': ['security'],
                               'description': 'Finding triggers whenever there '
                                              'is a strcat or strncat used.\n'
                                              'This is an issue because strcat '
                                              'or strncat can lead to buffer '
                                              'overflow vulns.\n'
                                              'Fix this by using strcat_s '
                                              'instead.',
                               'display_name': 'InsecureUseStrcatFn',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'insecure use strcat fn'},
    'InsecureUseStringCopyFn': {   'categories': ['security'],
                                   'description': 'Finding triggers whenever '
                                                  'there is a strcpy or '
                                                  'strncpy used.\n'
                                                  'This is an issue because '
                                                  'strcpy or strncpy can lead '
                                                  'to buffer overflow vulns.\n'
                                                  'Fix this by using strcpy_s '
                                                  'instead.',
                                   'display_name': 'InsecureUseStringCopyFn',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'insecure use string copy fn'},
    'InsecureUseStrtokFn': {   'categories': ['security'],
                               'description': "Avoid using 'strtok()'. This "
                                              'function directly modifies the '
                                              'first argument buffer, '
                                              'permanently erasing the\n'
                                              'delimiter character. Use '
                                              "'strtok_r()' instead.",
                               'display_name': 'InsecureUseStrtokFn',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'insecure use strtok fn'},
    'InsufficientDsaKeySize': {   'categories': ['security'],
                                  'description': 'Detected an insufficient key '
                                                 'size for DSA. NIST '
                                                 'recommends\n'
                                                 'a key size of 2048 or '
                                                 'higher.',
                                  'display_name': 'InsufficientDsaKeySize',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'insufficient dsa key size'},
    'InsufficientEcKeySize': {   'categories': ['security'],
                                 'description': 'Detected an insufficient '
                                                'curve size for EC. NIST '
                                                'recommends\n'
                                                'a key size of 224 or higher. '
                                                'For example, use '
                                                "'ec.SECP256R1'.",
                                 'display_name': 'InsufficientEcKeySize',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'insufficient ec key size'},
    'InsufficientPostmessageOriginValidation': {   'categories': ['security'],
                                                   'description': 'No '
                                                                  'validation '
                                                                  'of origin '
                                                                  'is done by '
                                                                  'the '
                                                                  'addEventListener '
                                                                  'API. It may '
                                                                  'be possible '
                                                                  'to exploit '
                                                                  'this flaw '
                                                                  'to perform '
                                                                  'Cross '
                                                                  'Origin '
                                                                  'attacks '
                                                                  'such as '
                                                                  'Cross-Site '
                                                                  'Scripting(XSS).',
                                                   'display_name': 'InsufficientPostmessageOriginValidation',
                                                   'file': '%(issue.file)s',
                                                   'line': '%(issue.line)s',
                                                   'severity': '1',
                                                   'title': 'insufficient '
                                                            'postmessage '
                                                            'origin '
                                                            'validation'},
    'InsufficientRsaKeySize': {   'categories': ['security'],
                                  'description': 'Detected an insufficient key '
                                                 'size for RSA. NIST '
                                                 'recommends\n'
                                                 'a key size of 2048 or '
                                                 'higher.',
                                  'display_name': 'InsufficientRsaKeySize',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'insufficient rsa key size'},
    'IntegerOverflowInt16': {   'categories': ['security'],
                                'description': 'Potential Integer overflow '
                                               'made by strconv.Atoi result '
                                               'conversion to int16',
                                'display_name': 'IntegerOverflowInt16',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'integer overflow int16'},
    'IntegerOverflowInt32': {   'categories': ['security'],
                                'description': 'Potential Integer overflow '
                                               'made by strconv.Atoi result '
                                               'conversion to int32',
                                'display_name': 'IntegerOverflowInt32',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'integer overflow int32'},
    'InvalidBaseUrl': {   'categories': ['security'],
                          'description': "The 'baseURL' is invalid. This may "
                                         'cause links to not work if '
                                         'deployed.\n'
                                         'Include the scheme (e.g., https://).',
                          'display_name': 'InvalidBaseUrl',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'hugo: invalid base url'},
    'InvalidPort': {   'categories': ['security'],
                       'description': 'Detected an invalid port number. Valid '
                                      'ports are 0 through 65535.\n'
                                      '{"include": ["*dockerfile*", '
                                      '"*Dockerfile*"]}',
                       'display_name': 'InvalidPort',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'dockerfile: invalid port'},
    'IsNotIsNot': {   'categories': ['security'],
                      'description': "In Python 'X is not ...' is different "
                                     "from 'X is (not ...)'.\n"
                                     "In the latter the 'not' converts the "
                                     "'...' directly to boolean.",
                      'display_name': 'IsNotIsNot',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'is not is not'},
    'JavaJwtDecodeWithoutVerify': {   'categories': ['security'],
                                      'description': 'Detected the decoding of '
                                                     'a JWT token without a '
                                                     'verify step.\n'
                                                     'JWT tokens must be '
                                                     'verified before use, '
                                                     "otherwise the token's\n"
                                                     'integrity is unknown. '
                                                     'This means a malicious '
                                                     'actor could forge\n'
                                                     'a JWT token with any '
                                                     "claims. Call '.verify()' "
                                                     'before using the token.',
                                      'display_name': 'JavaJwtDecodeWithoutVerify',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'java jwt decode without '
                                               'verify'},
    'JavaJwtHardcodedSecret': {   'categories': ['security'],
                                  'description': 'Hardcoded JWT secret or '
                                                 'private key is used.\n'
                                                 'This is a Insufficiently '
                                                 'Protected Credentials '
                                                 'weakness: '
                                                 'https://cwe.mitre.org/data/definitions/522.html\n'
                                                 'Consider using an '
                                                 'appropriate security '
                                                 'mechanism to protect the '
                                                 'credentials (e.g. keeping '
                                                 'secrets in environment '
                                                 'variables)',
                                  'display_name': 'JavaJwtHardcodedSecret',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'java jwt hardcoded secret'},
    'JavaJwtNoneAlg': {   'categories': ['security'],
                          'description': "Detected use of the 'none' algorithm "
                                         'in a JWT token.\n'
                                         "The 'none' algorithm assumes the "
                                         'integrity of the token has already\n'
                                         'been verified. This would allow a '
                                         'malicious actor to forge a JWT '
                                         'token\n'
                                         'that will automatically be verified. '
                                         "Do not explicitly use the 'none'\n"
                                         'algorithm. Instead, use an algorithm '
                                         "such as 'HS256'.",
                          'display_name': 'JavaJwtNoneAlg',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'java jwt none alg'},
    'JavascriptAlert': {   'categories': ['security'],
                           'description': 'found alert() call; should this be '
                                          'in production code?',
                           'display_name': 'JavascriptAlert',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'javascript alert'},
    'JavascriptConfirm': {   'categories': ['security'],
                             'description': 'found conform() call; should this '
                                            'be in production code?',
                             'display_name': 'JavascriptConfirm',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'javascript confirm'},
    'JavascriptDebugger': {   'categories': ['security'],
                              'description': 'found debugger call; should this '
                                             'be in production code?',
                              'display_name': 'JavascriptDebugger',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'javascript debugger'},
    'JavascriptPrompt': {   'categories': ['security'],
                            'description': 'found prompt() call; should this '
                                           'be in production code?',
                            'display_name': 'JavascriptPrompt',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'javascript prompt'},
    'JaxRsPathTraversal': {   'categories': ['security'],
                              'description': 'Detected a potential path '
                                             'traversal. A malicious actor\n'
                                             'could control the location of '
                                             'this file, to include going '
                                             'backwards\n'
                                             "in the directory with '../'. To "
                                             'address this, ensure that '
                                             'user-controlled\n'
                                             'variables in file paths are '
                                             'sanitized. You may aslso '
                                             'consider using a utility\n'
                                             'method such as '
                                             'org.apache.commons.io.FilenameUtils.getName(...) '
                                             'to only\n'
                                             'retrieve the file name from the '
                                             'path.',
                              'display_name': 'JaxRsPathTraversal',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'jax rs path traversal'},
    'JdbcSqlFormattedString': {   'categories': ['security'],
                                  'description': 'Possible JDBC injection '
                                                 'detected. Use the '
                                                 'parameterized query\n'
                                                 'feature available in '
                                                 'queryForObject instead of '
                                                 'concatenating or formatting '
                                                 'strings:\n'
                                                 '\'jdbc.queryForObject("select '
                                                 '* from table where name = '
                                                 '?", Integer.class, '
                                                 "parameterName);'",
                                  'display_name': 'JdbcSqlFormattedString',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'jdbc sql formatted string'},
    'JdbcSqli': {   'categories': ['security'],
                    'description': 'Detected a formatted string in a SQL '
                                   'statement. This could lead to SQL\n'
                                   'injection if variables in the SQL '
                                   'statement are not properly sanitized.\n'
                                   'Use a prepared statements '
                                   '(java.sql.PreparedStatement) instead. You\n'
                                   'can obtain a PreparedStatement using '
                                   "'connection.prepareStatement'.",
                    'display_name': 'JdbcSqli',
                    'file': '%(issue.file)s',
                    'line': '%(issue.line)s',
                    'severity': '1',
                    'title': 'jdbc sqli'},
    'JdoSqli': {   'categories': ['security'],
                   'description': 'Detected a formatted string in a SQL '
                                  'statement. This could lead to SQL\n'
                                  'injection if variables in the SQL statement '
                                  'are not properly sanitized.\n'
                                  'Use a prepared statements '
                                  '(java.sql.PreparedStatement) instead. You\n'
                                  'can obtain a PreparedStatement using '
                                  "'connection.prepareStatement'.",
                   'display_name': 'JdoSqli',
                   'file': '%(issue.file)s',
                   'line': '%(issue.line)s',
                   'severity': '1',
                   'title': 'jdo sqli'},
    'JjwtNoneAlg': {   'categories': ['security'],
                       'description': "Detected use of the 'none' algorithm in "
                                      'a JWT token.\n'
                                      "The 'none' algorithm assumes the "
                                      'integrity of the token has already\n'
                                      'been verified. This would allow a '
                                      'malicious actor to forge a JWT token\n'
                                      'that will automatically be verified. Do '
                                      "not explicitly use the 'none'\n"
                                      'algorithm. Instead, use an algorithm '
                                      "such as 'HS256'.",
                       'display_name': 'JjwtNoneAlg',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'jjwt none alg'},
    'JoinResolvePathTraversal': {   'categories': ['security'],
                                    'description': 'Path constructed with user '
                                                   'input can result in Path '
                                                   'Traversal. Ensure that '
                                                   'user input does not reach '
                                                   '`join()` or `resolve()`.',
                                    'display_name': 'JoinResolvePathTraversal',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'join resolve path traversal'},
    'JoseExposedData': {   'categories': ['security'],
                           'description': 'The object is passed strictly to '
                                          'jose.JWT.sign(...)\n'
                                          'Make sure that sensitive '
                                          'information is not exposed through '
                                          'JWT token payload.',
                           'display_name': 'JoseExposedData',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'jose exposed data'},
    'JpaSqli': {   'categories': ['security'],
                   'description': 'Detected a formatted string in a SQL '
                                  'statement. This could lead to SQL\n'
                                  'injection if variables in the SQL statement '
                                  'are not properly sanitized.\n'
                                  'Use a prepared statements '
                                  '(java.sql.PreparedStatement) instead. You\n'
                                  'can obtain a PreparedStatement using '
                                  "'connection.prepareStatement'.",
                   'display_name': 'JpaSqli',
                   'file': '%(issue.file)s',
                   'line': '%(issue.line)s',
                   'severity': '1',
                   'title': 'jpa sqli'},
    'JqueryInsecureMethod': {   'categories': ['security'],
                                'description': 'User controlled data in a '
                                               "jQuery's `.$METHOD(...)` is an "
                                               'anti-pattern that can lead to '
                                               'XSS vulnerabilities',
                                'display_name': 'JqueryInsecureMethod',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'jquery insecure method'},
    'JqueryInsecureSelector': {   'categories': ['security'],
                                  'description': 'User controlled data in a '
                                                 '`$(...)` is an anti-pattern '
                                                 'that can lead to XSS '
                                                 'vulnerabilities',
                                  'display_name': 'JqueryInsecureSelector',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'jquery insecure selector'},
    'JrubyXml': {   'categories': ['security'],
                    'description': 'The JDOM backend for XmlMini has a '
                                   'vulnerability that lets an attacker '
                                   'perform a denial of service attack\n'
                                   'or gain access to files on the application '
                                   'server. This affects versions 3.0, but is '
                                   'fixed in versions\n'
                                   '3.1.12 and 3.2.13. To fix, either upgrade '
                                   'or use XmlMini.backend="REXML".',
                    'display_name': 'JrubyXml',
                    'file': '%(issue.file)s',
                    'line': '%(issue.line)s',
                    'severity': '1',
                    'title': 'jruby xml'},
    'JsOpenRedirect': {   'categories': ['security'],
                          'description': 'Possible open redirect',
                          'display_name': 'JsOpenRedirect',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'js open redirect'},
    'JsonEncoding': {   'categories': ['security'],
                        'description': "When a 'Hash' with user-supplied input "
                                       "is encoded in JSPN, Rails doesn't "
                                       'provide adequate escaping.\n'
                                       'If the JSON string is supplied into '
                                       'HTML, the page will be vulnerable to '
                                       'XXS attacks.\n'
                                       'The affected ruby versions are 3.0.x, '
                                       '3.1.x, 3.2.x, 4.1.x, 4.2.x.\n'
                                       'To fix, either upgrade or add an '
                                       'initializer.',
                        'display_name': 'JsonEncoding',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'json encoding'},
    'JsonEntityEscape': {   'categories': ['security'],
                            'description': 'Checks if HTML escaping is '
                                           'globally disabled for JSON output. '
                                           'This could lead to XSS.',
                            'display_name': 'JsonEntityEscape',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'json entity escape'},
    'JwtDecodeWithoutVerify': {   'categories': ['security'],
                                  'description': 'Detected the decoding of a '
                                                 'JWT token without a verify '
                                                 'step.\n'
                                                 'JWT tokens must be verified '
                                                 'before use, otherwise the '
                                                 "token's\n"
                                                 'integrity is unknown. This '
                                                 'means a malicious actor '
                                                 'could forge\n'
                                                 'a JWT token with any claims. '
                                                 "Call '.verify()' before "
                                                 'using the token.',
                                  'display_name': 'JwtDecodeWithoutVerify',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'jwt decode without verify'},
    'JwtExposedCredentials': {   'categories': ['security'],
                                 'description': 'Password is exposed through '
                                                'JWT token payload. This is '
                                                'not encrypted and  the '
                                                'password could be '
                                                'compromised. Do not store '
                                                'passwords in JWT tokens.',
                                 'display_name': 'JwtExposedCredentials',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'jwt exposed credentials'},
    'JwtExposedData': {   'categories': ['security'],
                          'description': 'The object is passed strictly to '
                                         'jose.JWT.sign(...). Make sure  that '
                                         'sensitive information is not exposed '
                                         'through JWT token payload.',
                          'display_name': 'JwtExposedData',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'jwt exposed data'},
    'JwtExpressHardcoded': {   'categories': ['security'],
                               'description': 'Hardcoded JWT secret or private '
                                              'key was found. Store it '
                                              'properly in  an environment '
                                              'variable.',
                               'display_name': 'JwtExpressHardcoded',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'jwt express hardcoded'},
    'JwtGoNoneAlgorithm': {   'categories': ['security'],
                              'description': "Detected use of the 'none' "
                                             'algorithm in a JWT token.\n'
                                             "The 'none' algorithm assumes the "
                                             'integrity of the token has '
                                             'already\n'
                                             'been verified. This would allow '
                                             'a malicious actor to forge a JWT '
                                             'token\n'
                                             'that will automatically be '
                                             'verified. Do not explicitly use '
                                             "the 'none'\n"
                                             'algorithm. Instead, use an '
                                             "algorithm such as 'HS256'.",
                              'display_name': 'JwtGoNoneAlgorithm',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'jwt go none algorithm'},
    'JwtGoParseUnverified': {   'categories': ['security'],
                                'description': 'Detected the decoding of a JWT '
                                               'token without a verify step.\n'
                                               "Don't use `ParseUnverified` "
                                               "unless you know what you're "
                                               'doing\n'
                                               'This method parses the token '
                                               "but doesn't validate the "
                                               "signature. It's only ever "
                                               'useful in cases where you know '
                                               'the signature is valid '
                                               '(because it has been checked '
                                               'previously in the stack) and '
                                               'you want to extract values '
                                               'from it.',
                                'display_name': 'JwtGoParseUnverified',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'jwt go parse unverified'},
    'JwtNoneAlg': {   'categories': ['security'],
                      'description': "Detected use of the 'none' algorithm in "
                                     'a JWT token.\n'
                                     "The 'none' algorithm assumes the "
                                     'integrity of the token has already\n'
                                     'been verified. This would allow a '
                                     'malicious actor to forge a JWT token\n'
                                     'that will automatically be verified. Do '
                                     "not explicitly use the 'none'\n"
                                     'algorithm. Instead, use an algorithm '
                                     "such as 'HS256'.",
                      'display_name': 'JwtNoneAlg',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'jwt none alg'},
    'JwtNotRevoked': {   'categories': ['security'],
                         'description': 'No token revoking configured for '
                                        '`express-jwt`. A leaked token could '
                                        'still be used and unable to be '
                                        'revoked. Consider using function as '
                                        'the `isRevoked` option.',
                         'display_name': 'JwtNotRevoked',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'jwt not revoked'},
    'JwtPythonExposedCredentials': {   'categories': ['security'],
                                       'description': 'Password is exposed '
                                                      'through JWT token '
                                                      'payload. This is not '
                                                      'encrypted and\n'
                                                      'the password could be '
                                                      'compromised. Do not '
                                                      'store passwords in JWT '
                                                      'tokens.',
                                       'display_name': 'JwtPythonExposedCredentials',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'jwt python exposed '
                                                'credentials'},
    'JwtPythonExposedData': {   'categories': ['security'],
                                'description': 'The object is passed strictly '
                                               'to jwt.encode(...)\n'
                                               'Make sure that sensitive '
                                               'information is not exposed '
                                               'through JWT token payload.',
                                'display_name': 'JwtPythonExposedData',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'jwt python exposed data'},
    'JwtPythonHardcodedSecret': {   'categories': ['security'],
                                    'description': 'Hardcoded JWT secret or '
                                                   'private key is used.\n'
                                                   'This is a Insufficiently '
                                                   'Protected Credentials '
                                                   'weakness: '
                                                   'https://cwe.mitre.org/data/definitions/522.html\n'
                                                   'Consider using an '
                                                   'appropriate security '
                                                   'mechanism to protect the '
                                                   'credentials (e.g. keeping '
                                                   'secrets in environment '
                                                   'variables)',
                                    'display_name': 'JwtPythonHardcodedSecret',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'jwt python hardcoded secret'},
    'JwtPythonNoneAlg': {   'categories': ['security'],
                            'description': "Detected use of the 'none' "
                                           'algorithm in a JWT token.\n'
                                           "The 'none' algorithm assumes the "
                                           'integrity of the token has '
                                           'already\n'
                                           'been verified. This would allow a '
                                           'malicious actor to forge a JWT '
                                           'token\n'
                                           'that will automatically be '
                                           'verified. Do not explicitly use '
                                           "the 'none'\n"
                                           'algorithm. Instead, use an '
                                           "algorithm such as 'HS256'.",
                            'display_name': 'JwtPythonNoneAlg',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'jwt python none alg'},
    'LastUserIsRoot': {   'categories': ['security'],
                          'description': 'The last user in the container is '
                                         "'root'. This is a security hazard "
                                         'because if an attacker gains control '
                                         'of the container they will have root '
                                         'access. Switch back to another user '
                                         "after running commands as 'root'.\n"
                                         '{"include": ["*dockerfile*", '
                                         '"*Dockerfile*"]}',
                          'display_name': 'LastUserIsRoot',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'dockerfile: last user is root'},
    'Layer7ObjectDos': {   'categories': ['security'],
                           'description': 'Layer7 Denial of Service. Looping '
                                          'over user controlled objects can '
                                          'result in DoS.',
                           'display_name': 'Layer7ObjectDos',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'layer7 object dos'},
    'LdapEntryPoisoning': {   'categories': ['security'],
                              'description': 'An object-returning LDAP search '
                                             'will allow attackers to control '
                                             'the LDAP response. This could\n'
                                             'lead to Remote Code Execution.',
                              'display_name': 'LdapEntryPoisoning',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'ldap entry poisoning'},
    'LdapInjection': {   'categories': ['security'],
                         'description': 'Detected non-constant data passed '
                                        'into an LDAP query. If this data can '
                                        'be\n'
                                        'controlled by an external user, this '
                                        'is an LDAP injection.\n'
                                        'Ensure data passed to an LDAP query '
                                        'is not controllable; or properly '
                                        'sanitize\n'
                                        'the data.',
                         'display_name': 'LdapInjection',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'ldap injection'},
    'LenAllCount': {   'categories': ['security'],
                       'description': 'Using QUERY.count() instead of '
                                      'len(QUERY.all()) sends less data to the '
                                      'client since the SQLAlchemy method is '
                                      'performed server-side.',
                       'display_name': 'LenAllCount',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'len all count'},
    'ListModifyWhileIterate': {   'categories': ['security'],
                                  'description': 'It appears that `$LIST` is a '
                                                 'list that is being modified '
                                                 'while in a for loop.\n'
                                                 'This will likely cause a '
                                                 'runtime error or an infinite '
                                                 'loop.',
                                  'display_name': 'ListModifyWhileIterate',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'list modify while iterate'},
    'ListenEval': {   'categories': ['security'],
                      'description': 'Because portions of the logging '
                                     'configuration are passed through '
                                     'eval(),\n'
                                     'use of this function may open its users '
                                     'to a security risk. While the\n'
                                     'function only binds to a socket on '
                                     'localhost, and so does not accept\n'
                                     'connections from remote machines, there '
                                     'are scenarios where untrusted\n'
                                     'code could be run under the account of '
                                     'the process which calls listen().\n'
                                     'See more details at '
                                     'https://docs.python.org/3/library/logging.config.html?highlight=security#logging.config.listen',
                      'display_name': 'ListenEval',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'listen eval'},
    'LocalhostBaseUrl': {   'categories': ['security'],
                            'description': "The 'baseURL' is set to localhost. "
                                           'This may cause links to not work '
                                           'if deployed.',
                            'display_name': 'LocalhostBaseUrl',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'hugo: localhost base url'},
    'Log4jMessageInjection': {   'categories': ['security'],
                                 'description': '检查log4j类的error(…), warn(…), '
                                                'info(…), debug(…), fatal(…), '
                                                'trace(…), log(level, '
                                                '…)等api调用方法',
                                 'display_name': 'Log4jMessageInjection',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'Possible injection into Log4j '
                                          'messages'},
    'Log4jMessageLookupInjection': {   'categories': ['security'],
                                       'description': '检查error(...), '
                                                      'warn(...), info(...), '
                                                      'debug(...), fatal(...), '
                                                      'trace(...), log(level, '
                                                      '...)等常用logger api调用方法\n'
                                                      '\n'
                                                      'Possible Lookup '
                                                      'injection into Log4j '
                                                      'messages. Lookups '
                                                      'provide a way to add '
                                                      'values to the Log4j '
                                                      'messages at arbitrary\n'
                                                      '    places. If the '
                                                      'message parameter '
                                                      'contains an attacker '
                                                      'controlled string, the '
                                                      'attacker could inject '
                                                      'arbitrary lookups,\n'
                                                      '    for instance '
                                                      "'${java:runtime}'. This "
                                                      'cloud lead to '
                                                      'information disclosure '
                                                      'or even remove code '
                                                      'execution if '
                                                      "'log4j2.formatMsgNoLookups'\n"
                                                      '    is enabled. This '
                                                      'was enabled by default '
                                                      'until version 2.15.0.',
                                       'display_name': 'Log4jMessageLookupInjection',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'log4j message lookup '
                                                'injection'},
    'MaintainerIsDeprecated': {   'categories': ['security'],
                                  'description': 'MAINTAINER has been '
                                                 'deprecated.\n'
                                                 '\n'
                                                 '{"include": ["*dockerfile*", '
                                                 '"*Dockerfile*"]}',
                                  'display_name': 'MaintainerIsDeprecated',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'dockerfile: maintainer is '
                                           'deprecated'},
    'MakeResponseWithUnknownContent': {   'categories': ['security'],
                                          'description': 'Be careful with '
                                                         '`flask.make_response()`. '
                                                         'If this response is '
                                                         'rendered onto a '
                                                         'webpage, this could '
                                                         'create a cross-site '
                                                         'scripting (XSS) '
                                                         'vulnerability. '
                                                         '`flask.make_response()` '
                                                         'will not autoescape '
                                                         'HTML. If you are '
                                                         'rendering HTML, '
                                                         'write your HTML in a '
                                                         'template file and '
                                                         'use '
                                                         '`flask.render_template()` '
                                                         'which will take care '
                                                         'of escaping. If you '
                                                         'are returning data '
                                                         'from an API, '
                                                         'consider using '
                                                         '`flask.jsonify()`.',
                                          'display_name': 'MakeResponseWithUnknownContent',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'make response with unknown '
                                                   'content'},
    'MakoTemplatesDetected': {   'categories': ['security'],
                                 'description': 'Mako templates do not provide '
                                                'a global HTML escaping '
                                                'mechanism.\n'
                                                'This means you must escape '
                                                'all sensitive data in your '
                                                'templates\n'
                                                "using '| u' for URL escaping "
                                                "or '| h' for HTML escaping.\n"
                                                'If you are using Mako to '
                                                'serve web content, consider '
                                                'using\n'
                                                'a system such as Jinja2 which '
                                                'enables global escaping.',
                                 'display_name': 'MakoTemplatesDetected',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'mako templates detected'},
    'ManualCounterCreate': {   'categories': ['security'],
                               'description': 'manually creating a counter - '
                                              'use collections.Counter',
                               'display_name': 'ManualCounterCreate',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'manual counter create'},
    'ManualDefaultdictDictCreate': {   'categories': ['security'],
                                       'description': 'manually creating a '
                                                      'defaultdict - use '
                                                      'collections.defaultdict(dict)',
                                       'display_name': 'ManualDefaultdictDictCreate',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'manual defaultdict dict '
                                                'create'},
    'ManualDefaultdictListCreate': {   'categories': ['security'],
                                       'description': 'manually creating a '
                                                      'defaultdict - use '
                                                      'collections.defaultdict(list)',
                                       'display_name': 'ManualDefaultdictListCreate',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'manual defaultdict list '
                                                'create'},
    'ManualDefaultdictSetCreate': {   'categories': ['security'],
                                      'description': 'manually creating a '
                                                     'defaultdict - use '
                                                     'collections.defaultdict(set)',
                                      'display_name': 'ManualDefaultdictSetCreate',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'manual defaultdict set create'},
    'ManualTemplateCreation': {   'categories': ['security'],
                                  'description': 'Detected manual creation of '
                                                 'an ERB template. Manual '
                                                 'creation of templates\n'
                                                 'may expose your application '
                                                 'to server-side template '
                                                 'injection (SSTI) or\n'
                                                 'cross-site scripting (XSS) '
                                                 'attacks if user input is '
                                                 'used to create the\n'
                                                 'template. Instead, create a '
                                                 "'.erb' template file and use "
                                                 "'render'.",
                                  'display_name': 'ManualTemplateCreation',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'manual template creation'},
    'MarshalUsage': {   'categories': ['security'],
                        'description': 'The marshal module is not intended to '
                                       'be secure against erroneous or '
                                       'maliciously constructed data.\n'
                                       'Never unmarshal data received from an '
                                       'untrusted or unauthenticated source.\n'
                                       'See more details: '
                                       'https://docs.python.org/3/library/marshal.html?highlight=security',
                        'display_name': 'MarshalUsage',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'marshal usage'},
    'MassAssignment': {   'categories': ['security'],
                          'description': 'Mass assignment detected. This can '
                                         'result in assignment to\n'
                                         'model fields that are unintended and '
                                         'can be exploited by\n'
                                         'an attacker. Instead of using '
                                         "'**request.$W', assign each field "
                                         'you\n'
                                         'want to edit individually to prevent '
                                         'mass assignment. You can read\n'
                                         'more about mass assignment at\n'
                                         'https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html.',
                          'display_name': 'MassAssignment',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'mass assignment'},
    'MassAssignmentProtectionDisabled': {   'categories': ['security'],
                                            'description': 'Mass assignment '
                                                           'protection '
                                                           'disabled for '
                                                           "'$MODEL'. This "
                                                           'could\n'
                                                           'permit assignment '
                                                           'to sensitive model '
                                                           'fields without '
                                                           'intention. '
                                                           'Instead,\n'
                                                           'use '
                                                           "'attr_accessible' "
                                                           'for the model or '
                                                           'disable mass '
                                                           'assigment using\n'
                                                           "'config.active_record.whitelist_attributes "
                                                           "= true'.\n"
                                                           "':without_protection "
                                                           "=> true' must be "
                                                           'removed for this '
                                                           'to take effect.',
                                            'display_name': 'MassAssignmentProtectionDisabled',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'mass assignment '
                                                     'protection disabled'},
    'MassAssignmentVuln': {   'categories': ['security'],
                              'description': 'Checks for calls to '
                                             'without_protection during mass '
                                             'assignment (which allows record '
                                             'creation from hash values).\n'
                                             'This can lead to users bypassing '
                                             'permissions protections. For '
                                             'Rails 4 and higher, mass '
                                             'protection is on by default.\n'
                                             "Fix: Don't use "
                                             ':without_protection => true. '
                                             'Instead, configure '
                                             'attr_acessible to control '
                                             'attribute access.',
                              'display_name': 'MassAssignmentVuln',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'mass assignment vuln'},
    'MathRandomUsed': {   'categories': ['security'],
                          'description': 'Do not use `math/rand`. Use '
                                         '`crypto/rand` instead.',
                          'display_name': 'MathRandomUsed',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'math random used'},
    'MbEregReplaceEval': {   'categories': ['security'],
                             'description': 'Calling mb_ereg_replace with user '
                                            'input in the options can lead to '
                                            'arbitrary\n'
                                            'code execution. The eval modifier '
                                            '(`e`) evaluates the replacement '
                                            'argument\n'
                                            'as code.',
                             'display_name': 'MbEregReplaceEval',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'mb ereg replace eval'},
    'McryptUse': {   'categories': ['security'],
                     'description': 'Mcrypt functionality has been deprecated '
                                    'and/or removed in recent PHP\n'
                                    'versions. Consider using Sodium or '
                                    'OpenSSL.',
                     'display_name': 'McryptUse',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'mcrypt use'},
    'Md5LooseEquality': {   'categories': ['security'],
                            'description': 'Make sure comparisons involving '
                                           'md5 values are strict (use `===` '
                                           'not `==`) to avoid type juggling '
                                           'issues',
                            'display_name': 'Md5LooseEquality',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'md5 loose equality'},
    'MissingApkNoCache': {   'categories': ['security'],
                             'description': 'This apk command is missing '
                                            "'--no-cache'. This forces apk to "
                                            'use a package\n'
                                            'index instead of a local package '
                                            'cache, removing the need for '
                                            "'--update'\n"
                                            'and the deletion of '
                                            "'/var/cache/apk/*'. Add "
                                            "'--no-cache' to your apk "
                                            'command.\n'
                                            '\n'
                                            '{"include": ["*dockerfile*", '
                                            '"*Dockerfile*"]}',
                             'display_name': 'MissingApkNoCache',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'dockerfile: missing apk no cache'},
    'MissingAssumeYesSwitch': {   'categories': ['security'],
                                  'description': "This 'apt-get install' is "
                                                 "missing the '-y' switch. "
                                                 'This might stall\n'
                                                 'builds because it requires '
                                                 'human intervention. Add the '
                                                 "'-y' switch.\n"
                                                 '\n'
                                                 '{"include": ["*dockerfile*", '
                                                 '"*Dockerfile*"]}',
                                  'display_name': 'MissingAssumeYesSwitch',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'dockerfile: missing assume yes '
                                           'switch'},
    'MissingCsrfProtection': {   'categories': ['security'],
                                 'description': 'Detected controller which '
                                                'does not enable cross-site '
                                                'request forgery\n'
                                                'protections using '
                                                "'protect_from_forgery'. Add\n"
                                                "'protect_from_forgery :with "
                                                "=> :exception' to your "
                                                'controller class.',
                                 'display_name': 'MissingCsrfProtection',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'missing csrf protection'},
    'MissingDnfAssumeYesSwitch': {   'categories': ['security'],
                                     'description': "This 'dnf install' is "
                                                    "missing the '-y' switch. "
                                                    'This might stall\n'
                                                    'builds because it '
                                                    'requires human '
                                                    'intervention. Add the '
                                                    "'-y' switch.\n"
                                                    '\n'
                                                    '{"include": '
                                                    '["*dockerfile*", '
                                                    '"*Dockerfile*"]}',
                                     'display_name': 'MissingDnfAssumeYesSwitch',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'dockerfile: missing dnf assume '
                                              'yes switch'},
    'MissingDnfCleanAll': {   'categories': ['security'],
                              'description': 'This dnf command does not end '
                                             "with '&& dnf clean all'. Running "
                                             "'dnf clean all' will remove "
                                             'cached data and reduce package '
                                             'size. (This must be performed in '
                                             'the same RUN step.)\n'
                                             '\n'
                                             '{"include": ["*dockerfile*", '
                                             '"*Dockerfile*"]}',
                              'display_name': 'MissingDnfCleanAll',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'dockerfile: missing dnf clean all'},
    'MissingHashWithEq': {   'categories': ['security'],
                             'description': 'Class `$A` has defined `__eq__` '
                                            'which means it should also have '
                                            'defined `__hash__`;',
                             'display_name': 'MissingHashWithEq',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'missing hash with eq'},
    'MissingImageVersion': {   'categories': ['security'],
                               'description': 'Images should be tagged with an '
                                              'explicit version to produce '
                                              'deterministic container '
                                              'images.\n'
                                              '{"include": ["*dockerfile*", '
                                              '"*Dockerfile*"]}',
                               'display_name': 'MissingImageVersion',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'dockerfile: missing image version'},
    'MissingInternal': {   'categories': ['security'],
                           'description': 'This location block contains a '
                                          "'proxy_pass' directive but does not "
                                          "contain the 'internal' directive. "
                                          "The 'internal' directive restricts "
                                          'access to this location to internal '
                                          "requests. Without 'internal', an "
                                          'attacker could use your server for '
                                          'server-side request forgeries '
                                          "(SSRF). Include the 'internal' "
                                          'directive in this block to limit '
                                          'exposure.\n'
                                          '{"include": ["*.conf", "*.vhost", '
                                          '"sites-available/*", '
                                          '"sites-enabled/*"]}',
                           'display_name': 'MissingInternal',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'nginx: missing internal'},
    'MissingNoInstallRecommends': {   'categories': ['security'],
                                      'description': "This 'apt-get install' "
                                                     'is missing '
                                                     "'--no-install-recommends'. "
                                                     'This prevents\n'
                                                     'unnecessary packages '
                                                     'from being installed, '
                                                     'thereby reducing image '
                                                     'size. Add\n'
                                                     "'--no-install-recommends'.\n"
                                                     '\n'
                                                     '{"include": '
                                                     '["*dockerfile*", '
                                                     '"*Dockerfile*"]}',
                                      'display_name': 'MissingNoInstallRecommends',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'dockerfile: missing no install '
                                               'recommends'},
    'MissingNoopener': {   'categories': ['security'],
                           'description': 'This anchor tag with '
                                          '\'target="_blank"\' is missing '
                                          "'noopener'. A page opened with "
                                          '\'target="_blank"\' can access the '
                                          'window object of the origin page. '
                                          'This means it can manipulate the '
                                          "'window.opener' property, which "
                                          'could redirect the origin page to a '
                                          'malicious URL. This is called '
                                          'reverse tabnabbing. To prevent '
                                          "this, include 'rel=noopener' on "
                                          'this tag',
                           'display_name': 'MissingNoopener',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'missing noopener'},
    'MissingNoreferrer': {   'categories': ['security'],
                             'description': 'This anchor tag with '
                                            '\'target="_blank"\' is missing '
                                            "'noreferrer'. A page opened with "
                                            '\'target="_blank"\' can access '
                                            'the window object of the origin '
                                            'page. This means it can '
                                            "manipulate the 'window.opener' "
                                            'property, which could redirect '
                                            'the origin page to a malicious '
                                            'URL. This is called reverse '
                                            'tabnabbing. To prevent this, '
                                            "include 'rel=noreferrer' on this "
                                            'tag.',
                             'display_name': 'MissingNoreferrer',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'missing noreferrer'},
    'MissingPipNoCacheDir': {   'categories': ['security'],
                                'description': "This '$PIP install' is missing "
                                               "'--no-cache-dir'. This flag "
                                               'prevents\n'
                                               'package archives from being '
                                               'kept around, thereby reducing '
                                               'image size.\n'
                                               "Add '--no-cache-dir'.\n"
                                               '\n'
                                               '{"include": ["*dockerfile*", '
                                               '"*Dockerfile*"]}',
                                'display_name': 'MissingPipNoCacheDir',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'dockerfile: missing pip no cache '
                                         'dir'},
    'MissingRatelimit': {   'categories': ['security'],
                            'description': "Function '$FUNC' is missing a "
                                           'rate-limiting decorator.\n'
                                           'High volume traffic to this '
                                           'function could starve application\n'
                                           'resources. Consider adding rate '
                                           'limiting from a library such\n'
                                           "as 'django-ratelimit'.",
                            'display_name': 'MissingRatelimit',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'missing ratelimit'},
    'MissingSslMinversion': {   'categories': ['security'],
                                'description': '`MinVersion` is missing from '
                                               'this TLS configuration. The '
                                               'default\n'
                                               'value is TLS1.0 which is '
                                               'considered insecure. '
                                               'Explicitly set the\n'
                                               '`MinVersion` to a secure '
                                               'version of TLS, such as '
                                               '`VersionTLS13`.',
                                'display_name': 'MissingSslMinversion',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'missing ssl minversion'},
    'MissingSslVersion': {   'categories': ['security'],
                             'description': 'This server configuration is '
                                            "missing the 'ssl_protocols' "
                                            'directive. By default, this '
                                            "server will use 'ssl_protocols "
                                            "TLSv1 TLSv1.1 TLSv1.2', and "
                                            'versions older than TLSv1.2 are '
                                            'known to be broken. Explicitly '
                                            "specify 'ssl_protocols TLSv1.2 "
                                            "TLSv1.3' to use secure TLS "
                                            'versions.\n'
                                            '{"include": ["*.conf", "*.vhost", '
                                            '"sites-available/*", '
                                            '"sites-enabled/*"]}',
                             'display_name': 'MissingSslVersion',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'nginx: missing ssl version'},
    'MissingThrottleConfig': {   'categories': ['security'],
                                 'description': 'Django REST framework '
                                                'configuration is missing '
                                                'default rate-\n'
                                                'limiting options. This could '
                                                'inadvertently allow resource\n'
                                                'starvation or Denial of '
                                                'Service (DoS) attacks. Add\n'
                                                "'DEFAULT_THROTTLE_CLASSES' "
                                                "and 'DEFAULT_THROTTLE_RATES'\n"
                                                'to add rate-limiting to your '
                                                'application.',
                                 'display_name': 'MissingThrottleConfig',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'missing throttle config'},
    'MissingUser': {   'categories': ['security'],
                       'description': 'By not specifying a USER, a programs in '
                                      "the container may run as 'root'. This "
                                      'is a security hazard. If an attacker '
                                      'can control a process running as root, '
                                      'they may have control over the '
                                      'container. Ensure that the last USER in '
                                      'a Dockerfile is a USER other than '
                                      "'root'.\n"
                                      '{"include": ["*Dockerfile*", '
                                      '"*dockerfile*"]}',
                       'display_name': 'MissingUser',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'dockerfile: missing user'},
    'MissingYumAssumeYesSwitch': {   'categories': ['security'],
                                     'description': "This 'yum install' is "
                                                    "missing the '-y' switch. "
                                                    'This might stall\n'
                                                    'builds because it '
                                                    'requires human '
                                                    'intervention. Add the '
                                                    "'-y' switch.\n"
                                                    '\n'
                                                    '{"include": '
                                                    '["*dockerfile*", '
                                                    '"*Dockerfile*"]}',
                                     'display_name': 'MissingYumAssumeYesSwitch',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'dockerfile: missing yum assume '
                                              'yes switch'},
    'MissingYumCleanAll': {   'categories': ['security'],
                              'description': 'This yum command does not end '
                                             "with '&& yum clean all'. Running "
                                             "'yum clean all' will remove "
                                             'cached data and reduce package '
                                             'size. (This must be performed in '
                                             'the same RUN step.)\n'
                                             '\n'
                                             '{"include": ["*dockerfile*", '
                                             '"*Dockerfile*"]}',
                              'display_name': 'MissingYumCleanAll',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'dockerfile: missing yum clean all'},
    'MissingZypperClean': {   'categories': ['security'],
                              'description': 'This zypper command does not end '
                                             "with '&& zypper clean'. Running "
                                             "'zypper clean' will remove "
                                             'cached data and reduce package '
                                             'size. (This must be performed in '
                                             'the same RUN step.)\n'
                                             '\n'
                                             '{"include": ["*dockerfile*", '
                                             '"*Dockerfile*"]}',
                              'display_name': 'MissingZypperClean',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'dockerfile: missing zypper clean'},
    'MissingZypperNoConfirmSwitch': {   'categories': ['security'],
                                        'description': "This 'zypper install' "
                                                       "is missing the '-y' "
                                                       'switch. This might '
                                                       'stall\n'
                                                       'builds because it '
                                                       'requires human '
                                                       'intervention. Add the '
                                                       "'-y' switch.\n"
                                                       '\n'
                                                       '{"include": '
                                                       '["*dockerfile*", '
                                                       '"*Dockerfile*"]}',
                                        'display_name': 'MissingZypperNoConfirmSwitch',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'dockerfile: missing zypper '
                                                 'no confirm switch'},
    'ModelAttrAccessible': {   'categories': ['security'],
                               'description': 'Checks for dangerous permitted '
                                              'attributes that can lead to '
                                              'mass assignment '
                                              'vulnerabilities. Query '
                                              'parameters allowed using '
                                              'permit\n'
                                              'and attr_accessible are checked '
                                              'for allowance of dangerous '
                                              'attributes admin, banned, role, '
                                              'and account_id. Also checks for '
                                              'usages of\n'
                                              'params.permit!, which allows '
                                              "everything. Fix: don't allow "
                                              'admin, banned, role, and '
                                              'account_id using permit or '
                                              'attr_accessible.',
                               'display_name': 'ModelAttrAccessible',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'model attr accessible'},
    'ModelAttributesAttrAccessible': {   'categories': ['security'],
                                         'description': 'Checks for models '
                                                        'that do not use '
                                                        'attr_accessible. This '
                                                        'means there is no '
                                                        'limiting of which '
                                                        'variables can be '
                                                        'manipulated\n'
                                                        'through mass '
                                                        'assignment. For newer '
                                                        'Rails applications, '
                                                        'parameters should be '
                                                        'allowlisted using '
                                                        'strong parameters.\n'
                                                        'For older Ruby '
                                                        'versions, they should '
                                                        'be allowlisted using '
                                                        'strong_attributes.',
                                         'display_name': 'ModelAttributesAttrAccessible',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'model attributes attr '
                                                  'accessible'},
    'ModelAttributesAttrProtected': {   'categories': ['security'],
                                        'description': 'Checks for models that '
                                                       'use attr_protected, as '
                                                       'use of allowlist '
                                                       'instead of denylist is '
                                                       'better practice.\n'
                                                       'Attr_protected was '
                                                       'also found to be '
                                                       'vulnerable to bypass. '
                                                       'The fixed versions of '
                                                       'Ruby are: 3.2.12, '
                                                       '3.1.11, 2.3.17.\n'
                                                       'To prevent bypass, use '
                                                       'attr_accessible '
                                                       'instead.',
                                        'display_name': 'ModelAttributesAttrProtected',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'model attributes attr '
                                                 'protected'},
    'MongoClientBadAuth': {   'categories': ['security'],
                              'description': 'Warning MONGODB-CR was '
                                             'deprecated with the release of '
                                             'MongoDB 3.6 and is no longer '
                                             'supported by MongoDB 4.0 (see '
                                             'https://api.mongodb.com/python/current/examples/authentication.html '
                                             'for details).',
                              'display_name': 'MongoClientBadAuth',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'mongo client bad auth'},
    'MultiargsCodeExecution': {   'categories': ['security'],
                                  'description': 'Potential arbitrary code '
                                                 'execution, piped to eval',
                                  'display_name': 'MultiargsCodeExecution',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'multiargs code execution'},
    'MultipleCmdInstructions': {   'categories': ['security'],
                                   'description': 'Multiple CMD instructions '
                                                  'were found. Only the last '
                                                  'one will take effect.\n'
                                                  '\n'
                                                  '{"include": '
                                                  '["*dockerfile*", '
                                                  '"*Dockerfile*"]}',
                                   'display_name': 'MultipleCmdInstructions',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'dockerfile: multiple cmd '
                                            'instructions'},
    'MultipleEntrypointInstructions': {   'categories': ['security'],
                                          'description': 'Multiple ENTRYPOINT '
                                                         'instructions were '
                                                         'found. Only the last '
                                                         'one will take '
                                                         'effect.\n'
                                                         '\n'
                                                         '{"include": '
                                                         '["*dockerfile*", '
                                                         '"*Dockerfile*"]}',
                                          'display_name': 'MultipleEntrypointInstructions',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'dockerfile: multiple '
                                                   'entrypoint instructions'},
    'MultiprocessingRecv': {   'categories': ['security'],
                               'description': 'The Connection.recv() method '
                                              'automatically unpickles the '
                                              'data it receives, which can be '
                                              'a security risk unless you can '
                                              'trust the process which sent '
                                              'the message. Therefore, unless '
                                              'the connection object was '
                                              'produced using Pipe() you '
                                              'should only use the recv() and '
                                              'send() methods after performing '
                                              'some sort of authentication. '
                                              'See more dettails: '
                                              'https://docs.python.org/3/library/multiprocessing.html?highlight=security#multiprocessing.connection.Connection',
                               'display_name': 'MultiprocessingRecv',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'multiprocessing recv'},
    'NestedAttributes': {   'categories': ['security'],
                            'description': 'Checks for models that enable '
                                           'nested attributes. A vulnerability '
                                           'in nested_attributes_for results '
                                           'in an attacker\n'
                                           'begin able to change parameters '
                                           'apart from the ones intended by '
                                           'the developer. Affected Ruby '
                                           'verions: 3.0.0, 2.3.9.\n'
                                           "Fix: don't use "
                                           'accepts_nested_attributes_for or '
                                           'upgrade Ruby version.',
                            'display_name': 'NestedAttributes',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'nested attributes'},
    'NestedAttributesBypass': {   'categories': ['security'],
                                  'description': 'Checks for nested attributes '
                                                 'vulnerability '
                                                 '(CVE-2015-7577). Setting '
                                                 'allow_destroy: false in\n'
                                                 'accepts_nested_attributes_for '
                                                 'can lead to attackers '
                                                 'setting attributes to '
                                                 'invalid values and clearing '
                                                 'all attributes.\n'
                                                 'This affects versions 3.1.0 '
                                                 'and newer, with fixed '
                                                 'versions 5.0.0.beta1.1, '
                                                 '4.2.5.1, 4.1.14.1, '
                                                 '3.2.22.1.\n'
                                                 'To fix, upgrade to a newer '
                                                 'version or use the '
                                                 'initializer specified in the '
                                                 'google groups.',
                                  'display_name': 'NestedAttributesBypass',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'nested attributes bypass'},
    'NestjsHeaderCorsAny': {   'categories': ['security'],
                               'description': 'Access-Control-Allow-Origin '
                                              'response header is set to "*". '
                                              'This will disable CORS Same '
                                              'Origin Policy restrictions.',
                               'display_name': 'NestjsHeaderCorsAny',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'nestjs header cors any'},
    'NestjsHeaderXssDisabled': {   'categories': ['security'],
                                   'description': 'X-XSS-Protection header is '
                                                  'set to 0. This will disable '
                                                  "the browser's XSS Filter.",
                                   'display_name': 'NestjsHeaderXssDisabled',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'nestjs header xss disabled'},
    'NestjsOpenRedirect': {   'categories': ['security'],
                              'description': 'Untrusted user input in {url: '
                                             '...} can result in Open Redirect '
                                             'vulnerability.',
                              'display_name': 'NestjsOpenRedirect',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'nestjs open redirect'},
    'NewFunctionDetected': {   'categories': ['security'],
                               'description': 'Detected the use of new '
                                              'Function(), which can be '
                                              'dangerous if used to evaluate\n'
                                              'dynamic content. If this '
                                              'content can be input from '
                                              'outside the program, this\n'
                                              'may be a code injection '
                                              'vulnerability. Ensure evaluated '
                                              'content is not definable\n'
                                              'by external sources.',
                               'display_name': 'NewFunctionDetected',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'new function detected'},
    'NoAuthOverHttp': {   'categories': ['security'],
                          'description': 'Authentication detected over HTTP. '
                                         'HTTP does not provide any\n'
                                         'encryption or protection for these '
                                         'authentication credentials.\n'
                                         'This may expose these credentials to '
                                         'unauthhorized parties.\n'
                                         "Use 'https://' instead.",
                          'display_name': 'NoAuthOverHttp',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'no auth over http'},
    'NoCsrfExempt': {   'categories': ['security'],
                        'description': 'There is rarely a good reason to use '
                                       '@csrf_exempt as is used for `$R`.',
                        'display_name': 'NoCsrfExempt',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'no csrf exempt'},
    'NoDirectResponseWriter': {   'categories': ['security'],
                                  'description': 'Detected a direct write to '
                                                 'the HTTP response. This '
                                                 'bypasses any\n'
                                                 'view or template '
                                                 'environments, including HTML '
                                                 'escaping, which may\n'
                                                 'expose this application to '
                                                 'cross-site scripting (XSS) '
                                                 'vulnerabilities.\n'
                                                 'Consider using a view '
                                                 'technology such as '
                                                 'JavaServer Faces (JSFs) '
                                                 'which\n'
                                                 'automatically escapes HTML '
                                                 'views.',
                                  'display_name': 'NoDirectResponseWriter',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'no direct response writer'},
    'NoDirectWriteToResponsewriter': {   'categories': ['security'],
                                         'description': 'Detected directly '
                                                        'writing or similar in '
                                                        "'http.ResponseWriter.write()'.\n"
                                                        'This bypasses HTML '
                                                        'escaping that '
                                                        'prevents cross-site '
                                                        'scripting\n'
                                                        'vulnerabilities. '
                                                        'Instead, use the '
                                                        "'html/template' "
                                                        'package\n'
                                                        'and render data using '
                                                        "'template.Execute()'.",
                                         'display_name': 'NoDirectWriteToResponsewriter',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'no direct write to '
                                                  'responsewriter'},
    'NoFprintfToResponsewriter': {   'categories': ['security'],
                                     'description': "Detected 'Fprintf' or "
                                                    'similar writing to '
                                                    "'http.ResponseWriter'.\n"
                                                    'This bypasses HTML '
                                                    'escaping that prevents '
                                                    'cross-site scripting\n'
                                                    'vulnerabilities. Instead, '
                                                    "use the 'html/template' "
                                                    'package\n'
                                                    'to render data to users.',
                                     'display_name': 'NoFprintfToResponsewriter',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'no fprintf to responsewriter'},
    'NoFractionalCpuLimits': {   'categories': ['security'],
                                 'description': 'When you set a fractional CPU '
                                                'limit on a container,\n'
                                                'the CPU cycles available will '
                                                'be throttled,\n'
                                                'even though most nodes can '
                                                'handle processes\n'
                                                'alternating between using '
                                                '100% of the CPU.',
                                 'display_name': 'NoFractionalCpuLimits',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'kubernetes: no fractional cpu '
                                          'limits'},
    'NoInterpolationInTag': {   'categories': ['security'],
                                'description': 'Detected template variable '
                                               'interpolation in an HTML tag.\n'
                                               'This is potentially vulnerable '
                                               'to cross-site scripting (XSS)\n'
                                               'attacks because a malicious '
                                               'actor has control over HTML\n'
                                               'but without the need to use '
                                               'escaped characters. Use '
                                               'explicit\n'
                                               'tags instead.',
                                'display_name': 'NoInterpolationInTag',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'no interpolation in tag'},
    'NoInterpolationJsTemplateString': {   'categories': ['security'],
                                           'description': 'Detected template '
                                                          'variable '
                                                          'interpolation in a '
                                                          'JavaScript template '
                                                          'string. This is '
                                                          'potentially '
                                                          'vulnerable to '
                                                          'cross-site '
                                                          'scripting (XSS) '
                                                          'attacks because a '
                                                          'malicious actor has '
                                                          'control over '
                                                          'JavaScript but '
                                                          'without the need to '
                                                          'use escaped '
                                                          'characters. '
                                                          'Instead, obtain '
                                                          'this variable '
                                                          'outside of the '
                                                          'template string and '
                                                          'ensure your '
                                                          'template is '
                                                          'properly escaped.',
                                           'display_name': 'NoInterpolationJsTemplateString',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'no interpolation js '
                                                    'template string'},
    'NoIoWritestringToResponsewriter': {   'categories': ['security'],
                                           'description': 'Detected '
                                                          "'io.WriteString()' "
                                                          'writing directly to '
                                                          "'http.ResponseWriter'.\n"
                                                          'This bypasses HTML '
                                                          'escaping that '
                                                          'prevents cross-site '
                                                          'scripting\n'
                                                          'vulnerabilities. '
                                                          'Instead, use the '
                                                          "'html/template' "
                                                          'package\n'
                                                          'to render data to '
                                                          'users.',
                                           'display_name': 'NoIoWritestringToResponsewriter',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'no io writestring to '
                                                    'responsewriter'},
    'NoNullCipher': {   'categories': ['security'],
                        'description': 'NullCipher was detected. This will not '
                                       'encrypt anything;\n'
                                       'the cipher text will be the same as '
                                       'the plain text. Use\n'
                                       'a valid, secure cipher: '
                                       'Cipher.getInstance("AES/CBC/PKCS7PADDING").\n'
                                       'See '
                                       'https://owasp.org/www-community/Using_the_Java_Cryptographic_Extensions\n'
                                       'for more information.',
                        'display_name': 'NoNullCipher',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'no null cipher'},
    'NoNullStringField': {   'categories': ['security'],
                             'description': 'Avoid using null on string-based '
                                            'fields such as CharField and '
                                            'TextField. If a string-based '
                                            'field\n'
                                            'has null=True, that means it has '
                                            'two possible values for "no '
                                            'data": NULL, and the empty '
                                            'string. In\n'
                                            "most cases, it's redundant to "
                                            'have two possible values for "no '
                                            'data;" the Django convention is '
                                            'to\n'
                                            'use the empty string, not NULL.',
                             'display_name': 'NoNullStringField',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'no null string field'},
    'NoPrintfInResponsewriter': {   'categories': ['security'],
                                    'description': "Detected 'printf' or "
                                                   'similar in '
                                                   "'http.ResponseWriter.write()'.\n"
                                                   'This bypasses HTML '
                                                   'escaping that prevents '
                                                   'cross-site scripting\n'
                                                   'vulnerabilities. Instead, '
                                                   "use the 'html/template' "
                                                   'package\n'
                                                   'to render data to users.',
                                    'display_name': 'NoPrintfInResponsewriter',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'no printf in responsewriter'},
    'NoReplaceall': {   'categories': ['security'],
                        'description': 'The string method replaceAll is not '
                                       'supported in all versions of '
                                       'javascript, and is not supported by '
                                       'older browser versions. Consider using '
                                       'replace() with a regex as the first '
                                       'argument instead like '
                                       'mystring.replace(/bad/g, "good") '
                                       'instead of mystring.replaceAll("bad", '
                                       '"good") '
                                       '(https://discourse.threejs.org/t/replaceall-is-not-a-function/14585)',
                        'display_name': 'NoReplaceall',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'no replaceall'},
    'NoScriptlets': {   'categories': ['security'],
                        'description': 'JSP scriptlet detected. Scriptlets are '
                                       'difficult to use securely and\n'
                                       'are considered bad practice. See '
                                       'https://stackoverflow.com/a/3180202.\n'
                                       'Instead, consider migrating to JSF or '
                                       'using the Expression Language\n'
                                       "'${...}' with the escapeXml function "
                                       'in your JSP files.',
                        'display_name': 'NoScriptlets',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'no scriptlets'},
    'NoSetCiphers': {   'categories': ['security'],
                        'description': "The 'ssl' module disables insecure "
                                       'cipher suites by default. Therefore,\n'
                                       "use of 'set_ciphers()' should only be "
                                       'used when you have very specialized\n'
                                       'requirements. Otherwise, you risk '
                                       'lowering the security of the SSL '
                                       'channel.',
                        'display_name': 'NoSetCiphers',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'no set ciphers'},
    'NoStaticInitializationVector': {   'categories': ['security'],
                                        'description': 'Initialization Vectors '
                                                       '(IVs) for block '
                                                       'ciphers should be '
                                                       'randomly generated\n'
                                                       'each time they are '
                                                       'used. Using a static '
                                                       'IV means the same '
                                                       'plaintext\n'
                                                       'encrypts to the same '
                                                       'ciphertext every time, '
                                                       'weakening the '
                                                       'strength\n'
                                                       'of the encryption.',
                                        'display_name': 'NoStaticInitializationVector',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'no static initialization '
                                                 'vector'},
    'NoStringEqeq': {   'categories': ['security'],
                        'description': 'Strings should not be compared with '
                                       "'=='.\n"
                                       'This is a reference comparison '
                                       'operator.\n'
                                       "Use '.equals()' instead.",
                        'display_name': 'NoStringEqeq',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'no string eqeq'},
    'NoStringsAsBooleans': {   'categories': ['security'],
                               'description': 'Using strings as booleans in '
                                              'Python has unexpected results.\n'
                                              '`"one" and "two"` will return '
                                              '"two".\n'
                                              '`"one" or "two"` will return '
                                              '"one".\n'
                                              ' In Python, strings are truthy, '
                                              'and strings with a non-zero '
                                              'length evaluate to True.',
                               'display_name': 'NoStringsAsBooleans',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'no strings as booleans'},
    'NodeAesEcb': {   'categories': ['security'],
                      'description': 'AES with ECB mode is deterministic in '
                                     'nature and not suitable for encrypting '
                                     'large amount of repetitive data.',
                      'display_name': 'NodeAesEcb',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'node aes ecb'},
    'NodeAesNoiv': {   'categories': ['security'],
                       'description': 'AES algorithms requires an '
                                      'initialization vector (IV). Providing '
                                      'no or null IV in some implementation '
                                      'results to a 0 IV. Use of a '
                                      'deterministic IV makes dictionary '
                                      'attacks easier.',
                       'display_name': 'NodeAesNoiv',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'node aes noiv'},
    'NodeApiKey': {   'categories': ['security'],
                      'description': 'A hardcoded API Key is identified. Store '
                                     'it properly in an environment variable.',
                      'display_name': 'NodeApiKey',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'node api key'},
    'NodeCurlSslVerifyDisable': {   'categories': ['security'],
                                    'description': 'SSL Certificate '
                                                   'verification for node-curl '
                                                   'is disabled.',
                                    'display_name': 'NodeCurlSslVerifyDisable',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'node curl ssl verify disable'},
    'NodeDeserialize': {   'categories': ['security'],
                           'description': 'User controlled data in '
                                          "'unserialize()' or 'deserialize()' "
                                          'function can result in Object '
                                          'Injection or Remote Code Injection.',
                           'display_name': 'NodeDeserialize',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'node deserialize'},
    'NodeEntityExpansion': {   'categories': ['security'],
                               'description': 'User controlled data in XML '
                                              'Parsers can result in XML '
                                              'Internal Entity Processing '
                                              'vulnerabilities like in DoS.',
                               'display_name': 'NodeEntityExpansion',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'node entity expansion'},
    'NodeErrorDisclosure': {   'categories': ['security'],
                               'description': 'Error messages with stack '
                                              'traces can expose sensitive '
                                              'information about the '
                                              'application.',
                               'display_name': 'NodeErrorDisclosure',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'node error disclosure'},
    'NodeInsecureRandomGenerator': {   'categories': ['security'],
                                       'description': 'crypto.pseudoRandomBytes()/Math.random() '
                                                      'is a cryptographically '
                                                      'weak random number '
                                                      'generator.',
                                       'display_name': 'NodeInsecureRandomGenerator',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'node insecure random '
                                                'generator'},
    'NodeJwtNoneAlgorithm': {   'categories': ['security'],
                                'description': 'Algorithm is set to none for '
                                               'JWT token. This can nullify '
                                               'the integrity of JWT '
                                               'signature.',
                                'display_name': 'NodeJwtNoneAlgorithm',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'node jwt none algorithm'},
    'NodeKnexSqliInjection': {   'categories': ['security'],
                                 'description': 'Untrusted input concatinated '
                                                'with raw SQL query using knex '
                                                'raw()  or whereRaw() '
                                                'functions can result in SQL '
                                                'Injection.',
                                 'display_name': 'NodeKnexSqliInjection',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'node knex sqli injection'},
    'NodeLogicBypass': {   'categories': ['security'],
                           'description': 'User controlled data is used for '
                                          'application business logic decision '
                                          'making. This expose protected data '
                                          'or functionality.',
                           'display_name': 'NodeLogicBypass',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'node logic bypass'},
    'NodeMd5': {   'categories': ['security'],
                   'description': 'MD5 is a a weak hash which is known to have '
                                  'collision. Use a strong hashing function.',
                   'display_name': 'NodeMd5',
                   'file': '%(issue.file)s',
                   'line': '%(issue.line)s',
                   'severity': '1',
                   'title': 'node md5'},
    'NodeNosqliInjection': {   'categories': ['security'],
                               'description': 'Untrusted user input in '
                                              'findOne() function can result '
                                              'in NoSQL Injection.',
                               'display_name': 'NodeNosqliInjection',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'node nosqli injection'},
    'NodeNosqliJsInjection': {   'categories': ['security'],
                                 'description': 'Untrusted user input in '
                                                'MongoDB $where operator can '
                                                'result in NoSQL JavaScript '
                                                'Injection.',
                                 'display_name': 'NodeNosqliJsInjection',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'node nosqli js injection'},
    'NodePassword': {   'categories': ['security'],
                        'description': 'A hardcoded password in plain text is '
                                       'identified. Store it properly in an '
                                       'environment variable.',
                        'display_name': 'NodePassword',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'node password'},
    'NodePostgresSqli': {   'categories': ['security'],
                            'description': 'Detected string concatenation with '
                                           'a non-literal variable in a '
                                           'node-postgres\n'
                                           'JS SQL statement. This could lead '
                                           'to SQL injection if the variable '
                                           'is user-controlled\n'
                                           'and not properly sanitized. In '
                                           'order to prevent SQL injection,\n'
                                           'used parameterized queries or '
                                           'prepared statements instead.\n'
                                           'You can use parameterized '
                                           'statements like so:\n'
                                           "`client.query('SELECT $1 from "
                                           "table', [userinput])`",
                            'display_name': 'NodePostgresSqli',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'node postgres sqli'},
    'NodeSecret': {   'categories': ['security'],
                      'description': 'A hardcoded secret is identified. Store '
                                     'it properly in an environment variable.',
                      'display_name': 'NodeSecret',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'node secret'},
    'NodeSha1': {   'categories': ['security'],
                    'description': 'SHA1 is a a weak hash which is known to '
                                   'have collision. Use a strong hashing '
                                   'function.',
                    'display_name': 'NodeSha1',
                    'file': '%(issue.file)s',
                    'line': '%(issue.line)s',
                    'severity': '1',
                    'title': 'node sha1'},
    'NodeSqliInjection': {   'categories': ['security'],
                             'description': 'Untrusted input concatinated with '
                                            'raw SQL query can result in SQL '
                                            'Injection.',
                             'display_name': 'NodeSqliInjection',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'node sqli injection'},
    'NodeSsrf': {   'categories': ['security'],
                    'description': 'User controlled URL in http client '
                                   'libraries can result in Server Side '
                                   'Request Forgery (SSRF).',
                    'display_name': 'NodeSsrf',
                    'file': '%(issue.file)s',
                    'line': '%(issue.line)s',
                    'severity': '1',
                    'title': 'node ssrf'},
    'NodeTimingAttack': {   'categories': ['security'],
                            'description': "String comparisons using '===', "
                                           "'!==', '!=' and '==' is vulnerable "
                                           'to timing attacks. More info: '
                                           'https://snyk.io/blog/node-js-timing-attack-ccc-ctf/',
                            'display_name': 'NodeTimingAttack',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'node timing attack'},
    'NodeTlsReject': {   'categories': ['security'],
                         'description': 'Setting '
                                        "'NODE_TLS_REJECT_UNAUTHORIZED' to 0 "
                                        'will allow node server to accept self '
                                        'signed certificates and is not a '
                                        'secure behaviour.',
                         'display_name': 'NodeTlsReject',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'node tls reject'},
    'NodeUsername': {   'categories': ['security'],
                        'description': 'A hardcoded username in plain text is '
                                       'identified. Store it properly in an '
                                       'environment variable.',
                        'display_name': 'NodeUsername',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'node username'},
    'NodeWeakCrypto': {   'categories': ['security'],
                          'description': 'A weak or broken cryptographic '
                                         'algorithm was identified. Using '
                                         'these functions will introduce '
                                         'vulnerabilities or downgrade the '
                                         'security of your application.',
                          'display_name': 'NodeWeakCrypto',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'node weak crypto'},
    'NodeXpathInjection': {   'categories': ['security'],
                              'description': 'User controlled data in '
                                             'xpath.parse() can result in '
                                             'XPATH injection vulnerability.',
                              'display_name': 'NodeXpathInjection',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'node xpath injection'},
    'NodeXxe': {   'categories': ['security'],
                   'description': 'User controlled data in XML parsers can '
                                  'result in XML External or Internal Entity '
                                  '(XXE) Processing vulnerabilities',
                   'display_name': 'NodeXxe',
                   'file': '%(issue.file)s',
                   'line': '%(issue.line)s',
                   'severity': '1',
                   'title': 'node xxe'},
    'NonConstantSqlQuery': {   'categories': ['security'],
                               'description': 'Non-constant SQL query '
                                              'detected. Ensure this is not '
                                              'controlled\n'
                                              'by external data, otherwise '
                                              'this is a SQL injection.',
                               'display_name': 'NonConstantSqlQuery',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'non constant sql query'},
    'NonsensicalCommand': {   'categories': ['security'],
                              'description': 'Some commands such as `$CMD` do '
                                             'not make sense in a container. '
                                             'Do not use these.\n'
                                             '{"include": ["*dockerfile*", '
                                             '"*Dockerfile*"]}',
                              'display_name': 'NonsensicalCommand',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'dockerfile: nonsensical command'},
    'NontextFieldMustSetNullTrue': {   'categories': ['security'],
                                       'description': 'null=True should be set '
                                                      'if blank=True is set on '
                                                      'non-text fields.',
                                       'display_name': 'NontextFieldMustSetNullTrue',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'nontext field must set null '
                                                'true'},
    'ObjectDeserialization': {   'categories': ['security'],
                                 'description': 'Found object deserialization '
                                                'using ObjectInputStream. '
                                                'Deserializing entire\n'
                                                'Java objects is dangerous '
                                                'because malicious actors can '
                                                'create Java object\n'
                                                'streams with unintended '
                                                'consequences. Ensure that the '
                                                'objects being deserialized\n'
                                                'are not user-controlled. If '
                                                'this must be done, consider '
                                                'using HMACs to sign\n'
                                                'the data stream to make sure '
                                                'it is not tampered with, or '
                                                'consider only\n'
                                                'transmitting object fields '
                                                'and populating a new object.',
                                 'display_name': 'ObjectDeserialization',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'object deserialization'},
    'OgnlInjection': {   'categories': ['security'],
                         'description': 'A expression is built with a dynamic '
                                        'value. The source of the value(s) '
                                        'should be verified to avoid that '
                                        'unfiltered values fall into this '
                                        'risky code evaluation.',
                         'display_name': 'OgnlInjection',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'ognl injection'},
    'OpenNeverClosed': {   'categories': ['security'],
                           'description': 'file object opened without '
                                          'corresponding close',
                           'display_name': 'OpenNeverClosed',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'open never closed'},
    'OpenRedirect': {   'categories': ['security'],
                        'description': 'Data from request is passed to '
                                       'redirect().\n'
                                       'This is an open redirect and could be '
                                       'exploited.\n'
                                       "Consider using 'url_for()' to generate "
                                       'links to known locations.\n'
                                       'If you must use a URL to unknown '
                                       "pages, consider using 'urlparse()'\n"
                                       'or similar and checking if the '
                                       "'netloc' property is the same as\n"
                                       "your site's host name. See the "
                                       'references for more information.',
                        'display_name': 'OpenRedirect',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'open redirect'},
    'OsSystemInjection': {   'categories': ['security'],
                             'description': 'User data detected in os.system. '
                                            'This could be vulnerable to a '
                                            'command injection and should be '
                                            'avoided. If this must be done, '
                                            "use the 'subprocess' module "
                                            'instead and pass the arguments as '
                                            'a list.',
                             'display_name': 'OsSystemInjection',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'os system injection'},
    'OverlyPermissiveFilePermission': {   'categories': ['security'],
                                          'description': 'It is generally a '
                                                         'bad practices to set '
                                                         'overly permissive '
                                                         'file permission such '
                                                         'as read+write+exec '
                                                         'for all users.\n'
                                                         'If the file affected '
                                                         'is a configuration, '
                                                         'a binary, a script '
                                                         'or sensitive data, '
                                                         'it can lead to '
                                                         'privilege escalation '
                                                         'or information '
                                                         'leakage.',
                                          'display_name': 'OverlyPermissiveFilePermission',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'overly permissive file '
                                                   'permission'},
    'ParamikoExecCommand': {   'categories': ['security'],
                               'description': 'Unverified SSL context '
                                              'detected. This will permit '
                                              'insecure connections without '
                                              'verifying\n'
                                              'SSL certificates. Use '
                                              "'ssl.create_default_context()' "
                                              'instead.',
                               'display_name': 'ParamikoExecCommand',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'paramiko exec command'},
    'ParamikoImplicitTrustHostKey': {   'categories': ['security'],
                                        'description': 'Detected a paramiko '
                                                       'host key policy that '
                                                       'implicitly trusts a '
                                                       "server's\n"
                                                       'host key. Host keys '
                                                       'should be verified to '
                                                       'ensure the connection\n'
                                                       'is not to a malicious '
                                                       'server. Use '
                                                       'RejectPolicy or a '
                                                       'custom subclass\n'
                                                       'instead.',
                                        'display_name': 'ParamikoImplicitTrustHostKey',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'paramiko implicit trust host '
                                                 'key'},
    'PassBodyFn': {   'categories': ['security'],
                      'description': '`pass` is the body of function $X. '
                                     'Consider removing this or raise '
                                     'NotImplementedError() if this is a TODO',
                      'display_name': 'PassBodyFn',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'pass body fn'},
    'PassBodyRange': {   'categories': ['security'],
                         'description': '`pass` is the body of for $X in $Y. '
                                        'Consider removing this or raise '
                                        'NotImplementedError() if this is a '
                                        'TODO',
                         'display_name': 'PassBodyRange',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'pass body range'},
    'PasswordEmptyString': {   'categories': ['security'],
                               'description': "'$VAR' is the empty string and "
                                              'is being used to set the '
                                              "password on '$MODEL'.\n"
                                              'If you meant to set an unusable '
                                              'password, set the password to '
                                              'None or call\n'
                                              "'set_unusable_password()'.",
                               'display_name': 'PasswordEmptyString',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'password empty string'},
    'PathJoinResolveTraversal': {   'categories': ['security'],
                                    'description': 'Possible writing outside '
                                                   'of the destination,\n'
                                                   'make sure that the target '
                                                   'path is nested in the '
                                                   'intended destination',
                                    'display_name': 'PathJoinResolveTraversal',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'path join resolve traversal'},
    'PathTraversalFileName': {   'categories': ['security'],
                                 'description': 'Data from request is passed '
                                                'to a file name `$FILE`.\n'
                                                'This is a path traversal '
                                                'vulnerability: '
                                                'https://owasp.org/www-community/attacks/Path_Traversal\n'
                                                'To mitigate, consider using '
                                                'os.path.abspath or '
                                                'os.path.realpath or Path '
                                                'library.',
                                 'display_name': 'PathTraversalFileName',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'path traversal file name'},
    'PathTraversalInsideZipExtraction': {   'categories': ['security'],
                                            'description': 'File traversal '
                                                           'when extracting '
                                                           'zip archive',
                                            'display_name': 'PathTraversalInsideZipExtraction',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'path traversal inside '
                                                     'zip extraction'},
    'PathTraversalJoin': {   'categories': ['security'],
                             'description': 'Data from request is passed to '
                                            'os.path.join() and to open().\n'
                                            'This is a path traversal '
                                            'vulnerability: '
                                            'https://owasp.org/www-community/attacks/Path_Traversal\n'
                                            'To mitigate, consider using '
                                            'os.path.abspath or '
                                            'os.path.realpath or Path library.',
                             'display_name': 'PathTraversalJoin',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'path traversal join'},
    'PathTraversalOpen': {   'categories': ['security'],
                             'description': 'Found request data in a call to '
                                            "'open'. Ensure the request data "
                                            'is validated or sanitized, '
                                            'otherwise it could result in path '
                                            'traversal attacks.',
                             'display_name': 'PathTraversalOpen',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'path traversal open'},
    'PdbRemove': {   'categories': ['security'],
                     'description': 'pdb is an interactive debugging tool and '
                                    'you may have forgotten to remove it '
                                    'before committing your code',
                     'display_name': 'PdbRemove',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'pdb remove'},
    'PermissiveCors': {   'categories': ['security'],
                          'description': 'https://find-sec-bugs.github.io/bugs.htm#PERMISSIVE_CORS\n'
                                         'Permissive CORS policy will allow a '
                                         'malicious application to communicate '
                                         'with the victim application in an '
                                         'inappropriate way, leading to '
                                         'spoofing, data theft, relay and '
                                         'other attacks.',
                          'display_name': 'PermissiveCors',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'permissive cors'},
    'Pg8000Sqli': {   'categories': ['security'],
                      'description': 'Detected string concatenation with a '
                                     'non-literal variable in a pg8000\n'
                                     'Python SQL statement. This could lead to '
                                     'SQL injection if the variable is '
                                     'user-controlled\n'
                                     'and not properly sanitized. In order to '
                                     'prevent SQL injection,\n'
                                     'used parameterized queries or prepared '
                                     'statements instead.\n'
                                     'You can create parameterized queries '
                                     'like so:\n'
                                     '\'conn.run("SELECT :value FROM table", '
                                     "value=myvalue)'.\n"
                                     'You can also create prepared statements '
                                     "with 'conn.prepare':\n"
                                     '\'conn.prepare("SELECT (:v) FROM '
                                     'table")\'',
                      'display_name': 'Pg8000Sqli',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'pg8000 sqli'},
    'PgOrmSqli': {   'categories': ['security'],
                     'description': 'Detected string concatenation with a '
                                    'non-literal variable in a go-pg ORM\n'
                                    'SQL statement. This could lead to SQL '
                                    'injection if the variable is '
                                    'user-controlled\n'
                                    'and not properly sanitized. In order to '
                                    'prevent SQL injection,\n'
                                    'do not use strings concatenated with '
                                    'user-controlled input.\n'
                                    'Instead, use parameterized statements.',
                     'display_name': 'PgOrmSqli',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'pg orm sqli'},
    'PgSqli': {   'categories': ['security'],
                  'description': 'Detected string concatenation with a '
                                 'non-literal variable in a go-pg\n'
                                 'SQL statement. This could lead to SQL '
                                 'injection if the variable is '
                                 'user-controlled\n'
                                 'and not properly sanitized. In order to '
                                 'prevent SQL injection,\n'
                                 'used parameterized queries instead of string '
                                 'concatenation. You can use parameterized '
                                 'queries like so:\n'
                                 "'(SELECT ? FROM table, data1)'",
                  'display_name': 'PgSqli',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'pg sqli'},
    'PgxSqli': {   'categories': ['security'],
                   'description': 'Detected string concatenation with a '
                                  'non-literal variable in a pgx Go SQL '
                                  'statement. This could lead to SQL injection '
                                  'if the variable is user-controlled and not '
                                  'properly sanitized. In order to prevent SQL '
                                  'injection, used parameterized queries '
                                  'instead. You can use parameterized queries '
                                  'like so: (`SELECT $1 FROM table`, `data1)',
                   'display_name': 'PgxSqli',
                   'file': '%(issue.file)s',
                   'line': '%(issue.line)s',
                   'severity': '1',
                   'title': 'pgx sqli'},
    'PhantomInjection': {   'categories': ['security'],
                            'description': 'If unverified user data can reach '
                                           'the `phantom` page methods it can '
                                           'result in Server-Side Request '
                                           'Forgery vulnerabilities',
                            'display_name': 'PhantomInjection',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'phantom injection'},
    'PhantomSsrf': {   'categories': ['security'],
                       'description': 'If unverified user data can reach the '
                                      '`phantom` methods it can result in '
                                      'Server-Side Request Forgery '
                                      'vulnerabilities.',
                       'display_name': 'PhantomSsrf',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'phantom ssrf'},
    'PhpinfoUse': {   'categories': ['security'],
                      'description': "The 'phpinfo' function may reveal "
                                     'sensitive information about your '
                                     'environment.',
                      'display_name': 'PhpinfoUse',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'phpinfo use'},
    'PlaywrightAddinitscriptCodeInjection': {   'categories': ['security'],
                                                'description': 'If unverified '
                                                               'user data can '
                                                               'reach the '
                                                               '`addInitScript` '
                                                               'method it can '
                                                               'result in '
                                                               'Server-Side '
                                                               'Request '
                                                               'Forgery '
                                                               'vulnerabilities',
                                                'display_name': 'PlaywrightAddinitscriptCodeInjection',
                                                'file': '%(issue.file)s',
                                                'line': '%(issue.line)s',
                                                'severity': '1',
                                                'title': 'playwright '
                                                         'addinitscript code '
                                                         'injection'},
    'PlaywrightEvaluateArgInjection': {   'categories': ['security'],
                                          'description': 'If unverified user '
                                                         'data can reach the '
                                                         '`evaluate` method it '
                                                         'can result in '
                                                         'Server-Side Request '
                                                         'Forgery '
                                                         'vulnerabilities',
                                          'display_name': 'PlaywrightEvaluateArgInjection',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'playwright evaluate arg '
                                                   'injection'},
    'PlaywrightEvaluateCodeInjection': {   'categories': ['security'],
                                           'description': 'If unverified user '
                                                          'data can reach the '
                                                          '`evaluate` method '
                                                          'it can result in '
                                                          'Server-Side Request '
                                                          'Forgery '
                                                          'vulnerabilities',
                                           'display_name': 'PlaywrightEvaluateCodeInjection',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'playwright evaluate code '
                                                    'injection'},
    'PlaywrightExposedChromeDevtools': {   'categories': ['security'],
                                           'description': 'Remote debugging '
                                                          'protocol does not '
                                                          'perform any '
                                                          'authentication, so '
                                                          'exposing it too '
                                                          'widely can be a '
                                                          'security risk.',
                                           'display_name': 'PlaywrightExposedChromeDevtools',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'playwright exposed chrome '
                                                    'devtools'},
    'PlaywrightGotoInjection': {   'categories': ['security'],
                                   'description': 'If unverified user data can '
                                                  'reach the `goto` method it '
                                                  'can result in Server-Side '
                                                  'Request Forgery '
                                                  'vulnerabilities',
                                   'display_name': 'PlaywrightGotoInjection',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'playwright goto injection'},
    'PlaywrightSetcontentInjection': {   'categories': ['security'],
                                         'description': 'If unverified user '
                                                        'data can reach the '
                                                        '`setContent` method '
                                                        'it can result in '
                                                        'Server-Side Request '
                                                        'Forgery '
                                                        'vulnerabilities',
                                         'display_name': 'PlaywrightSetcontentInjection',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'playwright setcontent '
                                                  'injection'},
    'PlaywrightSsrf': {   'categories': ['security'],
                          'description': 'If unverified user data can reach '
                                         'the `puppeteer` methods it can '
                                         'result in Server-Side Request '
                                         'Forgery vulnerabilities.',
                          'display_name': 'PlaywrightSsrf',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'playwright ssrf'},
    'PossibleNginxH2cSmuggling': {   'categories': ['security'],
                                     'description': 'Conditions for Nginx H2C '
                                                    'smuggling identified. H2C '
                                                    'smuggling allows '
                                                    'upgrading HTTP/1.1 '
                                                    'connections to '
                                                    'lesser-known HTTP/2 over '
                                                    'cleartext (h2c) '
                                                    'connections which can '
                                                    'allow a bypass of reverse '
                                                    'proxy access controls,and '
                                                    'lead to long-lived, '
                                                    'unrestricted HTTP traffic '
                                                    'directly to back-end '
                                                    'servers. To mitigate: '
                                                    'WebSocket support '
                                                    'required: Allow only the '
                                                    'value websocket for '
                                                    'HTTP/1.1 upgrade headers '
                                                    '(e.g., Upgrade: '
                                                    'websocket). WebSocket '
                                                    'support not required: Do '
                                                    'not forward Upgrade '
                                                    'headers.',
                                     'display_name': 'PossibleNginxH2cSmuggling',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'nginx: possible nginx h2c '
                                              'smuggling'},
    'PotentialDosViaDecompressionBomb': {   'categories': ['security'],
                                            'description': 'Detected a '
                                                           'possible '
                                                           'denial-of-service '
                                                           'via a zip bomb '
                                                           'attack. By '
                                                           'limiting the max '
                                                           'bytes read, you '
                                                           'can mitigate this '
                                                           'attack. '
                                                           '`io.CopyN()` can '
                                                           'specify a size. '
                                                           'Refer to '
                                                           'https://bomb.codes/ '
                                                           'to learn more '
                                                           'about this attack '
                                                           'and other ways to '
                                                           'mitigate it.',
                                            'display_name': 'PotentialDosViaDecompressionBomb',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'potential dos via '
                                                     'decompression bomb'},
    'PprofDebugExposure': {   'categories': ['security'],
                              'description': "The profiling 'pprof' endpoint "
                                             'is automatically exposed on '
                                             '/debug/pprof.\n'
                                             'This could leak information '
                                             'about the server.\n'
                                             'Instead, use `import '
                                             '"net/http/pprof"`. See\n'
                                             'https://www.farsightsecurity.com/blog/txt-record/go-remote-profiling-20161028/\n'
                                             'for more information and '
                                             'mitigation.',
                              'display_name': 'PprofDebugExposure',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'pprof debug exposure'},
    'PreferAptGet': {   'categories': ['security'],
                        'description': "'apt-get' is preferred as an "
                                       "unattended tool for stability. 'apt' "
                                       'is discouraged.\n'
                                       '{"include": ["*dockerfile*", '
                                       '"*Dockerfile*"]}',
                        'display_name': 'PreferAptGet',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'dockerfile: prefer apt get'},
    'PreferCopyOverAdd': {   'categories': ['security'],
                             'description': 'The ADD command will accept and '
                                            'include files from a URL.\n'
                                            'This potentially exposes the '
                                            'container to a man-in-the-middle '
                                            'attack.\n'
                                            'Since ADD can have this and other '
                                            'unexpected side effects, the use '
                                            'of\n'
                                            'the more explicit COPY command is '
                                            'preferred.\n'
                                            '\n'
                                            '{"include": ["*dockerfile*", '
                                            '"*Dockerfile*"]}',
                             'display_name': 'PreferCopyOverAdd',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'dockerfile: prefer copy over add'},
    'PreferJsonNotation': {   'categories': ['security'],
                              'description': 'Prefer JSON notation when using '
                                             'CMD or ENTRYPOINT. This allows '
                                             'signals to be passed from the '
                                             'OS.\n'
                                             '{"include": ["*dockerfile*", '
                                             '"*Dockerfile*"]}',
                              'display_name': 'PreferJsonNotation',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'dockerfile: prefer json notation'},
    'PregReplaceEval': {   'categories': ['security'],
                           'description': 'Calling preg_replace with user '
                                          'input in the pattern can lead to '
                                          'arbitrary\n'
                                          'code execution. The eval modifier '
                                          '(`/e`) evaluates the replacement '
                                          'argument\n'
                                          'as code.',
                           'display_name': 'PregReplaceEval',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'preg replace eval'},
    'PrivilegedContainer': {   'categories': ['security'],
                               'description': 'Container or pod is running in '
                                              'privileged mode. This grants '
                                              'the\n'
                                              'container the equivalent of '
                                              'root capabilities on the host '
                                              'machine. This\n'
                                              'can lead to container escapes, '
                                              'privilege escalation, and other '
                                              'security\n'
                                              'concerns. Remove the '
                                              "'privileged' key to disable "
                                              'this capability.',
                               'display_name': 'PrivilegedContainer',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'kubernetes: privileged container'},
    'ProhibitJqueryHtml': {   'categories': ['security'],
                              'description': "JQuery's html function can lead "
                                             'to XSS. If the string is plain '
                                             'test, use the text function '
                                             'instead.\n'
                                             'Otherwise, use a function that '
                                             "escapes html such as edx's "
                                             'HtmlUtils.setHtml.',
                              'display_name': 'ProhibitJqueryHtml',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'prohibit jquery html'},
    'PsycopgSqli': {   'categories': ['security'],
                       'description': 'Detected string concatenation with a '
                                      'non-literal variable in a psycopg2\n'
                                      'Python SQL statement. This could lead '
                                      'to SQL injection if the variable is '
                                      'user-controlled\n'
                                      'and not properly sanitized. In order to '
                                      'prevent SQL injection,\n'
                                      'used parameterized queries or prepared '
                                      'statements instead.\n'
                                      'You can use prepared statements by '
                                      "creating a 'sql.SQL' string. You can "
                                      'also use the pyformat binding style to '
                                      'create parameterized queries. For '
                                      'example:\n'
                                      "'cur.execute(SELECT * FROM table WHERE "
                                      "name=%s, user_input)'",
                       'display_name': 'PsycopgSqli',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'psycopg sqli'},
    'PuppeteerEvaluateArgInjection': {   'categories': ['security'],
                                         'description': 'If unverified user '
                                                        'data can reach the '
                                                        '`evaluate` method it '
                                                        'can result in '
                                                        'Server-Side Request '
                                                        'Forgery '
                                                        'vulnerabilities',
                                         'display_name': 'PuppeteerEvaluateArgInjection',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'puppeteer evaluate arg '
                                                  'injection'},
    'PuppeteerEvaluateCodeInjection': {   'categories': ['security'],
                                          'description': 'If unverified user '
                                                         'data can reach the '
                                                         '`evaluate` method it '
                                                         'can result in '
                                                         'Server-Side Request '
                                                         'Forgery '
                                                         'vulnerabilities',
                                          'display_name': 'PuppeteerEvaluateCodeInjection',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'puppeteer evaluate code '
                                                   'injection'},
    'PuppeteerExposedChromeDevtools': {   'categories': ['security'],
                                          'description': 'Remote debugging '
                                                         'protocol does not '
                                                         'perform any '
                                                         'authentication, so '
                                                         'exposing it too '
                                                         'widely can be a '
                                                         'security risk.',
                                          'display_name': 'PuppeteerExposedChromeDevtools',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'puppeteer exposed chrome '
                                                   'devtools'},
    'PuppeteerGotoInjection': {   'categories': ['security'],
                                  'description': 'If unverified user data can '
                                                 'reach the `goto` method it '
                                                 'can result in Server-Side '
                                                 'Request Forgery '
                                                 'vulnerabilities',
                                  'display_name': 'PuppeteerGotoInjection',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'puppeteer goto injection'},
    'PuppeteerSetcontentInjection': {   'categories': ['security'],
                                        'description': 'If unverified user '
                                                       'data can reach the '
                                                       '`setContent` method it '
                                                       'can result in '
                                                       'Server-Side Request '
                                                       'Forgery '
                                                       'vulnerabilities',
                                        'display_name': 'PuppeteerSetcontentInjection',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'puppeteer setcontent '
                                                 'injection'},
    'PuppeteerSsrf': {   'categories': ['security'],
                         'description': 'If unverified user data can reach the '
                                        '`puppeteer` methods it can result in '
                                        'Server-Side Request Forgery '
                                        'vulnerabilities.',
                         'display_name': 'PuppeteerSsrf',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'puppeteer ssrf'},
    'Python.requests.bestPractice.useRequestJsonShortcut': {   'categories': [   'security'],
                                                               'description': 'The '
                                                                              'requests '
                                                                              'library '
                                                                              'has '
                                                                              'a '
                                                                              'convenient '
                                                                              'shortcut '
                                                                              'for '
                                                                              'sending '
                                                                              'JSON '
                                                                              'requests,\n'
                                                                              'which '
                                                                              'lets '
                                                                              'you '
                                                                              'stop '
                                                                              'worrying '
                                                                              'about '
                                                                              'serializing '
                                                                              'the '
                                                                              'body '
                                                                              'yourself.\n'
                                                                              'To '
                                                                              'use '
                                                                              'it, '
                                                                              'replace '
                                                                              '`body=json.dumps(...)` '
                                                                              'with '
                                                                              '`json=...`.',
                                                               'display_name': 'Python.requests.bestPractice.useRequestJsonShortcut',
                                                               'file': '%(issue.file)s',
                                                               'line': '%(issue.line)s',
                                                               'severity': '1',
                                                               'title': 'python.requests.best '
                                                                        'practice.use '
                                                                        'request '
                                                                        'json '
                                                                        'shortcut'},
    'Python.requests.bestPractice.useResponseJsonShortcut': {   'categories': [   'security'],
                                                                'description': 'The '
                                                                               'requests '
                                                                               'library '
                                                                               'has '
                                                                               'a '
                                                                               'convenient '
                                                                               'shortcut '
                                                                               'for '
                                                                               'reading '
                                                                               'JSON '
                                                                               'responses,\n'
                                                                               'which '
                                                                               'lets '
                                                                               'you '
                                                                               'stop '
                                                                               'worrying '
                                                                               'about '
                                                                               'deserializing '
                                                                               'the '
                                                                               'response '
                                                                               'yourself.',
                                                                'display_name': 'Python.requests.bestPractice.useResponseJsonShortcut',
                                                                'file': '%(issue.file)s',
                                                                'line': '%(issue.line)s',
                                                                'severity': '1',
                                                                'title': 'python.requests.best '
                                                                         'practice.use '
                                                                         'response '
                                                                         'json '
                                                                         'shortcut'},
    'Python36CompatibilityPopen1': {   'categories': ['security'],
                                       'description': 'the `errors` argument '
                                                      'to Popen is only '
                                                      'available on Python '
                                                      '3.6+',
                                       'display_name': 'Python36CompatibilityPopen1',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'python36 compatibility '
                                                'Popen1'},
    'Python36CompatibilityPopen2': {   'categories': ['security'],
                                       'description': 'the `encoding` argument '
                                                      'to Popen is only '
                                                      'available on Python '
                                                      '3.6+',
                                       'display_name': 'Python36CompatibilityPopen2',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'python36 compatibility '
                                                'Popen2'},
    'Python36CompatibilitySsl': {   'categories': ['security'],
                                    'description': 'this function is only '
                                                   'available on Python 3.6+',
                                    'display_name': 'Python36CompatibilitySsl',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'python36 compatibility ssl'},
    'Python37CompatabilityOsModule': {   'categories': ['security'],
                                         'description': 'this function is only '
                                                        'available on Python '
                                                        '3.7+',
                                         'display_name': 'Python37CompatabilityOsModule',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'python37 compatability os '
                                                  'module'},
    'Python37CompatibilityHttpconn': {   'categories': ['security'],
                                         'description': 'HTTPConnection '
                                                        'blocksize keyword '
                                                        'argument is Python '
                                                        '3.7+ only',
                                         'display_name': 'Python37CompatibilityHttpconn',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'python37 compatibility '
                                                  'httpconn'},
    'Python37CompatibilityHttpsconn': {   'categories': ['security'],
                                          'description': 'HTTPSConnection '
                                                         'blocksize keyword '
                                                         'argument is Python '
                                                         '3.7+ only',
                                          'display_name': 'Python37CompatibilityHttpsconn',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'python37 compatibility '
                                                   'httpsconn'},
    'Python37CompatibilityImportlib': {   'categories': ['security'],
                                          'description': 'this function is '
                                                         'only available on '
                                                         'Python 3.7+',
                                          'display_name': 'Python37CompatibilityImportlib',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'python37 compatibility '
                                                   'importlib'},
    'Python37CompatibilityImportlib2': {   'categories': ['security'],
                                           'description': 'this module is only '
                                                          'available on Python '
                                                          '3.7+; use '
                                                          'importlib_resources '
                                                          'for older Python '
                                                          'versions',
                                           'display_name': 'Python37CompatibilityImportlib2',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'python37 compatibility '
                                                    'importlib2'},
    'Python37CompatibilityImportlib3': {   'categories': ['security'],
                                           'description': 'this module is only '
                                                          'available on Python '
                                                          '3.7+',
                                           'display_name': 'Python37CompatibilityImportlib3',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'python37 compatibility '
                                                    'importlib3'},
    'Python37CompatibilityIpv4network1': {   'categories': ['security'],
                                             'description': 'this function is '
                                                            'only available on '
                                                            'Python 3.7+',
                                             'display_name': 'Python37CompatibilityIpv4network1',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': 'python37 compatibility '
                                                      'ipv4network1'},
    'Python37CompatibilityIpv4network2': {   'categories': ['security'],
                                             'description': 'this function is '
                                                            'only available on '
                                                            'Python 3.7+',
                                             'display_name': 'Python37CompatibilityIpv4network2',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': 'python37 compatibility '
                                                      'ipv4network2'},
    'Python37CompatibilityIpv6network1': {   'categories': ['security'],
                                             'description': 'this function is '
                                                            'only available on '
                                                            'Python 3.7+',
                                             'display_name': 'Python37CompatibilityIpv6network1',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': 'python37 compatibility '
                                                      'ipv6network1'},
    'Python37CompatibilityIpv6network2': {   'categories': ['security'],
                                             'description': 'this function is '
                                                            'only available on '
                                                            'Python 3.7+',
                                             'display_name': 'Python37CompatibilityIpv6network2',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': 'python37 compatibility '
                                                      'ipv6network2'},
    'Python37CompatibilityLocale1': {   'categories': ['security'],
                                        'description': 'this function is only '
                                                       'available on Python '
                                                       '3.7+',
                                        'display_name': 'Python37CompatibilityLocale1',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'python37 compatibility '
                                                 'locale1'},
    'Python37CompatibilityMath1': {   'categories': ['security'],
                                      'description': 'this function is only '
                                                     'available on Python 3.7+',
                                      'display_name': 'Python37CompatibilityMath1',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'python37 compatibility math1'},
    'Python37CompatibilityMultiprocess1': {   'categories': ['security'],
                                              'description': 'this function is '
                                                             'only available '
                                                             'on Python 3.7+',
                                              'display_name': 'Python37CompatibilityMultiprocess1',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '1',
                                              'title': 'python37 compatibility '
                                                       'multiprocess1'},
    'Python37CompatibilityMultiprocess2': {   'categories': ['security'],
                                              'description': 'this function is '
                                                             'only available '
                                                             'on Python 3.7+',
                                              'display_name': 'Python37CompatibilityMultiprocess2',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '1',
                                              'title': 'python37 compatibility '
                                                       'multiprocess2'},
    'Python37CompatibilityOs1': {   'categories': ['security'],
                                    'description': 'this function is only '
                                                   'available on Python 3.7+',
                                    'display_name': 'Python37CompatibilityOs1',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'python37 compatibility os1'},
    'Python37CompatibilityOs2Ok2': {   'categories': ['security'],
                                       'description': 'this function is only '
                                                      'available on Python '
                                                      '3.7+',
                                       'display_name': 'Python37CompatibilityOs2Ok2',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'python37 compatibility os2 '
                                                'ok2'},
    'Python37CompatibilityPdb': {   'categories': ['security'],
                                    'description': 'this function is only '
                                                   'available on Python 3.7+',
                                    'display_name': 'Python37CompatibilityPdb',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'python37 compatibility pdb'},
    'Python37CompatibilityTextiowrapper': {   'categories': ['security'],
                                              'description': 'this function is '
                                                             'only available '
                                                             'on Python 3.7+',
                                              'display_name': 'Python37CompatibilityTextiowrapper',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '1',
                                              'title': 'python37 compatibility '
                                                       'textiowrapper'},
    'PythonDebuggerFound': {   'categories': ['security'],
                               'description': 'Importing the python debugger; '
                                              'did you mean to leave this in?',
                               'display_name': 'PythonDebuggerFound',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'python debugger found'},
    'PythonLoggerCredentialDisclosure': {   'categories': ['security'],
                                            'description': 'Logger call may be '
                                                           'exposing a secret '
                                                           'credential in '
                                                           '$FORMAT_STRING',
                                            'display_name': 'PythonLoggerCredentialDisclosure',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'python logger credential '
                                                     'disclosure'},
    'RaiseNotBaseException': {   'categories': ['security'],
                                 'description': 'In Python3, a runtime '
                                                '`TypeError` will be thrown if '
                                                'you attempt to raise an '
                                                'object or class which does '
                                                'not inherit from '
                                                '`BaseException`',
                                 'display_name': 'RaiseNotBaseException',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'raise not base exception'},
    'RandomFdExhaustion': {   'categories': ['security'],
                              'description': "Call to 'read()' without error "
                                             'checking is susceptible to file '
                                             'descriptor\n'
                                             'exhaustion. Consider using the '
                                             "'getrandom()' function.",
                              'display_name': 'RandomFdExhaustion',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'random fd exhaustion'},
    'RateLimitControl': {   'categories': ['security'],
                            'description': 'This application has API rate '
                                           'limiting controls.',
                            'display_name': 'RateLimitControl',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'rate limit control'},
    'RawHtmlConcat': {   'categories': ['security'],
                         'description': 'User controlled data in a HTML string '
                                        'may result in XSS',
                         'display_name': 'RawHtmlConcat',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'raw html concat'},
    'ReactControlledComponentPassword': {   'categories': ['security'],
                                            'description': 'Password can be '
                                                           'leaked if CSS '
                                                           'injection exists '
                                                           'on the page.',
                                            'display_name': 'ReactControlledComponentPassword',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'react controlled '
                                                     'component password'},
    'ReactCssInjection': {   'categories': ['security'],
                             'description': 'User controlled data in a `style` '
                                            'attribute is an anti-pattern that '
                                            'can lead to XSS vulnerabilities',
                             'display_name': 'ReactCssInjection',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'react css injection'},
    'ReactDangerouslysetinnerhtml': {   'categories': ['security'],
                                        'description': 'Setting HTML from code '
                                                       'is risky because it’s '
                                                       'easy to inadvertently '
                                                       'expose your users to a '
                                                       'cross-site scripting '
                                                       '(XSS) attack.',
                                        'display_name': 'ReactDangerouslysetinnerhtml',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'react '
                                                 'dangerouslysetinnerhtml'},
    'ReactFindDom': {   'categories': ['security'],
                        'description': 'findDOMNode is an escape hatch used to '
                                       'access the underlying DOM node. In '
                                       'most cases, use of this escape hatch '
                                       'is discouraged because it pierces the '
                                       'component abstraction.',
                        'display_name': 'ReactFindDom',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'react find dom'},
    'ReactHrefVar': {   'categories': ['security'],
                        'description': 'Detected a variable used in an anchor '
                                       "tag with the 'href' attribute. A "
                                       'malicious actor may be able to input '
                                       "the 'javascript:' URI, which could "
                                       'cause cross-site scripting (XSS). If '
                                       'you are generating a URL to a known '
                                       'host, hardcode the base link (or '
                                       'retrieve it from a configuration) and '
                                       'append the path. You may also consider '
                                       'funneling link generation through a '
                                       'safe method which sanitizes URLs for '
                                       "the 'javascript:' URI.",
                        'display_name': 'ReactHrefVar',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'react href var'},
    'ReactHtmlElementSpreading': {   'categories': ['security'],
                                     'description': 'It is a good practice to '
                                                    'avoid spreading for JSX '
                                                    'attributes. This prevents '
                                                    'accidentally\n'
                                                    'passing '
                                                    '`dangerouslySetInnerHTML` '
                                                    'to an element.',
                                     'display_name': 'ReactHtmlElementSpreading',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'react html element spreading'},
    'ReactHttpLeak': {   'categories': ['security'],
                         'description': "This HTML element '$EL' and attribute "
                                        "'$ATTR' together may load an external "
                                        'resource. This means that if dynamic '
                                        'content can enter this attribute it '
                                        'may be possible for an attacker to '
                                        'send HTTP requests to unintended '
                                        'locations which may leak data about '
                                        'your users. If this element is '
                                        'reaching out to a known host, '
                                        'consider hardcoding the host (or '
                                        'loading from a configuration) and '
                                        'appending the dynamic path. See '
                                        'https://github.com/cure53/HTTPLeaks '
                                        'for more information.',
                         'display_name': 'ReactHttpLeak',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'react http leak'},
    'ReactInsecureRequest': {   'categories': ['security'],
                                'description': 'Unencrypted request over HTTP '
                                               'detected.',
                                'display_name': 'ReactInsecureRequest',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'react insecure request'},
    'ReactJwtDecodedProperty': {   'categories': ['security'],
                                   'description': 'Property decoded from JWT '
                                                  'token without verifying and '
                                                  'cannot be trustworthy.',
                                   'display_name': 'ReactJwtDecodedProperty',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'react jwt decoded property'},
    'ReactJwtInLocalstorage': {   'categories': ['security'],
                                  'description': 'Storing JWT tokens in '
                                                 'localStorage known to be a '
                                                 'bad practice, consider '
                                                 'moving your tokens from '
                                                 'localStorage to a HTTP '
                                                 'cookie.',
                                  'display_name': 'ReactJwtInLocalstorage',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'react jwt in localstorage'},
    'ReactLegacyComponent': {   'categories': ['security'],
                                'description': 'Legacy component lifecycle was '
                                               'detected - $METHOD.',
                                'display_name': 'ReactLegacyComponent',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'react legacy component'},
    'ReactMarkdownInsecureHtml': {   'categories': ['security'],
                                     'description': 'Overwriting '
                                                    '`transformLinkUri` or '
                                                    '`transformImageUri` to '
                                                    'something insecure or '
                                                    'turning '
                                                    '`allowDangerousHtml` on, '
                                                    'will open code up to XSS '
                                                    'vectors.',
                                     'display_name': 'ReactMarkdownInsecureHtml',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'react markdown insecure html'},
    'ReactMissingNoopener': {   'categories': ['security'],
                                'description': "Missing 'noopener' on an "
                                               'anchor tag where '
                                               "target='_blank'. This could "
                                               'introduce\n'
                                               'a reverse tabnabbing '
                                               'vulnerability. Include '
                                               "'noopener' when using "
                                               "target='_blank'.",
                                'display_name': 'ReactMissingNoopener',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'react missing noopener'},
    'ReactMissingNoreferrer': {   'categories': ['security'],
                                  'description': 'This anchor tag with '
                                                 '\'target="_blank"\' is '
                                                 "missing 'noreferrer'.\n"
                                                 'A page opened with '
                                                 '\'target="_blank"\' can '
                                                 'access the window object of '
                                                 'the origin page.\n'
                                                 'This means it can manipulate '
                                                 "the 'window.opener' "
                                                 'property, which could '
                                                 'redirect the origin page to '
                                                 'a malicious URL.\n'
                                                 'This is called reverse '
                                                 'tabnabbing. To prevent this, '
                                                 "include 'rel=noreferrer' on "
                                                 'this tag.',
                                  'display_name': 'ReactMissingNoreferrer',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'react missing noreferrer'},
    'ReactNoRefs': {   'categories': ['security'],
                       'description': '`ref` usage found, refs give direct DOM '
                                      'access and may create a possibility for '
                                      'XSS',
                       'display_name': 'ReactNoRefs',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'react no refs'},
    'ReactPropsInState': {   'categories': ['security'],
                             'description': 'It is a bad practice to stop the '
                                            'data flow in rendering by copying '
                                            'props into state.',
                             'display_name': 'ReactPropsInState',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'react props in state'},
    'ReactPropsInjection': {   'categories': ['security'],
                               'description': 'Inject arbitrary props into the '
                                              'new element. It may introduce '
                                              'an XSS vulnerability.',
                               'display_name': 'ReactPropsInjection',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'react props injection'},
    'ReactPropsSpreading': {   'categories': ['security'],
                               'description': 'It is a good practice to avoid '
                                              'spreading for JSX attributes. '
                                              'This forces the code to be '
                                              'explicit about which props are '
                                              'given to the component. This '
                                              'avoids situations where '
                                              'warnings are caused by invalid '
                                              'HTML props passed to HTML '
                                              'elements, and further, it '
                                              'avoids passing unintentional '
                                              'extra props by malicious '
                                              'actors. Instead, consider '
                                              'explicitly passing props to the '
                                              'component.',
                               'display_name': 'ReactPropsSpreading',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'react props spreading'},
    'ReactRouterRedirect': {   'categories': ['security'],
                               'description': 'User controlled data in '
                                              '<Redirect /> can lead to '
                                              'unpredicted redirects.',
                               'display_name': 'ReactRouterRedirect',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'react router redirect'},
    'ReactStyledComponentsInjection': {   'categories': ['security'],
                                          'description': 'User controlled data '
                                                         'in a styled '
                                                         "component's css is "
                                                         'an anti-pattern that '
                                                         'can lead to XSS '
                                                         'vulnerabilities',
                                          'display_name': 'ReactStyledComponentsInjection',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'react styled components '
                                                   'injection'},
    'ReactUnsanitizedMethod': {   'categories': ['security'],
                                  'description': 'User controlled data in a '
                                                 'insertAdjacentHTML, '
                                                 'document.write or '
                                                 'document.writeln is an '
                                                 'anti-pattern that can lead '
                                                 'to XSS vulnerabilities',
                                  'display_name': 'ReactUnsanitizedMethod',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'react unsanitized method'},
    'ReactUnsanitizedProperty': {   'categories': ['security'],
                                    'description': 'User controlled data in a '
                                                   '`$X` is an anti-pattern '
                                                   'that can lead to XSS '
                                                   'vulnerabilities',
                                    'display_name': 'ReactUnsanitizedProperty',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'react unsanitized property'},
    'ReflectMakefunc': {   'categories': ['security'],
                           'description': "'reflect.MakeFunc' detected. This "
                                          'will sidestep protections that are\n'
                                          "normally afforded by Go's type "
                                          'system. Audit this call and be sure '
                                          'that\n'
                                          'user input cannot be used to affect '
                                          'the code generated by MakeFunc;\n'
                                          'otherwise, you will have a serious '
                                          'security vulnerability.',
                           'display_name': 'ReflectMakefunc',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'reflect makefunc'},
    'ReflectedDataHttpresponse': {   'categories': ['security'],
                                     'description': 'Found request data '
                                                    'reflected into '
                                                    'HttpResponse. This could '
                                                    'be vulnerable to XSS. '
                                                    'Ensure the request data '
                                                    'is properly escaped or '
                                                    'sanitzed.',
                                     'display_name': 'ReflectedDataHttpresponse',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'reflected data httpresponse'},
    'ReflectedDataHttpresponsebadrequest': {   'categories': ['security'],
                                               'description': 'Found request '
                                                              'data reflected '
                                                              'into '
                                                              'HttpResponseBadRequest. '
                                                              'This could be '
                                                              'vulnerable to '
                                                              'XSS. Ensure the '
                                                              'request data is '
                                                              'properly '
                                                              'escaped or '
                                                              'sanitzed.',
                                               'display_name': 'ReflectedDataHttpresponsebadrequest',
                                               'file': '%(issue.file)s',
                                               'line': '%(issue.line)s',
                                               'severity': '1',
                                               'title': 'reflected data '
                                                        'httpresponsebadrequest'},
    'RegexDos': {   'categories': ['security'],
                    'description': 'Ensure that the regex used to compare with '
                                   'user supplied input is safe from regular '
                                   'expression denial of service.',
                    'display_name': 'RegexDos',
                    'file': '%(issue.file)s',
                    'line': '%(issue.line)s',
                    'severity': '1',
                    'title': 'regex dos'},
    'RegexInjectionDos': {   'categories': ['security'],
                             'description': 'User controlled data in RegExp() '
                                            'can make the application '
                                            'vulnerable to layer 7 DoS.',
                             'display_name': 'RegexInjectionDos',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'regex injection dos'},
    'RemovePackageCache': {   'categories': ['security'],
                              'description': 'The package cache was not '
                                             "deleted after running 'apt-get "
                                             "update', which increases the "
                                             'size of the image. Remove the '
                                             "package cache by appending '&& "
                                             "apt-get clean' at the end of "
                                             'apt-get command chain.\n'
                                             '{"include": ["*dockerfile*", '
                                             '"*Dockerfile*"]}',
                              'display_name': 'RemovePackageCache',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'dockerfile: remove package cache'},
    'RemovePackageLists': {   'categories': ['security'],
                              'description': 'The package lists were not '
                                             "deleted after running 'apt-get "
                                             "update', which increases the "
                                             'size of the image. Remove the '
                                             "package lists by appending '&& "
                                             "rm -rf /var/lib/apt/lists/*' at "
                                             'the end of apt-get command '
                                             'chain.\n'
                                             '{"include": ["*dockerfile*", '
                                             '"*Dockerfile*"]}',
                              'display_name': 'RemovePackageLists',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'dockerfile: remove package lists'},
    'RenderTemplateString': {   'categories': ['security'],
                                'description': 'Found a template created with '
                                               'string formatting. This is '
                                               'susceptible to server-side '
                                               'template injection and '
                                               'cross-site scripting attacks.',
                                'display_name': 'RenderTemplateString',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'render template string'},
    'RequestDataFileresponse': {   'categories': ['security'],
                                   'description': 'Found request data opening '
                                                  'a file into FileResponse. '
                                                  'This is dangerous because '
                                                  'an attacker could specify '
                                                  'an arbitrary file to read, '
                                                  'leaking data. Be sure to '
                                                  'validate or sanitize the '
                                                  'filename before using it in '
                                                  'FileResponse.',
                                   'display_name': 'RequestDataFileresponse',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'request data fileresponse'},
    'RequestDataWrite': {   'categories': ['security'],
                            'description': 'Found request data in '
                                           "'.write(...)'. This could be "
                                           'dangerous if a malicious\n'
                                           'actor is able to control data into '
                                           'sensitive files. For example, a '
                                           'malicious\n'
                                           'actor could force rolling of '
                                           'critical log files, or cause a '
                                           'denial-of-service\n'
                                           'by using up available disk space. '
                                           'Ensure content is validated.',
                            'display_name': 'RequestDataWrite',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'request data write'},
    'RequestHostUsed': {   'categories': ['security'],
                           'description': "'$http_host' uses the 'Host' "
                                          'request header which could be '
                                          'controlled by an attacker. Use the '
                                          "'$host' variable instead, which "
                                          'will use server names listed in the '
                                          "'server_name' directive.\n"
                                          '{"include": ["*conf*", "*nginx*", '
                                          '"*vhost*", "sites-available/*", '
                                          '"sites-enabled/*"]}',
                           'display_name': 'RequestHostUsed',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'nginx: request host used'},
    'RequestSessionHttpInWithContext': {   'categories': ['security'],
                                           'description': 'Detected a request '
                                                          "using 'http://'. "
                                                          'This request will '
                                                          'be unencrypted. Use '
                                                          "'https://' instead.",
                                           'display_name': 'RequestSessionHttpInWithContext',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'request session http in '
                                                    'with context'},
    'RequestSessionWithHttp': {   'categories': ['security'],
                                  'description': 'Detected a request using '
                                                 "'http://'. This request will "
                                                 'be unencrypted. Use '
                                                 "'https://' instead.",
                                  'display_name': 'RequestSessionWithHttp',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'request session with http'},
    'RequestWithHttp': {   'categories': ['security'],
                           'description': "Detected a request using 'http://'. "
                                          'This request will be unencrypted. '
                                          "Use 'https://' instead.",
                           'display_name': 'RequestWithHttp',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'request with http'},
    'RequireEncryption': {   'categories': ['security'],
                             'description': 'Initializing the a security '
                                            'context for Dask (`distributed`) '
                                            'without "require_encription" '
                                            'keyword argument may silently '
                                            'fail to provide security. See '
                                            'https://distributed.dask.org/en/latest/tls.html?highlight=require_encryption#parameters',
                             'display_name': 'RequireEncryption',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'require encryption'},
    'RequireRequest': {   'categories': ['security'],
                          'description': 'If an attacker controls the x in '
                                         'require(x) then they can cause code '
                                         'to load that was not intended to run '
                                         'on the server.',
                          'display_name': 'RequireRequest',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'require request'},
    'ResRenderInjection': {   'categories': ['security'],
                              'description': 'If an attacker controls the x in '
                                             'res.render(x) then they can '
                                             'cause code to load that was not '
                                             'intended to run on the server.',
                              'display_name': 'ResRenderInjection',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'res render injection'},
    'ResponseContainsUnsanitizedInput': {   'categories': ['security'],
                                            'description': 'Flask response '
                                                           'reflects '
                                                           'unsanitized user '
                                                           'input. This could '
                                                           'lead to a\n'
                                                           'cross-site '
                                                           'scripting '
                                                           'vulnerability '
                                                           '(https://owasp.org/www-community/attacks/xss/)\n'
                                                           'in which an '
                                                           'attacker causes '
                                                           'arbitrary code to '
                                                           'be executed in the '
                                                           "user's browser.\n"
                                                           'To prevent, please '
                                                           'sanitize the user '
                                                           'input, e.g. by '
                                                           'rendering the '
                                                           'response\n'
                                                           'in a Jinja2 '
                                                           'template (see '
                                                           'considerations in '
                                                           'https://flask.palletsprojects.com/en/1.0.x/security/).',
                                            'display_name': 'ResponseContainsUnsanitizedInput',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'response contains '
                                                     'unsanitized input'},
    'ReturnInInit': {   'categories': ['security'],
                        'description': '`return` should never appear inside a '
                                       'class __init__ function. This will '
                                       'cause a runtime error.',
                        'display_name': 'ReturnInInit',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'return in init'},
    'ReturnNotInFunction': {   'categories': ['security'],
                               'description': '`return` only makes sense '
                                              'inside a function',
                               'display_name': 'ReturnNotInFunction',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'return not in function'},
    'RobotsDenied': {   'categories': ['security'],
                        'description': 'This page denies crawlers from '
                                       'indexing the page. Remove the robots '
                                       "'meta' tag.",
                        'display_name': 'RobotsDenied',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'robots denied'},
    'RsaNoPadding': {   'categories': ['security'],
                        'description': 'Using RSA without OAEP mode weakens '
                                       'the encryption.',
                        'display_name': 'RsaNoPadding',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'rsa no padding'},
    'RubyEval': {   'categories': ['security'],
                    'description': 'Use of eval detected. This can run '
                                   'arbitrary code. Ensure external data\n'
                                   'does not reach here, otherwise this is a '
                                   'security vulnerability.\n'
                                   'Consider other ways to do this without '
                                   'eval.',
                    'display_name': 'RubyEval',
                    'file': '%(issue.file)s',
                    'line': '%(issue.line)s',
                    'severity': '1',
                    'title': 'ruby eval'},
    'RubyJwtDecodeWithoutVerify': {   'categories': ['security'],
                                      'description': 'Detected the decoding of '
                                                     'a JWT token without a '
                                                     'verify step.\n'
                                                     'JWT tokens must be '
                                                     'verified before use, '
                                                     "otherwise the token's\n"
                                                     'integrity is unknown. '
                                                     'This means a malicious '
                                                     'actor could forge\n'
                                                     'a JWT token with any '
                                                     'claims.',
                                      'display_name': 'RubyJwtDecodeWithoutVerify',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'ruby jwt decode without '
                                               'verify'},
    'RubyJwtExposedCredentials': {   'categories': ['security'],
                                     'description': 'Password is exposed '
                                                    'through JWT token '
                                                    'payload. This is not '
                                                    'encrypted and\n'
                                                    'the password could be '
                                                    'compromised. Do not store '
                                                    'passwords in JWT tokens.',
                                     'display_name': 'RubyJwtExposedCredentials',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'ruby jwt exposed credentials'},
    'RubyJwtExposedData': {   'categories': ['security'],
                              'description': 'The object is passed strictly to '
                                             'jsonwebtoken.sign(...)\n'
                                             'Make sure that sensitive '
                                             'information is not exposed '
                                             'through JWT token payload.',
                              'display_name': 'RubyJwtExposedData',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'ruby jwt exposed data'},
    'RubyJwtHardcodedSecret': {   'categories': ['security'],
                                  'description': 'Hardcoded JWT secret or '
                                                 'private key is used.\n'
                                                 'This is a Insufficiently '
                                                 'Protected Credentials '
                                                 'weakness: '
                                                 'https://cwe.mitre.org/data/definitions/522.html\n'
                                                 'Consider using an '
                                                 'appropriate security '
                                                 'mechanism to protect the '
                                                 'credentials (e.g. keeping '
                                                 'secrets in environment '
                                                 'variables)',
                                  'display_name': 'RubyJwtHardcodedSecret',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'ruby jwt hardcoded secret'},
    'RubyJwtNoneAlg': {   'categories': ['security'],
                          'description': "Detected use of the 'none' algorithm "
                                         'in a JWT token.\n'
                                         "The 'none' algorithm assumes the "
                                         'integrity of the token has already\n'
                                         'been verified. This would allow a '
                                         'malicious actor to forge a JWT '
                                         'token\n'
                                         'that will automatically be verified. '
                                         "Do not explicitly use the 'none'\n"
                                         'algorithm. Instead, use an algorithm '
                                         "such as 'HS256'.",
                          'display_name': 'RubyJwtNoneAlg',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'ruby jwt none alg'},
    'RubyPgSqli': {   'categories': ['security'],
                      'description': 'Detected string concatenation with a '
                                     'non-literal variable in a pg\n'
                                     'Ruby SQL statement. This could lead to '
                                     'SQL injection if the variable is '
                                     'user-controlled\n'
                                     'and not properly sanitized. In order to '
                                     'prevent SQL injection,\n'
                                     'used parameterized queries or prepared '
                                     'statements instead.\n'
                                     'You can use parameterized queries like '
                                     'so:\n'
                                     "    `conn.exec_params('SELECT $1 AS a, "
                                     "$2 AS b, $3 AS c', [1, 2, nil])`\n"
                                     'And you can use prepared statements with '
                                     '`exec_prepared`.',
                      'display_name': 'RubyPgSqli',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'ruby pg sqli'},
    'RunAsNonRoot': {   'categories': ['security'],
                        'description': 'Container allows for running '
                                       'applications as root. This can result '
                                       'in\n'
                                       'privilege escalation attacks. Add '
                                       "'runAsNonRoot: true' in "
                                       "'securityContext'\n"
                                       'to prevent this.',
                        'display_name': 'RunAsNonRoot',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'kubernetes: run as non root'},
    'SandboxCodeInjection': {   'categories': ['security'],
                                'description': 'Unrusted data in `sandbox` can '
                                               'result in code injection.',
                                'display_name': 'SandboxCodeInjection',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'sandbox code injection'},
    'SaxXxe': {   'categories': ['security'],
                  'description': "Use of 'ondoctype' in 'sax' library "
                                 "detected. By default, 'sax'\n"
                                 "won't do anything with custom DTD entity "
                                 "definitions. If you're\n"
                                 'implementing a custom DTD entity definition, '
                                 'be sure not to introduce\n'
                                 'XML External Entity (XXE) vulnerabilities, '
                                 'or be absolutely sure that\n'
                                 'external entities received from a trusted '
                                 'source while processing XML.',
                  'display_name': 'SaxXxe',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'sax xxe'},
    'ScriptEngineInjection': {   'categories': ['security'],
                                 'description': 'Detected potential code '
                                                'injection using ScriptEngine. '
                                                'Ensure\n'
                                                'user-controlled data cannot '
                                                "enter '.eval()', otherwise, "
                                                'this is\n'
                                                'a code injection '
                                                'vulnerability.',
                                 'display_name': 'ScriptEngineInjection',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'script engine injection'},
    'SeamLogInjection': {   'categories': ['security'],
                            'description': 'Seam Logging API support an '
                                           'expression language to introduce '
                                           'bean property to log messages.\n'
                                           'The expression language can also '
                                           'be the source to unwanted code '
                                           'execution.\n'
                                           'In this context, an expression is '
                                           'built with a dynamic value.\n'
                                           'The source of the value(s) should '
                                           'be verified to avoid that '
                                           'unfiltered values fall into this '
                                           'risky code evaluation.',
                            'display_name': 'SeamLogInjection',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'seam log injection'},
    'SeccompConfinementDisabled': {   'categories': ['security'],
                                      'description': 'Container is explicitly '
                                                     'disabling seccomp '
                                                     'confinement. This runs '
                                                     'the\n'
                                                     'service in an '
                                                     'unrestricted state. '
                                                     "Remove 'seccompProfile: "
                                                     "unconfined' to\n"
                                                     'prevent this.',
                                      'display_name': 'SeccompConfinementDisabled',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'kubernetes: seccomp '
                                               'confinement disabled'},
    'SecureSetCookie': {   'categories': ['security'],
                           'description': 'Flask cookies should be handled '
                                          'securely by setting secure=True, '
                                          "httponly=True, and samesite='Lax' "
                                          'in\n'
                                          'response.set_cookie(...). If your '
                                          'situation calls for different '
                                          'settings, explicitly disable the '
                                          'setting.\n'
                                          'If you want to send the cookie over '
                                          'http, set secure=False.  If you '
                                          'want to let client-side JavaScript\n'
                                          'read the cookie, set '
                                          'httponly=False. If you want to '
                                          'attach cookies to requests for '
                                          'external sites,\n'
                                          'set samesite=None.',
                           'display_name': 'SecureSetCookie',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'secure set cookie'},
    'SequelizeEnforceTls': {   'categories': ['security'],
                               'description': 'If TLS is disabled on server '
                                              'side (Postgresql server), '
                                              'Sequelize establishes '
                                              'connection without TLS and no '
                                              'error will be thrown. To '
                                              'prevent MITN (Man In The '
                                              'Middle) attack, TLS must be '
                                              'enforce by Sequelize. Set "ssl: '
                                              'true" or define settings "ssl: '
                                              '{...}"',
                               'display_name': 'SequelizeEnforceTls',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'sequelize enforce tls'},
    'SequelizeRawQuery': {   'categories': ['security'],
                             'description': 'Avoiding SQL string '
                                            'concatenation: untrusted input '
                                            'concatinated with raw SQL query '
                                            'can result in SQL Injection. Data '
                                            'replacement or data binding '
                                            'should be used. See '
                                            'https://sequelize.org/master/manual/raw-queries.html',
                             'display_name': 'SequelizeRawQuery',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'sequelize raw query'},
    'SequelizeTls': {   'categories': ['security'],
                        'description': 'The Sequelize connection string '
                                       'indicates that database server does '
                                       'not use TLS. Non TLS connections are '
                                       'susceptible to man in the middle '
                                       '(MITM) attacks.',
                        'display_name': 'SequelizeTls',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'sequelize tls'},
    'SequelizeTlsCertValidation': {   'categories': ['security'],
                                      'description': 'The Sequelize connection '
                                                     'string indicates that '
                                                     'TLS certificate '
                                                     'vailidation of database '
                                                     'server is disabled. This '
                                                     'is equivalent to not '
                                                     'having TLS. An attacker '
                                                     'can present any invalid '
                                                     'certificate and '
                                                     'Sequelize will make '
                                                     'database connection '
                                                     'ignoring certificate '
                                                     'errors. This setting '
                                                     'make the connection '
                                                     'susceptible to man in '
                                                     'the middle (MITM) '
                                                     'attacks. Not applicable '
                                                     'to SQLite database.',
                                      'display_name': 'SequelizeTlsCertValidation',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'sequelize tls cert validation'},
    'SequelizeTlsDisabledCertValidation': {   'categories': ['security'],
                                              'description': 'Set '
                                                             '"rejectUnauthorized" '
                                                             'to false is a '
                                                             'convenient way '
                                                             'to resolve '
                                                             'certificate '
                                                             'error. But this '
                                                             'method is unsafe '
                                                             'because it '
                                                             'disables the '
                                                             'server '
                                                             'certificate '
                                                             'verification, '
                                                             'making the Node '
                                                             'app open to MITM '
                                                             'attack. '
                                                             '"rejectUnauthorized" '
                                                             'option must be '
                                                             'alway set to '
                                                             'True (default '
                                                             'value). With '
                                                             'self -signed '
                                                             'certificat or '
                                                             'custom CA, use '
                                                             '"ca" option to '
                                                             'define Root '
                                                             'Certicate. This '
                                                             'rule checks TLS '
                                                             'configuration '
                                                             'only for '
                                                             'Postgresql, '
                                                             'MariaDB and '
                                                             'MySQL. SQLite is '
                                                             'not really '
                                                             'concerned by TLS '
                                                             'configuration. '
                                                             'This rule could '
                                                             'be extended for '
                                                             'MSSQL, but the '
                                                             'dialectOptions '
                                                             'is specific for '
                                                             'Tedious.',
                                              'display_name': 'SequelizeTlsDisabledCertValidation',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '1',
                                              'title': 'sequelize tls disabled '
                                                       'cert validation'},
    'SequelizeWeakTls': {   'categories': ['security'],
                            'description': 'The Sequelize connection string '
                                           'indicates that an older version of '
                                           'TLS is in use. TLS1.0 and TLS1.1 '
                                           'are deprecated and should be used. '
                                           'By default, Sequelize use TLSv1.2 '
                                           "but it's recommended to use "
                                           'TLS1.3. Not applicable to SQLite '
                                           'database.',
                            'display_name': 'SequelizeWeakTls',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'sequelize weak tls'},
    'SequelizeWeakTlsVersion': {   'categories': ['security'],
                                   'description': 'TLS1.0 and TLS1.1 are '
                                                  'deprecated and should be '
                                                  'used anymore. By default, '
                                                  'NodeJS used TLSv1.2. So, '
                                                  'TLS min version must not be '
                                                  'downgrade to TLS1.0 or '
                                                  'TLS1.1. Enforce TLS1.3 is '
                                                  'hightly recommanded This '
                                                  'rule checks TLS '
                                                  'configuration only for '
                                                  'Postgresql, MariaDB and '
                                                  'MySQL. SQLite is not really '
                                                  'concerned by TLS '
                                                  'configuration. This rule '
                                                  'could be extended for '
                                                  'MSSQL, but the '
                                                  'dialectOptions is specific '
                                                  'for Tedious.',
                                   'display_name': 'SequelizeWeakTlsVersion',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'sequelize weak tls version'},
    'SerializetojsDeserialize': {   'categories': ['security'],
                                    'description': 'User controlled data in '
                                                   "'unserialize()' or "
                                                   "'deserialize()' function "
                                                   'can result in Object '
                                                   'Injection or Remote Code '
                                                   'Injection.',
                                    'display_name': 'SerializetojsDeserialize',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'serializetojs deserialize'},
    'ServerDangerousClassDeserialization': {   'categories': ['security'],
                                               'description': 'Using a '
                                                              'non-primitive '
                                                              'class with Java '
                                                              'RMI may be an '
                                                              'insecure '
                                                              'deserialization '
                                                              'vulnerability. '
                                                              'Depending\n'
                                                              'on the '
                                                              'underlying '
                                                              'implementation. '
                                                              'This object '
                                                              'could be '
                                                              'manipulated by '
                                                              'a malicious '
                                                              'actor allowing '
                                                              'them to\n'
                                                              'execute code on '
                                                              'your system. '
                                                              'Instead, use an '
                                                              'integer ID to '
                                                              'look up your '
                                                              'object, or '
                                                              'consider '
                                                              'alternative\n'
                                                              'serializiation '
                                                              'schemes such as '
                                                              'JSON.',
                                               'display_name': 'ServerDangerousClassDeserialization',
                                               'file': '%(issue.file)s',
                                               'line': '%(issue.line)s',
                                               'severity': '1',
                                               'title': 'server dangerous '
                                                        'class '
                                                        'deserialization'},
    'ServerDangerousObjectDeserialization': {   'categories': ['security'],
                                                'description': 'Using an '
                                                               'arbitrary '
                                                               'object '
                                                               "('Object "
                                                               "$PARAM') with "
                                                               'Java RMI is an '
                                                               'insecure '
                                                               'deserialization\n'
                                                               'vulnerability. '
                                                               'This object '
                                                               'can be '
                                                               'manipulated by '
                                                               'a malicious '
                                                               'actor allowing '
                                                               'them to '
                                                               'execute\n'
                                                               'code on your '
                                                               'system. '
                                                               'Instead, use '
                                                               'an integer ID '
                                                               'to look up '
                                                               'your object, '
                                                               'or consider '
                                                               'alternative\n'
                                                               'serializiation '
                                                               'schemes such '
                                                               'as JSON.',
                                                'display_name': 'ServerDangerousObjectDeserialization',
                                                'file': '%(issue.file)s',
                                                'line': '%(issue.line)s',
                                                'severity': '1',
                                                'title': 'server dangerous '
                                                         'object '
                                                         'deserialization'},
    'ServerSideTemplateInjection': {   'categories': ['security'],
                                       'description': 'Untrusted user input in '
                                                      "templating engine's "
                                                      'compile() function can '
                                                      'result in Remote Code '
                                                      'Execution via server '
                                                      'side template '
                                                      'injection.',
                                       'display_name': 'ServerSideTemplateInjection',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'server side template '
                                                'injection'},
    'ServletresponseWriterXss': {   'categories': ['security'],
                                    'description': 'Cross-site scripting '
                                                   'detected in '
                                                   'HttpServletResponse writer '
                                                   "with variable '$VAR'. "
                                                   'User\n'
                                                   'input was detected going '
                                                   'directly from the '
                                                   'HttpServletRequest into '
                                                   'output. Ensure your\n'
                                                   'data is properly encoded '
                                                   'using '
                                                   'org.owasp.encoder.Encode.forHtml: '
                                                   "'Encode.forHtml($VAR)'.",
                                    'display_name': 'ServletresponseWriterXss',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'servletresponse writer xss'},
    'SessionCookieMissingHttponly': {   'categories': ['security'],
                                        'description': 'A session cookie was '
                                                       'detected without '
                                                       "setting the 'HttpOnly' "
                                                       'flag.\n'
                                                       "The 'HttpOnly' flag "
                                                       'for cookies instructs '
                                                       'the browser to forbid\n'
                                                       'client-side scripts '
                                                       'from reading the '
                                                       'cookie which mitigates '
                                                       'XSS\n'
                                                       'attacks. Set the '
                                                       "'HttpOnly' flag by "
                                                       "setting 'HttpOnly' to "
                                                       "'true'\n"
                                                       'in the Options struct.',
                                        'display_name': 'SessionCookieMissingHttponly',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'session cookie missing '
                                                 'httponly'},
    'SessionCookieMissingSecure': {   'categories': ['security'],
                                      'description': 'A session cookie was '
                                                     'detected without setting '
                                                     "the 'Secure' flag.\n"
                                                     "The 'secure' flag for "
                                                     'cookies prevents the '
                                                     'client from '
                                                     'transmitting\n'
                                                     'the cookie over insecure '
                                                     'channels such as HTTP.  '
                                                     "Set the 'Secure'\n"
                                                     "flag by setting 'Secure' "
                                                     "to 'true' in the Options "
                                                     'struct.',
                                      'display_name': 'SessionCookieMissingSecure',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'session cookie missing secure'},
    'SetPipefail': {   'categories': ['security'],
                       'description': 'Only the exit code from the final '
                                      'command in this RUN instruction will be '
                                      "evaluated unless 'pipefail' is set.\n"
                                      'If you want to fail the command at any '
                                      "stage in the pipe, set 'pipefail' by "
                                      'including \'SHELL ["/bin/bash", "-o", '
                                      '"pipefail", "-c"] before the command.\n'
                                      "If you're using alpine and don't have "
                                      'bash installed, communicate this '
                                      'explicitly with `SHELL ["/bin/ash"]`.\n'
                                      '\n'
                                      '{"include": ["*dockerfile*", '
                                      '"*Dockerfile*"]}',
                       'display_name': 'SetPipefail',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'dockerfile: set pipefail'},
    'ShelljsExecInjection': {   'categories': ['security'],
                                'description': 'If unverified user data can '
                                               'reach the `exec` method it can '
                                               'result in Remote Code '
                                               'Execution',
                                'display_name': 'ShelljsExecInjection',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'shelljs exec injection'},
    'ShelljsOsCommandExec': {   'categories': ['security'],
                                'description': 'User controlled data in '
                                               "'shelljs.exec()' can result in "
                                               'Remote OS Command Execution.',
                                'display_name': 'ShelljsOsCommandExec',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'shelljs os command exec'},
    'SkipTlsVerifyCluster': {   'categories': ['security'],
                                'description': 'Cluster is disabling TLS '
                                               'certificate verification when '
                                               'communicating with\n'
                                               'the server. This makes your '
                                               'HTTPS connections insecure. '
                                               'Remove the\n'
                                               "'insecure-skip-tls-verify: "
                                               "true' key to secure "
                                               'communication.',
                                'display_name': 'SkipTlsVerifyCluster',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'kubernetes: skip tls verify cluster'},
    'SkipTlsVerifyService': {   'categories': ['security'],
                                'description': 'Service is disabling TLS '
                                               'certificate verification when '
                                               'communicating with\n'
                                               'the server. This makes your '
                                               'HTTPS connections insecure. '
                                               'Remove the\n'
                                               "'insecureSkipTLSVerify: true' "
                                               'key to secure communication.',
                                'display_name': 'SkipTlsVerifyService',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'kubernetes: skip tls verify service'},
    'SpawnGitClone': {   'categories': ['security'],
                         'description': 'Git allows shell commands to be '
                                        'specified in ext URLs for remote '
                                        'repositories.\n'
                                        "For example, git clone 'ext::sh -c "
                                        "whoami% >&2' will execute the whoami "
                                        'command to try to connect to a remote '
                                        'repository.\n'
                                        'Make sure that the URL is not '
                                        'controlled by external input.',
                         'display_name': 'SpawnGitClone',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'spawn git clone'},
    'SpawnShellTrue': {   'categories': ['security'],
                          'description': "Found '$SPAWN' with '{shell: "
                                         "$SHELL}'. This is dangerous because "
                                         'this call will spawn\n'
                                         'the command using a shell process. '
                                         'Doing so propagates current shell '
                                         'settings and variables, which\n'
                                         'makes it much easier for a malicious '
                                         'actor to execute commands. Use '
                                         "'{shell: false}' instead.",
                          'display_name': 'SpawnShellTrue',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'spawn shell true'},
    'SpelInjection': {   'categories': ['security'],
                         'description': 'A Spring expression is built with a '
                                        'dynamic value. The source of the '
                                        'value(s) should be verified to avoid '
                                        'that unfiltered values fall into this '
                                        'risky code evaluation.',
                         'display_name': 'SpelInjection',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'spel injection'},
    'SpringActuatorFullyEnabled': {   'categories': ['security'],
                                      'description': 'Spring Boot Actuator is '
                                                     'fully enabled. This '
                                                     'exposes sensitive '
                                                     'endpoints such as '
                                                     '/actuator/env, '
                                                     '/actuator/logfile, '
                                                     '/actuator/heapdump and '
                                                     'others.\n'
                                                     'Unless you have Spring '
                                                     'Security enabled or '
                                                     'another means to protect '
                                                     'these endpoints, this '
                                                     'functionality is '
                                                     'available without '
                                                     'authentication, causing '
                                                     'a severe security risk.',
                                      'display_name': 'SpringActuatorFullyEnabled',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'spring actuator fully enabled'},
    'SpringCsrfDisabled': {   'categories': ['security'],
                              'description': 'CSRF is disabled for this '
                                             'configuration. This is a '
                                             'security risk.',
                              'display_name': 'SpringCsrfDisabled',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'spring csrf disabled'},
    'SpringJspEval': {   'categories': ['security'],
                         'description': 'A Spring expression is built with a '
                                        'dynamic value. The source of the '
                                        'value(s) should be verified to avoid '
                                        'that unfiltered values fall into this '
                                        'risky code evaluation.',
                         'display_name': 'SpringJspEval',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'spring jsp eval'},
    'SpringSqli': {   'categories': ['security'],
                      'description': 'Detected a formatted string in a SQL '
                                     'statement. This could lead to SQL\n'
                                     'injection if variables in the SQL '
                                     'statement are not properly sanitized.\n'
                                     'Use a prepared statements '
                                     '(java.sql.PreparedStatement) instead. '
                                     'You\n'
                                     'can obtain a PreparedStatement using '
                                     "'connection.prepareStatement'.",
                      'display_name': 'SpringSqli',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'spring sqli'},
    'SpringUnvalidatedRedirect': {   'categories': ['security'],
                                     'description': 'Application redirects a '
                                                    'user to a destination URL '
                                                    'specified by a user '
                                                    'supplied parameter that '
                                                    'is not validated.',
                                     'display_name': 'SpringUnvalidatedRedirect',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'spring unvalidated redirect'},
    'SqlInjectionDbCursorExecute': {   'categories': ['security'],
                                       'description': 'Data from request is '
                                                      'passed to execute(). '
                                                      'This is a SQL injection '
                                                      'and could be exploited. '
                                                      'See '
                                                      'https://docs.djangoproject.com/en/3.0/topics/security/#sql-injection-protection '
                                                      'to learn how to '
                                                      'mitigate. See '
                                                      'https://cwe.mitre.org/data/definitions/89.html '
                                                      'to learn about SQLi.',
                                       'display_name': 'SqlInjectionDbCursorExecute',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'sql injection db cursor '
                                                'execute'},
    'SqlInjectionUsingExtraWhere': {   'categories': ['security'],
                                       'description': 'Data from request is '
                                                      'passed to extra(). This '
                                                      'is a SQL injection and '
                                                      'could be exploited. See '
                                                      'https://docs.djangoproject.com/en/3.0/ref/models/expressions/#.objects.extra '
                                                      'to learn how to '
                                                      'mitigate. See '
                                                      'https://cwe.mitre.org/data/definitions/89.html '
                                                      'to learn about SQLi.',
                                       'display_name': 'SqlInjectionUsingExtraWhere',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'sql injection using extra '
                                                'where'},
    'SqlInjectionUsingRaw': {   'categories': ['security'],
                                'description': 'Data from request is passed to '
                                               'raw(). This is a SQL injection '
                                               'and could be exploited. See '
                                               'https://docs.djangoproject.com/en/3.0/topics/security/#sql-injection-protection '
                                               'to learn how to mitigate. See '
                                               'https://cwe.mitre.org/data/definitions/89.html '
                                               'to learn about SQLi.',
                                'display_name': 'SqlInjectionUsingRaw',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'sql injection using raw'},
    'SqlInjectionUsingRawsql': {   'categories': ['security'],
                                   'description': 'Data from request is passed '
                                                  'to RawSQL(). This is a SQL '
                                                  'injection and could be '
                                                  'exploited. See '
                                                  'https://docs.djangoproject.com/en/3.0/ref/models/expressions/#django.db.models.expressions.RawSQL '
                                                  'to learn how to mitigate. '
                                                  'See '
                                                  'https://cwe.mitre.org/data/definitions/89.html '
                                                  'to learn about SQLi.',
                                   'display_name': 'SqlInjectionUsingRawsql',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'sql injection using rawsql'},
    'SqlalchemyExecuteRawQuery': {   'categories': ['security'],
                                     'description': 'Avoiding SQL string '
                                                    'concatenation: untrusted '
                                                    'input concatinated with '
                                                    'raw SQL query can result '
                                                    'in SQL Injection. In '
                                                    'order to execute raw '
                                                    'query safely, prepared '
                                                    'statement should be used. '
                                                    'SQLAlchemy provides '
                                                    'TextualSQL to easily used '
                                                    'prepared statement with '
                                                    'named parameters. For '
                                                    'complexe SQL composition, '
                                                    'use SQL Expression '
                                                    'Languague or Schema '
                                                    'Definition Language. In '
                                                    'most cases, SQLAlchemy '
                                                    'ORM will be a better '
                                                    'option.',
                                     'display_name': 'SqlalchemyExecuteRawQuery',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'sqlalchemy execute raw query'},
    'SqlalchemySqlInjection': {   'categories': ['security'],
                                  'description': 'Distinct, Having, Group_by, '
                                                 'Order_by, and Filter in '
                                                 'SQLAlchemy can cause sql '
                                                 'injections\n'
                                                 'if the developer inputs raw '
                                                 'SQL into the '
                                                 'before-mentioned clauses.\n'
                                                 'This pattern captures '
                                                 'relevant cases in which the '
                                                 'developer inputs raw SQL '
                                                 'into the distinct, having, '
                                                 'group_by, order_by or filter '
                                                 'clauses and\n'
                                                 'injects user-input into the '
                                                 'raw SQL with any function '
                                                 'besides "bindparams". Use '
                                                 'bindParams to securely bind '
                                                 'user-input\n'
                                                 'to SQL statements.',
                                  'display_name': 'SqlalchemySqlInjection',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'sqlalchemy sql injection'},
    'SquirrellyAutoescape': {   'categories': ['security'],
                                'description': 'Handlebars SafeString will not '
                                               'escape the data passed through '
                                               'it. Untrusted user input '
                                               'passing through SafeString can '
                                               'cause XSS.',
                                'display_name': 'SquirrellyAutoescape',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'squirrelly autoescape'},
    'SslModeNoVerify': {   'categories': ['security'],
                           'description': 'Detected SSL that will accept an '
                                          'unverified connection.\n'
                                          'This makes the connections '
                                          'susceptible to man-in-the-middle '
                                          'attacks.\n'
                                          "Use 'OpenSSL::SSL::VERIFY_PEER' "
                                          'intead.',
                           'display_name': 'SslModeNoVerify',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'ssl mode no verify'},
    'SslV3IsInsecure': {   'categories': ['security'],
                           'description': 'SSLv3 is insecure because it has '
                                          'known vulnerabilities.\n'
                                          'Starting with go1.14, SSLv3 will be '
                                          'removed. Instead, use\n'
                                          "'tls.VersionTLS13'.",
                           'display_name': 'SslV3IsInsecure',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'ssl v3 is insecure'},
    'SslWrapSocketIsDeprecated': {   'categories': ['security'],
                                     'description': "'ssl.wrap_socket()' is "
                                                    'deprecated. This function '
                                                    'creates an insecure '
                                                    'socket\n'
                                                    'without server name '
                                                    'indication or hostname '
                                                    'matching. Instead, create '
                                                    'an SSL\n'
                                                    'context using '
                                                    "'ssl.SSLContext()' and "
                                                    'use that to wrap a '
                                                    'socket.',
                                     'display_name': 'SslWrapSocketIsDeprecated',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'ssl wrap socket is deprecated'},
    'SsrfInjectionRequests': {   'categories': ['security'],
                                 'description': 'Data from request object is '
                                                'passed to a new server-side '
                                                'request.\n'
                                                'This could lead to a '
                                                'server-side request forgery '
                                                '(SSRF). To mitigate,\n'
                                                'ensure that schemes and hosts '
                                                'are validated against an '
                                                'allowlist,\n'
                                                'do not forward the response '
                                                'to the user, and ensure '
                                                'proper authentication\n'
                                                'and transport-layer security '
                                                'in the proxied request.\n'
                                                'See '
                                                'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery '
                                                'to\n'
                                                'learn more about SSRF '
                                                'vulnerabilities.',
                                 'display_name': 'SsrfInjectionRequests',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'ssrf injection requests'},
    'SsrfInjectionUrllib': {   'categories': ['security'],
                               'description': 'Data from request object is '
                                              'passed to a new server-side '
                                              'request.\n'
                                              'This could lead to a '
                                              'server-side request forgery '
                                              '(SSRF). To mitigate,\n'
                                              'ensure that schemes and hosts '
                                              'are validated against an '
                                              'allowlist,\n'
                                              'do not forward the response to '
                                              'the user, and ensure proper '
                                              'authentication\n'
                                              'and transport-layer security in '
                                              'the proxied request.\n'
                                              'See '
                                              'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery\n'
                                              'to learn more about SSRF '
                                              'vulnerabilities.',
                               'display_name': 'SsrfInjectionUrllib',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'ssrf injection urllib'},
    'SsrfRequests': {   'categories': ['security'],
                        'description': 'Data from request object is passed to '
                                       'a new server-side request. This could '
                                       'lead to a server-side request forgery '
                                       '(SSRF). To mitigate, ensure that '
                                       'schemes and hosts are validated '
                                       'against an allowlist, do not forward '
                                       'the response to the user, and ensure '
                                       'proper authentication and '
                                       'transport-layer security in the '
                                       'proxied request.',
                        'display_name': 'SsrfRequests',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'ssrf requests'},
    'StringConcat': {   'categories': ['security'],
                        'description': 'Detected string concatenation or '
                                       'formatting in a call to a command via '
                                       "'sh'.\n"
                                       'This could be a command injection '
                                       'vulnerability if the data is '
                                       'user-controlled.\n'
                                       'Instead, use a list and append the '
                                       'argument.',
                        'display_name': 'StringConcat',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'string concat'},
    'StringConcatInList': {   'categories': ['security'],
                              'description': 'Detected strings that are '
                                             'implicitly concatenated inside a '
                                             'list.\n'
                                             'Python will implicitly '
                                             'concatenate strings when not '
                                             'explicitly delimited.\n'
                                             'Was this supposed to be '
                                             'individual elements of the list?',
                              'display_name': 'StringConcatInList',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'string concat in list'},
    'StringFieldMustSetNullTrue': {   'categories': ['security'],
                                      'description': 'If a text field declares '
                                                     'unique=True and '
                                                     'blank=True, null=True '
                                                     'must also be set to '
                                                     'avoid unique constraint '
                                                     'violations when saving '
                                                     'multiple objects with '
                                                     'blank values.',
                                      'display_name': 'StringFieldMustSetNullTrue',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'string field must set null '
                                               'true'},
    'StringFormattedQuery': {   'categories': ['security'],
                                'description': 'String-formatted SQL query '
                                               'detected. This could lead to '
                                               'SQL injection if\n'
                                               'the string is not sanitized '
                                               'properly. Audit this call to '
                                               'ensure the\n'
                                               'SQL is not manipulatable by '
                                               'external data.',
                                'display_name': 'StringFormattedQuery',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'string formatted query'},
    'StringIsComparison': {   'categories': ['security'],
                              'description': 'Found string comparison using '
                                             "'is' operator. The 'is' "
                                             'operator\n'
                                             'is for reference equality, not '
                                             'value equality, and therefore '
                                             'should\n'
                                             'not be used to compare strings. '
                                             'For more information, see\n'
                                             'https://github.com/satwikkansal/wtfpython#-how-not-to-use-is-operator"',
                              'display_name': 'StringIsComparison',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'string is comparison'},
    'SubprocessShellTrue': {   'categories': ['security'],
                               'description': "Found 'subprocess' function "
                                              "'$FUNC' with 'shell=True'. This "
                                              'is dangerous because this call '
                                              'will spawn\n'
                                              'the command using a shell '
                                              'process. Doing so propagates '
                                              'current shell settings and '
                                              'variables, which\n'
                                              'makes it much easier for a '
                                              'malicious actor to execute '
                                              "commands. Use 'shell=False' "
                                              'instead.',
                               'display_name': 'SubprocessShellTrue',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'subprocess shell true'},
    'SystemWildcardDetected': {   'categories': ['security'],
                                  'description': 'Detected use of the wildcard '
                                                 'character in a system call '
                                                 'that spawns a shell.\n'
                                                 'This subjects the wildcard '
                                                 'to normal shell expansion, '
                                                 'which can have unintended '
                                                 'consequences\n'
                                                 'if there exist any '
                                                 'non-standard file names. '
                                                 "Consider a file named '-e sh "
                                                 "script.sh' -- this\n"
                                                 'will execute a script when '
                                                 "'rsync' is called. See\n"
                                                 'https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt\n'
                                                 'for more information.',
                                  'display_name': 'SystemWildcardDetected',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'system wildcard detected'},
    'TarPathOverwrite': {   'categories': ['security'],
                            'description': 'Insecure TAR archive extraction '
                                           'can result in arbitrary path over '
                                           'write and can result in code '
                                           'injection.',
                            'display_name': 'TarPathOverwrite',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'tar path overwrite'},
    'Telnetlib': {   'categories': ['security'],
                     'description': 'Telnet does not encrypt communications. '
                                    'Use SSH instead.',
                     'display_name': 'Telnetlib',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'telnetlib'},
    'TempfileInsecure': {   'categories': ['security'],
                            'description': 'Use tempfile.NamedTemporaryFile '
                                           'instead. From the official Python '
                                           'documentation: THIS FUNCTION IS '
                                           'UNSAFE AND SHOULD NOT BE USED. The '
                                           'file name may refer to a file that '
                                           'did not exist at some point, but '
                                           'by the time you get around to '
                                           'creating it, someone else may have '
                                           'beaten you to the punch.',
                            'display_name': 'TempfileInsecure',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'tempfile insecure'},
    'TempfileWithoutFlush': {   'categories': ['security'],
                                'description': "Using '$F.name' without "
                                               "'.flush()' or '.close()' may "
                                               'cause an error because the '
                                               'file may not exist when '
                                               "'$F.name' is used. Use "
                                               "'.flush()' or close the file "
                                               "before using '$F.name'.",
                                'display_name': 'TempfileWithoutFlush',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'tempfile without flush'},
    'TemplateAndAttributes': {   'categories': ['security'],
                                 'description': 'Detected a unescaped '
                                                'variables using '
                                                "'&attributes'.\n"
                                                'If external data can reach '
                                                'these locations,\n'
                                                'your application is exposed '
                                                'to a cross-site scripting '
                                                '(XSS)\n'
                                                'vulnerability. If you must do '
                                                'this, ensure no external '
                                                'data\n'
                                                'can reach this location.',
                                 'display_name': 'TemplateAndAttributes',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'template and attributes'},
    'TemplateAutoescapeOff': {   'categories': ['security'],
                                 'description': 'Detected a segment of a Flask '
                                                'template where autoescaping '
                                                'is explicitly disabled with '
                                                "'{% autoescape off %}'. This "
                                                'allows rendering of raw HTML '
                                                'in this segment. Ensure no '
                                                'user data is rendered here, '
                                                'otherwise this is a '
                                                'cross-site scripting (XSS) '
                                                'vulnerability, or turn '
                                                'autoescape on.',
                                 'display_name': 'TemplateAutoescapeOff',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'template autoescape off'},
    'TemplateBlocktranslateNoEscape': {   'categories': ['security'],
                                          'description': 'Translated strings '
                                                         'will not be escaped '
                                                         'when rendered in a '
                                                         'template.\n'
                                                         'This leads to a '
                                                         'vulnerability where '
                                                         'translators could '
                                                         'include malicious '
                                                         'script tags in their '
                                                         'translations.\n'
                                                         'Consider using '
                                                         '`force_escape` to '
                                                         'explicitly escape a '
                                                         'translated text.',
                                          'display_name': 'TemplateBlocktranslateNoEscape',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'template blocktranslate no '
                                                   'escape'},
    'TemplateExplicitUnescape': {   'categories': ['security'],
                                    'description': 'Detected an explicit '
                                                   'unescape in a Pug '
                                                   'template, using either\n'
                                                   "'!=' or '!{...}'. If "
                                                   'external data can reach '
                                                   'these locations,\n'
                                                   'your application is '
                                                   'exposed to a cross-site '
                                                   'scripting (XSS)\n'
                                                   'vulnerability. If you must '
                                                   'do this, ensure no '
                                                   'external data\n'
                                                   'can reach this location.',
                                    'display_name': 'TemplateExplicitUnescape',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'template explicit unescape'},
    'TemplateHrefVar': {   'categories': ['security'],
                           'description': 'Detected a template variable used '
                                          "in an anchor tag with the 'href' "
                                          'attribute. This allows a malicious '
                                          "actor to input the 'javascript:' "
                                          'URI and is subject to cross- site '
                                          'scripting (XSS) attacks. Use '
                                          "'url_for()' to safely generate a "
                                          'URL. You may also consider setting '
                                          'the Content Security Policy (CSP) '
                                          'header.',
                           'display_name': 'TemplateHrefVar',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'template href var'},
    'TemplateTranslateAsNoEscape': {   'categories': ['security'],
                                       'description': 'Translated strings will '
                                                      'not be escaped when '
                                                      'rendered in a '
                                                      'template.\n'
                                                      'This leads to a '
                                                      'vulnerability where '
                                                      'translators could '
                                                      'include malicious '
                                                      'script tags in their '
                                                      'translations.\n'
                                                      'Consider using '
                                                      '`force_escape` to '
                                                      'explicitly escape a '
                                                      'transalted text.',
                                       'display_name': 'TemplateTranslateAsNoEscape',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'template translate as no '
                                                'escape'},
    'TemplateTranslateNoEscape': {   'categories': ['security'],
                                     'description': 'Translated strings will '
                                                    'not be escaped when '
                                                    'rendered in a template.\n'
                                                    'This leads to a '
                                                    'vulnerability where '
                                                    'translators could include '
                                                    'malicious script tags in '
                                                    'their translations.\n'
                                                    'Consider using '
                                                    '`force_escape` to '
                                                    'explicitly escape a '
                                                    'transalted text.',
                                     'display_name': 'TemplateTranslateNoEscape',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'template translate no escape'},
    'TemplateUnescapedWithSafe': {   'categories': ['security'],
                                     'description': 'Detected a segment of a '
                                                    'Flask template where '
                                                    'autoescaping is '
                                                    'explicitly disabled with '
                                                    "'| safe' filter. This "
                                                    'allows rendering of raw '
                                                    'HTML in this segment. '
                                                    'Ensure no user data is '
                                                    'rendered here, otherwise '
                                                    'this is a cross-site '
                                                    'scripting (XSS) '
                                                    'vulnerability.',
                                     'display_name': 'TemplateUnescapedWithSafe',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'template unescaped with safe'},
    'TemplateUnquotedAttributeVar': {   'categories': ['security'],
                                        'description': 'Detected a unquoted '
                                                       'template variable as '
                                                       'an attribute. If '
                                                       'unquoted, a malicious '
                                                       'actor could inject '
                                                       'custom JavaScript '
                                                       'handlers. To fix this, '
                                                       'add quotes around the '
                                                       'template expression, '
                                                       'like this: "{{ expr '
                                                       '}}".',
                                        'display_name': 'TemplateUnquotedAttributeVar',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'template unquoted attribute '
                                                 'var'},
    'TemplateVarUnescapedWithSafeseq': {   'categories': ['security'],
                                           'description': 'Detected a template '
                                                          'variable where '
                                                          'autoescaping is '
                                                          'explicitly\n'
                                                          "disabled with '| "
                                                          "safeseq' filter. "
                                                          'This allows '
                                                          'rendering of raw '
                                                          'HTML\n'
                                                          'in this segment. '
                                                          'Ensure no user data '
                                                          'is rendered here, '
                                                          'otherwise this\n'
                                                          'is a cross-site '
                                                          'scripting (XSS) '
                                                          'vulnerability. If '
                                                          'you must do this,\n'
                                                          'use `mark_safe` in '
                                                          'your Python code.',
                                           'display_name': 'TemplateVarUnescapedWithSafeseq',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'template var unescaped '
                                                    'with safeseq'},
    'TimingAttack': {   'categories': ['security'],
                        'description': 'Checks for unsafe use of method '
                                       'http_basic_authenticate_with, which is '
                                       'vulnerable to timing attacks as it\n'
                                       'does not use constant-time checking '
                                       'when comparing passwords. Affected '
                                       'Rails versions include:\n'
                                       '5.0.0.beta1.1, 4.2.5.1, 4.1.14.1, '
                                       '3.2.22.1. Avoid this function if '
                                       'possible.',
                        'display_name': 'TimingAttack',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'timing attack'},
    'TlsWithInsecureCipher': {   'categories': ['security'],
                                 'description': 'Detected an insecure '
                                                "CipherSuite via the 'tls' "
                                                'module. This suite is '
                                                'considered weak.\n'
                                                'Use the function '
                                                "'tls.CipherSuites()' to get a "
                                                'list of good cipher suites.\n'
                                                'See '
                                                'https://golang.org/pkg/crypto/tls/#InsecureCipherSuites\n'
                                                'for why and what other cipher '
                                                'suites to use.',
                                 'display_name': 'TlsWithInsecureCipher',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'tls with insecure cipher'},
    'TofastpropertiesCodeExecution': {   'categories': ['security'],
                                         'description': 'Potential arbitrary '
                                                        'code execution, '
                                                        'whatever is provided '
                                                        'to `toFastProperties` '
                                                        'is sent straight to '
                                                        'eval()',
                                         'display_name': 'TofastpropertiesCodeExecution',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'tofastproperties code '
                                                  'execution'},
    'TurbineSqli': {   'categories': ['security'],
                       'description': 'Detected a formatted string in a SQL '
                                      'statement. This could lead to SQL\n'
                                      'injection if variables in the SQL '
                                      'statement are not properly sanitized.\n'
                                      'Use a prepared statements '
                                      '(java.sql.PreparedStatement) instead. '
                                      'You\n'
                                      'can obtain a PreparedStatement using '
                                      "'connection.prepareStatement'.",
                       'display_name': 'TurbineSqli',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'turbine sqli'},
    'UncaughtExecutorExceptions': {   'categories': ['security'],
                                      'description': 'Values returned by '
                                                     'thread pool map must be '
                                                     'read in order to raise '
                                                     'exceptions. Consider '
                                                     'using `for _ in '
                                                     '$EXECUTOR.map(...): '
                                                     'pass`.',
                                      'display_name': 'UncaughtExecutorExceptions',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'uncaught executor exceptions'},
    'UncheckedSubprocessCall': {   'categories': ['security'],
                                   'description': 'This is not checking the '
                                                  'return value of this '
                                                  'subprocess call; if it '
                                                  'fails no exception will be '
                                                  'raised. Consider '
                                                  'subprocess.check_call() '
                                                  'instead',
                                   'display_name': 'UncheckedSubprocessCall',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'unchecked subprocess call'},
    'UnencryptedSocket': {   'categories': ['security'],
                             'description': 'This socket is not encrypted.\n'
                                            'The traffic could be read by an '
                                            'attacker intercepting the network '
                                            'traffic.\n'
                                            'Use an SSLSocket created by '
                                            "'SSLSocketFactory' or "
                                            "'SSLServerSocketFactory'\n"
                                            'instead',
                             'display_name': 'UnencryptedSocket',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'unencrypted socket'},
    'UnescapedDataInHtmlattr': {   'categories': ['security'],
                                   'description': 'Found a formatted template '
                                                  'string passed to '
                                                  "'template.HTMLAttr()'.\n"
                                                  "'template.HTMLAttr()' does "
                                                  'not escape contents. Be '
                                                  'absolutely sure\n'
                                                  'there is no user-controlled '
                                                  'data in this template.',
                                   'display_name': 'UnescapedDataInHtmlattr',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'unescaped data in htmlattr'},
    'UnescapedDataInJs': {   'categories': ['security'],
                             'description': 'Found a formatted template string '
                                            "passed to 'template.JS()'.\n"
                                            "'template.JS()' does not escape "
                                            'contents. Be absolutely sure\n'
                                            'there is no user-controlled data '
                                            'in this template.',
                             'display_name': 'UnescapedDataInJs',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'unescaped data in js'},
    'UnescapedDataInUrl': {   'categories': ['security'],
                              'description': 'Found a formatted template '
                                             'string passed to '
                                             "'template.URL()'.\n"
                                             "'template.URL()' does not escape "
                                             'contents. Be absolutely sure\n'
                                             'there is no user-controlled data '
                                             'in this template.',
                              'display_name': 'UnescapedDataInUrl',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'unescaped data in url'},
    'UnescapedTemplateExtension': {   'categories': ['security'],
                                      'description': 'Flask does not '
                                                     'automatically escape '
                                                     'Jinja templates unless '
                                                     'they have\n'
                                                     '.html, .htm, .xml, or '
                                                     '.xhtml extensions. This '
                                                     'could lead to XSS '
                                                     'attacks.\n'
                                                     'Use .html, .htm, .xml, '
                                                     'or .xhtml for your '
                                                     'template extensions.\n'
                                                     'See '
                                                     'https://flask.palletsprojects.com/en/1.1.x/templating/#jinja-setup\n'
                                                     'for more information.',
                                      'display_name': 'UnescapedTemplateExtension',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'unescaped template extension'},
    'UnknownValueInRedirect': {   'categories': ['security'],
                                  'description': "It looks like '$UNK' is read "
                                                 'from user input and it is '
                                                 'used to as a redirect. '
                                                 'Ensure\n'
                                                 "'$UNK' is not externally "
                                                 'controlled, otherwise this '
                                                 'is an open redirect.',
                                  'display_name': 'UnknownValueInRedirect',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'unknown value in redirect'},
    'UnknownValueWithScriptTag': {   'categories': ['security'],
                                     'description': 'Cannot determine what '
                                                    "'$UNK' is and it is used "
                                                    "with a '<script>' tag. "
                                                    'This\n'
                                                    'could be susceptible to '
                                                    'cross-site scripting '
                                                    "(XSS). Ensure '$UNK' is "
                                                    'not\n'
                                                    'externally controlled, or '
                                                    'sanitize this data.',
                                     'display_name': 'UnknownValueWithScriptTag',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'unknown value with script tag'},
    'UnquotedAttribute': {   'categories': ['security'],
                             'description': 'Detected a unquoted template '
                                            'variable as an attribute. If '
                                            'unquoted, a\n'
                                            'malicious actor could inject '
                                            'custom JavaScript handlers. To '
                                            'fix this,\n'
                                            'add quotes around the template '
                                            'expression, like this: "<%= expr '
                                            '%>".',
                             'display_name': 'UnquotedAttribute',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'unquoted attribute'},
    'UnquotedAttributeVar': {   'categories': ['security'],
                                'description': 'Detected a unquoted template '
                                               'variable as an attribute. If '
                                               'unquoted, a malicious actor '
                                               'could inject custom JavaScript '
                                               'handlers. To fix this, add '
                                               'quotes around the template '
                                               'expression, like this: "{{ '
                                               'expr }}".\n'
                                               '{"include": ["*.html", '
                                               '"*.mustache", "*.hbs"]}',
                                'display_name': 'UnquotedAttributeVar',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'html-templates: unquoted attribute '
                                         'var'},
    'UnquotedCsvWriter': {   'categories': ['security'],
                             'description': 'Found an unquoted CSV writer. '
                                            'This is susceptible to injection. '
                                            "Use 'quoting=csv.QUOTE_ALL'.",
                             'display_name': 'UnquotedCsvWriter',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'unquoted csv writer'},
    'UnrestrictedRequestMapping': {   'categories': ['security'],
                                      'description': 'Detected a method '
                                                     'annotated with '
                                                     "'RequestMapping' that "
                                                     'does not specify the '
                                                     'HTTP method. CSRF '
                                                     'protections are not '
                                                     'enabled for GET, HEAD, '
                                                     'TRACE, or OPTIONS, and '
                                                     'by default all HTTP '
                                                     'methods are allowed when '
                                                     'the HTTP method is not '
                                                     'explicitly specified. '
                                                     'This means that a method '
                                                     'that performs state '
                                                     'changes could be '
                                                     'vulnerable to CSRF '
                                                     'attacks. To mitigate, '
                                                     "add the 'method' field "
                                                     'and specify the HTTP '
                                                     'method (such as '
                                                     "'RequestMethod.POST').",
                                      'display_name': 'UnrestrictedRequestMapping',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'unrestricted request mapping'},
    'UnsafeReflectByName': {   'categories': ['security'],
                               'description': 'If an attacker can supply '
                                              'values that the application '
                                              'then uses to determine which '
                                              'method or field to invoke,\n'
                                              'the potential exists for the '
                                              'attacker to create control flow '
                                              'paths through the application\n'
                                              'that were not intended by the '
                                              'application developers.\n'
                                              'This attack vector may allow '
                                              'the attacker to bypass '
                                              'authentication or access '
                                              'control checks\n'
                                              'or otherwise cause the '
                                              'application to behave in an '
                                              'unexpected manner.',
                               'display_name': 'UnsafeReflectByName',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'unsafe reflect by name'},
    'UnsafeReflection': {   'categories': ['security'],
                            'description': 'If an attacker can supply values '
                                           'that the application then uses to '
                                           'determine which class to '
                                           'instantiate or which method to '
                                           'invoke,\n'
                                           'the potential exists for the '
                                           'attacker to create control flow '
                                           'paths through the application\n'
                                           'that were not intended by the '
                                           'application developers.\n'
                                           'This attack vector may allow the '
                                           'attacker to bypass authentication '
                                           'or access control checks\n'
                                           'or otherwise cause the application '
                                           'to behave in an unexpected manner.',
                            'display_name': 'UnsafeReflection',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'unsafe reflection'},
    'UnsafeSerializeJavascript': {   'categories': ['security'],
                                     'description': '`serialize-javascript` '
                                                    'used with `unsafe` '
                                                    'parameter, this could be '
                                                    'vulnerable to XSS.',
                                     'display_name': 'UnsafeSerializeJavascript',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'unsafe serialize javascript'},
    'UnsafeTemplateType': {   'categories': ['security'],
                              'description': 'Semgrep could not determine that '
                                             'the argument to '
                                             "'template.HTML()'\n"
                                             "is a constant. 'template.HTML()' "
                                             'and similar does not escape '
                                             'contents.\n'
                                             'Be absolutely sure there is no '
                                             'user-controlled data in this\n'
                                             'template. If user data can reach '
                                             'this template, you may have\n'
                                             'a XSS vulnerability. Instead, do '
                                             'not use this function and\n'
                                             "use 'template.Execute()'.",
                              'display_name': 'UnsafeTemplateType',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'unsafe template type'},
    'UnvalidatedPassword': {   'categories': ['security'],
                               'description': "The password on '$MODEL' is "
                                              'being set without validating '
                                              'the password.\n'
                                              'Call '
                                              'django.contrib.auth.password_validation.validate_password() '
                                              'with\n'
                                              'validation functions before '
                                              'setting the password. See\n'
                                              'https://docs.djangoproject.com/en/3.0/topics/auth/passwords/\n'
                                              'for more information.',
                               'display_name': 'UnvalidatedPassword',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'unvalidated password'},
    'UnvalidatedRedirect': {   'categories': ['security'],
                               'description': 'Application redirects to a '
                                              'destination URL specified by a '
                                              'user-supplied\n'
                                              'parameter that is not '
                                              'validated. This could direct '
                                              'users to malicious locations.\n'
                                              'Consider using an allowlist to '
                                              'validate URLs.',
                               'display_name': 'UnvalidatedRedirect',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'unvalidated redirect'},
    'UnverifiedJwtDecode': {   'categories': ['security'],
                               'description': 'Detected JWT token decoded with '
                                              "'verify=False'. This bypasses "
                                              'any integrity\n'
                                              'checks for the token which '
                                              'means the token could be '
                                              'tampered with by\n'
                                              'malicious actors. Ensure that '
                                              'the JWT token is verified.',
                               'display_name': 'UnverifiedJwtDecode',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'unverified jwt decode'},
    'UnverifiedSslContext': {   'categories': ['security'],
                                'description': 'Unverified SSL context '
                                               'detected. This will permit '
                                               'insecure connections without '
                                               'verifying\n'
                                               'SSL certificates. Use '
                                               "'ssl.create_default_context()' "
                                               'instead.',
                                'display_name': 'UnverifiedSslContext',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'unverified ssl context'},
    'UrlRewriting': {   'categories': ['security'],
                        'description': 'URL rewriting has significant security '
                                       'risks.\n'
                                       'Since session ID appears in the URL, '
                                       'it may be easily seen by third '
                                       'parties.',
                        'display_name': 'UrlRewriting',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'url rewriting'},
    'UseAbsoluteWorkdir': {   'categories': ['security'],
                              'description': 'Detected a relative WORKDIR. Use '
                                             'absolute paths. This prevents '
                                             'issues based on assumptions '
                                             'about the WORKDIR of previous '
                                             'containers.\n'
                                             '{"include": ["*dockerfile*", '
                                             '"*Dockerfile*"]}',
                              'display_name': 'UseAbsoluteWorkdir',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'dockerfile: use absolute workdir'},
    'UseAfterFree': {   'categories': ['security'],
                        'description': "Variable '$VAR' was used after being "
                                       'freed. This can lead to undefined '
                                       'behavior.',
                        'display_name': 'UseAfterFree',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'use after free'},
    'UseClickSecho': {   'categories': ['security'],
                         'description': 'Use `click.secho($X)` instead. It '
                                        'combines click.echo() and '
                                        'click.style().',
                         'display_name': 'UseClickSecho',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'use click secho'},
    'UseCountMethod': {   'categories': ['security'],
                          'description': 'Looks like you need to determine the '
                                         'number of records. Django provides '
                                         'the count() method which is more '
                                         'efficient than .len(). See '
                                         'https://docs.djangoproject.com/en/3.0/ref/models/querysets/',
                          'display_name': 'UseCountMethod',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'use count method'},
    'UseDecimalfieldForMoney': {   'categories': ['security'],
                                   'description': 'Found a FloatField used for '
                                                  'variable $F. Use '
                                                  'DecimalField for currency '
                                                  'fields to avoid '
                                                  'float-rounding errors.',
                                   'display_name': 'UseDecimalfieldForMoney',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'use decimalfield for money'},
    'UseDefusedXml': {   'categories': ['security'],
                         'description': 'Found use of the native Python XML '
                                        'libraries, which is vulnerable to XML '
                                        'external entity (XXE)\n'
                                        'attacks. The Python documentation '
                                        "recommends the 'defusedxml' library "
                                        "instead. Use 'defusedxml'.\n"
                                        'See '
                                        'https://github.com/tiran/defusedxml '
                                        'for more information.',
                         'display_name': 'UseDefusedXml',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'use defused xml'},
    'UseDefusedXmlrpc': {   'categories': ['security'],
                            'description': 'Detected use of xmlrpc. xmlrpc is '
                                           'not inherently safe from '
                                           'vulnerabilities.\n'
                                           'Use defusedxml.xmlrpc instead.',
                            'display_name': 'UseDefusedXmlrpc',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'use defused xmlrpc'},
    'UseDjangoEnviron': {   'categories': ['security'],
                            'description': 'You are using environment '
                                           'variables inside django app. Use '
                                           '`django-environ` as it a better '
                                           'alternative for deployment.',
                            'display_name': 'UseDjangoEnviron',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'use django environ'},
    'UseEarliestOrLatest': {   'categories': ['security'],
                               'description': 'Looks like you are only '
                                              'accessing first element of an '
                                              'ordered QuerySet. Use '
                                              '`latest()` or `earliest()` '
                                              'instead. See '
                                              'https://docs.djangoproject.com/en/3.0/ref/models/querysets/#django.db.models.query.QuerySet.latest',
                               'display_name': 'UseEarliestOrLatest',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'use earliest or latest'},
    'UseEitherWgetOrCurl': {   'categories': ['security'],
                               'description': "'wget' and 'curl' are similar "
                                              'tools. Choose one and do not '
                                              'install the other to decrease '
                                              'image size.\n'
                                              '\n'
                                              '{"include": ["*dockerfile*", '
                                              '"*Dockerfile*"]}',
                               'display_name': 'UseEitherWgetOrCurl',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'dockerfile: use either wget or curl'},
    'UseEscapexml': {   'categories': ['security'],
                        'description': 'Detected an Expression Language '
                                       'segment that does not escape\n'
                                       'output. This is dangerous because if '
                                       'any data in this expression\n'
                                       'can be controlled externally, it is a '
                                       'cross-site scripting\n'
                                       'vulnerability. Instead, use the '
                                       "'escapeXml' function from\n"
                                       'the JSTL taglib. See '
                                       'https://www.tutorialspoint.com/jsp/jstl_function_escapexml.htm\n'
                                       'for more information.',
                        'display_name': 'UseEscapexml',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'use escapexml'},
    'UseFtpTls': {   'categories': ['security'],
                     'description': "The 'FTP' class sends information "
                                    'unencrypted. Consider using\n'
                                    "the 'FTP_TLS' class instead.",
                     'display_name': 'UseFtpTls',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'use ftp tls'},
    'UseJsonResponse': {   'categories': ['security'],
                           'description': 'Use JsonResponse instead',
                           'display_name': 'UseJsonResponse',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'use json response'},
    'UseJsonify': {   'categories': ['security'],
                      'description': 'flask.jsonify() is a Flask helper method '
                                     'which handles the correct settings for '
                                     'returning JSON from Flask routes',
                      'display_name': 'UseJsonify',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'use jsonify'},
    'UseJstlEscaping': {   'categories': ['security'],
                           'description': 'Detected an Expression Language '
                                          'segment in a tag that does not '
                                          'escape\n'
                                          'output. This is dangerous because '
                                          'if any data in this expression\n'
                                          'can be controlled externally, it is '
                                          'a cross-site scripting\n'
                                          'vulnerability. Instead, use the '
                                          "'out' tag from the JSTL taglib\n"
                                          'to escape this expression.\n'
                                          'See '
                                          'https://www.tutorialspoint.com/jsp/jstl_core_out_tag.htm\n'
                                          'for more information.',
                           'display_name': 'UseJstlEscaping',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'use jstl escaping'},
    'UseNoneForPasswordDefault': {   'categories': ['security'],
                                     'description': "'$VAR' is using the empty "
                                                    'string as its default and '
                                                    'is being used to set\n'
                                                    "the password on '$MODEL'. "
                                                    'If you meant to set an '
                                                    'unusable password, set\n'
                                                    'the default value to '
                                                    "'None' or call "
                                                    "'set_unusable_password()'.",
                                     'display_name': 'UseNoneForPasswordDefault',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'use none for password default'},
    'UseOfDes': {   'categories': ['security'],
                    'description': 'Detected DES cipher algorithm which is '
                                   'insecure. The algorithm is\n'
                                   'considered weak and has been deprecated. '
                                   'Use AES instead.',
                    'display_name': 'UseOfDes',
                    'file': '%(issue.file)s',
                    'line': '%(issue.line)s',
                    'severity': '1',
                    'title': 'use of DES'},
    'UseOfMd5': {   'categories': ['security'],
                    'description': 'Detected MD5 hash algorithm which is '
                                   'considered insecure. MD5 is not\n'
                                   'collision resistant and is therefore not '
                                   'suitable as a cryptographic\n'
                                   'signature. Use SHA256 or SHA3 instead.',
                    'display_name': 'UseOfMd5',
                    'file': '%(issue.file)s',
                    'line': '%(issue.line)s',
                    'severity': '1',
                    'title': 'use of md5'},
    'UseOfRc4': {   'categories': ['security'],
                    'description': 'Detected RC4 cipher algorithm which is '
                                   'insecure. The algorithm has many\n'
                                   'known vulnerabilities. Use AES instead.',
                    'display_name': 'UseOfRc4',
                    'file': '%(issue.file)s',
                    'line': '%(issue.line)s',
                    'severity': '1',
                    'title': 'use of rc4'},
    'UseOfSha1': {   'categories': ['security'],
                     'description': 'Detected SHA1 hash algorithm which is '
                                    'considered insecure. SHA1 is not\n'
                                    'collision resistant and is therefore not '
                                    'suitable as a cryptographic\n'
                                    'signature. Use SHA256 or SHA3 instead.',
                     'display_name': 'UseOfSha1',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'use of sha1'},
    'UseOfUnsafeBlock': {   'categories': ['security'],
                            'description': 'Using the unsafe package in Go '
                                           'gives you low-level memory '
                                           'management and\n'
                                           'many of the strengths of the C '
                                           'language but also gives '
                                           'flexibility to the attacker\n'
                                           'of your application.',
                            'display_name': 'UseOfUnsafeBlock',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'use of unsafe block'},
    'UseOfWeakRsaKey': {   'categories': ['security'],
                           'description': 'RSA keys should be at least 2048 '
                                          'bits',
                           'display_name': 'UseOfWeakRsaKey',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'use of weak rsa key'},
    'UseOnetoonefield': {   'categories': ['security'],
                            'description': 'Use '
                                           "'django.db.models.OneToOneField' "
                                           "instead of 'ForeignKey' with "
                                           'unique=True.\n'
                                           "'OneToOneField' is used to create "
                                           'one-to-one relationships.',
                            'display_name': 'UseOnetoonefield',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'use onetoonefield'},
    'UseRaiseForStatus': {   'categories': ['security'],
                             'description': "There's an HTTP request made with "
                                            'requests,\n'
                                            'but the raise_for_status() '
                                            "utility method isn't used.\n"
                                            'This can result in request errors '
                                            'going unnoticed\n'
                                            'and your code behaving in '
                                            'unexpected ways,\n'
                                            'such as if your authorization API '
                                            'returns a 500 error\n'
                                            "while you're only checking for a "
                                            '401.',
                             'display_name': 'UseRaiseForStatus',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'use raise for status'},
    'UseShellInstruction': {   'categories': ['security'],
                               'description': 'Use the SHELL instruction to '
                                              'set the default shell instead '
                                              "of overwriting '/bin/sh'.\n"
                                              '\n'
                                              '{"include": ["*dockerfile*", '
                                              '"*Dockerfile*"]}',
                               'display_name': 'UseShellInstruction',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'dockerfile: use shell instruction'},
    'UseSysExit': {   'categories': ['security'],
                      'description': 'Use `sys.exit` over the python shell '
                                     '`exit` built-in. `exit` is a helper for '
                                     'the interactive shell and may not be '
                                     'available on all Python implementations. '
                                     'https://stackoverflow.com/questions/6501121/difference-between-exit-and-sys-exit-in-python',
                      'display_name': 'UseSysExit',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'use sys exit'},
    'UseTimeout': {   'categories': ['security'],
                      'description': "By default, 'requests' calls wait until "
                                     'the connection is closed.\n'
                                     "This means a 'requests' call without a "
                                     'timeout will hang the program\n'
                                     'if a response is never received. '
                                     'Consider setting a timeout for all\n'
                                     "'requests'.",
                      'display_name': 'UseTimeout',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'use timeout'},
    'UseTls': {   'categories': ['security'],
                  'description': 'Found an HTTP server without TLS. Use '
                                 "'http.ListenAndServeTLS' instead. See "
                                 'https://golang.org/pkg/net/http/#ListenAndServeTLS '
                                 'for more information.',
                  'display_name': 'UseTls',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'use tls'},
    'UseWorkdir': {   'categories': ['security'],
                      'description': "Use 'WORKDIR' instead of 'RUN cd ...'. "
                                     "Using 'RUN cd ...' may not work as "
                                     'expected in a conatiner.\n'
                                     '{"include": ["*dockerfile*", '
                                     '"*Dockerfile*"]}',
                      'display_name': 'UseWorkdir',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'dockerfile: use workdir'},
    'UselessAssignment': {   'categories': ['security'],
                             'description': '`$X` is assigned twice; the first '
                                            'assignment is useless',
                             'display_name': 'UselessAssignment',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'useless assignment'},
    'UselessAssignmentKeyed': {   'categories': ['security'],
                                  'description': 'key `$Y` in `$X` is assigned '
                                                 'twice; the first assignment '
                                                 'is useless',
                                  'display_name': 'UselessAssignmentKeyed',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'useless assignment keyed'},
    'UselessEqeq': {   'categories': ['security'],
                       'description': 'This expression is always True: `$X == '
                                      '$X` or `$X != $X`. If testing for '
                                      'floating point NaN, use '
                                      '`math.isnan($X)`, or `cmath.isnan($X)` '
                                      'if the number is complex.',
                       'display_name': 'UselessEqeq',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'useless eqeq'},
    'UselessIfBody': {   'categories': ['security'],
                         'description': 'Detected identical if-statement '
                                        'bodies. Is this intentional?',
                         'display_name': 'UselessIfBody',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'useless if body'},
    'UselessIfConditional': {   'categories': ['security'],
                                'description': 'Detected an if block that '
                                               'checks for the same condition '
                                               'on both branches (`$X`)',
                                'display_name': 'UselessIfConditional',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'useless if conditional'},
    'UselessInnerFunction': {   'categories': ['security'],
                                'description': 'function `$FF` is defined '
                                               'inside a function but never '
                                               'used',
                                'display_name': 'UselessInnerFunction',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'useless inner function'},
    'UselessLiteralDict': {   'categories': ['security'],
                              'description': 'key `$X` is uselessly assigned '
                                             'twice',
                              'display_name': 'UselessLiteralDict',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'useless literal dict'},
    'UselessLiteralSet': {   'categories': ['security'],
                             'description': '`$X` is uselessly assigned twice '
                                            'inside the creation of the set',
                             'display_name': 'UselessLiteralSet',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'useless literal set'},
    'UserEval': {   'categories': ['security'],
                    'description': "Found user data in a call to 'eval'. This "
                                   'is extremely dangerous because\n'
                                   'it can enable an attacker to execute '
                                   'remote code. See\n'
                                   'https://owasp.org/www-community/attacks/Code_Injection '
                                   'for more information',
                    'display_name': 'UserEval',
                    'file': '%(issue.file)s',
                    'line': '%(issue.line)s',
                    'severity': '1',
                    'title': 'user eval'},
    'UserEvalFormatString': {   'categories': ['security'],
                                'description': 'Found user data in a call to '
                                               "'eval'. This is extremely "
                                               'dangerous because\n'
                                               'it can enable an attacker to '
                                               'execute remote code. See\n'
                                               'https://owasp.org/www-community/attacks/Code_Injection '
                                               'for more information.',
                                'display_name': 'UserEvalFormatString',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'user eval format string'},
    'UserExec': {   'categories': ['security'],
                    'description': "Found user data in a call to 'exec'. This "
                                   'is extremely dangerous because\n'
                                   'it can enable an attacker to execute '
                                   'remote code. See\n'
                                   'https://owasp.org/www-community/attacks/Code_Injection '
                                   'for more information.',
                    'display_name': 'UserExec',
                    'file': '%(issue.file)s',
                    'line': '%(issue.line)s',
                    'severity': '1',
                    'title': 'user exec'},
    'UserExecFormatString': {   'categories': ['security'],
                                'description': 'Found user data in a call to '
                                               "'exec'. This is extremely "
                                               'dangerous because\n'
                                               'it can enable an attacker to '
                                               'execute remote code. See\n'
                                               'https://owasp.org/www-community/attacks/Code_Injection '
                                               'for more information.',
                                'display_name': 'UserExecFormatString',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'user exec format string'},
    'VarInHref': {   'categories': ['security'],
                     'description': 'Detected a template variable used in an '
                                    'anchor tag with\n'
                                    "the 'href' attribute. This allows a "
                                    'malicious actor to\n'
                                    "input the 'javascript:' URI and is "
                                    'subject to cross-\n'
                                    'site scripting (XSS) attacks. If using a '
                                    'relative URL,\n'
                                    'start with a literal forward slash and '
                                    'concatenate the URL,\n'
                                    "like this: a(href='/'+url). You may also "
                                    'consider setting\n'
                                    'the Content Security Policy (CSP) header.',
                     'display_name': 'VarInHref',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'var in href'},
    'VarInScriptSrc': {   'categories': ['security'],
                          'description': 'Detected a template variable used as '
                                         "the 'src' in a script tag. Although "
                                         'template variables are HTML escaped, '
                                         'HTML escaping does not always '
                                         'prevent malicious URLs from being '
                                         'injected and could results in a '
                                         'cross-site scripting (XSS) '
                                         'vulnerability. Prefer not to '
                                         "dynamically generate the 'src' "
                                         'attribute and use static URLs '
                                         'instead. If you must do this, '
                                         'carefully check URLs against an '
                                         'allowlist and be sure to URL-encode '
                                         'the result.',
                          'display_name': 'VarInScriptSrc',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'var in script src'},
    'VarInScriptTag': {   'categories': ['security'],
                          'description': 'Detected a template variable used in '
                                         'a script tag. Although template '
                                         'variables are HTML escaped, HTML '
                                         'escaping does not always prevent '
                                         'cross-site scripting (XSS) attacks '
                                         'when used directly in JavaScript. If '
                                         'you need this data on the rendered '
                                         'page, consider placing it in the '
                                         'HTML portion (outside of a script '
                                         'tag). Alternatively, use a '
                                         'JavaScript-specific encoder, such as '
                                         'the one available in OWASP ESAPI. '
                                         'For Django, you may also consider '
                                         "using the 'json_script' template tag "
                                         'and retrieving the data in your '
                                         'script by using the element ID '
                                         '(e.g., `document.getElementById`).',
                          'display_name': 'VarInScriptTag',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'var in script tag'},
    'VertxSqli': {   'categories': ['security'],
                     'description': 'Detected a formatted string in a SQL '
                                    'statement. This could lead to SQL\n'
                                    'injection if variables in the SQL '
                                    'statement are not properly sanitized.\n'
                                    'Use a prepared statements '
                                    '(java.sql.PreparedStatement) instead. '
                                    'You\n'
                                    'can obtain a PreparedStatement using '
                                    "'connection.prepareStatement'.",
                     'display_name': 'VertxSqli',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'vertx sqli'},
    'Vm2CodeInjection': {   'categories': ['security'],
                            'description': 'Untrusted user input reaching '
                                           '`vm2` can result in code '
                                           'injection.',
                            'display_name': 'Vm2CodeInjection',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'vm2 code injection'},
    'Vm2ContextInjection': {   'categories': ['security'],
                               'description': 'Untrusted user input reaching '
                                              '`vm2` sandbox can result in '
                                              'context injection.',
                               'display_name': 'Vm2ContextInjection',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'vm2 context injection'},
    'VmCodeInjection': {   'categories': ['security'],
                           'description': 'Untrusted user input reaching `vm` '
                                          'can result in code injection.',
                           'display_name': 'VmCodeInjection',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'vm code injection'},
    'VmCompilefunctionCodeInjection': {   'categories': ['security'],
                                          'description': 'Make sure that '
                                                         'unverified user data '
                                                         'can not reach '
                                                         'vm.compileFunction.',
                                          'display_name': 'VmCompilefunctionCodeInjection',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'vm compilefunction code '
                                                   'injection'},
    'VmCompilefunctionContextInjection': {   'categories': ['security'],
                                             'description': 'Make sure that '
                                                            'unverified user '
                                                            'data can not '
                                                            'reach '
                                                            'vm.compileFunction.',
                                             'display_name': 'VmCompilefunctionContextInjection',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': 'vm compilefunction '
                                                      'context injection'},
    'VmCompilefunctionInjection': {   'categories': ['security'],
                                      'description': 'Untrusted user input in '
                                                     '`vm.compileFunction()` '
                                                     'can result in code '
                                                     'injection.',
                                      'display_name': 'VmCompilefunctionInjection',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'vm compilefunction injection'},
    'VmRunincontextCodeInjection': {   'categories': ['security'],
                                       'description': 'Make sure that '
                                                      'unverified user data '
                                                      'can not reach '
                                                      'vm.runInContext.',
                                       'display_name': 'VmRunincontextCodeInjection',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'vm runincontext code '
                                                'injection'},
    'VmRunincontextContextInjection': {   'categories': ['security'],
                                          'description': 'Make sure that '
                                                         'unverified user data '
                                                         'can not reach '
                                                         'vm.runInContext.',
                                          'display_name': 'VmRunincontextContextInjection',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'vm runincontext context '
                                                   'injection'},
    'VmRunincontextInjection': {   'categories': ['security'],
                                   'description': 'Untrusted user input in '
                                                  '`vm.runInContext()` can '
                                                  'result in code injection.',
                                   'display_name': 'VmRunincontextInjection',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'vm runincontext injection'},
    'VmRuninnewcontextCodeInjection': {   'categories': ['security'],
                                          'description': 'Make sure that '
                                                         'unverified user data '
                                                         'can not reach '
                                                         'vm.runInNewContext.',
                                          'display_name': 'VmRuninnewcontextCodeInjection',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'vm runinnewcontext code '
                                                   'injection'},
    'VmRuninnewcontextContextInjection': {   'categories': ['security'],
                                             'description': 'Make sure that '
                                                            'unverified user '
                                                            'data can not '
                                                            'reach '
                                                            'vm.runInNewContext.',
                                             'display_name': 'VmRuninnewcontextContextInjection',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': 'vm runinnewcontext '
                                                      'context injection'},
    'VmRuninnewcontextInjection': {   'categories': ['security'],
                                      'description': 'Untrusted user input in '
                                                     '`vm.runInNewContext()` '
                                                     'can result in code '
                                                     'injection.',
                                      'display_name': 'VmRuninnewcontextInjection',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'vm runinnewcontext injection'},
    'VmRuninthiscontextCodeInjection': {   'categories': ['security'],
                                           'description': 'Make sure that '
                                                          'unverified user '
                                                          'data can not reach '
                                                          'vm.runInThisContext.',
                                           'display_name': 'VmRuninthiscontextCodeInjection',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'vm runinthiscontext code '
                                                    'injection'},
    'VmScriptCodeInjection': {   'categories': ['security'],
                                 'description': 'Make sure that unverified '
                                                'user data can not reach '
                                                'vm.Script.',
                                 'display_name': 'VmScriptCodeInjection',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'vm script code injection'},
    'VmSourcetextmoduleCodeInjection': {   'categories': ['security'],
                                           'description': 'Make sure that '
                                                          'unverified user '
                                                          'data can not reach '
                                                          'vm.SourceTextModule.',
                                           'display_name': 'VmSourcetextmoduleCodeInjection',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'vm sourcetextmodule code '
                                                    'injection'},
    'WeakCrypto': {   'categories': ['security'],
                      'description': 'Detected usage of weak crypto function. '
                                     'Consider using stronger alternatives.',
                      'display_name': 'WeakCrypto',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'weak crypto'},
    'WeakHashesMd5': {   'categories': ['security'],
                         'description': 'Should not use md5 to generate '
                                        'hashes. md5 is proven to be '
                                        'vulnerable through the use of '
                                        'brute-force attacks.\n'
                                        'Could also result in '
                                        'collisions,leading to potential '
                                        'collision attacks. Use SHA256 or '
                                        'other hashing functions instead.',
                         'display_name': 'WeakHashesMd5',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'weak hashes md5'},
    'WeakHashesSha1': {   'categories': ['security'],
                          'description': 'Should not use SHA1 to generate '
                                         'hashes. There is a proven SHA1 hash '
                                         'collision by Google, which could '
                                         'lead to vulnerabilities.\n'
                                         'Use SHA256, SHA3 or other hashing '
                                         'functions instead.',
                          'display_name': 'WeakHashesSha1',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'weak hashes sha1'},
    'WeakSslContext': {   'categories': ['security'],
                          'description': 'An insecure SSL context was '
                                         'detected. TLS versions 1.0, 1.1, and '
                                         'all SSL versions\n'
                                         'are considered weak encryption and '
                                         'are deprecated.\n'
                                         'Use '
                                         'SSLContext.getInstance("TLSv1.2") '
                                         'for the best security.',
                          'display_name': 'WeakSslContext',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'weak ssl context'},
    'WeakSslVersion': {   'categories': ['security'],
                          'description': 'An insecure SSL version was '
                                         'detected. TLS versions 1.0, 1.1, and '
                                         'all SSL versions\n'
                                         'are considered weak encryption and '
                                         'are deprecated.\n'
                                         "Use 'ssl.PROTOCOL_TLSv1_2' or "
                                         'higher.',
                          'display_name': 'WeakSslVersion',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'weak ssl version'},
    'WildcardPostmessageConfiguration': {   'categories': ['security'],
                                            'description': 'The target origin '
                                                           'of the '
                                                           'window.postMessage() '
                                                           'API is set to "*". '
                                                           'This could allow '
                                                           'for information '
                                                           'disclosure due to '
                                                           'the possibility of '
                                                           'any origin allowed '
                                                           'to receive the '
                                                           'message.',
                                            'display_name': 'WildcardPostmessageConfiguration',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'wildcard postmessage '
                                                     'configuration'},
    'WipXssUsingResponsewriterAndPrintf': {   'categories': ['security'],
                                              'description': 'Found data going '
                                                             'from url query '
                                                             'parameters into '
                                                             'formatted data '
                                                             'written to '
                                                             'ResponseWriter.\n'
                                                             'This could be '
                                                             'XSS and should '
                                                             'not be done. If '
                                                             'you must do '
                                                             'this, ensure '
                                                             'your data is\n'
                                                             'sanitized or '
                                                             'escaped.',
                                              'display_name': 'WipXssUsingResponsewriterAndPrintf',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '1',
                                              'title': 'wip xss using '
                                                       'responsewriter and '
                                                       'printf'},
    'WkhtmltoimageInjection': {   'categories': ['security'],
                                  'description': 'If unverified user data can '
                                                 'reach the `wkhtmltoimage` it '
                                                 'can result in Server-Side '
                                                 'Request Forgery '
                                                 'vulnerabilities',
                                  'display_name': 'WkhtmltoimageInjection',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'wkhtmltoimage injection'},
    'WkhtmltoimageSsrf': {   'categories': ['security'],
                             'description': 'User controlled URL reached to '
                                            '`wkhtmltoimage` can result in '
                                            'Server Side Request Forgery '
                                            '(SSRF).',
                             'display_name': 'WkhtmltoimageSsrf',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'wkhtmltoimage ssrf'},
    'WkhtmltopdfInjection': {   'categories': ['security'],
                                'description': 'If unverified user data can '
                                               'reach the `wkhtmltopdf` it can '
                                               'result in Server-Side Request '
                                               'Forgery vulnerabilities',
                                'display_name': 'WkhtmltopdfInjection',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'wkhtmltopdf injection'},
    'WkhtmltopdfSsrf': {   'categories': ['security'],
                           'description': 'User controlled URL reached to '
                                          '`wkhtmltopdf` can result in Server '
                                          'Side Request Forgery (SSRF).',
                           'display_name': 'WkhtmltopdfSsrf',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'wkhtmltopdf ssrf'},
    'WritableFilesystemContainer': {   'categories': ['security'],
                                       'description': 'Container is running '
                                                      'with a writable root '
                                                      'filesystem. This may\n'
                                                      'allow malicious '
                                                      'applications to '
                                                      'download and run '
                                                      'additional payloads, '
                                                      'or\n'
                                                      'modify container files. '
                                                      'If an application '
                                                      'inside a container has '
                                                      'to save\n'
                                                      'something temporarily '
                                                      'consider using a tmpfs. '
                                                      'Add '
                                                      "'readOnlyRootFilesystem: "
                                                      "true'\n"
                                                      'to this container to '
                                                      'prevent this.',
                                       'display_name': 'WritableFilesystemContainer',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'kubernetes: writable '
                                                'filesystem container'},
    'WritingToFileInReadMode': {   'categories': ['security'],
                                   'description': "The file object '$FD' was "
                                                  'opened in read mode, but is '
                                                  'being\n'
                                                  'written to. This will cause '
                                                  'a runtime error.',
                                   'display_name': 'WritingToFileInReadMode',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'writing to file in read mode'},
    'Xml2jsonXxe': {   'categories': ['security'],
                       'description': 'If unverified user data can reach the '
                                      'XML Parser it can result in XML '
                                      'External or\n'
                                      'Internal Entity (XXE) Processing '
                                      'vulnerabilities',
                       'display_name': 'Xml2jsonXxe',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'xml2json xxe'},
    'XmlDecoder': {   'categories': ['security'],
                      'description': 'XMLDecoder should not be used to parse '
                                     'untrusted data.\n'
                                     'Deserializing user input can lead to '
                                     'arbitrary code execution.\n'
                                     'Use an alternative and explicitly '
                                     'disable external entities.\n'
                                     'See '
                                     'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html\n'
                                     'for alternatives and vulnerability '
                                     'prevention.',
                      'display_name': 'XmlDecoder',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'xml decoder'},
    'XmlinputfactoryExternalEntitiesEnabled': {   'categories': ['security'],
                                                  'description': 'XML external '
                                                                 'entities are '
                                                                 'enabled for '
                                                                 'this '
                                                                 'XMLInputFactory. '
                                                                 'This is '
                                                                 'vulnerable '
                                                                 'to XML '
                                                                 'external '
                                                                 'entity\n'
                                                                 'attacks. '
                                                                 'Disable '
                                                                 'external '
                                                                 'entities by '
                                                                 'setting '
                                                                 '"javax.xml.stream.isSupportingExternalEntities" '
                                                                 'to false.',
                                                  'display_name': 'XmlinputfactoryExternalEntitiesEnabled',
                                                  'file': '%(issue.file)s',
                                                  'line': '%(issue.line)s',
                                                  'severity': '1',
                                                  'title': 'xmlinputfactory '
                                                           'external entities '
                                                           'enabled'},
    'XmlinputfactoryPossibleXxe': {   'categories': ['security'],
                                      'description': 'XML external entities '
                                                     'are not explicitly '
                                                     'disabled for this '
                                                     'XMLInputFactory. This '
                                                     'could be vulnerable to '
                                                     'XML external entity\n'
                                                     'vulnerabilities. '
                                                     'Explicitly disable '
                                                     'external entities by '
                                                     'setting '
                                                     '"javax.xml.stream.isSupportingExternalEntities" '
                                                     'to false.',
                                      'display_name': 'XmlinputfactoryPossibleXxe',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'xmlinputfactory possible xxe'},
    'XssDisableMustacheEscape': {   'categories': ['security'],
                                    'description': 'Markup escaping disabled. '
                                                   'This can be used with some '
                                                   'template engines to escape '
                                                   'disabling of HTML '
                                                   'entities, which can lead '
                                                   'to XSS attacks.',
                                    'display_name': 'XssDisableMustacheEscape',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'xss disable mustache escape'},
    'XssHtmlEmailBody': {   'categories': ['security'],
                            'description': 'Found request data in an '
                                           'EmailMessage that is set to use '
                                           'HTML.\n'
                                           'This is dangerous because HTML '
                                           'emails are susceptible to XSS.\n'
                                           'An attacker could inject data into '
                                           'this HTML email, causing XSS.',
                            'display_name': 'XssHtmlEmailBody',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'xss html email body'},
    'XssSendMailHtmlMessage': {   'categories': ['security'],
                                  'description': 'Found request data in '
                                                 "'send_mail(...)' that uses "
                                                 "'html_message'.\n"
                                                 'This is dangerous because '
                                                 'HTML emails are susceptible '
                                                 'to XSS.\n'
                                                 'An attacker could inject '
                                                 'data into this HTML email, '
                                                 'causing XSS.',
                                  'display_name': 'XssSendMailHtmlMessage',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'xss send mail html message'},
    'XssSerializeJavascript': {   'categories': ['security'],
                                  'description': 'Untrusted user input '
                                                 'reaching '
                                                 '`serialize-javascript` with '
                                                 '`unsafe` attribute can cause '
                                                 'Cross Site Scripting (XSS).',
                                  'display_name': 'XssSerializeJavascript',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'xss serialize javascript'},
    'XssrequestwrapperIsInsecure': {   'categories': ['security'],
                                       'description': "It looks like you're "
                                                      'using an implementation '
                                                      'of XSSRequestWrapper '
                                                      'from dzone.\n'
                                                      '(https://www.javacodegeeks.com/2012/07/anti-cross-site-scripting-xss-filter.html)\n'
                                                      'The XSS filtering in '
                                                      'this code is not secure '
                                                      'and can be bypassed by '
                                                      'malicious actors.\n'
                                                      'It is recommended to '
                                                      'use a stack that '
                                                      'automatically escapes '
                                                      'in your view or '
                                                      'templates\n'
                                                      'instead of filtering '
                                                      'yourself.',
                                       'display_name': 'XssrequestwrapperIsInsecure',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'xssrequestwrapper is '
                                                'insecure'},
    'XxeExpat': {   'categories': ['security'],
                    'description': 'Make sure that unverified user data can '
                                   'not reach the XML Parser, as it can result '
                                   'in XML External or Internal Entity (XXE) '
                                   'Processing vulnerabilities.',
                    'display_name': 'XxeExpat',
                    'file': '%(issue.file)s',
                    'line': '%(issue.line)s',
                    'severity': '1',
                    'title': 'xxe expat'},
    'XxeSax': {   'categories': ['security'],
                  'description': "Use of 'ondoctype' in 'sax' library "
                                 "detected. By default, 'sax' won't do "
                                 'anything with custom DTD entity definitions. '
                                 "If you're implementing a custom DTD entity "
                                 'definition, be sure not to introduce XML '
                                 'External Entity (XXE) vulnerabilities, or be '
                                 'absolutely sure that external entities '
                                 'received from a trusted source while '
                                 'processing XML.',
                  'display_name': 'XxeSax',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'xxe sax'},
    'XxeXml2json': {   'categories': ['security'],
                       'description': 'Make sure that unverified user data can '
                                      'not reach the XML Parser, as it can '
                                      'result in XML External or Internal '
                                      'Entity (XXE) Processing '
                                      'vulnerabilities.',
                       'display_name': 'XxeXml2json',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'xxe xml2json'},
    'YamlDeserialize': {   'categories': ['security'],
                           'description': 'User controlled data in '
                                          "'yaml.load()' function can result "
                                          'in Remote Code Injection.',
                           'display_name': 'YamlDeserialize',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'yaml deserialize'},
    'YamlParsing': {   'categories': ['security'],
                       'description': 'Detected enabled YAML parsing. This is '
                                      'vulnerable to remote code execution in '
                                      'Rails 2.x\n'
                                      'versions up to 2.3.14. To fix, delete '
                                      'this line.',
                       'display_name': 'YamlParsing',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'yaml parsing'},
    'YieldInInit': {   'categories': ['security'],
                       'description': '`yield` should never appear inside a '
                                      'class __init__ function. This will '
                                      'cause a runtime error.',
                       'display_name': 'YieldInInit',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'yield in init'},
    'ZipPathOverwrite': {   'categories': ['security'],
                            'description': 'Insecure ZIP archive extraction '
                                           'can result in arbitrary path over '
                                           'write and can result in code '
                                           'injection.',
                            'display_name': 'ZipPathOverwrite',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'zip path overwrite'},
    'ZipPathOverwrite2': {   'categories': ['security'],
                             'description': 'Insecure ZIP archive extraction '
                                            'can result in arbitrary path over '
                                            'write and can result in code '
                                            'injection.',
                             'display_name': 'ZipPathOverwrite2',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'zip path overwrite2'},
    'ZlibAsyncLoop': {   'categories': ['security'],
                         'description': 'Creating and using a large number of '
                                        'zlib objects simultaneously\n'
                                        'can cause significant memory '
                                        'fragmentation. It is strongly '
                                        'recommended\n'
                                        'that the results of compression '
                                        'operations be cached or made '
                                        'synchronous\n'
                                        'to avoid duplication of effort.',
                         'display_name': 'ZlibAsyncLoop',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'zlib async loop'}}
