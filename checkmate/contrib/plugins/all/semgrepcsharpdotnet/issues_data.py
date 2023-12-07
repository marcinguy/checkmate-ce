issues_data = {   'X509Certificate2privkey': {   'categories': ['security'],
                                   'description': 'X509Certificate2.PrivateKey '
                                                  'is obsolete. Use a method '
                                                  'such as GetRSAPrivateKey() '
                                                  'or GetECDsaPrivateKey(). '
                                                  'Alternatively, use the '
                                                  'CopyWithPrivateKey() method '
                                                  'to create a new instance '
                                                  'with a private key. '
                                                  'Further, if you set '
                                                  'X509Certificate2.PrivateKey '
                                                  'to `null` or set it to '
                                                  'another key without '
                                                  'deleting it first, the '
                                                  'private key will be left on '
                                                  'disk. ',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'X509Certificate2 Privkey'},
    'X509subjectnamevalidation': {   'categories': ['security'],
                                     'description': 'Validating certificates '
                                                    'based on subject name is '
                                                    'bad practice. Use the '
                                                    'X509Certificate2.Verify() '
                                                    'method instead.',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'X509 Subject Name Validation'},
    'correctnessdoubleepsilonequality': {   'categories': ['security'],
                                            'description': 'Double.Epsilon is '
                                                           'defined by .NET as '
                                                           'the smallest value '
                                                           'that can be added '
                                                           'to or subtracted '
                                                           'from a zero-value '
                                                           'Double.  It is '
                                                           'unsuitable for '
                                                           'equality '
                                                           'comparisons of '
                                                           'non-zero Double '
                                                           'values. '
                                                           'Furthermore, the '
                                                           'value of '
                                                           'Double.Epsilon is '
                                                           'framework and '
                                                           'processor '
                                                           'architecture '
                                                           'dependent.  '
                                                           'Wherever possible, '
                                                           'developers should '
                                                           'prefer the '
                                                           'framework Equals() '
                                                           'method over custom '
                                                           'equality '
                                                           'implementations.',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'Correctness Double '
                                                     'Epsilon Equality'},
    'correctnessregioninfointerop': {   'categories': ['security'],
                                        'description': 'Potential '
                                                       'inter-process write of '
                                                       'RegionInfo $RI via '
                                                       '$PIPESTREAM $P that '
                                                       'was instantiated with '
                                                       'a two-character '
                                                       'culture code $REGION.  '
                                                       'Per .NET '
                                                       'documentation, if you '
                                                       'want to persist a '
                                                       'RegionInfo object or '
                                                       'communicate it between '
                                                       'processes, you should '
                                                       'instantiate it by '
                                                       'using a full culture '
                                                       'name rather than a '
                                                       'two-letter ISO region '
                                                       'code.',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'Correctness Regioninfo '
                                                 'Interop'},
    'correctnesssslcertificatetrusthandshakenotrust': {   'categories': [   'security'],
                                                          'description': 'Sending '
                                                                         'the '
                                                                         'trusted '
                                                                         'CA '
                                                                         'list '
                                                                         'increases '
                                                                         'the '
                                                                         'size '
                                                                         'of '
                                                                         'the '
                                                                         'handshake '
                                                                         'request '
                                                                         'and '
                                                                         'can '
                                                                         'leak '
                                                                         'system '
                                                                         'configuration '
                                                                         'information.',
                                                          'file': '%(issue.file)s',
                                                          'line': '%(issue.line)s',
                                                          'severity': '1',
                                                          'title': 'Correctness '
                                                                   'Sslcertificatetrust '
                                                                   'Handshake '
                                                                   'No Trust'},
    'csharpsqli': {   'categories': ['security'],
                      'description': 'Detected a formatted string in a SQL '
                                     'statement. This could lead to SQL '
                                     'injection if variables in the SQL '
                                     'statement are not properly sanitized. '
                                     'Use a prepared statements instead. You '
                                     'can obtain a PreparedStatement using '
                                     "'SqlCommand' and 'SqlParameter'.",
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Csharp Sqli'},
    'datacontractresolver': {   'categories': ['security'],
                                'description': 'Only use DataContractResolver '
                                               'if you are completely sure of '
                                               'what information is being '
                                               'serialized. Malicious types '
                                               'can cause unexpected behavior.',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Data Contract Resolver'},
    'htmlrawjson': {   'categories': ['security'],
                       'description': 'Unencoded JSON in HTML context is '
                                      'vulnerable to cross-site scripting, '
                                      'because `</script>` is not properly '
                                      'encoded.',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Html Raw Json'},
    'httplistenerwildcardbindings': {   'categories': ['security'],
                                        'description': 'The top level wildcard '
                                                       'bindings $PREFIX '
                                                       'leaves your '
                                                       'application open to '
                                                       'security '
                                                       'vulnerabilities and '
                                                       'give attackers more '
                                                       'control over where '
                                                       'traffic is routed. If '
                                                       'you must use '
                                                       'wildcards, consider '
                                                       'using subdomain '
                                                       'wildcard binding. For '
                                                       'example, you can use '
                                                       '"*.asdf.gov" if you '
                                                       'own all of "asdf.gov".',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'Http Listener Wildcard '
                                                 'Bindings'},
    'insecurebinaryformatterdeserialization': {   'categories': ['security'],
                                                  'description': 'The '
                                                                 'BinaryFormatter '
                                                                 'type is '
                                                                 'dangerous '
                                                                 'and is not '
                                                                 'recommended '
                                                                 'for data '
                                                                 'processing. '
                                                                 'Applications '
                                                                 'should stop '
                                                                 'using '
                                                                 'BinaryFormatter '
                                                                 'as soon as '
                                                                 'possible, '
                                                                 'even if they '
                                                                 'believe the '
                                                                 "data they're "
                                                                 'processing '
                                                                 'to be '
                                                                 'trustworthy. '
                                                                 'BinaryFormatter '
                                                                 'is insecure '
                                                                 "and can't be "
                                                                 'made secure',
                                                  'file': '%(issue.file)s',
                                                  'line': '%(issue.line)s',
                                                  'severity': '1',
                                                  'title': 'Insecure '
                                                           'Binaryformatter '
                                                           'Deserialization'},
    'insecurefastjsondeserialization': {   'categories': ['security'],
                                           'description': '$type extension has '
                                                          'the potential to be '
                                                          'unsafe, so use it '
                                                          'with common sense '
                                                          'and known json '
                                                          'sources and not '
                                                          'public facing ones '
                                                          'to be safe',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'Insecure Fastjson '
                                                    'Deserialization'},
    'insecurefspicklerdeserialization': {   'categories': ['security'],
                                            'description': 'The FsPickler is '
                                                           'dangerous and is '
                                                           'not recommended '
                                                           'for data '
                                                           'processing. '
                                                           'Default '
                                                           'configuration tend '
                                                           'to insecure '
                                                           'deserialization '
                                                           'vulnerability.',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'Insecure Fspickler '
                                                     'Deserialization'},
    'insecurejavascriptserializerdeserialization': {   'categories': [   'security'],
                                                       'description': 'The '
                                                                      'SimpleTypeResolver '
                                                                      'class '
                                                                      'is '
                                                                      'insecure '
                                                                      'and '
                                                                      'should '
                                                                      'not be '
                                                                      'used. '
                                                                      'Using '
                                                                      'SimpleTypeResolver '
                                                                      'to '
                                                                      'deserialize '
                                                                      'JSON '
                                                                      'could '
                                                                      'allow '
                                                                      'the '
                                                                      'remote '
                                                                      'client '
                                                                      'to '
                                                                      'execute '
                                                                      'malicious '
                                                                      'code '
                                                                      'within '
                                                                      'the app '
                                                                      'and '
                                                                      'take '
                                                                      'control '
                                                                      'of the '
                                                                      'web '
                                                                      'server.',
                                                       'file': '%(issue.file)s',
                                                       'line': '%(issue.line)s',
                                                       'severity': '1',
                                                       'title': 'Insecure '
                                                                'Javascriptserializer '
                                                                'Deserialization'},
    'insecurelosformatterdeserialization': {   'categories': ['security'],
                                               'description': 'The '
                                                              'LosFormatter '
                                                              'type is '
                                                              'dangerous and '
                                                              'is not '
                                                              'recommended for '
                                                              'data '
                                                              'processing. '
                                                              'Applications '
                                                              'should stop '
                                                              'using '
                                                              'LosFormatter as '
                                                              'soon as '
                                                              'possible, even '
                                                              'if they believe '
                                                              'the data '
                                                              "they're "
                                                              'processing to '
                                                              'be trustworthy. '
                                                              'LosFormatter is '
                                                              'insecure and '
                                                              "can't be made "
                                                              'secure',
                                               'file': '%(issue.file)s',
                                               'line': '%(issue.line)s',
                                               'severity': '1',
                                               'title': 'Insecure Losformatter '
                                                        'Deserialization'},
    'insecurenetdatacontractdeserialization': {   'categories': ['security'],
                                                  'description': 'The '
                                                                 'NetDataContractSerializer '
                                                                 'type is '
                                                                 'dangerous '
                                                                 'and is not '
                                                                 'recommended '
                                                                 'for data '
                                                                 'processing. '
                                                                 'Applications '
                                                                 'should stop '
                                                                 'using '
                                                                 'NetDataContractSerializer '
                                                                 'as soon as '
                                                                 'possible, '
                                                                 'even if they '
                                                                 'believe the '
                                                                 "data they're "
                                                                 'processing '
                                                                 'to be '
                                                                 'trustworthy. '
                                                                 'NetDataContractSerializer '
                                                                 'is insecure '
                                                                 "and can't be "
                                                                 'made secure',
                                                  'file': '%(issue.file)s',
                                                  'line': '%(issue.line)s',
                                                  'severity': '1',
                                                  'title': 'Insecure '
                                                           'Netdatacontract '
                                                           'Deserialization'},
    'insecurenewtonsoftdeserialization': {   'categories': ['security'],
                                             'description': 'TypeNameHandling '
                                                            '$TYPEHANDLER is '
                                                            'unsafe and can '
                                                            'lead to arbitrary '
                                                            'code execution in '
                                                            'the context of '
                                                            'the process.  Use '
                                                            'a custom '
                                                            'SerializationBinder '
                                                            'whenever using a '
                                                            'setting other '
                                                            'than '
                                                            'TypeNameHandling.None.',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': 'Insecure Newtonsoft '
                                                      'Deserialization'},
    'insecuresoapformatterdeserialization': {   'categories': ['security'],
                                                'description': 'The '
                                                               'SoapFormatter '
                                                               'type is '
                                                               'dangerous and '
                                                               'is not '
                                                               'recommended '
                                                               'for data '
                                                               'processing. '
                                                               'Applications '
                                                               'should stop '
                                                               'using '
                                                               'SoapFormatter '
                                                               'as soon as '
                                                               'possible, even '
                                                               'if they '
                                                               'believe the '
                                                               "data they're "
                                                               'processing to '
                                                               'be '
                                                               'trustworthy. '
                                                               'SoapFormatter '
                                                               'is insecure '
                                                               "and can't be "
                                                               'made secure',
                                                'file': '%(issue.file)s',
                                                'line': '%(issue.line)s',
                                                'severity': '1',
                                                'title': 'Insecure '
                                                         'Soapformatter '
                                                         'Deserialization'},
    'insecuretypefilterlevelfull': {   'categories': ['security'],
                                       'description': 'Using a .NET remoting '
                                                      'service can lead to '
                                                      'RCE, even if you try to '
                                                      'configure '
                                                      'TypeFilterLevel. '
                                                      'Recommended to switch '
                                                      'from .NET Remoting to '
                                                      'WCF '
                                                      'https://docs.microsoft.com/en-us/dotnet/framework/wcf/migrating-from-net-remoting-to-wcf',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'Insecure Typefilterlevel '
                                                'Full'},
    'jwttokenvalidationparametersnoexpiryvalidation': {   'categories': [   'security'],
                                                          'description': 'The '
                                                                         'TokenValidationParameters.$LIFETIME '
                                                                         'is '
                                                                         'set '
                                                                         'to '
                                                                         '$FALSE, '
                                                                         'this '
                                                                         'means '
                                                                         'the  '
                                                                         'JWT '
                                                                         'tokens '
                                                                         'lifetime '
                                                                         'is '
                                                                         'not '
                                                                         'validated. '
                                                                         'This '
                                                                         'can '
                                                                         'lead '
                                                                         'to '
                                                                         'an  '
                                                                         'JWT '
                                                                         'token '
                                                                         'being '
                                                                         'used '
                                                                         'after '
                                                                         'it '
                                                                         'has '
                                                                         'expired, '
                                                                         'which '
                                                                         'has '
                                                                         'security '
                                                                         'implications.  '
                                                                         'It '
                                                                         'is '
                                                                         'recommended '
                                                                         'to '
                                                                         'validate '
                                                                         'the '
                                                                         'JWT '
                                                                         'lifetime '
                                                                         'to '
                                                                         'ensure '
                                                                         'only '
                                                                         'valid '
                                                                         'tokens '
                                                                         'are '
                                                                         'used.',
                                                          'file': '%(issue.file)s',
                                                          'line': '%(issue.line)s',
                                                          'severity': '1',
                                                          'title': 'Jwt '
                                                                   'Tokenvalidationparameters '
                                                                   'No Expiry '
                                                                   'Validation'},
    'ldapinjection': {   'categories': ['security'],
                         'description': 'LDAP queries are constructed '
                                        'dynamically on user-controlled input. '
                                        'This vulnerability in code could lead '
                                        'to an arbitrary LDAP query execution.',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ldap Injection'},
    'massassignment': {   'categories': ['security'],
                          'description': 'Mass assignment or Autobinding '
                                         'vulnerability in code allows an '
                                         'attacker to execute over-posting '
                                         'attacks, which could create a new '
                                         'parameter in the binding request and '
                                         'manipulate the underlying object in '
                                         'the application.',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'Mass Assignment'},
    'memorymarshalcreatespan': {   'categories': ['security'],
                                   'description': 'MemoryMarshal.CreateSpan '
                                                  'and '
                                                  'MemoryMarshal.CreateReadOnlySpan '
                                                  'should be used with '
                                                  'caution, as the length '
                                                  'argument is not checked.',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'Memory Marshal Create Span'},
    'misconfiguredlockoutoption': {   'categories': ['security'],
                                      'description': 'A misconfigured lockout '
                                                     'mechanism allows an '
                                                     'attacker to execute '
                                                     'brute-force attacks. '
                                                     'Account lockout must be '
                                                     'correctly configured and '
                                                     'enabled to prevent these '
                                                     'attacks.',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'Misconfigured Lockout Option'},
    'missinghstsheader': {   'categories': ['security'],
                             'description': 'The HSTS HTTP response security '
                                            'header is missing, allowing '
                                            'interaction and communication to '
                                            'be sent over the insecure HTTP '
                                            'protocol.',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Missing Hsts Header'},
    'missingorbrokenauthorization': {   'categories': ['security'],
                                        'description': 'Anonymous access '
                                                       "shouldn't be allowed "
                                                       'unless explicit by '
                                                       'design. Access control '
                                                       'checks are missing and '
                                                       'potentially can be '
                                                       'bypassed. This finding '
                                                       'violates the principle '
                                                       'of least privilege or '
                                                       'deny by default, where '
                                                       'access should only be '
                                                       'permitted for a '
                                                       'specific set of roles '
                                                       'or conforms to a '
                                                       'custom policy or '
                                                       'users.',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'Missing Or Broken '
                                                 'Authorization'},
    'mvcmissingantiforgery': {   'categories': ['security'],
                                 'description': '$METHOD is a state-changing '
                                                'MVC method that does not '
                                                'validate the antiforgery '
                                                'token or do strict '
                                                'content-type checking. '
                                                'State-changing controller '
                                                'methods should either enforce '
                                                'antiforgery tokens or do '
                                                'strict content-type checking '
                                                'to prevent simple HTTP '
                                                'request types from bypassing '
                                                'CORS preflight controls.',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'Mvc Missing Antiforgery'},
    'netwebconfigdebug': {   'categories': ['security'],
                             'description': 'ASP.NET applications built with '
                                            '`debug` set to true in production '
                                            'may leak debug information to '
                                            'attackers. Debug mode also '
                                            'affects performance and '
                                            'reliability. Set `debug` to '
                                            '`false` or remove it from '
                                            '`<compilation ... />`',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Net Webconfig Debug'},
    'netwebconfigtraceenabled': {   'categories': ['security'],
                                    'description': 'OWASP guidance recommends '
                                                   'disabling tracing for '
                                                   'production applications to '
                                                   'prevent accidental leakage '
                                                   'of sensitive application '
                                                   'information.',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'Net Webconfig Trace Enabled'},
    'opendirectorylisting': {   'categories': ['security'],
                                'description': 'An open directory listing is '
                                               'potentially exposed, '
                                               'potentially revealing '
                                               'sensitive information to '
                                               'attackers.',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Open Directory Listing'},
    'openredirect': {   'categories': ['security'],
                        'description': 'A query string parameter may contain a '
                                       'URL value that could cause the web '
                                       'application to redirect the request to '
                                       'a malicious website controlled by an '
                                       'attacker. Make sure to sanitize this '
                                       'parameter sufficiently.',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Open Redirect'},
    'oscommandinjection': {   'categories': ['security'],
                              'description': 'The software constructs all or '
                                             'part of an OS command using '
                                             'externally-influenced input from '
                                             'an upstream component, but it '
                                             'does not neutralize or '
                                             'incorrectly neutralizes special '
                                             'elements that could modify the '
                                             'intended OS command when it is '
                                             'sent to a downstream component.',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'Os Command Injection'},
    'razortemplateinjection': {   'categories': ['security'],
                                  'description': 'User-controllable string '
                                                 'passed to Razor.Parse.  This '
                                                 'leads directly to code '
                                                 'execution in the context of '
                                                 'the process.',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'Razor Template Injection'},
    'razoruseofhtmlstring': {   'categories': ['security'],
                                'description': 'ASP.NET Core MVC provides an '
                                               "HtmlString class which isn't "
                                               'automatically encoded upon '
                                               'output. This should never be '
                                               'used in combination with '
                                               'untrusted input as this will '
                                               'expose an XSS vulnerability.',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Razor Use Of Htmlstring'},
    'regularexpressiondos': {   'categories': ['security'],
                                'description': 'An attacker can then cause a '
                                               'program using a regular '
                                               'expression to enter these '
                                               'extreme situations and then '
                                               'hang for a very long time.',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Regular Expression Dos'},
    'regularexpressiondosinfinitetimeout': {   'categories': ['security'],
                                               'description': 'Specifying the '
                                                              'regex timeout '
                                                              'leaves the '
                                                              'system '
                                                              'vulnerable to a '
                                                              'regex-based '
                                                              'Denial of '
                                                              'Service (DoS) '
                                                              'attack.  '
                                                              'Consider '
                                                              'setting the '
                                                              'timeout to a '
                                                              'short amount of '
                                                              'time like 2 or '
                                                              '3 seconds. If '
                                                              'you are sure '
                                                              'you need an '
                                                              'infinite '
                                                              'timeout, double '
                                                              'check that your '
                                                              'context meets '
                                                              'the conditions '
                                                              'outlined in the '
                                                              '"Notes to '
                                                              'Callers" '
                                                              'section at the '
                                                              'bottom of this '
                                                              'page:  '
                                                              'https://docs.microsoft.com/en-us/dotnet/api/system.text.regularexpressions.regex.-ctor?view=net-6.0',
                                               'file': '%(issue.file)s',
                                               'line': '%(issue.line)s',
                                               'severity': '1',
                                               'title': 'Regular Expression '
                                                        'Dos Infinite Timeout'},
    'ssrf': {   'categories': ['security'],
                'description': 'The web server receives a URL or similar '
                               'request from an upstream component and '
                               'retrieves the contents of this URL, but it '
                               'does not sufficiently ensure that the request '
                               'is being sent to the expected destination. '
                               'Many different options exist to fix this issue '
                               'depending the use case (Application can send '
                               'request only to identified and trusted '
                               'applications, Application can send requests to '
                               'ANY external IP address or domain name).',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'Ssrf'},
    'stacktracedisclosure': {   'categories': ['security'],
                                'description': 'Stacktrace information is '
                                               'displayed in a non-Development '
                                               'environment. Accidentally '
                                               'disclosing sensitive stack '
                                               'trace information in a '
                                               'production environment aids an '
                                               'attacker in reconnaissance and '
                                               'information gathering.',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Stacktrace Disclosure'},
    'structuredlogging': {   'categories': ['security'],
                             'description': 'String interpolation in log '
                                            'message obscures the distinction '
                                            'between variables and the log '
                                            'message. Use structured logging '
                                            'instead, where the variables are '
                                            'passed as additional arguments '
                                            'and the interpolation is '
                                            'performed by the logging library. '
                                            'This reduces the possibility of '
                                            'log injection and makes it easier '
                                            'to search through logs.',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Structured Logging'},
    'unsafepathcombine': {   'categories': ['security'],
                             'description': 'String argument $A is used to '
                                            'read or write data from a file '
                                            'via Path.Combine without direct '
                                            'sanitization via '
                                            'Path.GetFileName. If the path is '
                                            'user-supplied data this can lead '
                                            'to path traversal.',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Unsafe Path Combine'},
    'unsignedsecuritytoken': {   'categories': ['security'],
                                 'description': 'Accepting unsigned security '
                                                'tokens as valid security '
                                                'tokens allows an attacker to '
                                                'remove its signature and '
                                                'potentially forge an '
                                                'identity. As a fix, set '
                                                'RequireSignedTokens to be '
                                                'true.',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'Unsigned Security Token'},
    'usedeprecatedcipheralgorithm': {   'categories': ['security'],
                                        'description': 'Usage of deprecated '
                                                       'cipher algorithm '
                                                       'detected. Use Aes or '
                                                       'ChaCha20Poly1305 '
                                                       'instead.',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'Use Deprecated Cipher '
                                                 'Algorithm'},
    'useecbmode': {   'categories': ['security'],
                      'description': 'Usage of the insecure ECB mode detected. '
                                     'You should use an authenticated '
                                     'encryption mode instead, which is '
                                     'implemented by the classes AesGcm or '
                                     'ChaCha20Poly1305.',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Use Ecb Mode'},
    'useweakrngforkeygeneration': {   'categories': ['security'],
                                      'description': 'You are using an '
                                                     'insecure random number '
                                                     'generator (RNG) to '
                                                     'create a cryptographic '
                                                     'key. System.Random must '
                                                     'never be used for '
                                                     'cryptographic purposes. '
                                                     'Use '
                                                     'System.Security.Cryptography.RandomNumberGenerator '
                                                     'instead.',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'Use Weak Rng For '
                                               'Keygeneration'},
    'useweakrsaencryptionpadding': {   'categories': ['security'],
                                       'description': 'You are using the '
                                                      'outdated PKCS#1 v1.5 '
                                                      'encryption padding for '
                                                      'your RSA key. Use the '
                                                      'OAEP padding instead.',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'Use Weak Rsa Encryption '
                                                'Padding'},
    'webconfiginsecurecookiesettings': {   'categories': ['security'],
                                           'description': 'Cookie Secure flag '
                                                          'is explicitly '
                                                          'disabled. You '
                                                          'should enforce this '
                                                          'value to avoid '
                                                          'accidentally '
                                                          'presenting '
                                                          'sensitive cookie '
                                                          'values over '
                                                          'plaintext HTTP '
                                                          'connections.',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'Web Config Insecure '
                                                    'Cookie Settings'},
    'xmldocumentunsafeparseroverride': {   'categories': ['security'],
                                           'description': 'XmlReaderSettings '
                                                          'found with '
                                                          'DtdProcessing.Parse '
                                                          'on an XmlReader '
                                                          'handling a string '
                                                          'argument from a '
                                                          'public method.  '
                                                          'Enabling Document '
                                                          'Type Definition '
                                                          '(DTD) parsing may '
                                                          'cause XML External '
                                                          'Entity (XXE) '
                                                          'injection if '
                                                          'supplied with '
                                                          'user-controllable '
                                                          'data.',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'Xmldocument Unsafe Parser '
                                                    'Override'},
    'xmlreadersettingsunsafeparseroverride': {   'categories': ['security'],
                                                 'description': 'XmlReaderSettings '
                                                                'found with '
                                                                'DtdProcessing.Parse '
                                                                'on an '
                                                                'XmlReader '
                                                                'handling a '
                                                                'string '
                                                                'argument from '
                                                                'a public '
                                                                'method.  '
                                                                'Enabling '
                                                                'Document Type '
                                                                'Definition '
                                                                '(DTD) parsing '
                                                                'may cause XML '
                                                                'External '
                                                                'Entity (XXE) '
                                                                'injection if '
                                                                'supplied with '
                                                                'user-controllable '
                                                                'data.',
                                                 'file': '%(issue.file)s',
                                                 'line': '%(issue.line)s',
                                                 'severity': '1',
                                                 'title': 'Xmlreadersettings '
                                                          'Unsafe Parser '
                                                          'Override'},
    'xmltextreaderunsafedefaults': {   'categories': ['security'],
                                       'description': 'XmlReaderSettings found '
                                                      'with '
                                                      'DtdProcessing.Parse on '
                                                      'an XmlReader handling a '
                                                      'string argument from a '
                                                      'public method.  '
                                                      'Enabling Document Type '
                                                      'Definition (DTD) '
                                                      'parsing may cause XML '
                                                      'External Entity (XXE) '
                                                      'injection if supplied '
                                                      'with user-controllable '
                                                      'data.',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'Xmltextreader Unsafe '
                                                'Defaults'},
    'xpathinjection': {   'categories': ['security'],
                          'description': 'XPath queries are constructed '
                                         'dynamically on user-controlled '
                                         'input. This vulnerability in code '
                                         'could lead to an XPath Injection '
                                         'exploitation.',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'Xpath Injection'}}
