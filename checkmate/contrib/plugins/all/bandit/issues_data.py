issues_data = {   'B101': {   'categories': ['security'],
                'description': 'Use of assert detected. The enclosed code will '
                               'be removed when compiling to optimised byte '
                               'code.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'assert used'},
    'B102': {   'categories': ['security'],
                'description': 'Use of exec detected.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'exec used'},
    'B103': {   'categories': ['security'],
                'description': 'Chmod setting a permissive mask 0777 on file '
                               '(key file).',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '3',
                'title': 'set bad file permissions'},
    'B104': {   'categories': ['security'],
                'description': 'Possible binding to all interfaces.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'hardcoded bind all interfaces'},
    'B105': {   'categories': ['security'],
                'description': "Possible hardcoded password: 'blerg'",
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'hardcoded password string'},
    'B106': {   'categories': ['security'],
                'description': "Possible hardcoded password: 'blerg'",
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'hardcoded password funcarg'},
    'B107': {   'categories': ['security'],
                'description': "Possible hardcoded password: 'blerg'",
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'hardcoded password default'},
    'B108': {   'categories': ['security'],
                'description': 'Probable insecure usage of temp '
                               'file/directory.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'hardcoded tmp directory'},
    'B110': {   'categories': ['security'],
                'description': 'Try, Except, Pass detected.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'try except pass'},
    'B112': {   'categories': ['security'],
                'description': 'Try, Except, Continue detected.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'try except continue'},
    'B201': {   'categories': ['security'],
                'description': 'A Flask app appears to be run with debug=True, '
                               'which exposes the Werkzeug debugger and allows '
                               'the execution of arbitrary code.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '3',
                'title': 'flask debug true'},
    'B301': {   'categories': ['security'],
                'description': 'Pickle library appears to be in use, possible '
                               'security issue.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B302': {   'categories': ['security'],
                'description': 'Deserialization with the marshal module is '
                               'possibly dangerous.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B303': {   'categories': ['security'],
                'description': 'Use of insecure MD2, MD4, MD5, or SHA1 hash '
                               'function.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B304': {   'categories': ['security'],
                'description': 'Use of insecure cipher '
                               'cryptography.hazmat.primitives.ciphers.algorithms.IDEA. '
                               'Replace with a known secure cipher such as '
                               'AES.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '3',
                'title': 'blacklist'},
    'B305': {   'categories': ['security'],
                'description': 'Use of insecure cipher mode '
                               'cryptography.hazmat.primitives.ciphers.modes.ECB.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B306': {   'categories': ['security'],
                'description': 'Use of insecure and deprecated function '
                               '(mktemp).',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B307': {   'categories': ['security'],
                'description': 'Use of possibly insecure function - consider '
                               'using safer ast.literal eval.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B308': {   'categories': ['security'],
                'description': 'Use of mark safe() may expose cross-site '
                               'scripting vulnerabilities and should be '
                               'reviewed.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B309': {   'categories': ['security'],
                'description': 'Use of HTTPSConnection on older versions of '
                               'Python prior to 2.7.9 and 3.4.3 do not provide '
                               'security, see '
                               'https://wiki.openstack.org/wiki/OSSN/OSSN-0033',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B310': {   'categories': ['security'],
                'description': 'Audit url open for permitted schemes. Allowing '
                               'use of file:/ or custom schemes is often '
                               'unexpected.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B311': {   'categories': ['security'],
                'description': 'Standard pseudo-random generators are not '
                               'suitable for security/cryptographic purposes.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'blacklist'},
    'B312': {   'categories': ['security'],
                'description': 'Telnet-related functions are being called. '
                               'Telnet is considered insecure. Use SSH or some '
                               'other encrypted protocol.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '3',
                'title': 'blacklist'},
    'B313': {   'categories': ['security'],
                'description': 'Using xml.etree.cElementTree.XMLParser to '
                               'parse untrusted XML data is known to be '
                               'vulnerable to XML attacks. Replace '
                               'xml.etree.cElementTree.XMLParser with its '
                               'defusedxml equivalent function or make sure '
                               'defusedxml.defuse stdlib() is called',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B314': {   'categories': ['security'],
                'description': 'Using xml.etree.ElementTree.XMLParser to parse '
                               'untrusted XML data is known to be vulnerable '
                               'to XML attacks. Replace '
                               'xml.etree.ElementTree.XMLParser with its '
                               'defusedxml equivalent function or make sure '
                               'defusedxml.defuse stdlib() is called',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B315': {   'categories': ['security'],
                'description': 'Using xml.sax.expatreader.create parser to '
                               'parse untrusted XML data is known to be '
                               'vulnerable to XML attacks. Replace '
                               'xml.sax.expatreader.create parser with its '
                               'defusedxml equivalent function or make sure '
                               'defusedxml.defuse stdlib() is called',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B316': {   'categories': ['security'],
                'description': 'Using xml.dom.expatbuilder.parseString to '
                               'parse untrusted XML data is known to be '
                               'vulnerable to XML attacks. Replace '
                               'xml.dom.expatbuilder.parseString with its '
                               'defusedxml equivalent function or make sure '
                               'defusedxml.defuse stdlib() is called',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B317': {   'categories': ['security'],
                'description': 'Using xml.sax.make parser to parse untrusted '
                               'XML data is known to be vulnerable to XML '
                               'attacks. Replace xml.sax.make parser with its '
                               'defusedxml equivalent function or make sure '
                               'defusedxml.defuse stdlib() is called',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B318': {   'categories': ['security'],
                'description': 'Using xml.dom.minidom.parse to parse untrusted '
                               'XML data is known to be vulnerable to XML '
                               'attacks. Replace xml.dom.minidom.parse with '
                               'its defusedxml equivalent function or make '
                               'sure defusedxml.defuse stdlib() is called',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B319': {   'categories': ['security'],
                'description': 'Using xml.dom.pulldom.parse to parse untrusted '
                               'XML data is known to be vulnerable to XML '
                               'attacks. Replace xml.dom.pulldom.parse with '
                               'its defusedxml equivalent function or make '
                               'sure defusedxml.defuse stdlib() is called',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B320': {   'categories': ['security'],
                'description': 'Using lxml.etree.fromstring to parse untrusted '
                               'XML data is known to be vulnerable to XML '
                               'attacks. Replace lxml.etree.fromstring with '
                               'its defusedxml equivalent function.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B321': {   'categories': ['security'],
                'description': 'FTP-related functions are being called. FTP is '
                               'considered insecure. Use SSH/SFTP/SCP or some '
                               'other encrypted protocol.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '3',
                'title': 'blacklist'},
    'B322': {   'categories': ['security'],
                'description': 'The input method in Python 2 will read from '
                               'standard input, evaluate and run the resulting '
                               'string as python source code. This is similar, '
                               'though in many ways worse, then using eval. On '
                               'Python 2, use raw input instead, input is safe '
                               'in Python 3.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '3',
                'title': 'blacklist'},
    'B323': {   'categories': ['security'],
                'description': 'By default, Python will create a secure, '
                               'verified ssl context for use in such classes '
                               'as HTTPSConnection. However, it still allows '
                               'using an insecure context via the  create '
                               'unverified context that reverts to the '
                               'previous behavior that does not validate '
                               'certificates or perform hostname checks.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B324': {   'categories': ['security'],
                'description': 'Use of insecure MD4 or MD5 hash function.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'hashlib new'},
    'B325': {   'categories': ['security'],
                'description': 'Use of os.tempnam() and os.tmpnam() is '
                               'vulnerable to symlink attacks. Consider using '
                               'tmpfile() instead.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'blacklist'},
    'B401': {   'categories': ['security'],
                'description': 'A telnet-related module is being imported.  '
                               'Telnet is considered insecure. Use SSH or some '
                               'other encrypted protocol.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '3',
                'title': 'blacklist'},
    'B402': {   'categories': ['security'],
                'description': 'A FTP-related module is being imported.  FTP '
                               'is considered insecure. Use SSH/SFTP/SCP or '
                               'some other encrypted protocol.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '3',
                'title': 'blacklist'},
    'B403': {   'categories': ['security'],
                'description': 'Consider possible security implications '
                               'associated with pickle module.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'blacklist'},
    'B404': {   'categories': ['security'],
                'description': 'Consider possible security implications '
                               'associated with subprocess module.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'blacklist'},
    'B405': {   'categories': ['security'],
                'description': 'Using xml.etree.ElementTree to parse untrusted '
                               'XML data is known to be vulnerable to XML '
                               'attacks. Replace xml.etree.ElementTree with '
                               'the equivalent defusedxml package, or make '
                               'sure defusedxml.defuse stdlib() is called.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'blacklist'},
    'B406': {   'categories': ['security'],
                'description': 'Using sax to parse untrusted XML data is known '
                               'to be vulnerable to XML attacks. Replace sax '
                               'with the equivalent defusedxml package, or '
                               'make sure defusedxml.defuse stdlib() is '
                               'called.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'blacklist'},
    'B407': {   'categories': ['security'],
                'description': 'Using xml.dom.expatbuilder to parse untrusted '
                               'XML data is known to be vulnerable to XML '
                               'attacks. Replace xml.dom.expatbuilder with the '
                               'equivalent defusedxml package, or make sure '
                               'defusedxml.defuse stdlib() is called.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'blacklist'},
    'B408': {   'categories': ['security'],
                'description': 'Using parse to parse untrusted XML data is '
                               'known to be vulnerable to XML attacks. Replace '
                               'parse with the equivalent defusedxml package, '
                               'or make sure defusedxml.defuse stdlib() is '
                               'called.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'blacklist'},
    'B409': {   'categories': ['security'],
                'description': 'Using parse to parse untrusted XML data is '
                               'known to be vulnerable to XML attacks. Replace '
                               'parse with the equivalent defusedxml package, '
                               'or make sure defusedxml.defuse stdlib() is '
                               'called.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'blacklist'},
    'B410': {   'categories': ['security'],
                'description': 'Using etree to parse untrusted XML data is '
                               'known to be vulnerable to XML attacks. Replace '
                               'etree with the equivalent defusedxml package.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'blacklist'},
    'B411': {   'categories': ['security'],
                'description': 'Using xmlrpclib to parse untrusted XML data is '
                               'known to be vulnerable to XML attacks. Use '
                               'defused.xmlrpc.monkey patch() function to '
                               'monkey-patch xmlrpclib and mitigate XML '
                               'vulnerabilities.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '3',
                'title': 'blacklist'},
    'B412': {   'categories': ['security'],
                'description': 'Consider possible security implications '
                               'associated with twisted.web.twcgi.CGIScript '
                               'module.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '3',
                'title': 'blacklist'},
    'B413': {   'categories': ['security'],
                'description': 'The pyCrypto library and its module RSA are no '
                               'longer actively maintained and have been '
                               'deprecated. Consider using pyca/cryptography '
                               'library.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '3',
                'title': 'blacklist'},
    'B414': {   'categories': ['security'],
                'description': 'The pycryptodome library is not considered a '
                               'secure alternative to pycrypto.Consider using '
                               'pyca/cryptography library.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '3',
                'title': 'blacklist'},
    'B501': {   'categories': ['security'],
                'description': 'Requests call with verify=False disabling SSL '
                               'certificate checks, security issue.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '3',
                'title': 'request with no cert validation'},
    'B502': {   'categories': ['security'],
                'description': 'Function call with insecure SSL/TLS protocol '
                               'identified, possible security issue.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'ssl with bad version'},
    'B503': {   'categories': ['security'],
                'description': 'Function definition identified with insecure '
                               'SSL/TLS protocol version by default, possible '
                               'security issue.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'ssl with bad defaults'},
    'B504': {   'categories': ['security'],
                'description': 'ssl.wrap socket call with no SSL/TLS protocol '
                               'version specified, the default SSLv23 could be '
                               'insecure, possible security issue.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'ssl with no version'},
    'B505': {   'categories': ['security'],
                'description': 'RSA key sizes below 1024 bits are considered '
                               'breakable. ',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '3',
                'title': 'weak cryptographic key'},
    'B506': {   'categories': ['security'],
                'description': 'Use of unsafe yaml load. Allows instantiation '
                               'of arbitrary objects. Consider yaml.safe '
                               'load().',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'yaml load'},
    'B601': {   'categories': ['security'],
                'description': 'Possible shell injection via Paramiko call, '
                               'check inputs are properly sanitized.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'paramiko calls'},
    'B602': {   'categories': ['security'],
                'description': 'subprocess call with shell=True seems safe, '
                               'but may be changed in the future, consider '
                               'rewriting without shell',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'subprocess popen with shell equals true'},
    'B603': {   'categories': ['security'],
                'description': 'subprocess call - check for execution of '
                               'untrusted input.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'subprocess without shell equals true'},
    'B604': {   'categories': ['security'],
                'description': 'Function call with shell=True parameter '
                               'identified, possible security issue.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'any other function with shell equals true'},
    'B605': {   'categories': ['security'],
                'description': 'Starting a process with a shell: Seems safe, '
                               'but may be changed in the future, consider '
                               'rewriting without shell',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'start process with a shell'},
    'B606': {   'categories': ['security'],
                'description': 'Starting a process without a shell.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'start process with no shell'},
    'B607': {   'categories': ['security'],
                'description': 'Starting a process with a partial executable '
                               'path',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '1',
                'title': 'start process with partial path'},
    'B608': {   'categories': ['security'],
                'description': 'Possible SQL injection vector through '
                               'string-based query construction.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'hardcoded sql expressions'},
    'B609': {   'categories': ['security'],
                'description': 'Possible wildcard injection in call: '
                               'subprocess.Popen',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '3',
                'title': 'linux commands wildcard injection'},
    'B610': {   'categories': ['security'],
                'description': 'Use of extra potential SQL attack vector.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'django extra used'},
    'B611': {   'categories': ['security'],
                'description': 'Use of RawSQL potential SQL attack vector.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'django rawsql used'},
    'B701': {   'categories': ['security'],
                'description': 'Using jinja2 templates with autoescape=False '
                               'is dangerous and can lead to XSS. Ensure '
                               'autoescape=True or use the select autoescape '
                               'function to mitigate XSS vulnerabilities.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '3',
                'title': 'jinja2 autoescape false'},
    'B702': {   'categories': ['security'],
                'description': 'Mako templates allow HTML/JS rendering by '
                               'default and are inherently open to XSS '
                               'attacks. Ensure variables in all templates are '
                               "properly sanitized via the 'n', 'h' or 'x' "
                               'flags (depending on context). For example, to '
                               "HTML escape the variable 'data' do ${ data |h "
                               '}.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'use of mako templates'},
    'B703': {   'categories': ['security'],
                'description': 'Potential XSS on mark safe function.',
                'file': '%(issue.file)s',
                'line': '%(issue.line)s',
                'severity': '2',
                'title': 'django mark safe'}}
