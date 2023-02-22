# -*- coding: utf-8 -*-


issues_data = {
    "B101": {
        "severity": "1",
        "description": "Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.",
        "categories": ["security"],
        "title": "assert used"
    },
    "B104": {
        "severity": "2",
        "description": "Possible binding to all interfaces.",
        "categories": ["security"],
        "title": "hardcoded bind all interfaces"
    },
    "B305": {
        "severity": "2",
        "description": "Use of insecure cipher mode cryptography.hazmat.primitives.ciphers.modes.ECB.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B413": {
        "severity": "3",
        "description": "The pyCrypto library and its module RSA are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B414": {
        "severity": "3",
        "description": "The pycryptodome library is not considered a secure alternative to pycrypto.Consider using pyca/cryptography library.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B304": {
        "severity": "3",
        "description": "Use of insecure cipher cryptography.hazmat.primitives.ciphers.algorithms.IDEA. Replace with a known secure cipher such as AES.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B303": {
        "severity": "2",
        "description": "Use of insecure MD2, MD4, MD5, or SHA1 hash function.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B610": {
        "severity": "2",
        "description": "Use of extra potential SQL attack vector.",
        "categories": ["security"],
        "title": "django extra used"
    },
    "B611": {
        "severity": "2",
        "description": "Use of RawSQL potential SQL attack vector.",
        "categories": ["security"],
        "title": "django rawsql used"
    },
    "B307": {
        "severity": "2",
        "description": "Use of possibly insecure function - consider using safer ast.literal eval.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B102": {
        "severity": "2",
        "description": "Use of exec detected.",
        "categories": ["security"],
        "title": "exec used"
    },
    "B201": {
        "severity": "3",
        "description": "A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.",
        "categories": ["security"],
        "title": "flask debug true"
    },
    "B402": {
        "severity": "3",
        "description": "A FTP-related module is being imported.  FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B321": {
        "severity": "3",
        "description": "FTP-related functions are being called. FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B107": {
        "severity": "1",
        "description": "Possible hardcoded password: 'blerg'",
        "categories": ["security"],
        "title": "hardcoded password default"
    },
    "B105": {
        "severity": "1",
        "description": "Possible hardcoded password: 'blerg'",
        "categories": ["security"],
        "title": "hardcoded password string"
    },
    "B106": {
        "severity": "1",
        "description": "Possible hardcoded password: 'blerg'",
        "categories": ["security"],
        "title": "hardcoded password funcarg"
    },
    "B108": {
        "severity": "2",
        "description": "Probable insecure usage of temp file/directory.",
        "categories": ["security"],
        "title": "hardcoded tmp directory"
    },
    "B324": {
        "severity": "2",
        "description": "Use of insecure MD4 or MD5 hash function.",
        "categories": ["security"],
        "title": "hashlib new"
    },
    "B309": {
        "severity": "2",
        "description": "Use of HTTPSConnection on older versions of Python prior to 2.7.9 and 3.4.3 do not provide security, see https://wiki.openstack.org/wiki/OSSN/OSSN-0033",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B412": {
        "severity": "3",
        "description": "Consider possible security implications associated with twisted.web.twcgi.CGIScript module.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B404": {
        "severity": "1",
        "description": "Consider possible security implications associated with subprocess module.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B403": {
        "severity": "1",
        "description": "Consider possible security implications associated with pickle module.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B602": {
        "severity": "1",
        "description": "subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
        "categories": ["security"],
        "title": "subprocess popen with shell equals true"
    },
    "B301": {
        "severity": "2",
        "description": "Pickle library appears to be in use, possible security issue.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B322": {
        "severity": "3",
        "description": "The input method in Python 2 will read from standard input, evaluate and run the resulting string as python source code. This is similar, though in many ways worse, then using eval. On Python 2, use raw input instead, input is safe in Python 3.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B701": {
        "severity": "3",
        "description": "Using jinja2 templates with autoescape=False is dangerous and can lead to XSS. Ensure autoescape=True or use the select autoescape function to mitigate XSS vulnerabilities.",
        "categories": ["security"],
        "title": "jinja2 autoescape false"
    },
    "B702": {
        "severity": "2",
        "description": "Mako templates allow HTML/JS rendering by default and are inherently open to XSS attacks. Ensure variables in all templates are properly sanitized via the 'n', 'h' or 'x' flags (depending on context). For example, to HTML escape the variable 'data' do ${ data |h }.",
        "categories": ["security"],
        "title": "use of mako templates"
    },
    "B308": {
        "severity": "2",
        "description": "Use of mark safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B703": {
        "severity": "2",
        "description": "Potential XSS on mark safe function.",
        "categories": ["security"],
        "title": "django mark safe"
    },
    "B302": {
        "severity": "2",
        "description": "Deserialization with the marshal module is possibly dangerous.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B306": {
        "severity": "2",
        "description": "Use of insecure and deprecated function (mktemp).",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B506": {
        "severity": "2",
        "description": "Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe load().",
        "categories": ["security"],
        "title": "yaml load"
    },
    "B317": {
        "severity": "2",
        "description": "Using xml.sax.make parser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.make parser with its defusedxml equivalent function or make sure defusedxml.defuse stdlib() is called",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B103": {
        "severity": "3",
        "description": "Chmod setting a permissive mask 0777 on file (key file).",
        "categories": ["security"],
        "title": "set bad file permissions"
    },
    "B606": {
        "severity": "1",
        "description": "Starting a process without a shell.",
        "categories": ["security"],
        "title": "start process with no shell"
    },
    "B605": {
        "severity": "1",
        "description": "Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        "categories": ["security"],
        "title": "start process with a shell"
    },
    "B601": {
        "severity": "2",
        "description": "Possible shell injection via Paramiko call, check inputs are properly sanitized.",
        "categories": ["security"],
        "title": "paramiko calls"
    },
    "B603": {
        "severity": "1",
        "description": "subprocess call - check for execution of untrusted input.",
        "categories": ["security"],
        "title": "subprocess without shell equals true"
    },
    "B607": {
        "severity": "1",
        "description": "Starting a process with a partial executable path",
        "categories": ["security"],
        "title": "start process with partial path"
    },
    "B311": {
        "severity": "1",
        "description": "Standard pseudo-random generators are not suitable for security/cryptographic purposes.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B501": {
        "severity": "3",
        "description": "Requests call with verify=False disabling SSL certificate checks, security issue.",
        "categories": ["security"],
        "title": "request with no cert validation"
    },
    "B608": {
        "severity": "2",
        "description": "Possible SQL injection vector through string-based query construction.",
        "categories": ["security"],
        "title": "hardcoded sql expressions"
    },
    "B502": {
        "severity": "2",
        "description": "Function call with insecure SSL/TLS protocol identified, possible security issue.",
        "categories": ["security"],
        "title": "ssl with bad version"
    },
    "B504": {
        "severity": "1",
        "description": "ssl.wrap socket call with no SSL/TLS protocol version specified, the default SSLv23 could be insecure, possible security issue.",
        "categories": ["security"],
        "title": "ssl with no version"
    },
    "B503": {
        "severity": "2",
        "description": "Function definition identified with insecure SSL/TLS protocol version by default, possible security issue.",
        "categories": ["security"],
        "title": "ssl with bad defaults"
    },
    "B604": {
        "severity": "2",
        "description": "Function call with shell=True parameter identified, possible security issue.",
        "categories": ["security"],
        "title": "any other function with shell equals true"
    },
    "B401": {
        "severity": "3",
        "description": "A telnet-related module is being imported.  Telnet is considered insecure. Use SSH or some other encrypted protocol.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B312": {
        "severity": "3",
        "description": "Telnet-related functions are being called. Telnet is considered insecure. Use SSH or some other encrypted protocol.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B325": {
        "severity": "2",
        "description": "Use of os.tempnam() and os.tmpnam() is vulnerable to symlink attacks. Consider using tmpfile() instead.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B112": {
        "severity": "1",
        "description": "Try, Except, Continue detected.",
        "categories": ["security"],
        "title": "try except continue"
    },
    "B110": {
        "severity": "1",
        "description": "Try, Except, Pass detected.",
        "categories": ["security"],
        "title": "try except pass"
    },
    "B323": {
        "severity": "2",
        "description": "By default, Python will create a secure, verified ssl context for use in such classes as HTTPSConnection. However, it still allows using an insecure context via the  create unverified context that reverts to the previous behavior that does not validate certificates or perform hostname checks.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B310": {
        "severity": "2",
        "description": "Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B505": {
        "severity": "3",
        "description": "RSA key sizes below 1024 bits are considered breakable. ",
        "categories": ["security"],
        "title": "weak cryptographic key"
    },
    "B609": {
        "severity": "3",
        "description": "Possible wildcard injection in call: subprocess.Popen",
        "categories": ["security"],
        "title": "linux commands wildcard injection"
    },
    "B405": {
        "severity": "1",
        "description": "Using xml.etree.ElementTree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree with the equivalent defusedxml package, or make sure defusedxml.defuse stdlib() is called.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B313": {
        "severity": "2",
        "description": "Using xml.etree.cElementTree.XMLParser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.cElementTree.XMLParser with its defusedxml equivalent function or make sure defusedxml.defuse stdlib() is called",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B314": {
        "severity": "2",
        "description": "Using xml.etree.ElementTree.XMLParser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree.XMLParser with its defusedxml equivalent function or make sure defusedxml.defuse stdlib() is called",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B407": {
        "severity": "1",
        "description": "Using xml.dom.expatbuilder to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.expatbuilder with the equivalent defusedxml package, or make sure defusedxml.defuse stdlib() is called.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B316": {
        "severity": "2",
        "description": "Using xml.dom.expatbuilder.parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.expatbuilder.parseString with its defusedxml equivalent function or make sure defusedxml.defuse stdlib() is called",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B406": {
        "severity": "1",
        "description": "Using sax to parse untrusted XML data is known to be vulnerable to XML attacks. Replace sax with the equivalent defusedxml package, or make sure defusedxml.defuse stdlib() is called.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B315": {
        "severity": "2",
        "description": "Using xml.sax.expatreader.create parser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.expatreader.create parser with its defusedxml equivalent function or make sure defusedxml.defuse stdlib() is called",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B410": {
        "severity": "1",
        "description": "Using etree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace etree with the equivalent defusedxml package.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B320": {
        "severity": "2",
        "description": "Using lxml.etree.fromstring to parse untrusted XML data is known to be vulnerable to XML attacks. Replace lxml.etree.fromstring with its defusedxml equivalent function.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B408": {
        "severity": "1",
        "description": "Using parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace parse with the equivalent defusedxml package, or make sure defusedxml.defuse stdlib() is called.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B318": {
        "severity": "2",
        "description": "Using xml.dom.minidom.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.minidom.parse with its defusedxml equivalent function or make sure defusedxml.defuse stdlib() is called",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B409": {
        "severity": "1",
        "description": "Using parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace parse with the equivalent defusedxml package, or make sure defusedxml.defuse stdlib() is called.",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B319": {
        "severity": "2",
        "description": "Using xml.dom.pulldom.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.pulldom.parse with its defusedxml equivalent function or make sure defusedxml.defuse stdlib() is called",
        "categories": ["security"],
        "title": "blacklist"
    },
    "B411": {
        "severity": "3",
        "description": "Using xmlrpclib to parse untrusted XML data is known to be vulnerable to XML attacks. Use defused.xmlrpc.monkey patch() function to monkey-patch xmlrpclib and mitigate XML vulnerabilities.",
        "categories": ["security"],
        "title": "blacklist"
    }

}
