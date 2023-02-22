# -*- coding: utf-8 -*-


issues_data = {

  "DetectNoCsrfBeforeMethodOverride": {
    "title": "detect no csrf before method override",
    "display_name": "DetectNoCsrfBeforeMethodOverride",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected use of express.csrf() middleware before express.methodOverride(). This can\nallow GET requests (which are not checked by csrf) to turn into POST requests later."
  },
  "YamlParsing": {
    "title": "yaml parsing",
    "display_name": "YamlParsing",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected enabled YAML parsing. This is vulnerable to remote code execution in Rails 2.x\nversions up to 2.3.14. To fix, delete this line."
  },
  "UseSysExit": {
    "title": "use sys exit",
    "display_name": "UseSysExit",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use `sys.exit` over the python shell `exit` built-in. `exit` is a helper for the interactive shell and may not be available on all Python implementations. https://stackoverflow.com/questions/6501121/difference-between-exit-and-sys-exit-in-python"
  },
  "HeaderXssLusca": {
    "title": "header xss lusca",
    "display_name": "HeaderXssLusca",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "X-XSS-Protection header is set to 0. This will disable the browser's XSS Filter."
  },
  "NoPrintfInResponsewriter": {
    "title": "no printf in responsewriter",
    "display_name": "NoPrintfInResponsewriter",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected 'printf' or similar in 'http.ResponseWriter.write()'.\nThis bypasses HTML escaping that prevents cross-site scripting\nvulnerabilities. Instead, use the 'html/template' package\nto render data to users."
  },
  "TemplateExplicitUnescape": {
    "title": "template explicit unescape",
    "display_name": "TemplateExplicitUnescape",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected an explicit unescape in a Pug template, using either\n'!=' or '!{...}'. If external data can reach these locations,\nyour application is exposed to a cross-site scripting (XSS)\nvulnerability. If you must do this, ensure no external data\ncan reach this location."
  },
  "JwtPythonExposedData": {
    "title": "jwt python exposed data",
    "display_name": "JwtPythonExposedData",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The object is passed strictly to jwt.encode(...)\nMake sure that sensitive information is not exposed through JWT token payload."
  },
  "OverlyPermissiveFilePermission": {
    "title": "overly permissive file permission",
    "display_name": "OverlyPermissiveFilePermission",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "It is generally a bad practices to set overly permissive file permission such as read+write+exec for all users.\nIf the file affected is a configuration, a binary, a script or sensitive data, it can lead to privilege escalation or information leakage."
  },
  "ExpressBodyparser": {
    "title": "express bodyparser",
    "display_name": "ExpressBodyparser",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "POST Request to Express Body Parser 'bodyParser()' can create Temporary files and consume space."
  },
  "Python37CompatibilityImportlib2": {
    "title": "python37 compatibility importlib2",
    "display_name": "Python37CompatibilityImportlib2",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "this module is only available on Python 3.7+; use importlib_resources for older Python versions"
  },
  "UnknownValueWithScriptTag": {
    "title": "unknown value with script tag",
    "display_name": "UnknownValueWithScriptTag",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Cannot determine what '$UNK' is and it is used with a '<script>' tag. This\ncould be susceptible to cross-site scripting (XSS). Ensure '$UNK' is not\nexternally controlled, or sanitize this data."
  },
  "HelmetHeaderXssFilter": {
    "title": "helmet header xss filter",
    "display_name": "HelmetHeaderXssFilter",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "X-XSS-Protection header is present. More information: https://helmetjs.github.io/docs/xss-filter/"
  },
  "GenericOsCommandExec": {
    "title": "generic os command exec",
    "display_name": "GenericOsCommandExec",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in 'child_process.exec()' can result in Remote OS Command Execution."
  },
  "AvoidRenderText": {
    "title": "avoid render text",
    "display_name": "AvoidRenderText",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "'render text: ...' actually sets the content-type to 'text/html'.\nIf external data can reach here, this exposes your application\nto cross-site scripting (XSS) attacks. Instead, use 'render plain: ...' to\nrender non-HTML text."
  },
  "HelmetHeaderDnsPrefetch": {
    "title": "helmet header dns prefetch",
    "display_name": "HelmetHeaderDnsPrefetch",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "X-DNS-Prefetch-Control header is present and DNS Prefetch Control is enabled. More information: https://helmetjs.github.io/docs/dns-prefetch-control/"
  },
  "AvoidPyyamlLoad": {
    "title": "avoid pyyaml load",
    "display_name": "AvoidPyyamlLoad",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Avoid using `load()`. `PyYAML.load` can create arbitrary Python\nobjects. A malicious actor could exploit this to run arbitrary\ncode. Use `safe_load()` instead."
  },
  "AvoidMarkSafe": {
    "title": "avoid mark safe",
    "display_name": "AvoidMarkSafe",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "'mark_safe()' is used to mark a string as \"safe\" for HTML output.\nThis disables escaping and could therefore subject the content to\nXSS attacks. Use 'django.utils.html.format_html()' to build HTML\nfor rendering instead."
  },
  "UseDjangoEnviron": {
    "title": "use django environ",
    "display_name": "UseDjangoEnviron",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "You are using environment variables inside django app. Use `django-environ` as it a better alternative for deployment."
  },
  "GenericHeaderInjection": {
    "title": "generic header injection",
    "display_name": "GenericHeaderInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted user input in response header will result in HTTP Header Injection or Response Splitting Attacks."
  },
  "Md5LooseEquality": {
    "title": "md5 loose equality",
    "display_name": "Md5LooseEquality",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure comparisons involving md5 values are strict (use `===` not `==`) to avoid type juggling issues"
  },
  "ExpressVmCompilefunctionContextInjection": {
    "title": "express vm compilefunction context injection",
    "display_name": "ExpressVmCompilefunctionContextInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach vm.compileFunction."
  },
  "CookieMissingSecureFlag": {
    "title": "cookie missing secure flag",
    "display_name": "CookieMissingSecureFlag",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A cookie was detected without setting the 'secure' flag. The 'secure' flag\nfor cookies prevents the client from transmitting the cookie over insecure\nchannels such as HTTP. Set the 'secure' flag by calling '$COOKIE.setSecure(true);'"
  },
  "FormattedSqlQuery": {
    "title": "formatted sql query",
    "display_name": "FormattedSqlQuery",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected possible formatted SQL query. Use parameterized queries instead."
  },
  "CookieSessionNoHttponly": {
    "title": "cookie session no httponly",
    "display_name": "CookieSessionNoHttponly",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Session middleware settings: `httpOnly` is explicitly set to false.  It ensures that sensitive cookies cannot be accessed by client side  JavaScript and helps to protect against cross-site scripting attacks."
  },
  "DeleteWhereNoExecute": {
    "title": "delete where no execute",
    "display_name": "DeleteWhereNoExecute",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ".delete().where(...) results in a no-op in SQLAlchemy unless the command is executed, use .filter(...).delete() instead."
  },
  "ManualDefaultdictDictCreate": {
    "title": "manual defaultdict dict create",
    "display_name": "ManualDefaultdictDictCreate",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "manually creating a defaultdict - use collections.defaultdict(dict)"
  },
  "SqlInjectionUsingExtraWhere": {
    "title": "sql injection using extra where",
    "display_name": "SqlInjectionUsingExtraWhere",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Data from request is passed to extra(). This is a SQL injection and could be exploited. See https://docs.djangoproject.com/en/3.0/ref/models/expressions/#.objects.extra to learn how to mitigate. See https://cwe.mitre.org/data/definitions/89.html to learn about SQLi."
  },
  "LdapInjection": {
    "title": "ldap injection",
    "display_name": "LdapInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected non-constant data passed into an LDAP query. If this data can be\ncontrolled by an external user, this is an LDAP injection.\nEnsure data passed to an LDAP query is not controllable; or properly sanitize\nthe data."
  },
  "ModelAttrAccessible": {
    "title": "model attr accessible",
    "display_name": "ModelAttrAccessible",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Checks for dangerous permitted attributes that can lead to mass assignment vulnerabilities. Query parameters allowed using permit\nand attr_accessible are checked for allowance of dangerous attributes admin, banned, role, and account_id. Also checks for usages of\nparams.permit!, which allows everything. Fix: don't allow admin, banned, role, and account_id using permit or attr_accessible."
  },
  "DictDelWhileIterate": {
    "title": "dict del while iterate",
    "display_name": "DictDelWhileIterate",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "It appears that `$DICT[$KEY]` is a dict with items being deleted while in a for loop. This is usually a bad idea and will likely lead to a RuntimeError: dictionary changed size during iteration"
  },
  "SerializetojsDeserialize": {
    "title": "serializetojs deserialize",
    "display_name": "SerializetojsDeserialize",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in 'unserialize()' or 'deserialize()' function can result in Object Injection or Remote Code Injection."
  },
  "AliasForHtmlSafe": {
    "title": "alias for html safe",
    "display_name": "AliasForHtmlSafe",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The syntax `<%== ... %>` is an alias for `html_safe`. This means the\ncontent inside these tags will be rendered as raw HTML. This may expose\nyour application to cross-site scripting. If you need raw HTML, prefer\nusing the more explicit `html_safe` and be sure to correctly sanitize\nvariables using a library such as DOMPurify."
  },
  "DetectEvalWithExpression": {
    "title": "detect eval with expression",
    "display_name": "DetectEvalWithExpression",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected eval(variable), which could allow a malicious actor to run arbitrary code."
  },
  "Python37CompatibilityImportlib3": {
    "title": "python37 compatibility importlib3",
    "display_name": "Python37CompatibilityImportlib3",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "this module is only available on Python 3.7+"
  },
  "DetectedGoogleCloudApiKey": {
    "title": "secrets: detected google cloud api key",
    "display_name": "DetectedGoogleCloudApiKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Google Cloud API Key detected"
  },
  "Python37CompatibilityImportlib": {
    "title": "python37 compatibility importlib",
    "display_name": "Python37CompatibilityImportlib",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "this function is only available on Python 3.7+"
  },
  "Python37CompatibilityMath1": {
    "title": "python37 compatibility math1",
    "display_name": "Python37CompatibilityMath1",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "this function is only available on Python 3.7+"
  },
  "Avoid_hardcoded_config_secret_key": {
    "title": "avoid_hardcoded_config_SECRET_KEY",
    "display_name": "Avoid_hardcoded_config_secret_key",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Hardcoded variable `SECRET_KEY` detected. Use environment variables or config files instead"
  },
  "IncorrectUseAtoFn": {
    "title": "incorrect use ato fn",
    "display_name": "IncorrectUseAtoFn",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Avoid the 'ato*()' family of functions. Their use can lead to undefined\nbehavior, integer overflows, and lack of appropriate error handling. Instead\nprefer the 'strtol*()' family of functions."
  },
  "ExplicitUnescapeWithMarkup": {
    "title": "explicit unescape with markup",
    "display_name": "ExplicitUnescapeWithMarkup",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected explicitly unescaped content using 'Markup()'. This permits\nthe unescaped data to include unescaped HTML which could result in\ncross-site scripting. Ensure this data is not externally controlled,\nor consider rewriting to not use 'Markup()'."
  },
  "DetectedSqlDump": {
    "title": "secrets: detected sql dump",
    "display_name": "DetectedSqlDump",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "SQL dump detected"
  },
  "DirectUseOfJinja2": {
    "title": "direct use of jinja2",
    "display_name": "DirectUseOfJinja2",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected direct use of jinja2. If not done properly,\nthis may bypass HTML escaping which opens up the application to\ncross-site scripting (XSS) vulnerabilities. Prefer using the Flask\nmethod 'render_template()' and templates with a '.html' extension\nin order to prevent XSS."
  },
  "DomBasedXss": {
    "title": "dom based xss",
    "display_name": "DomBasedXss",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected possible DOM-based XSS. This occurs because a portion of the URL is being used\nto construct an element added directly to the page. For example, a malicious actor could\nsend someone a link like this: http://www.some.site/page.html?default=<script>alert(document.cookie)</script>\nwhich would add the script to the page.\nConsider allowlisting appropriate values or using an approach which does not involve the URL."
  },
  "RenderTemplateString": {
    "title": "render template string",
    "display_name": "RenderTemplateString",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found a template created with string formatting. This is susceptible to server-side template injection and cross-site scripting attacks."
  },
  "InsecureCipherAlgorithmRc2": {
    "title": "insecure cipher algorithm rc2",
    "display_name": "InsecureCipherAlgorithmRc2",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected RC2 cipher algorithm which is considered insecure. The algorithm has known vulnerabilities and is difficult to use securely. Use AES instead."
  },
  "ExpressVmRuninnewcontextContextInjection": {
    "title": "express vm runinnewcontext context injection",
    "display_name": "ExpressVmRuninnewcontextContextInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach vm.runInNewContext."
  },
  "SessionCookieMissingSecure": {
    "title": "session cookie missing secure",
    "display_name": "SessionCookieMissingSecure",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A session cookie was detected without setting the 'Secure' flag.\nThe 'secure' flag for cookies prevents the client from transmitting\nthe cookie over insecure channels such as HTTP.  Set the 'Secure'\nflag by setting 'Secure' to 'true' in the Options struct."
  },
  "WipXssUsingResponsewriterAndPrintf": {
    "title": "wip xss using responsewriter and printf",
    "display_name": "WipXssUsingResponsewriterAndPrintf",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found data going from url query parameters into formatted data written to ResponseWriter.\nThis could be XSS and should not be done. If you must do this, ensure your data is\nsanitized or escaped."
  },
  "MissingImageVersion": {
    "title": "dockerfile: missing image version",
    "display_name": "MissingImageVersion",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Images should be tagged with an explicit version to produce deterministic container images.\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "PlaywrightSetcontentInjection": {
    "title": "playwright setcontent injection",
    "display_name": "PlaywrightSetcontentInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `setContent` method it can result in Server-Side Request Forgery vulnerabilities"
  },
  "ResponseContainsUnsanitizedInput": {
    "title": "response contains unsanitized input",
    "display_name": "ResponseContainsUnsanitizedInput",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Flask response reflects unsanitized user input. This could lead to a\ncross-site scripting vulnerability (https://owasp.org/www-community/attacks/xss/)\nin which an attacker causes arbitrary code to be executed in the user's browser.\nTo prevent, please sanitize the user input, e.g. by rendering the response\nin a Jinja2 template (see considerations in https://flask.palletsprojects.com/en/1.0.x/security/)."
  },
  "HandlerAttributeReadFromMultipleSources": {
    "title": "handler attribute read from multiple sources",
    "display_name": "HandlerAttributeReadFromMultipleSources",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Attribute $ATT is read from two different sources: '$X.$ATT' and '$Y.$ATT'. Make sure this is intended, as this could cause logic bugs if they are treated as if they are the same object."
  },
  "ExpressExpatXxe": {
    "title": "express expat xxe",
    "display_name": "ExpressExpatXxe",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach the XML Parser,\nas it can result in XML External or Internal Entity (XXE) Processing vulnerabilities"
  },
  "CrlfInjectionLogs": {
    "title": "crlf injection logs",
    "display_name": "CrlfInjectionLogs",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "When data from an untrusted source is put into a logger and not neutralized correctly,\nan attacker could forge log entries or include malicious content."
  },
  "NestjsOpenRedirect": {
    "title": "nestjs open redirect",
    "display_name": "NestjsOpenRedirect",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted user input in {url: ...} can result in Open Redirect vulnerability."
  },
  "RequestDataFileresponse": {
    "title": "request data fileresponse",
    "display_name": "RequestDataFileresponse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found request data opening a file into FileResponse. This is dangerous because an attacker could specify an arbitrary file to read, leaking data. Be sure to validate or sanitize the filename before using it in FileResponse."
  },
  "ElectronExperimentalFeatures": {
    "title": "electron experimental features",
    "display_name": "ElectronExperimentalFeatures",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Experimental features are not expected to be in production ready applications."
  },
  "HandlebarsNoescape": {
    "title": "handlebars noescape",
    "display_name": "HandlebarsNoescape",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Disabling Escaping in Handlebars is not a secure behaviour. This can introduce XSS vulnerabilties."
  },
  "InvalidBaseUrl": {
    "title": "hugo: invalid base url",
    "display_name": "InvalidBaseUrl",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The 'baseURL' is invalid. This may cause links to not work if deployed.\nInclude the scheme (e.g., https://)."
  },
  "BadDeserialization": {
    "title": "bad deserialization",
    "display_name": "BadDeserialization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Checks for unsafe deserialization. Objects in Ruby can be serialized into strings,\nthen later loaded from strings. However, uses of load and object_load can cause remote code execution.\nLoading user input with YAML, MARSHAL, or CSV can potentially be dangerous. Use JSON securely instead."
  },
  "PreferCopyOverAdd": {
    "title": "dockerfile: prefer copy over add",
    "display_name": "PreferCopyOverAdd",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The ADD command will accept and include files from a URL.\nThis potentially exposes the container to a man-in-the-middle attack.\nSince ADD can have this and other unexpected side effects, the use of\nthe more explicit COPY command is preferred.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "NoFprintfToResponsewriter": {
    "title": "no fprintf to responsewriter",
    "display_name": "NoFprintfToResponsewriter",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected 'Fprintf' or similar writing to 'http.ResponseWriter'.\nThis bypasses HTML escaping that prevents cross-site scripting\nvulnerabilities. Instead, use the 'html/template' package\nto render data to users."
  },
  "ExpressPathJoinResolveTraversal": {
    "title": "express path join resolve traversal",
    "display_name": "ExpressPathJoinResolveTraversal",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Possible writing outside of the destination,\nmake sure that the target path is nested in the intended destination"
  },
  "HiddenGoroutine": {
    "title": "hidden goroutine",
    "display_name": "HiddenGoroutine",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a hidden goroutine. Function invocations are expected to synchronous,\nand this function will execute asynchronously because all it does is call a\ngoroutine. Instead, remove the internal goroutine and call the function using 'go'."
  },
  "GosqlSqli": {
    "title": "gosql sqli",
    "display_name": "GosqlSqli",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected string concatenation with a non-literal variable in a \"database/sql\"\nGo SQL statement. This could lead to SQL injection if the variable is user-controlled\nand not properly sanitized. In order to prevent SQL injection,\nused parameterized queries or prepared statements instead.\nYou can use prepared statements with the 'Prepare' and 'PrepareContext' calls."
  },
  "SpringUnvalidatedRedirect": {
    "title": "spring unvalidated redirect",
    "display_name": "SpringUnvalidatedRedirect",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Application redirects a user to a destination URL specified by a user supplied parameter that is not validated."
  },
  "DetectAngularTrustAsMethod": {
    "title": "detect angular trust as method",
    "display_name": "DetectAngularTrustAsMethod",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The use of $sce.trustAs can be dangerous if unsantiized user input flows through this API."
  },
  "DefaultMutableList": {
    "title": "default mutable list",
    "display_name": "DefaultMutableList",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Function $F mutates default list $D. Python only instantiates default function arguments once and shares the instance across the function calls. If the default function argument is mutated, that will modify the instance used by all future function calls. This can cause unexpected results, or lead to security vulnerabilities whereby one function consumer can view or modify the data of another function consumer. Instead, use a default argument (like None) to indicate that no argument was provided and instantiate a new list at that time. For example: `if $D is None: $D = []`."
  },
  "JdoSqli": {
    "title": "jdo sqli",
    "display_name": "JdoSqli",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a formatted string in a SQL statement. This could lead to SQL\ninjection if variables in the SQL statement are not properly sanitized.\nUse a prepared statements (java.sql.PreparedStatement) instead. You\ncan obtain a PreparedStatement using 'connection.prepareStatement'."
  },
  "RequestHostUsed": {
    "title": "nginx: request host used",
    "display_name": "RequestHostUsed",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "'$http_host' uses the 'Host' request header which could be controlled by an attacker. Use the '$host' variable instead, which will use server names listed in the 'server_name' directive.\n{\"include\": [\"*conf*\", \"*nginx*\", \"*vhost*\", \"sites-available/*\", \"sites-enabled/*\"]}"
  },
  "AttrMutableInitializer": {
    "title": "attr mutable initializer",
    "display_name": "AttrMutableInitializer",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Unsafe usage of mutable initializer with attr.s decorator.\nMultiple instances of this class will re-use the same data structure, which is likely not the desired behavior.\nConsider instead: replace assignment to mutable initializer (ex. dict() or {}) with attr.ib(factory=type) where type is dict, set, or list"
  },
  "TemplateAndAttributes": {
    "title": "template and attributes",
    "display_name": "TemplateAndAttributes",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a unescaped variables using '&attributes'.\nIf external data can reach these locations,\nyour application is exposed to a cross-site scripting (XSS)\nvulnerability. If you must do this, ensure no external data\ncan reach this location."
  },
  "Avoid_using_app_run_directly": {
    "title": "avoid_using_app_run_directly",
    "display_name": "Avoid_using_app_run_directly",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "top-level app.run(...) is ignored by flask. Consider putting app.run(...) behind a guard, like inside a function"
  },
  "Python.requests.bestPractice.useResponseJsonShortcut": {
    "title": "python.requests.best practice.use response json shortcut",
    "display_name": "Python.requests.bestPractice.useResponseJsonShortcut",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The requests library has a convenient shortcut for reading JSON responses,\nwhich lets you stop worrying about deserializing the response yourself."
  },
  "ElectronAllowHttp": {
    "title": "electron allow http",
    "display_name": "ElectronAllowHttp",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Application can load content over HTTP and that makes the app vulnerable to Man in the middle attacks."
  },
  "RubyEval": {
    "title": "ruby eval",
    "display_name": "RubyEval",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use of eval detected. This can run arbitrary code. Ensure external data\ndoes not reach here, otherwise this is a security vulnerability.\nConsider other ways to do this without eval."
  },
  "UseOfUnsafeBlock": {
    "title": "use of unsafe block",
    "display_name": "UseOfUnsafeBlock",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Using the unsafe package in Go gives you low-level memory management and\nmany of the strengths of the C language but also gives flexibility to the attacker\nof your application."
  },
  "ChromeRemoteInterfacePrinttopdfInjection": {
    "title": "chrome remote interface printtopdf injection",
    "display_name": "ChromeRemoteInterfacePrinttopdfInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `printToPDF` method it can result in Server-Side Request Forgery vulnerabilities"
  },
  "ExecUse": {
    "title": "exec use",
    "display_name": "ExecUse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Executing non-constant commands. This can lead to command injection."
  },
  "ListenEval": {
    "title": "listen eval",
    "display_name": "ListenEval",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Because portions of the logging configuration are passed through eval(),\nuse of this function may open its users to a security risk. While the\nfunction only binds to a socket on localhost, and so does not accept\nconnections from remote machines, there are scenarios where untrusted\ncode could be run under the account of the process which calls listen().\nSee more details at https://docs.python.org/3/library/logging.config.html?highlight=security#logging.config.listen"
  },
  "RubyJwtExposedData": {
    "title": "ruby jwt exposed data",
    "display_name": "RubyJwtExposedData",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The object is passed strictly to jsonwebtoken.sign(...)\nMake sure that sensitive information is not exposed through JWT token payload."
  },
  "VarInHref": {
    "title": "var in href",
    "display_name": "VarInHref",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a template variable used in an anchor tag with\nthe 'href' attribute. This allows a malicious actor to\ninput the 'javascript:' URI and is subject to cross-\nsite scripting (XSS) attacks. If using a relative URL,\nstart with a literal forward slash and concatenate the URL,\nlike this: a(href='/'+url). You may also consider setting\nthe Content Security Policy (CSP) header."
  },
  "OpenNeverClosed": {
    "title": "open never closed",
    "display_name": "OpenNeverClosed",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "file object opened without corresponding close"
  },
  "HttpNotHttpsConnection": {
    "title": "http not https connection",
    "display_name": "HttpNotHttpsConnection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected HTTPConnectionPool. This will transmit data in cleartext.\nIt is recommended to use HTTPSConnectionPool instead for to encrypt\ncommunications."
  },
  "NestjsHeaderXssDisabled": {
    "title": "nestjs header xss disabled",
    "display_name": "NestjsHeaderXssDisabled",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "X-XSS-Protection header is set to 0. This will disable the browser's XSS Filter."
  },
  "PossibleNginxH2cSmuggling": {
    "title": "nginx: possible nginx h2c smuggling",
    "display_name": "PossibleNginxH2cSmuggling",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Conditions for Nginx H2C smuggling identified. H2C smuggling allows upgrading HTTP/1.1 connections to lesser-known HTTP/2 over cleartext (h2c) connections which can allow a bypass of reverse proxy access controls,and lead to long-lived, unrestricted HTTP traffic directly to back-end servers. To mitigate: WebSocket support required: Allow only the value websocket for HTTP/1.1 upgrade headers (e.g., Upgrade: websocket). WebSocket support not required: Do not forward Upgrade headers."
  },
  "NoNullStringField": {
    "title": "no null string field",
    "display_name": "NoNullStringField",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Avoid using null on string-based fields such as CharField and TextField. If a string-based field\nhas null=True, that means it has two possible values for \"no data\": NULL, and the empty string. In\nmost cases, it's redundant to have two possible values for \"no data;\" the Django convention is to\nuse the empty string, not NULL."
  },
  "SystemWildcardDetected": {
    "title": "system wildcard detected",
    "display_name": "SystemWildcardDetected",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected use of the wildcard character in a system call that spawns a shell.\nThis subjects the wildcard to normal shell expansion, which can have unintended consequences\nif there exist any non-standard file names. Consider a file named '-e sh script.sh' -- this\nwill execute a script when 'rsync' is called. See\nhttps://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt\nfor more information."
  },
  "UselessInnerFunction": {
    "title": "useless inner function",
    "display_name": "UselessInnerFunction",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "function `$FF` is defined inside a function but never used"
  },
  "MissingRatelimit": {
    "title": "missing ratelimit",
    "display_name": "MissingRatelimit",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Function '$FUNC' is missing a rate-limiting decorator.\nHigh volume traffic to this function could starve application\nresources. Consider adding rate limiting from a library such\nas 'django-ratelimit'."
  },
  "SpelInjection": {
    "title": "spel injection",
    "display_name": "SpelInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A Spring expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation."
  },
  "DockerArbitraryContainerRun": {
    "title": "docker arbitrary container run",
    "display_name": "DockerArbitraryContainerRun",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `run` or `create` method it can result in runing arbitrary container."
  },
  "XmlinputfactoryExternalEntitiesEnabled": {
    "title": "xmlinputfactory external entities enabled",
    "display_name": "XmlinputfactoryExternalEntitiesEnabled",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "XML external entities are enabled for this XMLInputFactory. This is vulnerable to XML external entity\nattacks. Disable external entities by setting \"javax.xml.stream.isSupportingExternalEntities\" to false."
  },
  "VmCompilefunctionInjection": {
    "title": "vm compilefunction injection",
    "display_name": "VmCompilefunctionInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted user input in `vm.compileFunction()` can result in code injection."
  },
  "DetectBufferNoassert": {
    "title": "detect buffer noassert",
    "display_name": "DetectBufferNoassert",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected usage of noassert in Buffer API, which allows the offset the be beyond the\nend of the buffer. This could result in writing or reading beyond the end of the buffer."
  },
  "AnonymousLdapBind": {
    "title": "anonymous ldap bind",
    "display_name": "AnonymousLdapBind",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected anonymous LDAP bind.\nThis permits anonymous users to execute LDAP statements. Consider enforcing\nauthentication for LDAP. See https://docs.oracle.com/javase/tutorial/jndi/ldap/auth_mechs.html\nfor more information."
  },
  "SkipTlsVerifyCluster": {
    "title": "kubernetes: skip tls verify cluster",
    "display_name": "SkipTlsVerifyCluster",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Cluster is disabling TLS certificate verification when communicating with\nthe server. This makes your HTTPS connections insecure. Remove the\n'insecure-skip-tls-verify: true' key to secure communication."
  },
  "HelmetFeatureDisabled": {
    "title": "helmet feature disabled",
    "display_name": "HelmetFeatureDisabled",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "One or more Security Response header is explicitly disabled in Helmet."
  },
  "HardcodedTmpPath": {
    "title": "hardcoded tmp path",
    "display_name": "HardcodedTmpPath",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected hardcoded temp directory. Consider using 'tempfile.TemporaryFile' instead."
  },
  "InsecureCipherAlgorithmBlowfish": {
    "title": "insecure cipher algorithm blowfish",
    "display_name": "InsecureCipherAlgorithmBlowfish",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected Blowfish cipher algorithm which is considered insecure. The algorithm has many\nknown vulnerabilities. Use AES instead."
  },
  "ElectronDisableWebsecurity": {
    "title": "electron disable websecurity",
    "display_name": "ElectronDisableWebsecurity",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Disabling webSecurity will disable the same-origin policy and allows the execution of insecure code from any domain."
  },
  "UseJsonify": {
    "title": "use jsonify",
    "display_name": "UseJsonify",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "flask.jsonify() is a Flask helper method which handles the correct settings for returning JSON from Flask routes"
  },
  "RaiseNotBaseException": {
    "title": "raise not base exception",
    "display_name": "RaiseNotBaseException",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "In Python3, a runtime `TypeError` will be thrown if you attempt to raise an object or class which does not inherit from `BaseException`"
  },
  "JsOpenRedirect": {
    "title": "js open redirect",
    "display_name": "JsOpenRedirect",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Possible open redirect"
  },
  "GenericCors": {
    "title": "generic cors",
    "display_name": "GenericCors",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Access-Control-Allow-Origin response header is set to \"*\". This will disable CORS Same Origin Policy restrictions."
  },
  "DetectedStripeApiKey": {
    "title": "secrets: detected stripe api key",
    "display_name": "DetectedStripeApiKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Stripe API Key detected"
  },
  "InsecureJmsDeserialization": {
    "title": "insecure jms deserialization",
    "display_name": "InsecureJmsDeserialization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "JMS Object messages depend on Java Serialization for marshalling/unmarshalling of the message payload when ObjectMessage.getObject() is called.\nDeserialization of untrusted data can lead to security flaws; a remote attacker could via a crafted JMS ObjectMessage to execute\narbitrary code with the permissions of the application listening/consuming JMS Messages.\nIn this case, the JMS MessageListener consume an ObjectMessage type recieved inside\nthe onMessage method, which may lead to arbitrary code execution when calling the $Y.getObject method."
  },
  "DetectInsecureWebsocket": {
    "title": "detect insecure websocket",
    "display_name": "DetectInsecureWebsocket",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections."
  },
  "JqueryInsecureSelector": {
    "title": "jquery insecure selector",
    "display_name": "JqueryInsecureSelector",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in a `$(...)` is an anti-pattern that can lead to XSS vulnerabilities"
  },
  "DetectAngularTrustAsJsMethod": {
    "title": "detect angular trust as js method",
    "display_name": "DetectAngularTrustAsJsMethod",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The use of $sce.trustAsJs can be dangerous if unsantiized user input flows through this API."
  },
  "EqeqIsBad": {
    "title": "eqeq is bad",
    "display_name": "EqeqIsBad",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "useless comparison operation `$X == $X` or `$X != $X`"
  },
  "DefaultResteasyProviderAbuse": {
    "title": "default resteasy provider abuse",
    "display_name": "DefaultResteasyProviderAbuse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "When a Restful webservice endpoint isn't configured with a @Consumes annotation, an attacker could abuse the SerializableProvider by sending a HTTP Request with a Content-Type of application/x-java-serialized-object. The body of that request would be processed by the SerializationProvider and could contain a malicious payload, which may lead to arbitrary code execution."
  },
  "CookieMissingSecure": {
    "title": "cookie missing secure",
    "display_name": "CookieMissingSecure",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A session cookie was detected without setting the 'Secure' flag.\nThe 'secure' flag for cookies prevents the client from transmitting\nthe cookie over insecure channels such as HTTP.  Set the 'Secure'\nflag by setting 'Secure' to 'true' in the Options struct."
  },
  "RubyJwtNoneAlg": {
    "title": "ruby jwt none alg",
    "display_name": "RubyJwtNoneAlg",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected use of the 'none' algorithm in a JWT token.\nThe 'none' algorithm assumes the integrity of the token has already\nbeen verified. This would allow a malicious actor to forge a JWT token\nthat will automatically be verified. Do not explicitly use the 'none'\nalgorithm. Instead, use an algorithm such as 'HS256'."
  },
  "ServerSideTemplateInjection": {
    "title": "server side template injection",
    "display_name": "ServerSideTemplateInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted user input in templating engine's compile() function can result in Remote Code Execution via server side template injection."
  },
  "PlaywrightSsrf": {
    "title": "playwright ssrf",
    "display_name": "PlaywrightSsrf",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `puppeteer` methods it can result in Server-Side Request Forgery vulnerabilities."
  },
  "InsecureUrlopen": {
    "title": "insecure urlopen",
    "display_name": "InsecureUrlopen",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected 'urllib.urlopen()' using 'http://'. This request will not be\nencrypted. Use 'https://' instead."
  },
  "SsrfInjectionRequests": {
    "title": "ssrf injection requests",
    "display_name": "SsrfInjectionRequests",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Data from request object is passed to a new server-side request.\nThis could lead to a server-side request forgery (SSRF). To mitigate,\nensure that schemes and hosts are validated against an allowlist,\ndo not forward the response to the user, and ensure proper authentication\nand transport-layer security in the proxied request.\nSee https://owasp.org/www-community/attacks/Server_Side_Request_Forgery to\nlearn more about SSRF vulnerabilities."
  },
  "JoinResolvePathTraversal": {
    "title": "join resolve path traversal",
    "display_name": "JoinResolvePathTraversal",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Path constructed with user input can result in Path Traversal. Ensure that user input does not reach `join()` or `resolve()`."
  },
  "SeccompConfinementDisabled": {
    "title": "kubernetes: seccomp confinement disabled",
    "display_name": "SeccompConfinementDisabled",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Container is explicitly disabling seccomp confinement. This runs the\nservice in an unrestricted state. Remove 'seccompProfile: unconfined' to\nprevent this."
  },
  "DetectBracketObjectInjection": {
    "title": "detect bracket object injection",
    "display_name": "DetectBracketObjectInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Object injection via bracket notation via $FIELD"
  },
  "StringFormattedQuery": {
    "title": "string formatted query",
    "display_name": "StringFormattedQuery",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "String-formatted SQL query detected. This could lead to SQL injection if\nthe string is not sanitized properly. Audit this call to ensure the\nSQL is not manipulatable by external data."
  },
  "EvalUse": {
    "title": "eval use",
    "display_name": "EvalUse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Evaluating non-constant commands. This can lead to command injection."
  },
  "CookieIssecureFalse": {
    "title": "cookie issecure false",
    "display_name": "CookieIssecureFalse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Default session middleware settings: `setSecure` not set to true.\nThis ensures that the cookie is sent only over HTTPS to prevent cross-site scripting attacks."
  },
  "InsecureUseScanfFn": {
    "title": "insecure use scanf fn",
    "display_name": "InsecureUseScanfFn",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Avoid using 'scanf()'. This function, when used improperly, does not consider\nbuffer boundaries and can lead to buffer overflows. Use 'fgets()' instead\nfor reading input."
  },
  "DetectAngularResourceLoading": {
    "title": "detect angular resource loading",
    "display_name": "DetectAngularResourceLoading",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "$sceDelegateProvider allowlisting can be introduce security issues if wildcards are used."
  },
  "DoubleFree": {
    "title": "double free",
    "display_name": "DoubleFree",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Variable '$VAR' was freed twice. This can lead to undefined behavior."
  },
  "ReactFindDom": {
    "title": "react find dom",
    "display_name": "ReactFindDom",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "findDOMNode is an escape hatch used to access the underlying DOM node. In most cases, use of this escape hatch is discouraged because it pierces the component abstraction."
  },
  "ReflectMakefunc": {
    "title": "reflect makefunc",
    "display_name": "ReflectMakefunc",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "'reflect.MakeFunc' detected. This will sidestep protections that are\nnormally afforded by Go's type system. Audit this call and be sure that\nuser input cannot be used to affect the code generated by MakeFunc;\notherwise, you will have a serious security vulnerability."
  },
  "DangerousSpawnProcess": {
    "title": "dangerous spawn process",
    "display_name": "DangerousSpawnProcess",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found dynamic content when spawning a process. This is dangerous if external\ndata can reach this function call because it allows a malicious actor to\nexecute commands. Ensure no external data reaches here."
  },
  "PuppeteerEvaluateArgInjection": {
    "title": "puppeteer evaluate arg injection",
    "display_name": "PuppeteerEvaluateArgInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `evaluate` method it can result in Server-Side Request Forgery vulnerabilities"
  },
  "NodeAesNoiv": {
    "title": "node aes noiv",
    "display_name": "NodeAesNoiv",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "AES algorithms requires an initialization vector (IV). Providing no or null IV in some implementation results to a 0 IV. Use of a deterministic IV makes dictionary attacks easier."
  },
  "SpawnGitClone": {
    "title": "spawn git clone",
    "display_name": "SpawnGitClone",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Git allows shell commands to be specified in ext URLs for remote repositories.\nFor example, git clone 'ext::sh -c whoami% >&2' will execute the whoami command to try to connect to a remote repository.\nMake sure that the URL is not controlled by external input."
  },
  "UnescapedDataInJs": {
    "title": "unescaped data in js",
    "display_name": "UnescapedDataInJs",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found a formatted template string passed to 'template.JS()'.\n'template.JS()' does not escape contents. Be absolutely sure\nthere is no user-controlled data in this template."
  },
  "ParamikoImplicitTrustHostKey": {
    "title": "paramiko implicit trust host key",
    "display_name": "ParamikoImplicitTrustHostKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a paramiko host key policy that implicitly trusts a server's\nhost key. Host keys should be verified to ensure the connection\nis not to a malicious server. Use RejectPolicy or a custom subclass\ninstead."
  },
  "ShelljsOsCommandExec": {
    "title": "shelljs os command exec",
    "display_name": "ShelljsOsCommandExec",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in 'shelljs.exec()' can result in Remote OS Command Execution."
  },
  "HardcodedToken": {
    "title": "hardcoded token",
    "display_name": "HardcodedToken",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Hardcoded AWS access token detected. Use environment variables\nto access tokens (e.g., os.environ.get(...)) or use non version-controlled\nconfiguration files."
  },
  "TempfileInsecure": {
    "title": "tempfile insecure",
    "display_name": "TempfileInsecure",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use tempfile.NamedTemporaryFile instead. From the official Python documentation: THIS FUNCTION IS UNSAFE AND SHOULD NOT BE USED. The file name may refer to a file that did not exist at some point, but by the time you get around to creating it, someone else may have beaten you to the punch."
  },
  "InsufficientPostmessageOriginValidation": {
    "title": "insufficient postmessage origin validation",
    "display_name": "InsufficientPostmessageOriginValidation",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "No validation of origin is done by the addEventListener API. It may be possible to exploit this flaw to perform Cross Origin attacks such as Cross-Site Scripting(XSS)."
  },
  "CStringEquality": {
    "title": "c string equality",
    "display_name": "CStringEquality",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Using == on char* performs pointer comparison, use strcmp instead"
  },
  "CookieSessionNoMaxage": {
    "title": "cookie session no maxage",
    "display_name": "CookieSessionNoMaxage",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Session middleware settings: `maxAge` not set. Use it to set expiration date for cookies."
  },
  "ExpressJwtNotRevoked": {
    "title": "express jwt not revoked",
    "display_name": "ExpressJwtNotRevoked",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "No token revoking configured for `express-jwt`. A leaked token could still be used and unable to be revoked.\nConsider using function as the `isRevoked` option."
  },
  "DangerousOpen": {
    "title": "dangerous open",
    "display_name": "DangerousOpen",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected non-static command inside 'open'. Audit the input to 'open'.\nIf unverified user data can reach this call site, this is a code injection\nvulnerability. A malicious actor can inject a malicious script to execute\narbitrary code."
  },
  "InsecureUrlopenerRetrieveFtp": {
    "title": "insecure urlopener retrieve ftp",
    "display_name": "InsecureUrlopenerRetrieveFtp",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected an insecure transmission channel. 'URLopener.retrieve(...)' is\nbeing used with 'ftp://'. Use SFTP instead. urllib does not support\nSFTP, so consider using a library which supports SFTP."
  },
  "Python37CompatibilityHttpconn": {
    "title": "python37 compatibility httpconn",
    "display_name": "Python37CompatibilityHttpconn",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "HTTPConnection blocksize keyword argument is Python 3.7+ only"
  },
  "WritingToFileInReadMode": {
    "title": "writing to file in read mode",
    "display_name": "WritingToFileInReadMode",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The file object '$FD' was opened in read mode, but is being\nwritten to. This will cause a runtime error."
  },
  "DetectedAwsAccountId": {
    "title": "secrets: detected aws account id",
    "display_name": "DetectedAwsAccountId",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "AWS Account ID detected"
  },
  "DetectAngularSceDisabled": {
    "title": "detect angular sce disabled",
    "display_name": "DetectAngularSceDisabled",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "$sceProvider is set to false. Disabling Strict Contextual escaping (SCE) in an AngularJS application could provide additional attack surface for XSS vulnerabilities."
  },
  "AvoidCpickle": {
    "title": "avoid cPickle",
    "display_name": "AvoidCpickle",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Avoid using `cPickle`, which is known to lead to code execution vulnerabilities.\nWhen unpickling, the serialized data could be manipulated to run arbitrary code.\nInstead, consider serializing the relevant data as JSON or a similar text-based\nserialization format."
  },
  "DetectAngularTranslateproviderTranslationsMethod": {
    "title": "detect angular translateprovider translations method",
    "display_name": "DetectAngularTranslateproviderTranslationsMethod",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The use of $translateProvider.translations method can be dangerous if user input is provided to this API."
  },
  "NodeAesEcb": {
    "title": "node aes ecb",
    "display_name": "NodeAesEcb",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "AES with ECB mode is deterministic in nature and not suitable for encrypting large amount of repetitive data."
  },
  "ExposingDockerSocketHostpath": {
    "title": "kubernetes: exposing docker socket hostpath",
    "display_name": "ExposingDockerSocketHostpath",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Exposing host's Docker socket to containers via a volume. The owner of this\nsocket is root. Giving someone access to it is equivalent to giving\nunrestricted root access to your host. Remove 'docker.sock' from hostpath to\nprevent this."
  },
  "FindSqlStringConcatenation": {
    "title": "find sql string concatenation",
    "display_name": "FindSqlStringConcatenation",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "In $METHOD, $X is used to construct a SQL query via string concatenation."
  },
  "DangerousSystemCall": {
    "title": "dangerous system call",
    "display_name": "DangerousSystemCall",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found dynamic content used in a system call. This is dangerous if external data can reach this function call because it allows a malicious actor to execute commands. Use the 'subprocess' module instead, which is easier to use without accidentally exposing a command injection vulnerability."
  },
  "CreateWith": {
    "title": "create with",
    "display_name": "CreateWith",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Checks for strong parameter bypass through usage of create_with. Create_with bypasses strong parameter protection, which\ncould allow attackers to set arbitrary attributes on models. To fix this vulnerability, either remove all create_with calls\nor use the permit function to specify tags that are allowed to be set."
  },
  "XmlinputfactoryPossibleXxe": {
    "title": "xmlinputfactory possible xxe",
    "display_name": "XmlinputfactoryPossibleXxe",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "XML external entities are not explicitly disabled for this XMLInputFactory. This could be vulnerable to XML external entity\nvulnerabilities. Explicitly disable external entities by setting \"javax.xml.stream.isSupportingExternalEntities\" to false."
  },
  "RobotsDenied": {
    "title": "robots denied",
    "display_name": "RobotsDenied",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This page denies crawlers from indexing the page. Remove the robots 'meta' tag."
  },
  "InsecureRedirect": {
    "title": "nginx: insecure redirect",
    "display_name": "InsecureRedirect",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected an insecure redirect in this nginx configuration.\nIf no scheme is specified, nginx will forward the request with the\nincoming scheme. This could result in unencrypted communications.\nTo fix this, include the 'https' scheme.\n\n{\"include\": [\"*.conf\", \"*.vhost\", \"sites-available/*\", \"sites-enabled/*\"]}"
  },
  "ManualDefaultdictSetCreate": {
    "title": "manual defaultdict set create",
    "display_name": "ManualDefaultdictSetCreate",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "manually creating a defaultdict - use collections.defaultdict(set)"
  },
  "WkhtmltoimageInjection": {
    "title": "wkhtmltoimage injection",
    "display_name": "WkhtmltoimageInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `wkhtmltoimage` it can result in Server-Side Request Forgery vulnerabilities"
  },
  "AvoidYumUpdate": {
    "title": "dockerfile: avoid yum update",
    "display_name": "AvoidYumUpdate",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Packages in base images should be up-to-date, removing the need for\n'yum update'. If packages are out-of-date, consider contacting the\nbase image maintainer.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "XssrequestwrapperIsInsecure": {
    "title": "xssrequestwrapper is insecure",
    "display_name": "XssrequestwrapperIsInsecure",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "It looks like you're using an implementation of XSSRequestWrapper from dzone.\n(https://www.javacodegeeks.com/2012/07/anti-cross-site-scripting-xss-filter.html)\nThe XSS filtering in this code is not secure and can be bypassed by malicious actors.\nIt is recommended to use a stack that automatically escapes in your view or templates\ninstead of filtering yourself."
  },
  "TemplateTranslateAsNoEscape": {
    "title": "template translate as no escape",
    "display_name": "TemplateTranslateAsNoEscape",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Translated strings will not be escaped when rendered in a template.\nThis leads to a vulnerability where translators could include malicious script tags in their translations.\nConsider using `force_escape` to explicitly escape a transalted text."
  },
  "AvoidQuerySetExtra": {
    "title": "avoid query set extra",
    "display_name": "AvoidQuerySetExtra",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This is a last resort. You should be careful when using QuerySet.extra due to SQLi https://docs.djangoproject.com/en/3.0/ref/models/querysets/#django.db.models.query.QuerySet.extra"
  },
  "BufferNoassert": {
    "title": "buffer noassert",
    "display_name": "BufferNoassert",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected usage of noassert in Buffer API, which allows the offset the be beyond the end of the buffer. This could result in writing or reading beyond the end of the buffer."
  },
  "DetectedUsernameAndPasswordInUri": {
    "title": "secrets: detected username and password in uri",
    "display_name": "DetectedUsernameAndPasswordInUri",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Username and password in URI detected"
  },
  "AvoidDnfUpdate": {
    "title": "dockerfile: avoid dnf update",
    "display_name": "AvoidDnfUpdate",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Packages in base images should be up-to-date, removing the need for\n'dnf update'. If packages are out-of-date, consider contacting the\nbase image maintainer.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "InsecureCipherAlgorithmIdea": {
    "title": "insecure cipher algorithm idea",
    "display_name": "InsecureCipherAlgorithmIdea",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected IDEA cipher algorithm which is considered insecure. The algorithm is\nconsidered weak and has been deprecated. Use AES instead."
  },
  "AvoidAccessingRequestInWrongHandler": {
    "title": "avoid accessing request in wrong handler",
    "display_name": "AvoidAccessingRequestInWrongHandler",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Accessing request object inside a route handle for HTTP GET command will throw due to missing request body."
  },
  "HibernateSqli": {
    "title": "hibernate sqli",
    "display_name": "HibernateSqli",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a formatted string in a SQL statement. This could lead to SQL\ninjection if variables in the SQL statement are not properly sanitized.\nUse a prepared statements (java.sql.PreparedStatement) instead. You\ncan obtain a PreparedStatement using 'connection.prepareStatement'."
  },
  "UnsafeReflection": {
    "title": "unsafe reflection",
    "display_name": "UnsafeReflection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If an attacker can supply values that the application then uses to determine which class to instantiate or which method to invoke,\nthe potential exists for the attacker to create control flow paths through the application\nthat were not intended by the application developers.\nThis attack vector may allow the attacker to bypass authentication or access control checks\nor otherwise cause the application to behave in an unexpected manner."
  },
  "DetectedMailchimpApiKey": {
    "title": "secrets: detected mailchimp api key",
    "display_name": "DetectedMailchimpApiKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "MailChimp API Key detected"
  },
  "NodeEntityExpansion": {
    "title": "node entity expansion",
    "display_name": "NodeEntityExpansion",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in XML Parsers can result in XML Internal Entity Processing vulnerabilities like in DoS."
  },
  "NonsensicalCommand": {
    "title": "dockerfile: nonsensical command",
    "display_name": "NonsensicalCommand",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Some commands such as `$CMD` do not make sense in a container. Do not use these.\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "ExpressVmRunincontextContextInjection": {
    "title": "express vm runincontext context injection",
    "display_name": "ExpressVmRunincontextContextInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach vm.runInContext."
  },
  "XssDisableMustacheEscape": {
    "title": "xss disable mustache escape",
    "display_name": "XssDisableMustacheEscape",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Markup escaping disabled. This can be used with some template engines to escape disabling of HTML entities, which can lead to XSS attacks."
  },
  "WeakCrypto": {
    "title": "weak crypto",
    "display_name": "WeakCrypto",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected usage of weak crypto function. Consider using stronger alternatives."
  },
  "AvoidImplementingCustomDigests": {
    "title": "avoid implementing custom digests",
    "display_name": "AvoidImplementingCustomDigests",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Cryptographic algorithms are notoriously difficult to get right. By implementing\na custom message digest, you risk introducing security issues into your program.\nUse one of the many sound message digests already available to you:\nMessageDigest sha256Digest = MessageDigest.getInstance(\"SHA256\");"
  },
  "TimingAttack": {
    "title": "timing attack",
    "display_name": "TimingAttack",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Checks for unsafe use of method http_basic_authenticate_with, which is vulnerable to timing attacks as it\ndoes not use constant-time checking when comparing passwords. Affected Rails versions include:\n5.0.0.beta1.1, 4.2.5.1, 4.1.14.1, 3.2.22.1. Avoid this function if possible."
  },
  "ReactCssInjection": {
    "title": "react css injection",
    "display_name": "ReactCssInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in a `style` attribute is an anti-pattern that can lead to XSS vulnerabilities"
  },
  "UseJsonResponse": {
    "title": "use json response",
    "display_name": "UseJsonResponse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use JsonResponse instead"
  },
  "InsecureModuleUsed": {
    "title": "insecure module used",
    "display_name": "InsecureModuleUsed",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected use of an insecure cryptographic hashing method. This method is known to be broken and easily compromised. Use SHA256 or SHA3 instead."
  },
  "PuppeteerSetcontentInjection": {
    "title": "puppeteer setcontent injection",
    "display_name": "PuppeteerSetcontentInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `setContent` method it can result in Server-Side Request Forgery vulnerabilities"
  },
  "YieldInInit": {
    "title": "yield in init",
    "display_name": "YieldInInit",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "`yield` should never appear inside a class __init__ function. This will cause a runtime error."
  },
  "Exported_loop_pointer": {
    "title": "exported_loop_pointer",
    "display_name": "Exported_loop_pointer",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "`$VALUE` is a loop pointer that may be exported from the loop. This pointer is shared between loop iterations, so the exported reference will always point to the last loop value, which is likely unintentional. To fix, copy the pointer to a new pointer within the loop."
  },
  "VarInScriptSrc": {
    "title": "var in script src",
    "display_name": "VarInScriptSrc",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a template variable used as the 'src' in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent malicious URLs from being injected and could results in a cross-site scripting (XSS) vulnerability. Prefer not to dynamically generate the 'src' attribute and use static URLs instead. If you must do this, carefully check URLs against an allowlist and be sure to URL-encode the result."
  },
  "DangerousGroovyShell": {
    "title": "dangerous groovy shell",
    "display_name": "DangerousGroovyShell",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation."
  },
  "InsecureResteasyDeserialization": {
    "title": "insecure resteasy deserialization",
    "display_name": "InsecureResteasyDeserialization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "When a Restful webservice endpoint is configured to use wildcard mediaType {*/*} as a value for the @Consumes annotation, an attacker could abuse the SerializableProvider by sending a HTTP Request with a Content-Type of application/x-java-serialized-object. The body of that request would be processed by the SerializationProvider and could contain a malicious payload, which may lead to arbitrary code execution when calling the $Y.getObject method."
  },
  "NoStringEqeq": {
    "title": "no string eqeq",
    "display_name": "NoStringEqeq",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Strings should not be compared with '=='.\nThis is a reference comparison operator.\nUse '.equals()' instead."
  },
  "VmRunincontextCodeInjection": {
    "title": "vm runincontext code injection",
    "display_name": "VmRunincontextCodeInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach vm.runInContext."
  },
  "ChromeRemoteInterfaceCompilescriptInjection": {
    "title": "chrome remote interface compilescript injection",
    "display_name": "ChromeRemoteInterfaceCompilescriptInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `compileScript` method it can result in Server-Side Request Forgery vulnerabilities"
  },
  "PprofDebugExposure": {
    "title": "pprof debug exposure",
    "display_name": "PprofDebugExposure",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The profiling 'pprof' endpoint is automatically exposed on /debug/pprof.\nThis could leak information about the server.\nInstead, use `import \"net/http/pprof\"`. See\nhttps://www.farsightsecurity.com/blog/txt-record/go-remote-profiling-20161028/\nfor more information and mitigation."
  },
  "DesIsDeprecated": {
    "title": "des is deprecated",
    "display_name": "DesIsDeprecated",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "DES is considered deprecated. AES is the recommended cipher.\nUpgrade to use AES.\nSee https://www.nist.gov/news-events/news/2005/06/nist-withdraws-outdated-data-encryption-standard for more information."
  },
  "WeakHashesMd5": {
    "title": "weak hashes md5",
    "display_name": "WeakHashesMd5",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Should not use md5 to generate hashes. md5 is proven to be vulnerable through the use of brute-force attacks.\nCould also result in collisions,leading to potential collision attacks. Use SHA256 or other hashing functions instead."
  },
  "Python37CompatibilityMultiprocess1": {
    "title": "python37 compatibility multiprocess1",
    "display_name": "Python37CompatibilityMultiprocess1",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "this function is only available on Python 3.7+"
  },
  "CookieSessionNoPath": {
    "title": "cookie session no path",
    "display_name": "CookieSessionNoPath",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Default session middleware settings: `path` not set. It indicates the path of the cookie; use it to compare against the request path. If this and domain match, then send the cookie in the request."
  },
  "Python37CompatibilityMultiprocess2": {
    "title": "python37 compatibility multiprocess2",
    "display_name": "Python37CompatibilityMultiprocess2",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "this function is only available on Python 3.7+"
  },
  "ExpressOpenRedirect": {
    "title": "express open redirect",
    "display_name": "ExpressOpenRedirect",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted user input in redirect() can result in Open Redirect vulnerability."
  },
  "DetectedCodeclimate": {
    "title": "secrets: detected codeclimate",
    "display_name": "DetectedCodeclimate",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "CodeClimate detected"
  },
  "DefaultMutableDict": {
    "title": "default mutable dict",
    "display_name": "DefaultMutableDict",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Function $F mutates default dict $D. Python only instantiates default function arguments once and shares the instance across the function calls. If the default function argument is mutated, that will modify the instance used by all future function calls. This can cause unexpected results, or lead to security vulnerabilities whereby one function consumer can view or modify the data of another function consumer. Instead, use a default argument (like None) to indicate that no argument was provided and instantiate a new dictionary at that time. For example: `if $D is None: $D = {}`."
  },
  "PathTraversalOpen": {
    "title": "path traversal open",
    "display_name": "PathTraversalOpen",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found request data in a call to 'open'. Ensure the request data is validated or sanitized, otherwise it could result in path traversal attacks."
  },
  "InsufficientDsaKeySize": {
    "title": "insufficient dsa key size",
    "display_name": "InsufficientDsaKeySize",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected an insufficient key size for DSA. NIST recommends\na key size of 2048 or higher."
  },
  "PlaywrightEvaluateArgInjection": {
    "title": "playwright evaluate arg injection",
    "display_name": "PlaywrightEvaluateArgInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `evaluate` method it can result in Server-Side Request Forgery vulnerabilities"
  },
  "PythonLoggerCredentialDisclosure": {
    "title": "python logger credential disclosure",
    "display_name": "PythonLoggerCredentialDisclosure",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Logger call may be exposing a secret credential in $FORMAT_STRING"
  },
  "FileDisclosure": {
    "title": "file disclosure",
    "display_name": "FileDisclosure",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Special requests can determine whether a file exists on a filesystem that's outside the Ruby app's\nroot directory. To fix this, set config.serve_static_assets = false."
  },
  "NodeCurlSslVerifyDisable": {
    "title": "node curl ssl verify disable",
    "display_name": "NodeCurlSslVerifyDisable",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "SSL Certificate verification for node-curl is disabled."
  },
  "DetectedGenericApiKey": {
    "title": "secrets: detected generic api key",
    "display_name": "DetectedGenericApiKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Generic API Key detected"
  },
  "SessionCookieMissingHttponly": {
    "title": "session cookie missing httponly",
    "display_name": "SessionCookieMissingHttponly",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A session cookie was detected without setting the 'HttpOnly' flag.\nThe 'HttpOnly' flag for cookies instructs the browser to forbid\nclient-side scripts from reading the cookie which mitigates XSS\nattacks. Set the 'HttpOnly' flag by setting 'HttpOnly' to 'true'\nin the Options struct."
  },
  "InsecureTrustManager": {
    "title": "insecure trust manager",
    "display_name": "InsecureTrustManager",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected empty trust manager implementations. This is dangerous because it accepts any\ncertificate, enabling man-in-the-middle attacks. Consider using a KeyStore\nand TrustManagerFactory isntead.\nSee https://stackoverflow.com/questions/2642777/trusting-all-certificates-using-httpclient-over-https\nfor more information."
  },
  "JwtExposedData": {
    "title": "jwt exposed data",
    "display_name": "JwtExposedData",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The object is passed strictly to jose.JWT.sign(...). Make sure  that sensitive information is not exposed through JWT token payload."
  },
  "InsufficientEcKeySize": {
    "title": "insufficient ec key size",
    "display_name": "InsufficientEcKeySize",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected an insufficient curve size for EC. NIST recommends\na key size of 224 or higher. For example, use 'ec.SECP256R1'."
  },
  "HelmetHeaderCheckCsp": {
    "title": "helmet header check csp",
    "display_name": "HelmetHeaderCheckCsp",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Content Security Policy header is present. More Information: https://helmetjs.github.io/docs/csp/"
  },
  "WritableFilesystemContainer": {
    "title": "kubernetes: writable filesystem container",
    "display_name": "WritableFilesystemContainer",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Container is running with a writable root filesystem. This may\nallow malicious applications to download and run additional payloads, or\nmodify container files. If an application inside a container has to save\nsomething temporarily consider using a tmpfs. Add 'readOnlyRootFilesystem: true'\nto this container to prevent this."
  },
  "BadTmpFileCreation": {
    "title": "bad tmp file creation",
    "display_name": "BadTmpFileCreation",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "File creation in shared tmp directory without using ioutil.Tempfile"
  },
  "WeakSslVersion": {
    "title": "weak ssl version",
    "display_name": "WeakSslVersion",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "An insecure SSL version was detected. TLS versions 1.0, 1.1, and all SSL versions\nare considered weak encryption and are deprecated.\nUse 'ssl.PROTOCOL_TLSv1_2' or higher."
  },
  "AvoidRawSql": {
    "title": "avoid raw sql",
    "display_name": "AvoidRawSql",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "You should be very careful whenever you write raw SQL. Consider using Django ORM before raw SQL. See https://docs.djangoproject.com/en/3.0/topics/db/sql/#passing-parameters-into-raw"
  },
  "MarshalUsage": {
    "title": "marshal usage",
    "display_name": "MarshalUsage",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The marshal module is not intended to be secure against erroneous or maliciously constructed data.\nNever unmarshal data received from an untrusted or unauthenticated source.\nSee more details: https://docs.python.org/3/library/marshal.html?highlight=security"
  },
  "UseFtpTls": {
    "title": "use ftp tls",
    "display_name": "UseFtpTls",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The 'FTP' class sends information unencrypted. Consider using\nthe 'FTP_TLS' class instead."
  },
  "DoPrivilegedUse": {
    "title": "do privileged use",
    "display_name": "DoPrivilegedUse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Marking code as privileged enables a piece of trusted code to temporarily\nenable access to more resources than are available directly to the code\nthat called it. Be very careful in your use of the privileged construct,\nand always remember to make the privileged code section as small as possible."
  },
  "JpaSqli": {
    "title": "jpa sqli",
    "display_name": "JpaSqli",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a formatted string in a SQL statement. This could lead to SQL\ninjection if variables in the SQL statement are not properly sanitized.\nUse a prepared statements (java.sql.PreparedStatement) instead. You\ncan obtain a PreparedStatement using 'connection.prepareStatement'."
  },
  "JavaJwtNoneAlg": {
    "title": "java jwt none alg",
    "display_name": "JavaJwtNoneAlg",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected use of the 'none' algorithm in a JWT token.\nThe 'none' algorithm assumes the integrity of the token has already\nbeen verified. This would allow a malicious actor to forge a JWT token\nthat will automatically be verified. Do not explicitly use the 'none'\nalgorithm. Instead, use an algorithm such as 'HS256'."
  },
  "UnknownValueInRedirect": {
    "title": "unknown value in redirect",
    "display_name": "UnknownValueInRedirect",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "It looks like '$UNK' is read from user input and it is used to as a redirect. Ensure\n'$UNK' is not externally controlled, otherwise this is an open redirect."
  },
  "MultipleEntrypointInstructions": {
    "title": "dockerfile: multiple entrypoint instructions",
    "display_name": "MultipleEntrypointInstructions",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Multiple ENTRYPOINT instructions were found. Only the last one will take effect.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "CommandInjectionProcessBuilder": {
    "title": "command injection process builder",
    "display_name": "CommandInjectionProcessBuilder",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A formatted or concatenated string was detected as input to a ProcessBuilder call.\nThis is dangerous if a variable is controlled by user input and could result in a\ncommand injection. Ensure your variables are not controlled by users or sufficiently sanitized."
  },
  "UseOfDes": {
    "title": "use of DES",
    "display_name": "UseOfDes",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected DES cipher algorithm which is insecure. The algorithm is\nconsidered weak and has been deprecated. Use AES instead."
  },
  "NoIoWritestringToResponsewriter": {
    "title": "no io writestring to responsewriter",
    "display_name": "NoIoWritestringToResponsewriter",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected 'io.WriteString()' writing directly to 'http.ResponseWriter'.\nThis bypasses HTML escaping that prevents cross-site scripting\nvulnerabilities. Instead, use the 'html/template' package\nto render data to users."
  },
  "InsecureUrlretrieve": {
    "title": "insecure urlretrieve",
    "display_name": "InsecureUrlretrieve",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected 'urllib.urlretrieve()' using 'http://'. This request will not be\nencrypted. Use 'https://' instead."
  },
  "XssSendMailHtmlMessage": {
    "title": "xss send mail html message",
    "display_name": "XssSendMailHtmlMessage",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found request data in 'send_mail(...)' that uses 'html_message'.\nThis is dangerous because HTML emails are susceptible to XSS.\nAn attacker could inject data into this HTML email, causing XSS."
  },
  "UseTimeout": {
    "title": "use timeout",
    "display_name": "UseTimeout",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "By default, 'requests' calls wait until the connection is closed.\nThis means a 'requests' call without a timeout will hang the program\nif a response is never received. Consider setting a timeout for all\n'requests'."
  },
  "UseCountMethod": {
    "title": "use count method",
    "display_name": "UseCountMethod",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Looks like you need to determine the number of records. Django provides the count() method which is more efficient than .len(). See https://docs.djangoproject.com/en/3.0/ref/models/querysets/"
  },
  "HardcodedConditional": {
    "title": "hardcoded conditional",
    "display_name": "HardcodedConditional",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "useless if statement, always the same behavior"
  },
  "PgxSqli": {
    "title": "pgx sqli",
    "display_name": "PgxSqli",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected string concatenation with a non-literal variable in a pgx Go SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, used parameterized queries instead. You can use parameterized queries like so: (`SELECT $1 FROM table`, `data1)"
  },
  "SqlalchemySqlInjection": {
    "title": "sqlalchemy sql injection",
    "display_name": "SqlalchemySqlInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Distinct, Having, Group_by, Order_by, and Filter in SQLAlchemy can cause sql injections\nif the developer inputs raw SQL into the before-mentioned clauses.\nThis pattern captures relevant cases in which the developer inputs raw SQL into the distinct, having, group_by, order_by or filter clauses and\ninjects user-input into the raw SQL with any function besides \"bindparams\". Use bindParams to securely bind user-input\nto SQL statements."
  },
  "Python36CompatibilityPopen1": {
    "title": "python36 compatibility Popen1",
    "display_name": "Python36CompatibilityPopen1",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "the `errors` argument to Popen is only available on Python 3.6+"
  },
  "Python36CompatibilityPopen2": {
    "title": "python36 compatibility Popen2",
    "display_name": "Python36CompatibilityPopen2",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "the `encoding` argument to Popen is only available on Python 3.6+"
  },
  "ReturnNotInFunction": {
    "title": "return not in function",
    "display_name": "ReturnNotInFunction",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "`return` only makes sense inside a function"
  },
  "SecureSetCookie": {
    "title": "secure set cookie",
    "display_name": "SecureSetCookie",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Flask cookies should be handled securely by setting secure=True, httponly=True, and samesite='Lax' in\nresponse.set_cookie(...). If your situation calls for different settings, explicitly disable the setting.\nIf you want to send the cookie over http, set secure=False.  If you want to let client-side JavaScript\nread the cookie, set httponly=False. If you want to attach cookies to requests for external sites,\nset samesite=None."
  },
  "DetectedArtifactoryToken": {
    "title": "secrets: detected artifactory token",
    "display_name": "DetectedArtifactoryToken",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Artifactory token detected"
  },
  "HtmlMagicMethod": {
    "title": "html magic method",
    "display_name": "HtmlMagicMethod",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The `__html__` method indicates to the Django template engine that the\nvalue is 'safe' for rendering. This means that normal HTML escaping will\nnot be applied to the return value. This exposes your application to\ncross-site scripting (XSS) vulnerabilities. If you need to render raw HTML,\nconsider instead using `mark_safe()` which more clearly marks the intent\nto render raw HTML than a class with a magic method."
  },
  "ElectronBlinkIntegration": {
    "title": "electron blink integration",
    "display_name": "ElectronBlinkIntegration",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Blink's expirimental features are enabled in this application. Some of the features may affect the security of the application."
  },
  "Python37CompatibilityHttpsconn": {
    "title": "python37 compatibility httpsconn",
    "display_name": "Python37CompatibilityHttpsconn",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "HTTPSConnection blocksize keyword argument is Python 3.7+ only"
  },
  "UselessEqeq": {
    "title": "useless eqeq",
    "display_name": "UselessEqeq",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This expression is always True: `$X == $X` or `$X != $X`. If testing for floating point NaN, use `math.isnan($X)`, or `cmath.isnan($X)` if the number is complex."
  },
  "SpringCsrfDisabled": {
    "title": "spring csrf disabled",
    "display_name": "SpringCsrfDisabled",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "CSRF is disabled for this configuration. This is a security risk."
  },
  "AngularSanitizeNoneContext": {
    "title": "angular sanitize none context",
    "display_name": "AngularSanitizeNoneContext",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The output is not sanitized when calling with SecurityContext.NONE."
  },
  "CookieSessionNoDomain": {
    "title": "cookie session no domain",
    "display_name": "CookieSessionNoDomain",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Default session middleware settings: `domain` not set. It indicates the domain of the cookie; use it to compare against the domain of the server in which the URL is being requested. If they match, then check the path attribute next."
  },
  "NodePostgresSqli": {
    "title": "node postgres sqli",
    "display_name": "NodePostgresSqli",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected string concatenation with a non-literal variable in a node-postgres\nJS SQL statement. This could lead to SQL injection if the variable is user-controlled\nand not properly sanitized. In order to prevent SQL injection,\nused parameterized queries or prepared statements instead.\nYou can use parameterized statements like so:\n`client.query('SELECT $1 from table', [userinput])`"
  },
  "SpringJspEval": {
    "title": "spring jsp eval",
    "display_name": "SpringJspEval",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A Spring expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation."
  },
  "ReactHttpLeak": {
    "title": "react http leak",
    "display_name": "ReactHttpLeak",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This HTML element '$EL' and attribute '$ATTR' together may load an external resource. This means that if dynamic content can enter this attribute it may be possible for an attacker to send HTTP requests to unintended locations which may leak data about your users. If this element is reaching out to a known host, consider hardcoding the host (or loading from a configuration) and appending the dynamic path. See https://github.com/cure53/HTTPLeaks for more information."
  },
  "NodeJwtNoneAlgorithm": {
    "title": "node jwt none algorithm",
    "display_name": "NodeJwtNoneAlgorithm",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Algorithm is set to none for JWT token. This can nullify the integrity of JWT signature."
  },
  "PreferJsonNotation": {
    "title": "dockerfile: prefer json notation",
    "display_name": "PreferJsonNotation",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Prefer JSON notation when using CMD or ENTRYPOINT. This allows signals to be passed from the OS.\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "VarInScriptTag": {
    "title": "var in script tag",
    "display_name": "VarInScriptTag",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a template variable used in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent cross-site scripting (XSS) attacks when used directly in JavaScript. If you need this data on the rendered page, consider placing it in the HTML portion (outside of a script tag). Alternatively, use a JavaScript-specific encoder, such as the one available in OWASP ESAPI. For Django, you may also consider using the 'json_script' template tag and retrieving the data in your script by using the element ID (e.g., `document.getElementById`)."
  },
  "Bash_reverse_shell": {
    "title": "ci: bash_reverse_shell",
    "display_name": "Bash_reverse_shell",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Semgrep found a bash reverse shell"
  },
  "InsecureCipherModeEcb": {
    "title": "insecure cipher mode ecb",
    "display_name": "InsecureCipherModeEcb",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected ECB cipher mode which is considered insecure. The algorithm can\npotentially leak information about the plaintext. Use CBC mode instead."
  },
  "PuppeteerEvaluateCodeInjection": {
    "title": "puppeteer evaluate code injection",
    "display_name": "PuppeteerEvaluateCodeInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `evaluate` method it can result in Server-Side Request Forgery vulnerabilities"
  },
  "ExpressJwtHardcodedSecret": {
    "title": "express jwt hardcoded secret",
    "display_name": "ExpressJwtHardcodedSecret",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Hardcoded JWT secret or private key is used.\nThis is a Insufficiently Protected Credentials weakness: https://cwe.mitre.org/data/definitions/522.html\nConsider using an appropriate security mechanism to protect the credentials (e.g. keeping secrets in environment variables: process.env.SECRET)"
  },
  "SaxXxe": {
    "title": "sax xxe",
    "display_name": "SaxXxe",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use of 'ondoctype' in 'sax' library detected. By default, 'sax'\nwon't do anything with custom DTD entity definitions. If you're\nimplementing a custom DTD entity definition, be sure not to introduce\nXML External Entity (XXE) vulnerabilities, or be absolutely sure that\nexternal entities received from a trusted source while processing XML."
  },
  "InsecureUrlopenerOpen": {
    "title": "insecure urlopener open",
    "display_name": "InsecureUrlopenerOpen",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected an unsecured transmission channel. 'URLopener.open(...)' is\nbeing used with 'http://'. Use 'https://' instead to secure the channel."
  },
  "LenAllCount": {
    "title": "len all count",
    "display_name": "LenAllCount",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Using QUERY.count() instead of len(QUERY.all()) sends less data to the client since the SQLAlchemy method is performed server-side."
  },
  "HelmetHeaderNosniff": {
    "title": "helmet header nosniff",
    "display_name": "HelmetHeaderNosniff",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Content-Type-Options header is present. More information: https://helmetjs.github.io/docs/dont-sniff-mimetype/"
  },
  "InsecureHostnameVerifier": {
    "title": "insecure hostname verifier",
    "display_name": "InsecureHostnameVerifier",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Insecure HostnameVerifier implementation detected. This will accept\nany SSL certificate with any hostname, which creates the possibility\nfor man-in-the-middle attacks."
  },
  "ExpressWkhtmltopdfInjection": {
    "title": "express wkhtmltopdf injection",
    "display_name": "ExpressWkhtmltopdfInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `phantom` methods it can result in Server-Side Request Forgery vulnerabilities"
  },
  "PuppeteerSsrf": {
    "title": "puppeteer ssrf",
    "display_name": "PuppeteerSsrf",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `puppeteer` methods it can result in Server-Side Request Forgery vulnerabilities."
  },
  "CookieMissingSamesite": {
    "title": "cookie missing samesite",
    "display_name": "CookieMissingSamesite",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected cookie without the SameSite attribute."
  },
  "MultipleCmdInstructions": {
    "title": "dockerfile: multiple cmd instructions",
    "display_name": "MultipleCmdInstructions",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Multiple CMD instructions were found. Only the last one will take effect.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "ZlibAsyncLoop": {
    "title": "zlib async loop",
    "display_name": "ZlibAsyncLoop",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Creating and using a large number of zlib objects simultaneously\ncan cause significant memory fragmentation. It is strongly recommended\nthat the results of compression operations be cached or made synchronous\nto avoid duplication of effort."
  },
  "JwtExpressHardcoded": {
    "title": "jwt express hardcoded",
    "display_name": "JwtExpressHardcoded",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Hardcoded JWT secret or private key was found. Store it properly in  an environment variable."
  },
  "NoAuthOverHttp": {
    "title": "no auth over http",
    "display_name": "NoAuthOverHttp",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Authentication detected over HTTP. HTTP does not provide any\nencryption or protection for these authentication credentials.\nThis may expose these credentials to unauthhorized parties.\nUse 'https://' instead."
  },
  "HelmetHeaderCheckCrossdomain": {
    "title": "helmet header check crossdomain",
    "display_name": "HelmetHeaderCheckCrossdomain",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "X-Permitted-Cross-Domain-Policies header set to off. More information: https://helmetjs.github.io/docs/crossdomain/"
  },
  "EvalInjection": {
    "title": "eval injection",
    "display_name": "EvalInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected user data flowing into eval. This is code injection and should be avoided."
  },
  "ManualDefaultdictListCreate": {
    "title": "manual defaultdict list create",
    "display_name": "ManualDefaultdictListCreate",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "manually creating a defaultdict - use collections.defaultdict(list)"
  },
  "MbEregReplaceEval": {
    "title": "mb ereg replace eval",
    "display_name": "MbEregReplaceEval",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Calling mb_ereg_replace with user input in the options can lead to arbitrary\ncode execution. The eval modifier (`e`) evaluates the replacement argument\nas code."
  },
  "Eqeq": {
    "title": "eqeq",
    "display_name": "Eqeq",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "`$X == $X` or `$X != $X` is always true. (Unless the value compared is a float or double).\nTo test if `$X` is not-a-number, use `Double.isNaN($X)`."
  },
  "UseTls": {
    "title": "use tls",
    "display_name": "UseTls",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found an HTTP server without TLS. Use 'http.ListenAndServeTLS' instead. See https://golang.org/pkg/net/http/#ListenAndServeTLS for more information."
  },
  "JavascriptPrompt": {
    "title": "javascript prompt",
    "display_name": "JavascriptPrompt",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "found prompt() call; should this be in production code?"
  },
  "RateLimitControl": {
    "title": "rate limit control",
    "display_name": "RateLimitControl",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This application has API rate limiting controls."
  },
  "GlobalAutoescapeOff": {
    "title": "global autoescape off",
    "display_name": "GlobalAutoescapeOff",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Autoescape is globally disbaled for this Django application. If you are\nrendering any web pages, this exposes your application to cross-site\nscripting (XSS) vulnerabilities. Remove 'autoescape: False' or set it\nto 'True'."
  },
  "DetectedEtcShadow": {
    "title": "secrets: detected etc shadow",
    "display_name": "DetectedEtcShadow",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "linux shadow file detected"
  },
  "MissingInternal": {
    "title": "nginx: missing internal",
    "display_name": "MissingInternal",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This location block contains a 'proxy_pass' directive but does not contain the 'internal' directive. The 'internal' directive restricts access to this location to internal requests. Without 'internal', an attacker could use your server for server-side request forgeries (SSRF). Include the 'internal' directive in this block to limit exposure.\n{\"include\": [\"*.conf\", \"*.vhost\", \"sites-available/*\", \"sites-enabled/*\"]}"
  },
  "HardcodedJwtSecret": {
    "title": "hardcoded jwt secret",
    "display_name": "HardcodedJwtSecret",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Hardcoded JWT secret was found. Store it properly in an environment variable."
  },
  "ReactHtmlElementSpreading": {
    "title": "react html element spreading",
    "display_name": "ReactHtmlElementSpreading",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "It is a good practice to avoid spreading for JSX attributes. This prevents accidentally\npassing `dangerouslySetInnerHTML` to an element."
  },
  "InsecureUseGetsFn": {
    "title": "insecure use gets fn",
    "display_name": "InsecureUseGetsFn",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Avoid 'gets()'. This function does not consider buffer boundaries and can lead\nto buffer overflows. Use 'fgets()' or 'gets_s()' instead."
  },
  "DetectedStripeRestrictedApiKey": {
    "title": "secrets: detected stripe restricted api key",
    "display_name": "DetectedStripeRestrictedApiKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Stripe Restricted API Key detected"
  },
  "ObjectDeserialization": {
    "title": "object deserialization",
    "display_name": "ObjectDeserialization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found object deserialization using ObjectInputStream. Deserializing entire\nJava objects is dangerous because malicious actors can create Java object\nstreams with unintended consequences. Ensure that the objects being deserialized\nare not user-controlled. If this must be done, consider using HMACs to sign\nthe data stream to make sure it is not tampered with, or consider only\ntransmitting object fields and populating a new object."
  },
  "UseAfterFree": {
    "title": "use after free",
    "display_name": "UseAfterFree",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Variable '$VAR' was used after being freed. This can lead to undefined behavior."
  },
  "RsaNoPadding": {
    "title": "rsa no padding",
    "display_name": "RsaNoPadding",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Using RSA without OAEP mode weakens the encryption."
  },
  "ReactPropsInjection": {
    "title": "react props injection",
    "display_name": "ReactPropsInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Inject arbitrary props into the new element. It may introduce an XSS vulnerability."
  },
  "SequelizeTls": {
    "title": "sequelize tls",
    "display_name": "SequelizeTls",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The Sequelize connection string indicates that database server does not use TLS. Non TLS connections are susceptible to man in the middle (MITM) attacks."
  },
  "Python37CompatibilityLocale1": {
    "title": "python37 compatibility locale1",
    "display_name": "Python37CompatibilityLocale1",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "this function is only available on Python 3.7+"
  },
  "AvoidUnsafeRuamel": {
    "title": "avoid unsafe ruamel",
    "display_name": "AvoidUnsafeRuamel",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Avoid using unsafe `ruamel.yaml.YAML()`. `ruamel.yaml.YAML` can\ncreate arbitrary Python objects. A malicious actor could exploit\nthis to run arbitrary code. Use `YAML(typ='rt')` or\n`YAML(typ='safe')` instead."
  },
  "McryptUse": {
    "title": "mcrypt use",
    "display_name": "McryptUse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Mcrypt functionality has been deprecated and/or removed in recent PHP\nversions. Consider using Sodium or OpenSSL."
  },
  "DetectedFacebookOauth": {
    "title": "secrets: detected facebook oauth",
    "display_name": "DetectedFacebookOauth",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Facebook OAuth detected"
  },
  "NestedAttributesBypass": {
    "title": "nested attributes bypass",
    "display_name": "NestedAttributesBypass",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Checks for nested attributes vulnerability (CVE-2015-7577). Setting allow_destroy: false in\naccepts_nested_attributes_for can lead to attackers setting attributes to invalid values and clearing all attributes.\nThis affects versions 3.1.0 and newer, with fixed versions 5.0.0.beta1.1, 4.2.5.1, 4.1.14.1, 3.2.22.1.\nTo fix, upgrade to a newer version or use the initializer specified in the google groups."
  },
  "WildcardPostmessageConfiguration": {
    "title": "wildcard postmessage configuration",
    "display_name": "WildcardPostmessageConfiguration",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The target origin of the window.postMessage() API is set to \"*\". This could allow for information disclosure due to the possibility of any origin allowed to receive the message."
  },
  "MissingDnfAssumeYesSwitch": {
    "title": "dockerfile: missing dnf assume yes switch",
    "display_name": "MissingDnfAssumeYesSwitch",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This 'dnf install' is missing the '-y' switch. This might stall\nbuilds because it requires human intervention. Add the '-y' switch.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "ReactControlledComponentPassword": {
    "title": "react controlled component password",
    "display_name": "ReactControlledComponentPassword",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Password can be leaked if CSS injection exists on the page."
  },
  "BaseclassAttributeOverride": {
    "title": "baseclass attribute override",
    "display_name": "BaseclassAttributeOverride",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Class $C inherits from both `$A` and `$B` which both have a method named\n`$F`; one of these methods will be overwritten."
  },
  "Avoid_hardcoded_config_env": {
    "title": "avoid_hardcoded_config_ENV",
    "display_name": "Avoid_hardcoded_config_env",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Hardcoded variable `ENV` detected. Set this by using FLASK_ENV environment variable"
  },
  "AvoidPlatformWithFrom": {
    "title": "dockerfile: avoid platform with from",
    "display_name": "AvoidPlatformWithFrom",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Using '--platform' with FROM restricts the image to build on a single platform. Further, this must be the same as the build platform. If you intended to specify the target platform, use the utility 'docker buildx --platform=' instead.\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "HttpsconnectionDetected": {
    "title": "httpsconnection detected",
    "display_name": "HttpsconnectionDetected",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The HTTPSConnection API has changed frequently with minor releases of Python.\nEnsure you are using the API for your version of Python securely.\nFor example, Python 3 versions prior to 3.4.3 will not verify SSL certificates by default.\nSee https://docs.python.org/3/library/http.client.html#http.client.HTTPSConnection\nfor more information."
  },
  "NodeWeakCrypto": {
    "title": "node weak crypto",
    "display_name": "NodeWeakCrypto",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A weak or broken cryptographic algorithm was identified. Using these functions will introduce vulnerabilities or downgrade the security of your application."
  },
  "Python36CompatibilitySsl": {
    "title": "python36 compatibility ssl",
    "display_name": "Python36CompatibilitySsl",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "this function is only available on Python 3.6+"
  },
  "BokehDeprecatedApis": {
    "title": "bokeh deprecated apis",
    "display_name": "BokehDeprecatedApis",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "These APIs are deprecated in Bokeh see https://docs.bokeh.org/en/latest/docs/releases.html#api-deprecations"
  },
  "Avoid_app_run_with_bad_host": {
    "title": "avoid_app_run_with_bad_host",
    "display_name": "Avoid_app_run_with_bad_host",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Running flask app with host 0.0.0.0 could expose the server publicly."
  },
  "ImportTextTemplate": {
    "title": "import text template",
    "display_name": "ImportTextTemplate",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "'text/template' does not escape HTML content. If you need\nto escape HTML content, use 'html/template' instead."
  },
  "FlaskWtfCsrfDisabled": {
    "title": "flask wtf csrf disabled",
    "display_name": "FlaskWtfCsrfDisabled",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Setting 'WTF_CSRF_ENABLED' to 'False' explicitly disables CSRF protection."
  },
  "JwtPythonExposedCredentials": {
    "title": "jwt python exposed credentials",
    "display_name": "JwtPythonExposedCredentials",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Password is exposed through JWT token payload. This is not encrypted and\nthe password could be compromised. Do not store passwords in JWT tokens."
  },
  "SpringActuatorFullyEnabled": {
    "title": "spring actuator fully enabled",
    "display_name": "SpringActuatorFullyEnabled",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Spring Boot Actuator is fully enabled. This exposes sensitive endpoints such as /actuator/env, /actuator/logfile, /actuator/heapdump and others.\nUnless you have Spring Security enabled or another means to protect these endpoints, this functionality is available without authentication, causing a severe security risk."
  },
  "MathRandomUsed": {
    "title": "math random used",
    "display_name": "MathRandomUsed",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Do not use `math/rand`. Use `crypto/rand` instead."
  },
  "UserExecFormatString": {
    "title": "user exec format string",
    "display_name": "UserExecFormatString",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found user data in a call to 'exec'. This is extremely dangerous because\nit can enable an attacker to execute remote code. See\nhttps://owasp.org/www-community/attacks/Code_Injection for more information."
  },
  "MissingThrottleConfig": {
    "title": "missing throttle config",
    "display_name": "MissingThrottleConfig",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Django REST framework configuration is missing default rate-\nlimiting options. This could inadvertently allow resource\nstarvation or Denial of Service (DoS) attacks. Add\n'DEFAULT_THROTTLE_CLASSES' and 'DEFAULT_THROTTLE_RATES'\nto add rate-limiting to your application."
  },
  "DangerousExecCommand": {
    "title": "dangerous exec command",
    "display_name": "DangerousExecCommand",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected non-static command inside Command. Audit the input to 'exec.Command'.\nIf unverified user data can reach this call site, this is a code injection\nvulnerability. A malicious actor can inject a malicious script to execute\narbitrary code."
  },
  "Log4jMessageLookupInjection": {
    "title": "log4j message lookup injection",
    "display_name": "Log4jMessageLookupInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "\u68c0\u67e5error(...), warn(...), info(...), debug(...), fatal(...), trace(...), log(level, ...)\u7b49\u5e38\u7528logger api\u8c03\u7528\u65b9\u6cd5\n\nPossible Lookup injection into Log4j messages. Lookups provide a way to add values to the Log4j messages at arbitrary\n    places. If the message parameter contains an attacker controlled string, the attacker could inject arbitrary lookups,\n    for instance '${java:runtime}'. This cloud lead to information disclosure or even remove code execution if 'log4j2.formatMsgNoLookups'\n    is enabled. This was enabled by default until version 2.15.0."
  },
  "Python.requests.bestPractice.useRequestJsonShortcut": {
    "title": "python.requests.best practice.use request json shortcut",
    "display_name": "Python.requests.bestPractice.useRequestJsonShortcut",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The requests library has a convenient shortcut for sending JSON requests,\nwhich lets you stop worrying about serializing the body yourself.\nTo use it, replace `body=json.dumps(...)` with `json=...`."
  },
  "PlaywrightEvaluateCodeInjection": {
    "title": "playwright evaluate code injection",
    "display_name": "PlaywrightEvaluateCodeInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `evaluate` method it can result in Server-Side Request Forgery vulnerabilities"
  },
  "UseOfRc4": {
    "title": "use of rc4",
    "display_name": "UseOfRc4",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected RC4 cipher algorithm which is insecure. The algorithm has many\nknown vulnerabilities. Use AES instead."
  },
  "DetectAngularTrustAsUrlMethod": {
    "title": "detect angular trust as url method",
    "display_name": "DetectAngularTrustAsUrlMethod",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The use of $sce.trustAsUrl can be dangerous if unsantiized user input flows through this API."
  },
  "NodeSha1": {
    "title": "node sha1",
    "display_name": "NodeSha1",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "SHA1 is a a weak hash which is known to have collision. Use a strong hashing function."
  },
  "PreferAptGet": {
    "title": "dockerfile: prefer apt get",
    "display_name": "PreferAptGet",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "'apt-get' is preferred as an unattended tool for stability. 'apt' is discouraged.\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "VmRunincontextInjection": {
    "title": "vm runincontext injection",
    "display_name": "VmRunincontextInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted user input in `vm.runInContext()` can result in code injection."
  },
  "InsecureUseStringCopyFn": {
    "title": "insecure use string copy fn",
    "display_name": "InsecureUseStringCopyFn",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Finding triggers whenever there is a strcpy or strncpy used.\nThis is an issue because strcpy or strncpy can lead to buffer overflow vulns.\nFix this by using strcpy_s instead."
  },
  "WkhtmltoimageSsrf": {
    "title": "wkhtmltoimage ssrf",
    "display_name": "WkhtmltoimageSsrf",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled URL reached to `wkhtmltoimage` can result in Server Side Request Forgery (SSRF)."
  },
  "ReactMissingNoopener": {
    "title": "react missing noopener",
    "display_name": "ReactMissingNoopener",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Missing 'noopener' on an anchor tag where target='_blank'. This could introduce\na reverse tabnabbing vulnerability. Include 'noopener' when using target='_blank'."
  },
  "MissingAssumeYesSwitch": {
    "title": "dockerfile: missing assume yes switch",
    "display_name": "MissingAssumeYesSwitch",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This 'apt-get install' is missing the '-y' switch. This might stall\nbuilds because it requires human intervention. Add the '-y' switch.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "EvalRequire": {
    "title": "eval require",
    "display_name": "EvalRequire",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted user input in `require()` function allows an attacker to load arbitrary code."
  },
  "XxeSax": {
    "title": "xxe sax",
    "display_name": "XxeSax",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use of 'ondoctype' in 'sax' library detected. By default, 'sax' won't do anything with custom DTD entity definitions. If you're implementing a custom DTD entity definition, be sure not to introduce XML External Entity (XXE) vulnerabilities, or be absolutely sure that external entities received from a trusted source while processing XML."
  },
  "ResRenderInjection": {
    "title": "res render injection",
    "display_name": "ResRenderInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If an attacker controls the x in res.render(x) then they can cause code to load that was not intended to run on the server."
  },
  "UnescapedDataInHtmlattr": {
    "title": "unescaped data in htmlattr",
    "display_name": "UnescapedDataInHtmlattr",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found a formatted template string passed to 'template.HTMLAttr()'.\n'template.HTMLAttr()' does not escape contents. Be absolutely sure\nthere is no user-controlled data in this template."
  },
  "FilterSkipping": {
    "title": "filter skipping",
    "display_name": "FilterSkipping",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Checks for use of action in Ruby routes. This can cause Rails to render an arbitrary view if an\nattacker creates an URL accurately. Affects 3.0 applications. Can avoid the vulnerability by providing\nadditional constraints."
  },
  "ExpressVm2CodeInjection": {
    "title": "express vm2 code injection",
    "display_name": "ExpressVm2CodeInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach `vm2`."
  },
  "JwtPythonHardcodedSecret": {
    "title": "jwt python hardcoded secret",
    "display_name": "JwtPythonHardcodedSecret",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Hardcoded JWT secret or private key is used.\nThis is a Insufficiently Protected Credentials weakness: https://cwe.mitre.org/data/definitions/522.html\nConsider using an appropriate security mechanism to protect the credentials (e.g. keeping secrets in environment variables)"
  },
  "UnvalidatedRedirect": {
    "title": "unvalidated redirect",
    "display_name": "UnvalidatedRedirect",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Application redirects to a destination URL specified by a user-supplied\nparameter that is not validated. This could direct users to malicious locations.\nConsider using an allowlist to validate URLs."
  },
  "ExpressXss": {
    "title": "express xss",
    "display_name": "ExpressXss",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted User Input in Response will result in Reflected Cross Site Scripting Vulnerability."
  },
  "InsecureOpenerdirectorOpenFtp": {
    "title": "insecure openerdirector open ftp",
    "display_name": "InsecureOpenerdirectorOpenFtp",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected an unsecured transmission channel. 'OpenerDirector.open(...)' is\nbeing used with 'ftp://'. Information sent over this connection will be\nunencrypted. Consider using SFTP instead. urllib does not support SFTP,\nso consider a library which supports SFTP."
  },
  "OgnlInjection": {
    "title": "ognl injection",
    "display_name": "OgnlInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation."
  },
  "NoFractionalCpuLimits": {
    "title": "kubernetes: no fractional cpu limits",
    "display_name": "NoFractionalCpuLimits",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "When you set a fractional CPU limit on a container,\nthe CPU cycles available will be throttled,\neven though most nodes can handle processes\nalternating between using 100% of the CPU."
  },
  "DangerousCommandWrite": {
    "title": "dangerous command write",
    "display_name": "DangerousCommandWrite",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected non-static command inside Write. Audit the input to '$CW.Write'.\nIf unverified user data can reach this call site, this is a code injection\nvulnerability. A malicious actor can inject a malicious script to execute\narbitrary code."
  },
  "SubprocessShellTrue": {
    "title": "subprocess shell true",
    "display_name": "SubprocessShellTrue",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found 'subprocess' function '$FUNC' with 'shell=True'. This is dangerous because this call will spawn\nthe command using a shell process. Doing so propagates current shell settings and variables, which\nmakes it much easier for a malicious actor to execute commands. Use 'shell=False' instead."
  },
  "HardcodedEqTrueOrFalse": {
    "title": "hardcoded eq true or false",
    "display_name": "HardcodedEqTrueOrFalse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "useless if statement, always the same behavior"
  },
  "FormattedSqlString": {
    "title": "formatted sql string",
    "display_name": "FormattedSqlString",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a formatted string in a SQL statement. This could lead to SQL\ninjection if variables in the SQL statement are not properly sanitized.\nUse a prepared statements (java.sql.PreparedStatement) instead. You\ncan obtain a PreparedStatement using 'connection.prepareStatement'."
  },
  "FlaskClassMethodGetSideEffects": {
    "title": "flask class method get side effects",
    "display_name": "FlaskClassMethodGetSideEffects",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Flask class method GET with side effects"
  },
  "ContextAutoescapeOff": {
    "title": "context autoescape off",
    "display_name": "ContextAutoescapeOff",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a Context with autoescape diabled. If you are\nrendering any web pages, this exposes your application to cross-site\nscripting (XSS) vulnerabilities. Remove 'autoescape: False' or set it\nto 'True'."
  },
  "DetectedPrivateKey": {
    "title": "secrets: detected private key",
    "display_name": "DetectedPrivateKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Private Key detected"
  },
  "UseEarliestOrLatest": {
    "title": "use earliest or latest",
    "display_name": "UseEarliestOrLatest",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Looks like you are only accessing first element of an ordered QuerySet. Use `latest()` or `earliest()` instead. See https://docs.djangoproject.com/en/3.0/ref/models/querysets/#django.db.models.query.QuerySet.latest"
  },
  "Double_goto": {
    "title": "double_goto",
    "display_name": "Double_goto",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The second goto statement will always be executed."
  },
  "WkhtmltopdfInjection": {
    "title": "wkhtmltopdf injection",
    "display_name": "WkhtmltopdfInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `wkhtmltopdf` it can result in Server-Side Request Forgery vulnerabilities"
  },
  "Layer7ObjectDos": {
    "title": "layer7 object dos",
    "display_name": "Layer7ObjectDos",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Layer7 Denial of Service. Looping over user controlled objects can result in DoS."
  },
  "Xml2jsonXxe": {
    "title": "xml2json xxe",
    "display_name": "Xml2jsonXxe",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the XML Parser it can result in XML External or\nInternal Entity (XXE) Processing vulnerabilities"
  },
  "MissingZypperClean": {
    "title": "dockerfile: missing zypper clean",
    "display_name": "MissingZypperClean",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This zypper command does not end with '&& zypper clean'. Running 'zypper clean' will remove cached data and reduce package size. (This must be performed in the same RUN step.)\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "XssSerializeJavascript": {
    "title": "xss serialize javascript",
    "display_name": "XssSerializeJavascript",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted user input reaching `serialize-javascript` with `unsafe` attribute can cause Cross Site Scripting (XSS)."
  },
  "MissingPipNoCacheDir": {
    "title": "dockerfile: missing pip no cache dir",
    "display_name": "MissingPipNoCacheDir",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This '$PIP install' is missing '--no-cache-dir'. This flag prevents\npackage archives from being kept around, thereby reducing image size.\nAdd '--no-cache-dir'.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "SequelizeWeakTlsVersion": {
    "title": "sequelize weak tls version",
    "display_name": "SequelizeWeakTlsVersion",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "TLS1.0 and TLS1.1 are deprecated and should be used anymore. By default, NodeJS used TLSv1.2. So, TLS min version must not be downgrade to TLS1.0 or TLS1.1. Enforce TLS1.3 is hightly recommanded This rule checks TLS configuration only for Postgresql, MariaDB and MySQL. SQLite is not really concerned by TLS configuration. This rule could be extended for MSSQL, but the dialectOptions is specific for Tedious."
  },
  "DefineStyledComponentsOnModuleLevel": {
    "title": "define styled components on module level",
    "display_name": "DefineStyledComponentsOnModuleLevel",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "By declaring a styled component inside the render method of a react component, you are dynamically creating a new component on every render. This means that React will have to discard and re-calculate that part of the DOM subtree on each subsequent render, instead of just calculating the difference of what changed between them. This leads to performance bottlenecks and unpredictable behavior."
  },
  "DetectedAwsSecretAccessKey": {
    "title": "secrets: detected aws secret access key",
    "display_name": "DetectedAwsSecretAccessKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "AWS Secret Access Key detected"
  },
  "DetectedGoogleOauthAccessToken": {
    "title": "secrets: detected google oauth access token",
    "display_name": "DetectedGoogleOauthAccessToken",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Google OAuth Access Token detected"
  },
  "VmRuninnewcontextContextInjection": {
    "title": "vm runinnewcontext context injection",
    "display_name": "VmRuninnewcontextContextInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach vm.runInNewContext."
  },
  "HelmetHeaderHsts": {
    "title": "helmet header hsts",
    "display_name": "HelmetHeaderHsts",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "HSTS header is present. More information: https://helmetjs.github.io/docs/hsts/"
  },
  "ExpressVmCodeInjection": {
    "title": "express vm code injection",
    "display_name": "ExpressVmCodeInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach vm instance."
  },
  "DetectDisableMustacheEscape": {
    "title": "detect disable mustache escape",
    "display_name": "DetectDisableMustacheEscape",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Markup escaping disabled. This can be used with some template engines to escape\ndisabling of HTML entities, which can lead to XSS attacks."
  },
  "StringConcatInList": {
    "title": "string concat in list",
    "display_name": "StringConcatInList",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected strings that are implicitly concatenated inside a list.\nPython will implicitly concatenate strings when not explicitly delimited.\nWas this supposed to be individual elements of the list?"
  },
  "NoInterpolationJsTemplateString": {
    "title": "no interpolation js template string",
    "display_name": "NoInterpolationJsTemplateString",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected template variable interpolation in a JavaScript template string. This is potentially vulnerable to cross-site scripting (XSS) attacks because a malicious actor has control over JavaScript but without the need to use escaped characters. Instead, obtain this variable outside of the template string and ensure your template is properly escaped."
  },
  "DefaulthttpclientIsDeprecated": {
    "title": "defaulthttpclient is deprecated",
    "display_name": "DefaulthttpclientIsDeprecated",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "DefaultHttpClient is deprecated. Further, it does not support connections\nusing TLS1.2, which makes using DefaultHttpClient a security hazard.\nUse SystemDefaultHttpClient instead, which supports TLS1.2."
  },
  "NodeErrorDisclosure": {
    "title": "node error disclosure",
    "display_name": "NodeErrorDisclosure",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Error messages with stack traces can expose sensitive information about the application."
  },
  "RegexDos": {
    "title": "regex dos",
    "display_name": "RegexDos",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Ensure that the regex used to compare with user supplied input is safe from regular expression denial of service."
  },
  "MissingDnfCleanAll": {
    "title": "dockerfile: missing dnf clean all",
    "display_name": "MissingDnfCleanAll",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This dnf command does not end with '&& dnf clean all'. Running 'dnf clean all' will remove cached data and reduce package size. (This must be performed in the same RUN step.)\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "UseAbsoluteWorkdir": {
    "title": "dockerfile: use absolute workdir",
    "display_name": "UseAbsoluteWorkdir",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a relative WORKDIR. Use absolute paths. This prevents issues based on assumptions about the WORKDIR of previous containers.\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "VmRuninnewcontextInjection": {
    "title": "vm runinnewcontext injection",
    "display_name": "VmRuninnewcontextInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted user input in `vm.runInNewContext()` can result in code injection."
  },
  "Python37CompatibilityTextiowrapper": {
    "title": "python37 compatibility textiowrapper",
    "display_name": "Python37CompatibilityTextiowrapper",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "this function is only available on Python 3.7+"
  },
  "SqlalchemyExecuteRawQuery": {
    "title": "sqlalchemy execute raw query",
    "display_name": "SqlalchemyExecuteRawQuery",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Avoiding SQL string concatenation: untrusted input concatinated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters. For complexe SQL composition, use SQL Expression Languague or Schema Definition Language. In most cases, SQLAlchemy ORM will be a better option."
  },
  "PathTraversalJoin": {
    "title": "path traversal join",
    "display_name": "PathTraversalJoin",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Data from request is passed to os.path.join() and to open().\nThis is a path traversal vulnerability: https://owasp.org/www-community/attacks/Path_Traversal\nTo mitigate, consider using os.path.abspath or os.path.realpath or Path library."
  },
  "FilterWithIsSafe": {
    "title": "filter with is safe",
    "display_name": "FilterWithIsSafe",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected Django filters flagged with 'is_safe'. 'is_safe' tells Django\nnot to apply escaping on the value returned by this filter (although the\ninput is escaped). Used improperly, 'is_safe' could expose your application\nto cross-site scripting (XSS) vulnerabilities. Ensure this filter does not\n1) add HTML characters, 2) remove characters, or 3) use external data in\nany way. Consider instead removing 'is_safe' and explicitly marking safe\ncontent with 'mark_safe()'."
  },
  "AvoidSshInsecureIgnoreHostKey": {
    "title": "avoid ssh insecure ignore host key",
    "display_name": "AvoidSshInsecureIgnoreHostKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Disabled host key verification detected. This allows man-in-the-middle\nattacks. Use the 'golang.org/x/crypto/ssh/knownhosts' package to do\nhost key verification.\nSee https://skarlso.github.io/2019/02/17/go-ssh-with-host-key-verification/\nto learn more about the problem and how to fix it."
  },
  "GoInsecureTemplates": {
    "title": "go insecure templates",
    "display_name": "GoInsecureTemplates",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "usage of insecure template types. They are documented as a security risk. See https://golang.org/pkg/html/template/#HTML."
  },
  "DynamicHttptraceClienttrace": {
    "title": "dynamic httptrace clienttrace",
    "display_name": "DynamicHttptraceClienttrace",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a potentially dynamic ClientTrace. This occurred because semgrep could not\nfind a static definition for '$TRACE'. Dynamic ClientTraces are dangerous because\nthey deserialize function code to run when certain Request events occur, which could lead\nto code being run without your knowledge. Ensure that your ClientTrace is statically defined."
  },
  "MissingZypperNoConfirmSwitch": {
    "title": "dockerfile: missing zypper no confirm switch",
    "display_name": "MissingZypperNoConfirmSwitch",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This 'zypper install' is missing the '-y' switch. This might stall\nbuilds because it requires human intervention. Add the '-y' switch.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "JavaJwtDecodeWithoutVerify": {
    "title": "java jwt decode without verify",
    "display_name": "JavaJwtDecodeWithoutVerify",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected the decoding of a JWT token without a verify step.\nJWT tokens must be verified before use, otherwise the token's\nintegrity is unknown. This means a malicious actor could forge\na JWT token with any claims. Call '.verify()' before using the token."
  },
  "DetectedTwitterAccessToken": {
    "title": "secrets: detected twitter access token",
    "display_name": "DetectedTwitterAccessToken",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Twitter Access Token detected"
  },
  "OsSystemInjection": {
    "title": "os system injection",
    "display_name": "OsSystemInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User data detected in os.system. This could be vulnerable to a command injection and should be avoided. If this must be done, use the 'subprocess' module instead and pass the arguments as a list."
  },
  "PsycopgSqli": {
    "title": "psycopg sqli",
    "display_name": "PsycopgSqli",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected string concatenation with a non-literal variable in a psycopg2\nPython SQL statement. This could lead to SQL injection if the variable is user-controlled\nand not properly sanitized. In order to prevent SQL injection,\nused parameterized queries or prepared statements instead.\nYou can use prepared statements by creating a 'sql.SQL' string. You can also use the pyformat binding style to create parameterized queries. For example:\n'cur.execute(SELECT * FROM table WHERE name=%s, user_input)'"
  },
  "ExpressCookieSessionNoExpires": {
    "title": "express cookie session no expires",
    "display_name": "ExpressCookieSessionNoExpires",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Default session middleware settings: `expires` not set.\nUse it to set expiration date for persistent cookies."
  },
  "UseDecimalfieldForMoney": {
    "title": "use decimalfield for money",
    "display_name": "UseDecimalfieldForMoney",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found a FloatField used for variable $F. Use DecimalField for currency fields to avoid float-rounding errors."
  },
  "MissingApkNoCache": {
    "title": "dockerfile: missing apk no cache",
    "display_name": "MissingApkNoCache",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This apk command is missing '--no-cache'. This forces apk to use a package\nindex instead of a local package cache, removing the need for '--update'\nand the deletion of '/var/cache/apk/*'. Add '--no-cache' to your apk command.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "MissingYumAssumeYesSwitch": {
    "title": "dockerfile: missing yum assume yes switch",
    "display_name": "MissingYumAssumeYesSwitch",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This 'yum install' is missing the '-y' switch. This might stall\nbuilds because it requires human intervention. Add the '-y' switch.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "UnescapedTemplateExtension": {
    "title": "unescaped template extension",
    "display_name": "UnescapedTemplateExtension",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Flask does not automatically escape Jinja templates unless they have\n.html, .htm, .xml, or .xhtml extensions. This could lead to XSS attacks.\nUse .html, .htm, .xml, or .xhtml for your template extensions.\nSee https://flask.palletsprojects.com/en/1.1.x/templating/#jinja-setup\nfor more information."
  },
  "SslV3IsInsecure": {
    "title": "ssl v3 is insecure",
    "display_name": "SslV3IsInsecure",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "SSLv3 is insecure because it has known vulnerabilities.\nStarting with go1.14, SSLv3 will be removed. Instead, use\n'tls.VersionTLS13'."
  },
  "UseDefusedXmlrpc": {
    "title": "use defused xmlrpc",
    "display_name": "UseDefusedXmlrpc",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected use of xmlrpc. xmlrpc is not inherently safe from vulnerabilities.\nUse defusedxml.xmlrpc instead."
  },
  "InsecureUrlopenerRetrieve": {
    "title": "insecure urlopener retrieve",
    "display_name": "InsecureUrlopenerRetrieve",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected an unsecured transmission channel. 'URLopener.retrieve(...)' is\nbeing used with 'http://'. Use 'https://' instead to secure the channel."
  },
  "Vm2CodeInjection": {
    "title": "vm2 code injection",
    "display_name": "Vm2CodeInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted user input reaching `vm2` can result in code injection."
  },
  "DetectAngularElementMethods": {
    "title": "detect angular element methods",
    "display_name": "DetectAngularElementMethods",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use of angular.element can lead to XSS if after,append,html,prepend,replaceWith,wrap are used with user-input."
  },
  "UseEscapexml": {
    "title": "use escapexml",
    "display_name": "UseEscapexml",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected an Expression Language segment that does not escape\noutput. This is dangerous because if any data in this expression\ncan be controlled externally, it is a cross-site scripting\nvulnerability. Instead, use the 'escapeXml' function from\nthe JSTL taglib. See https://www.tutorialspoint.com/jsp/jstl_function_escapexml.htm\nfor more information."
  },
  "UnsafeReflectByName": {
    "title": "unsafe reflect by name",
    "display_name": "UnsafeReflectByName",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If an attacker can supply values that the application then uses to determine which method or field to invoke,\nthe potential exists for the attacker to create control flow paths through the application\nthat were not intended by the application developers.\nThis attack vector may allow the attacker to bypass authentication or access control checks\nor otherwise cause the application to behave in an unexpected manner."
  },
  "DangerousSubshell": {
    "title": "dangerous subshell",
    "display_name": "DangerousSubshell",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected non-static command inside `...`.\nIf unverified user data can reach this call site, this is a code injection\nvulnerability. A malicious actor can inject a malicious script to execute\narbitrary code."
  },
  "InsecureUseStrcatFn": {
    "title": "insecure use strcat fn",
    "display_name": "InsecureUseStrcatFn",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Finding triggers whenever there is a strcat or strncat used.\nThis is an issue because strcat or strncat can lead to buffer overflow vulns.\nFix this by using strcat_s instead."
  },
  "UseNoneForPasswordDefault": {
    "title": "use none for password default",
    "display_name": "UseNoneForPasswordDefault",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "'$VAR' is using the empty string as its default and is being used to set\nthe password on '$MODEL'. If you meant to set an unusable password, set\nthe default value to 'None' or call 'set_unusable_password()'."
  },
  "DivideByZero": {
    "title": "divide by zero",
    "display_name": "DivideByZero",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Checks for divide by zero. Best practice involves not dividing a variable by zero, as this leads to a Ruby\nZeroDivisionError."
  },
  "PlaywrightAddinitscriptCodeInjection": {
    "title": "playwright addinitscript code injection",
    "display_name": "PlaywrightAddinitscriptCodeInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `addInitScript` method it can result in Server-Side Request Forgery vulnerabilities"
  },
  "UnrestrictedRequestMapping": {
    "title": "unrestricted request mapping",
    "display_name": "UnrestrictedRequestMapping",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a method annotated with 'RequestMapping' that does not specify the HTTP method. CSRF protections are not enabled for GET, HEAD, TRACE, or OPTIONS, and by default all HTTP methods are allowed when the HTTP method is not explicitly specified. This means that a method that performs state changes could be vulnerable to CSRF attacks. To mitigate, add the 'method' field and specify the HTTP method (such as 'RequestMethod.POST')."
  },
  "PythonDebuggerFound": {
    "title": "python debugger found",
    "display_name": "PythonDebuggerFound",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Importing the python debugger; did you mean to leave this in?"
  },
  "NodeKnexSqliInjection": {
    "title": "node knex sqli injection",
    "display_name": "NodeKnexSqliInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted input concatinated with raw SQL query using knex raw()  or whereRaw() functions can result in SQL Injection."
  },
  "AvoidInsecureDeserialization": {
    "title": "avoid insecure deserialization",
    "display_name": "AvoidInsecureDeserialization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Avoid using insecure deserialization library, backed by `pickle`, `_pickle`, `cpickle`, `dill`, `shelve`, or `yaml`, which are known to lead to remote code execution vulnerabilities."
  },
  "JavascriptAlert": {
    "title": "javascript alert",
    "display_name": "JavascriptAlert",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "found alert() call; should this be in production code?"
  },
  "DjangoCompat2_0CheckAggregateSupport": {
    "title": "django compat 2_0 check aggregate support",
    "display_name": "DjangoCompat2_0CheckAggregateSupport",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "django.db.backends.base.BaseDatabaseOperations.check_aggregate_support() is removed in Django 2.0."
  },
  "ZipPathOverwrite": {
    "title": "zip path overwrite",
    "display_name": "ZipPathOverwrite",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Insecure ZIP archive extraction can result in arbitrary path over write and can result in code injection."
  },
  "NontextFieldMustSetNullTrue": {
    "title": "nontext field must set null true",
    "display_name": "NontextFieldMustSetNullTrue",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "null=True should be set if blank=True is set on non-text fields."
  },
  "NoScriptlets": {
    "title": "no scriptlets",
    "display_name": "NoScriptlets",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "JSP scriptlet detected. Scriptlets are difficult to use securely and\nare considered bad practice. See https://stackoverflow.com/a/3180202.\nInstead, consider migrating to JSF or using the Expression Language\n'${...}' with the escapeXml function in your JSP files."
  },
  "HelmetHeaderFrameGuard": {
    "title": "helmet header frame guard",
    "display_name": "HelmetHeaderFrameGuard",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "X-Frame-Options header is present. More information: https://helmetjs.github.io/docs/frameguard/"
  },
  "UncheckedSubprocessCall": {
    "title": "unchecked subprocess call",
    "display_name": "UncheckedSubprocessCall",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This is not checking the return value of this subprocess call; if it fails no exception will be raised. Consider subprocess.check_call() instead"
  },
  "MakoTemplatesDetected": {
    "title": "mako templates detected",
    "display_name": "MakoTemplatesDetected",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Mako templates do not provide a global HTML escaping mechanism.\nThis means you must escape all sensitive data in your templates\nusing '| u' for URL escaping or '| h' for HTML escaping.\nIf you are using Mako to serve web content, consider using\na system such as Jinja2 which enables global escaping."
  },
  "NoNullCipher": {
    "title": "no null cipher",
    "display_name": "NoNullCipher",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "NullCipher was detected. This will not encrypt anything;\nthe cipher text will be the same as the plain text. Use\na valid, secure cipher: Cipher.getInstance(\"AES/CBC/PKCS7PADDING\").\nSee https://owasp.org/www-community/Using_the_Java_Cryptographic_Extensions\nfor more information."
  },
  "ExecDetected": {
    "title": "exec detected",
    "display_name": "ExecDetected",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected the use of exec(). exec() can be dangerous if used to evaluate\ndynamic content. If this content can be input from outside the program, this\nmay be a code injection vulnerability. Ensure evaluated content is not definable\nby external sources."
  },
  "UseClickSecho": {
    "title": "use click secho",
    "display_name": "UseClickSecho",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use `click.secho($X)` instead. It combines click.echo() and click.style()."
  },
  "HandlebarsSafestring": {
    "title": "handlebars safestring",
    "display_name": "HandlebarsSafestring",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Handlebars SafeString will not escape the data passed through it. Untrusted user input passing through SafeString can cause XSS."
  },
  "Avoid_hardcoded_config_testing": {
    "title": "avoid_hardcoded_config_TESTING",
    "display_name": "Avoid_hardcoded_config_testing",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Hardcoded variable `TESTING` detected. Use environment variables or config files instead"
  },
  "PregReplaceEval": {
    "title": "preg replace eval",
    "display_name": "PregReplaceEval",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Calling preg_replace with user input in the pattern can lead to arbitrary\ncode execution. The eval modifier (`/e`) evaluates the replacement argument\nas code."
  },
  "RequestWithHttp": {
    "title": "request with http",
    "display_name": "RequestWithHttp",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a request using 'http://'. This request will be unencrypted. Use 'https://' instead."
  },
  "ReflectedDataHttpresponsebadrequest": {
    "title": "reflected data httpresponsebadrequest",
    "display_name": "ReflectedDataHttpresponsebadrequest",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found request data reflected into HttpResponseBadRequest. This could be vulnerable to XSS. Ensure the request data is properly escaped or sanitzed."
  },
  "TemplateBlocktranslateNoEscape": {
    "title": "template blocktranslate no escape",
    "display_name": "TemplateBlocktranslateNoEscape",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Translated strings will not be escaped when rendered in a template.\nThis leads to a vulnerability where translators could include malicious script tags in their translations.\nConsider using `force_escape` to explicitly escape a translated text."
  },
  "IntegerOverflowInt32": {
    "title": "integer overflow int32",
    "display_name": "IntegerOverflowInt32",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Potential Integer overflow made by strconv.Atoi result conversion to int32"
  },
  "SpringSqli": {
    "title": "spring sqli",
    "display_name": "SpringSqli",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a formatted string in a SQL statement. This could lead to SQL\ninjection if variables in the SQL statement are not properly sanitized.\nUse a prepared statements (java.sql.PreparedStatement) instead. You\ncan obtain a PreparedStatement using 'connection.prepareStatement'."
  },
  "AiopgSqli": {
    "title": "aiopg sqli",
    "display_name": "AiopgSqli",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected string concatenation with a non-literal variable in an aiopg\nPython SQL statement. This could lead to SQL injection if the variable is user-controlled\nand not properly sanitized. In order to prevent SQL injection,\nuse parameterized queries instead.\nYou can create parameterized queries like so:\n'cur.execute(\"SELECT %s FROM table\", (user_value,))'."
  },
  "DetectedGoogleOauthUrl": {
    "title": "secrets: detected google oauth url",
    "display_name": "DetectedGoogleOauthUrl",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Google OAuth url detected"
  },
  "UnescapedDataInUrl": {
    "title": "unescaped data in url",
    "display_name": "UnescapedDataInUrl",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found a formatted template string passed to 'template.URL()'.\n'template.URL()' does not escape contents. Be absolutely sure\nthere is no user-controlled data in this template."
  },
  "PgSqli": {
    "title": "pg sqli",
    "display_name": "PgSqli",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected string concatenation with a non-literal variable in a go-pg\nSQL statement. This could lead to SQL injection if the variable is user-controlled\nand not properly sanitized. In order to prevent SQL injection,\nused parameterized queries instead of string concatenation. You can use parameterized queries like so:\n'(SELECT ? FROM table, data1)'"
  },
  "SandboxCodeInjection": {
    "title": "sandbox code injection",
    "display_name": "SandboxCodeInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Unrusted data in `sandbox` can result in code injection."
  },
  "HardcodedHttpAuthInController": {
    "title": "hardcoded http auth in controller",
    "display_name": "HardcodedHttpAuthInController",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected hardcoded password used in basic authentication in a controller\nclass. Including this password in version control could expose this\ncredential. Consider refactoring to use environment variables or\nconfiguration files."
  },
  "CookieMissingHttponly": {
    "title": "cookie missing httponly",
    "display_name": "CookieMissingHttponly",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A session cookie was detected without setting the 'HttpOnly' flag.\nThe 'HttpOnly' flag for cookies instructs the browser to forbid\nclient-side scripts from reading the cookie which mitigates XSS\nattacks. Set the 'HttpOnly' flag by setting 'HttpOnly' to 'true'\nin the Cookie."
  },
  "InvalidPort": {
    "title": "dockerfile: invalid port",
    "display_name": "InvalidPort",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected an invalid port number. Valid ports are 0 through 65535.\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "AvoidAptGetUpgrade": {
    "title": "dockerfile: avoid apt get upgrade",
    "display_name": "AvoidAptGetUpgrade",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Packages in base containers should be up-to-date, removing the need to upgrade or dist-upgrade. If a package is out of date, contact the maintainers.\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "IdenticalIsComparison": {
    "title": "identical is comparison",
    "display_name": "IdenticalIsComparison",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found identical comparison using is. Ensure this is what you intended."
  },
  "XmlDecoder": {
    "title": "xml decoder",
    "display_name": "XmlDecoder",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "XMLDecoder should not be used to parse untrusted data.\nDeserializing user input can lead to arbitrary code execution.\nUse an alternative and explicitly disable external entities.\nSee https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html\nfor alternatives and vulnerability prevention."
  },
  "BadOperatorInFilter": {
    "title": "bad operator in filter",
    "display_name": "BadOperatorInFilter",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Only comparison operators should be used inside SQLAlchemy filter expressions. Use `==` instead of `is`,\n`!=` instead of `is not`, `sqlalchemy.and_` instead of `and`, `sqlalchemy.or_` instead of `or`,\n`sqlalchemy.not_` instead of `not`, and `sqlalchemy.in_` instead of `in_`."
  },
  "ReactMissingNoreferrer": {
    "title": "react missing noreferrer",
    "display_name": "ReactMissingNoreferrer",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This anchor tag with 'target=\"_blank\"' is missing 'noreferrer'.\nA page opened with 'target=\"_blank\"' can access the window object of the origin page.\nThis means it can manipulate the 'window.opener' property, which could redirect the origin page to a malicious URL.\nThis is called reverse tabnabbing. To prevent this, include 'rel=noreferrer' on this tag."
  },
  "SeamLogInjection": {
    "title": "seam log injection",
    "display_name": "SeamLogInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Seam Logging API support an expression language to introduce bean property to log messages.\nThe expression language can also be the source to unwanted code execution.\nIn this context, an expression is built with a dynamic value.\nThe source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation."
  },
  "ReactLegacyComponent": {
    "title": "react legacy component",
    "display_name": "ReactLegacyComponent",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Legacy component lifecycle was detected - $METHOD."
  },
  "VmScriptCodeInjection": {
    "title": "vm script code injection",
    "display_name": "VmScriptCodeInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach vm.Script."
  },
  "CodeAfterUnconditionalReturn": {
    "title": "code after unconditional return",
    "display_name": "CodeAfterUnconditionalReturn",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "code after return statement will not be executed"
  },
  "DangerousExecCmd": {
    "title": "dangerous exec cmd",
    "display_name": "DangerousExecCmd",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected non-static command inside exec.Cmd. Audit the input to 'exec.Cmd'.\nIf unverified user data can reach this call site, this is a code injection\nvulnerability. A malicious actor can inject a malicious script to execute\narbitrary code."
  },
  "JdbcSqlFormattedString": {
    "title": "jdbc sql formatted string",
    "display_name": "JdbcSqlFormattedString",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Possible JDBC injection detected. Use the parameterized query\nfeature available in queryForObject instead of concatenating or formatting strings:\n'jdbc.queryForObject(\"select * from table where name = ?\", Integer.class, parameterName);'"
  },
  "DetectedSlackWebhook": {
    "title": "secrets: detected slack webhook",
    "display_name": "DetectedSlackWebhook",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Slack Webhook detected"
  },
  "ReactUnsanitizedMethod": {
    "title": "react unsanitized method",
    "display_name": "ReactUnsanitizedMethod",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in a insertAdjacentHTML, document.write or document.writeln is an anti-pattern that can lead to XSS vulnerabilities"
  },
  "DetectedGoogleGcmServiceAccount": {
    "title": "secrets: detected google gcm service account",
    "display_name": "DetectedGoogleGcmServiceAccount",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Google (GCM) Service account detected"
  },
  "UseOfSha1": {
    "title": "use of sha1",
    "display_name": "UseOfSha1",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected SHA1 hash algorithm which is considered insecure. SHA1 is not\ncollision resistant and is therefore not suitable as a cryptographic\nsignature. Use SHA256 or SHA3 instead."
  },
  "DetectedNpmRegistryAuthToken": {
    "title": "secrets: detected npm registry auth token",
    "display_name": "DetectedNpmRegistryAuthToken",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "NPM registry authentication token detected\n{\"include\": [\"*npmrc*\"]}"
  },
  "InsecureCipherAlgorithmRc4": {
    "title": "insecure cipher algorithm rc4",
    "display_name": "InsecureCipherAlgorithmRc4",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected RC4 cipher algorithm which is considered insecure. The algorithm has many\nknown vulnerabilities. Use AES instead."
  },
  "TemplateUnescapedWithSafe": {
    "title": "template unescaped with safe",
    "display_name": "TemplateUnescapedWithSafe",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability."
  },
  "JwtNotRevoked": {
    "title": "jwt not revoked",
    "display_name": "JwtNotRevoked",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "No token revoking configured for `express-jwt`. A leaked token could still be used and unable to be revoked. Consider using function as the `isRevoked` option."
  },
  "PathTraversalInsideZipExtraction": {
    "title": "path traversal inside zip extraction",
    "display_name": "PathTraversalInsideZipExtraction",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "File traversal when extracting zip archive"
  },
  "ReactInsecureRequest": {
    "title": "react insecure request",
    "display_name": "ReactInsecureRequest",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Unencrypted request over HTTP detected."
  },
  "DetectAngularTrustAsResourceurlMethod": {
    "title": "detect angular trust as resourceurl method",
    "display_name": "DetectAngularTrustAsResourceurlMethod",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The use of $sce.trustAsResourceUrl can be dangerous if unsantiized user input flows through this API."
  },
  "NodeMd5": {
    "title": "node md5",
    "display_name": "NodeMd5",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "MD5 is a a weak hash which is known to have collision. Use a strong hashing function."
  },
  "MaintainerIsDeprecated": {
    "title": "dockerfile: maintainer is deprecated",
    "display_name": "MaintainerIsDeprecated",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "MAINTAINER has been deprecated.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "DjangoSecureSetCookie": {
    "title": "django secure set cookie",
    "display_name": "DjangoSecureSetCookie",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Django cookies should be handled securely by setting secure=True, httponly=True, and samesite='Lax' in\nresponse.set_cookie(...). If your situation calls for different settings, explicitly disable the setting.\nIf you want to send the cookie over http, set secure=False.  If you want to let client-side JavaScript\nread the cookie, set httponly=False. If you want to attach cookies to requests for external sites,\nset samesite=None."
  },
  "NodeTimingAttack": {
    "title": "node timing attack",
    "display_name": "NodeTimingAttack",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "String comparisons using '===', '!==', '!=' and '==' is vulnerable to timing attacks. More info: https://snyk.io/blog/node-js-timing-attack-ccc-ctf/"
  },
  "DetectAngularTranslateproviderUsestrategyMethod": {
    "title": "detect angular translateprovider useStrategy method",
    "display_name": "DetectAngularTranslateproviderUsestrategyMethod",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If the $translateSanitization.useStrategy is set to null or blank this can be dangerous."
  },
  "NestedAttributes": {
    "title": "nested attributes",
    "display_name": "NestedAttributes",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Checks for models that enable nested attributes. A vulnerability in nested_attributes_for results in an attacker\nbegin able to change parameters apart from the ones intended by the developer. Affected Ruby verions: 3.0.0, 2.3.9.\nFix: don't use accepts_nested_attributes_for or upgrade Ruby version."
  },
  "AssignedUndefined": {
    "title": "assigned undefined",
    "display_name": "AssignedUndefined",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "`undefined` is not a reserved keyword in Javascript, so this is \"valid\" Javascript but highly confusing and likely to result in bugs."
  },
  "GrpcServerInsecureConnection": {
    "title": "grpc server insecure connection",
    "display_name": "GrpcServerInsecureConnection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found an insecure gRPC server without 'grpc.Creds()' or options with credentials. This allows for a connection without encryption to this server. A malicious attacker could tamper with the gRPC message, which could compromise the machine. Include credentials derived from an SSL certificate in order to create a secure gRPC connection. You can create credentials using 'credentials.NewServerTLSFromFile(\"cert.pem\", \"cert.key\")'."
  },
  "HeaderInjection": {
    "title": "nginx: header injection",
    "display_name": "HeaderInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The $$VARIABLE path parameter is added as a header in the response. This could allow an attacker to inject a newline and add a new header into the response. This is called HTTP response splitting. To fix, do not allow whitespace in the path parameter: '[^\\s]+'.\n{\"include\": [\"*.conf\", \"*.vhost\", \"sites-available/*\", \"sites-enabled/*\"]}"
  },
  "HttpResponseSplitting": {
    "title": "http response splitting",
    "display_name": "HttpResponseSplitting",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Older Java application servers are vulnreable to HTTP response splitting, which may occur if an HTTP\nrequest can be injected with CRLF characters. This finding is reported for completeness; it is recommended\nto ensure your environment is not affected by testing this yourself."
  },
  "RubyJwtDecodeWithoutVerify": {
    "title": "ruby jwt decode without verify",
    "display_name": "RubyJwtDecodeWithoutVerify",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected the decoding of a JWT token without a verify step.\nJWT tokens must be verified before use, otherwise the token's\nintegrity is unknown. This means a malicious actor could forge\na JWT token with any claims."
  },
  "RubyPgSqli": {
    "title": "ruby pg sqli",
    "display_name": "RubyPgSqli",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected string concatenation with a non-literal variable in a pg\nRuby SQL statement. This could lead to SQL injection if the variable is user-controlled\nand not properly sanitized. In order to prevent SQL injection,\nused parameterized queries or prepared statements instead.\nYou can use parameterized queries like so:\n    `conn.exec_params('SELECT $1 AS a, $2 AS b, $3 AS c', [1, 2, nil])`\nAnd you can use prepared statements with `exec_prepared`."
  },
  "DetectedPgpPrivateKeyBlock": {
    "title": "secrets: detected pgp private key block",
    "display_name": "DetectedPgpPrivateKeyBlock",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "PGP private key block detected"
  },
  "StringFieldMustSetNullTrue": {
    "title": "string field must set null true",
    "display_name": "StringFieldMustSetNullTrue",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If a text field declares unique=True and blank=True, null=True must also be set to avoid unique constraint violations when saving multiple objects with blank values."
  },
  "IntegerOverflowInt16": {
    "title": "integer overflow int16",
    "display_name": "IntegerOverflowInt16",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Potential Integer overflow made by strconv.Atoi result conversion to int16"
  },
  "ReactJwtDecodedProperty": {
    "title": "react jwt decoded property",
    "display_name": "ReactJwtDecodedProperty",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Property decoded from JWT token without verifying and cannot be trustworthy."
  },
  "PhpinfoUse": {
    "title": "phpinfo use",
    "display_name": "PhpinfoUse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The 'phpinfo' function may reveal sensitive information about your environment."
  },
  "ServerDangerousClassDeserialization": {
    "title": "server dangerous class deserialization",
    "display_name": "ServerDangerousClassDeserialization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Using a non-primitive class with Java RMI may be an insecure deserialization vulnerability. Depending\non the underlying implementation. This object could be manipulated by a malicious actor allowing them to\nexecute code on your system. Instead, use an integer ID to look up your object, or consider alternative\nserializiation schemes such as JSON."
  },
  "PlaywrightGotoInjection": {
    "title": "playwright goto injection",
    "display_name": "PlaywrightGotoInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `goto` method it can result in Server-Side Request Forgery vulnerabilities"
  },
  "DetectedSshPassword": {
    "title": "secrets: detected ssh password",
    "display_name": "DetectedSshPassword",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "SSH Password detected"
  },
  "PassBodyRange": {
    "title": "pass body range",
    "display_name": "PassBodyRange",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "`pass` is the body of for $X in $Y. Consider removing this or raise NotImplementedError() if this is a TODO"
  },
  "RubyJwtHardcodedSecret": {
    "title": "ruby jwt hardcoded secret",
    "display_name": "RubyJwtHardcodedSecret",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Hardcoded JWT secret or private key is used.\nThis is a Insufficiently Protected Credentials weakness: https://cwe.mitre.org/data/definitions/522.html\nConsider using an appropriate security mechanism to protect the credentials (e.g. keeping secrets in environment variables)"
  },
  "NodeInsecureRandomGenerator": {
    "title": "node insecure random generator",
    "display_name": "NodeInsecureRandomGenerator",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator."
  },
  "JavascriptConfirm": {
    "title": "javascript confirm",
    "display_name": "JavascriptConfirm",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "found conform() call; should this be in production code?"
  },
  "DjangoCompat2_0AssertRedirectsHelper": {
    "title": "django compat 2_0 assert redirects helper",
    "display_name": "DjangoCompat2_0AssertRedirectsHelper",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The host argument to assertRedirects is removed in Django 2.0."
  },
  "ChromeRemoteInterfaceEvaluateInjection": {
    "title": "chrome remote interface evaluate injection",
    "display_name": "ChromeRemoteInterfaceEvaluateInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `evaluate` method it can result in Server-Side Request Forgery vulnerabilities"
  },
  "RequestSessionWithHttp": {
    "title": "request session with http",
    "display_name": "RequestSessionWithHttp",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a request using 'http://'. This request will be unencrypted. Use 'https://' instead."
  },
  "WkhtmltopdfSsrf": {
    "title": "wkhtmltopdf ssrf",
    "display_name": "WkhtmltopdfSsrf",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled URL reached to `wkhtmltopdf` can result in Server Side Request Forgery (SSRF)."
  },
  "InfoLeakOnNonFormatedString": {
    "title": "info leak on non formated string",
    "display_name": "InfoLeakOnNonFormatedString",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use %s, %d, %c... to format your variables, otherwise this could leak information."
  },
  "AssertUse": {
    "title": "assert use",
    "display_name": "AssertUse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Calling assert with user input is equivalent to eval'ing."
  },
  "ReactPropsSpreading": {
    "title": "react props spreading",
    "display_name": "ReactPropsSpreading",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "It is a good practice to avoid spreading for JSX attributes. This forces the code to be explicit about which props are given to the component. This avoids situations where warnings are caused by invalid HTML props passed to HTML elements, and further, it avoids passing unintentional extra props by malicious actors. Instead, consider explicitly passing props to the component."
  },
  "ElectronNodejsIntegration": {
    "title": "electron nodejs integration",
    "display_name": "ElectronNodejsIntegration",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Node integration exposes node.js APIs to the electron app and this can introduce remote code execution vulnerabilities to the application if the app is vulnerable to Cross Site Scripting (XSS)."
  },
  "SslModeNoVerify": {
    "title": "ssl mode no verify",
    "display_name": "SslModeNoVerify",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected SSL that will accept an unverified connection.\nThis makes the connections susceptible to man-in-the-middle attacks.\nUse 'OpenSSL::SSL::VERIFY_PEER' intead."
  },
  "ReflectedDataHttpresponse": {
    "title": "reflected data httpresponse",
    "display_name": "ReflectedDataHttpresponse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found request data reflected into HttpResponse. This could be vulnerable to XSS. Ensure the request data is properly escaped or sanitzed."
  },
  "UselessLiteralDict": {
    "title": "useless literal dict",
    "display_name": "UselessLiteralDict",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "key `$X` is uselessly assigned twice"
  },
  "IncorrectUseSscanfFn": {
    "title": "incorrect use sscanf fn",
    "display_name": "IncorrectUseSscanfFn",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Avoid 'sscanf()' for number conversions. Its use can lead to undefined\nbehavior, slow processing, and integer overflows. Instead prefer the\n'strto*()' family of functions."
  },
  "DetectAngularTrustAsHtmlMethod": {
    "title": "detect angular trust as html method",
    "display_name": "DetectAngularTrustAsHtmlMethod",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The use of $sce.trustAsHtml can be dangerous if unsantiized user input flows through this API."
  },
  "HtmlSafe": {
    "title": "html safe",
    "display_name": "HtmlSafe",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "`html_safe()` add the `__html__` magic method to the provided class.\nThe `__html__` method indicates to the Django template engine that the\nvalue is 'safe' for rendering. This means that normal HTML escaping will\nnot be applied to the return value. This exposes your application to\ncross-site scripting (XSS) vulnerabilities. If you need to render raw HTML,\nconsider instead using `mark_safe()` which more clearly marks the intent\nto render raw HTML than a class with a magic method."
  },
  "TempfileWithoutFlush": {
    "title": "tempfile without flush",
    "display_name": "TempfileWithoutFlush",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Using '$F.name' without '.flush()' or '.close()' may cause an error because the file may not exist when '$F.name' is used. Use '.flush()' or close the file before using '$F.name'."
  },
  "JwtNoneAlg": {
    "title": "jwt none alg",
    "display_name": "JwtNoneAlg",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected use of the 'none' algorithm in a JWT token.\nThe 'none' algorithm assumes the integrity of the token has already\nbeen verified. This would allow a malicious actor to forge a JWT token\nthat will automatically be verified. Do not explicitly use the 'none'\nalgorithm. Instead, use an algorithm such as 'HS256'."
  },
  "RequireRequest": {
    "title": "require request",
    "display_name": "RequireRequest",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server."
  },
  "InsecureRequestObjectFtp": {
    "title": "insecure request object ftp",
    "display_name": "InsecureRequestObjectFtp",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a 'urllib.request.Request()' object using an insecure transport\nprotocol, 'ftp://'. This connection will not be encrypted. Consider using\nSFTP instead. urllib does not support SFTP natively, so consider using\na library which supports SFTP."
  },
  "InsecureCreatenodesfrommarkup": {
    "title": "insecure createnodesfrommarkup",
    "display_name": "InsecureCreatenodesfrommarkup",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in a `createNodesFromMarkup` is an anti-pattern that can lead to XSS vulnerabilities"
  },
  "UselessLiteralSet": {
    "title": "useless literal set",
    "display_name": "UselessLiteralSet",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "`$X` is uselessly assigned twice inside the creation of the set"
  },
  "ParamikoExecCommand": {
    "title": "paramiko exec command",
    "display_name": "ParamikoExecCommand",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Unverified SSL context detected. This will permit insecure connections without verifying\nSSL certificates. Use 'ssl.create_default_context()' instead."
  },
  "TemplateHrefVar": {
    "title": "template href var",
    "display_name": "TemplateHrefVar",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. Use 'url_for()' to safely generate a URL. You may also consider setting the Content Security Policy (CSP) header."
  },
  "MassAssignment": {
    "title": "mass assignment",
    "display_name": "MassAssignment",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Mass assignment detected. This can result in assignment to\nmodel fields that are unintended and can be exploited by\nan attacker. Instead of using '**request.$W', assign each field you\nwant to edit individually to prevent mass assignment. You can read\nmore about mass assignment at\nhttps://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html."
  },
  "PhantomSsrf": {
    "title": "phantom ssrf",
    "display_name": "PhantomSsrf",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `phantom` methods it can result in Server-Side Request Forgery vulnerabilities."
  },
  "TarPathOverwrite": {
    "title": "tar path overwrite",
    "display_name": "TarPathOverwrite",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Insecure TAR archive extraction can result in arbitrary path over write and can result in code injection."
  },
  "MakeResponseWithUnknownContent": {
    "title": "make response with unknown content",
    "display_name": "MakeResponseWithUnknownContent",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Be careful with `flask.make_response()`. If this response is rendered onto a webpage, this could create a cross-site scripting (XSS) vulnerability. `flask.make_response()` will not autoescape HTML. If you are rendering HTML, write your HTML in a template file and use `flask.render_template()` which will take care of escaping. If you are returning data from an API, consider using `flask.jsonify()`."
  },
  "ExpressPuppeteerInjection": {
    "title": "express puppeteer injection",
    "display_name": "ExpressPuppeteerInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `puppeteer` methods it can result in Server-Side Request Forgery vulnerabilities"
  },
  "MissingUser": {
    "title": "dockerfile: missing user",
    "display_name": "MissingUser",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "By not specifying a USER, a programs in the container may run as 'root'. This is a security hazard. If an attacker can control a process running as root, they may have control over the container. Ensure that the last USER in a Dockerfile is a USER other than 'root'.\n{\"include\": [\"*Dockerfile*\", \"*dockerfile*\"]}"
  },
  "DynamicUrllibUseDetected": {
    "title": "dynamic urllib use detected",
    "display_name": "DynamicUrllibUseDetected",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a dynamic value being used with urllib. urllib supports 'file://' schemes, so a dynamic value controlled by a malicious actor may allow them to read arbitrary files. Audit uses of urllib calls to ensure user data cannot control the URLs, or consider using the 'requests' library instead."
  },
  "GrpcNodejsInsecureConnection": {
    "title": "grpc nodejs insecure connection",
    "display_name": "GrpcNodejsInsecureConnection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found an insecure gRPC connection. This creates a connection without encryption to a gRPC client/server. A malicious attacker\ncould tamper with the gRPC message, which could compromise the machine."
  },
  "MissingCsrfProtection": {
    "title": "missing csrf protection",
    "display_name": "MissingCsrfProtection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected controller which does not enable cross-site request forgery\nprotections using 'protect_from_forgery'. Add\n'protect_from_forgery :with => :exception' to your controller class."
  },
  "UnquotedAttribute": {
    "title": "unquoted attribute",
    "display_name": "UnquotedAttribute",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a unquoted template variable as an attribute. If unquoted, a\nmalicious actor could inject custom JavaScript handlers. To fix this,\nadd quotes around the template expression, like this: \"<%= expr %>\"."
  },
  "SsrfRequests": {
    "title": "ssrf requests",
    "display_name": "SsrfRequests",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Data from request object is passed to a new server-side request. This could lead to a server-side request forgery (SSRF). To mitigate, ensure that schemes and hosts are validated against an allowlist, do not forward the response to the user, and ensure proper authentication and transport-layer security in the proxied request."
  },
  "JsonEntityEscape": {
    "title": "json entity escape",
    "display_name": "JsonEntityEscape",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Checks if HTML escaping is globally disabled for JSON output. This could lead to XSS."
  },
  "NodeApiKey": {
    "title": "node api key",
    "display_name": "NodeApiKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A hardcoded API Key is identified. Store it properly in an environment variable."
  },
  "UseDefusedXml": {
    "title": "use defused xml",
    "display_name": "UseDefusedXml",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found use of the native Python XML libraries, which is vulnerable to XML external entity (XXE)\nattacks. The Python documentation recommends the 'defusedxml' library instead. Use 'defusedxml'.\nSee https://github.com/tiran/defusedxml for more information."
  },
  "ElectronContextIsolation": {
    "title": "electron context isolation",
    "display_name": "ElectronContextIsolation",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Disabling context isolation can introduce Prototype Pollution vulnerabilities."
  },
  "ModelAttributesAttrProtected": {
    "title": "model attributes attr protected",
    "display_name": "ModelAttributesAttrProtected",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Checks for models that use attr_protected, as use of allowlist instead of denylist is better practice.\nAttr_protected was also found to be vulnerable to bypass. The fixed versions of Ruby are: 3.2.12, 3.1.11, 2.3.17.\nTo prevent bypass, use attr_accessible instead."
  },
  "HostnetworkPod": {
    "title": "kubernetes: hostnetwork pod",
    "display_name": "HostnetworkPod",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Pod may use the node network namespace. This gives the pod access to the\nloopback device, services listening on localhost, and could be used to\nsnoop on network activity of other pods on the same node. Remove the\n'hostNetwork' key to disable this functionality."
  },
  "ExpressLfrWarning": {
    "title": "express lfr warning",
    "display_name": "ExpressLfrWarning",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted user input in express render() function can result in arbitrary file read if hbs templating is used."
  },
  "ListModifyWhileIterate": {
    "title": "list modify while iterate",
    "display_name": "ListModifyWhileIterate",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "It appears that `$LIST` is a list that is being modified while in a for loop.\nThis will likely cause a runtime error or an infinite loop."
  },
  "FlaskApiMethodStringFormat": {
    "title": "flask api method string format",
    "display_name": "FlaskApiMethodStringFormat",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Method $METHOD in API controller $CLASS provides user arg $ARG to requests method $REQMETHOD"
  },
  "ClassExtendsSafestring": {
    "title": "class extends safestring",
    "display_name": "ClassExtendsSafestring",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found a class extending 'SafeString', 'SafeText' or 'SafeData'. These classes are\nfor bypassing the escaping enging built in to Django and should not be\nused directly. Improper use of this class exposes your application to\ncross-site scripting (XSS) vulnerabilities. If you need this functionality,\nuse 'mark_safe' instead and ensure no user data can reach it."
  },
  "LocalhostBaseUrl": {
    "title": "hugo: localhost base url",
    "display_name": "LocalhostBaseUrl",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The 'baseURL' is set to localhost. This may cause links to not work if deployed."
  },
  "SquirrellyAutoescape": {
    "title": "squirrelly autoescape",
    "display_name": "SquirrellyAutoescape",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Handlebars SafeString will not escape the data passed through it. Untrusted user input passing through SafeString can cause XSS."
  },
  "DetectAngularOpenRedirect": {
    "title": "detect angular open redirect",
    "display_name": "DetectAngularOpenRedirect",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use of $window.location.href can lead to open-redirect if user input is used for redirection."
  },
  "NodeNosqliJsInjection": {
    "title": "node nosqli js injection",
    "display_name": "NodeNosqliJsInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted user input in MongoDB $where operator can result in NoSQL JavaScript Injection."
  },
  "DetectedHerokuApiKey": {
    "title": "secrets: detected heroku api key",
    "display_name": "DetectedHerokuApiKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Heroku API Key detected"
  },
  "DangerousExecution": {
    "title": "dangerous execution",
    "display_name": "DangerousExecution",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected non-static script inside otto VM. Audit the input to 'VM.Run'.\nIf unverified user data can reach this call site, this is a code injection\nvulnerability. A malicious actor can inject a malicious script to execute\narbitrary code."
  },
  "TemplateTranslateNoEscape": {
    "title": "template translate no escape",
    "display_name": "TemplateTranslateNoEscape",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Translated strings will not be escaped when rendered in a template.\nThis leads to a vulnerability where translators could include malicious script tags in their translations.\nConsider using `force_escape` to explicitly escape a transalted text."
  },
  "VertxSqli": {
    "title": "vertx sqli",
    "display_name": "VertxSqli",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a formatted string in a SQL statement. This could lead to SQL\ninjection if variables in the SQL statement are not properly sanitized.\nUse a prepared statements (java.sql.PreparedStatement) instead. You\ncan obtain a PreparedStatement using 'connection.prepareStatement'."
  },
  "VmSourcetextmoduleCodeInjection": {
    "title": "vm sourcetextmodule code injection",
    "display_name": "VmSourcetextmoduleCodeInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach vm.SourceTextModule."
  },
  "ArbitrarySleep": {
    "title": "arbitrary sleep",
    "display_name": "ArbitrarySleep",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "time.sleep() call; did you mean to leave this in?"
  },
  "AliasMustBeUnique": {
    "title": "dockerfile: alias must be unique",
    "display_name": "AliasMustBeUnique",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Image aliases must have a unique name, and '$REF' is used twice. Use another name for '$REF'.\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "PotentialDosViaDecompressionBomb": {
    "title": "potential dos via decompression bomb",
    "display_name": "PotentialDosViaDecompressionBomb",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a possible denial-of-service via a zip bomb attack. By limiting the max bytes read, you can mitigate this attack. `io.CopyN()` can specify a size. Refer to https://bomb.codes/ to learn more about this attack and other ways to mitigate it."
  },
  "ZipPathOverwrite2": {
    "title": "zip path overwrite2",
    "display_name": "ZipPathOverwrite2",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Insecure ZIP archive extraction can result in arbitrary path over write and can result in code injection."
  },
  "HardcodedPasswordDefaultArgument": {
    "title": "hardcoded password default argument",
    "display_name": "HardcodedPasswordDefaultArgument",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Hardcoded password is used as a default argument to '$FUNC'. This could be dangerous if\na real password is not supplied."
  },
  "ExpressSandboxCodeInjection": {
    "title": "express sandbox code injection",
    "display_name": "ExpressSandboxCodeInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach `sandbox`."
  },
  "Telnetlib": {
    "title": "telnetlib",
    "display_name": "Telnetlib",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Telnet does not encrypt communications. Use SSH instead."
  },
  "BackticksUse": {
    "title": "backticks use",
    "display_name": "BackticksUse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Backticks use may lead to command injection vulnerabilities."
  },
  "Vm2ContextInjection": {
    "title": "vm2 context injection",
    "display_name": "Vm2ContextInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted user input reaching `vm2` sandbox can result in context injection."
  },
  "WeakSslContext": {
    "title": "weak ssl context",
    "display_name": "WeakSslContext",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "An insecure SSL context was detected. TLS versions 1.0, 1.1, and all SSL versions\nare considered weak encryption and are deprecated.\nUse SSLContext.getInstance(\"TLSv1.2\") for the best security."
  },
  "DangerousSpawnShell": {
    "title": "dangerous spawn shell",
    "display_name": "DangerousSpawnShell",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected non-literal calls to $EXEC(). This could lead to a command\ninjection vulnerability."
  },
  "WeakHashesSha1": {
    "title": "weak hashes sha1",
    "display_name": "WeakHashesSha1",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Should not use SHA1 to generate hashes. There is a proven SHA1 hash collision by Google, which could lead to vulnerabilities.\nUse SHA256, SHA3 or other hashing functions instead."
  },
  "ExpatXxe": {
    "title": "expat xxe",
    "display_name": "ExpatXxe",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the XML Parser it can result in XML External or\nInternal Entity (XXE) Processing vulnerabilities"
  },
  "AvoidHtmlSafe": {
    "title": "avoid html safe",
    "display_name": "AvoidHtmlSafe",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "'html_safe()' does not make the supplied string safe. 'html_safe()' bypasses\nHTML escaping. If external data can reach here, this exposes your application\nto cross-site scripting (XSS) attacks. Ensure no external data reaches here."
  },
  "SpawnShellTrue": {
    "title": "spawn shell true",
    "display_name": "SpawnShellTrue",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found '$SPAWN' with '{shell: $SHELL}'. This is dangerous because this call will spawn\nthe command using a shell process. Doing so propagates current shell settings and variables, which\nmakes it much easier for a malicious actor to execute commands. Use '{shell: false}' instead."
  },
  "SqlInjectionUsingRawsql": {
    "title": "sql injection using rawsql",
    "display_name": "SqlInjectionUsingRawsql",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Data from request is passed to RawSQL(). This is a SQL injection and could be exploited. See https://docs.djangoproject.com/en/3.0/ref/models/expressions/#django.db.models.expressions.RawSQL to learn how to mitigate. See https://cwe.mitre.org/data/definitions/89.html to learn about SQLi."
  },
  "MissingNoreferrer": {
    "title": "missing noreferrer",
    "display_name": "MissingNoreferrer",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This anchor tag with 'target=\"_blank\"' is missing 'noreferrer'. A page opened with 'target=\"_blank\"' can access the window object of the origin page. This means it can manipulate the 'window.opener' property, which could redirect the origin page to a malicious URL. This is called reverse tabnabbing. To prevent this, include 'rel=noreferrer' on this tag."
  },
  "InsecureInnerhtml": {
    "title": "insecure innerhtml",
    "display_name": "InsecureInnerhtml",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in a `$EL.innerHTML` is an anti-pattern that can lead to XSS vulnerabilities"
  },
  "AutoescapeDisabled": {
    "title": "autoescape disabled",
    "display_name": "AutoescapeDisabled",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected an element with disabled HTML escaping. If external\ndata can reach this, this is a cross-site scripting (XSS)\nvulnerability. Ensure no external data can reach here, or\nremove 'escape=false' from this element."
  },
  "TurbineSqli": {
    "title": "turbine sqli",
    "display_name": "TurbineSqli",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a formatted string in a SQL statement. This could lead to SQL\ninjection if variables in the SQL statement are not properly sanitized.\nUse a prepared statements (java.sql.PreparedStatement) instead. You\ncan obtain a PreparedStatement using 'connection.prepareStatement'."
  },
  "UncaughtExecutorExceptions": {
    "title": "uncaught executor exceptions",
    "display_name": "UncaughtExecutorExceptions",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Values returned by thread pool map must be read in order to raise exceptions. Consider using `for _ in $EXECUTOR.map(...): pass`."
  },
  "UselessAssignment": {
    "title": "useless assignment",
    "display_name": "UselessAssignment",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "`$X` is assigned twice; the first assignment is useless"
  },
  "HardcodedJwtKey": {
    "title": "hardcoded jwt key",
    "display_name": "HardcodedJwtKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "JWT token is hardcoded"
  },
  "FlaskDuplicateHandlerName": {
    "title": "flask duplicate handler name",
    "display_name": "FlaskDuplicateHandlerName",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Looks like `$R` is a flask function handler that registered to two different routes. This will cause a runtime error"
  },
  "DetectedSonarqubeDocsApiKey": {
    "title": "secrets: detected sonarqube docs api key",
    "display_name": "DetectedSonarqubeDocsApiKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "SonarQube Docs API Key detected"
  },
  "UserEvalFormatString": {
    "title": "user eval format string",
    "display_name": "UserEvalFormatString",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found user data in a call to 'eval'. This is extremely dangerous because\nit can enable an attacker to execute remote code. See\nhttps://owasp.org/www-community/attacks/Code_Injection for more information."
  },
  "RemovePackageCache": {
    "title": "dockerfile: remove package cache",
    "display_name": "RemovePackageCache",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The package cache was not deleted after running 'apt-get update', which increases the size of the image. Remove the package cache by appending '&& apt-get clean' at the end of apt-get command chain.\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "VmCompilefunctionContextInjection": {
    "title": "vm compilefunction context injection",
    "display_name": "VmCompilefunctionContextInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach vm.compileFunction."
  },
  "AvoidContentTag": {
    "title": "avoid content tag",
    "display_name": "AvoidContentTag",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "'content_tag()' bypasses HTML escaping for some portion of the content.\nIf external data can reach here, this exposes your application\nto cross-site scripting (XSS) attacks. Ensure no external data reaches here.\nIf you must do this, create your HTML manually and use 'html_safe'. Ensure no\nexternal data enters the HTML-safe string!"
  },
  "Avoid_hardcoded_config_debug": {
    "title": "avoid_hardcoded_config_DEBUG",
    "display_name": "Avoid_hardcoded_config_debug",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Hardcoded variable `DEBUG` detected. Set this by using FLASK_DEBUG environment variable"
  },
  "DirectUseOfHttpresponse": {
    "title": "direct use of httpresponse",
    "display_name": "DirectUseOfHttpresponse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected data rendered directly to the end user via 'HttpResponse'\nor a similar object. This bypasses Django's built-in cross-site scripting\n(XSS) defenses and could result in an XSS vulnerability. Use Django's\ntemplate engine to safely render HTML."
  },
  "DetectedSauceToken": {
    "title": "secrets: detected sauce token",
    "display_name": "DetectedSauceToken",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Sauce Token detected"
  },
  "ExpressCookieSessionNoDomain": {
    "title": "express cookie session no domain",
    "display_name": "ExpressCookieSessionNoDomain",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Default session middleware settings: `domain` not set.\nIt indicates the domain of the cookie; use it to compare against the domain of the server in which the URL is being requested.\nIf they match, then check the path attribute next."
  },
  "DetectedSquareAccessToken": {
    "title": "secrets: detected square access token",
    "display_name": "DetectedSquareAccessToken",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Square Access Token detected"
  },
  "UnvalidatedPassword": {
    "title": "unvalidated password",
    "display_name": "UnvalidatedPassword",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The password on '$MODEL' is being set without validating the password.\nCall django.contrib.auth.password_validation.validate_password() with\nvalidation functions before setting the password. See\nhttps://docs.djangoproject.com/en/3.0/topics/auth/passwords/\nfor more information."
  },
  "InsecureHashAlgorithmMd4": {
    "title": "insecure hash algorithm md4",
    "display_name": "InsecureHashAlgorithmMd4",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected MD4 hash algorithm which is considered insecure. This algorithm\nhas many known vulnerabilities and has been deprecated. Use SHA256 or SHA3 instead."
  },
  "DangerousOpen3Pipeline": {
    "title": "dangerous open3 pipeline",
    "display_name": "DangerousOpen3Pipeline",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected non-static command inside $PIPE. Audit the input to '$PIPE'.\nIf unverified user data can reach this call site, this is a code injection\nvulnerability. A malicious actor can inject a malicious script to execute\narbitrary code."
  },
  "InsecureHashAlgorithmMd2": {
    "title": "insecure hash algorithm md2",
    "display_name": "InsecureHashAlgorithmMd2",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected MD2 hash algorithm which is considered insecure. This algorithm\nhas many known vulnerabilities and has been deprecated. Use SHA256 or SHA3 instead."
  },
  "VmRuninnewcontextCodeInjection": {
    "title": "vm runinnewcontext code injection",
    "display_name": "VmRuninnewcontextCodeInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach vm.runInNewContext."
  },
  "GrpcClientInsecureConnection": {
    "title": "grpc client insecure connection",
    "display_name": "GrpcClientInsecureConnection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found an insecure gRPC connection using 'grpc.WithInsecure()'. This creates a connection without encryption to a gRPC server. A malicious attacker could tamper with the gRPC message, which could compromise the machine. Instead, establish a secure connection with an SSL certificate using the 'grpc.WithTransportCredentials()' function. You can create a create credentials using a 'tls.Config{}' struct with 'credentials.NewTLS()'. The final fix looks like this: 'grpc.WithTransportCredentials(credentials.NewTLS(<config>))'."
  },
  "CommandInjectionFormattedRuntimeCall": {
    "title": "command injection formatted runtime call",
    "display_name": "CommandInjectionFormattedRuntimeCall",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A formatted or concatenated string was detected as input to a java.lang.Runtime call.\nThis is dangerous if a variable is controlled by user input and could result in a\ncommand injection. Ensure your variables are not controlled by users or sufficiently sanitized."
  },
  "ExecInjection": {
    "title": "exec injection",
    "display_name": "ExecInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected user data flowing into exec. This is code injection and should be avoided."
  },
  "HostHeaderInjection": {
    "title": "host header injection",
    "display_name": "HostHeaderInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Using untrusted Host header for generating dynamic URLs can result in web cache and or password reset poisoning."
  },
  "NoDirectResponseWriter": {
    "title": "no direct response writer",
    "display_name": "NoDirectResponseWriter",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a direct write to the HTTP response. This bypasses any\nview or template environments, including HTML escaping, which may\nexpose this application to cross-site scripting (XSS) vulnerabilities.\nConsider using a view technology such as JavaServer Faces (JSFs) which\nautomatically escapes HTML views."
  },
  "UseOfWeakRsaKey": {
    "title": "use of weak rsa key",
    "display_name": "UseOfWeakRsaKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "RSA keys should be at least 2048 bits"
  },
  "UnsafeTemplateType": {
    "title": "unsafe template type",
    "display_name": "UnsafeTemplateType",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Semgrep could not determine that the argument to 'template.HTML()'\nis a constant. 'template.HTML()' and similar does not escape contents.\nBe absolutely sure there is no user-controlled data in this\ntemplate. If user data can reach this template, you may have\na XSS vulnerability. Instead, do not use this function and\nuse 'template.Execute()'."
  },
  "JrubyXml": {
    "title": "jruby xml",
    "display_name": "JrubyXml",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The JDOM backend for XmlMini has a vulnerability that lets an attacker perform a denial of service attack\nor gain access to files on the application server. This affects versions 3.0, but is fixed in versions\n3.1.12 and 3.2.13. To fix, either upgrade or use XmlMini.backend=\"REXML\"."
  },
  "RequestDataWrite": {
    "title": "request data write",
    "display_name": "RequestDataWrite",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found request data in '.write(...)'. This could be dangerous if a malicious\nactor is able to control data into sensitive files. For example, a malicious\nactor could force rolling of critical log files, or cause a denial-of-service\nby using up available disk space. Ensure content is validated."
  },
  "DetectedPaypalBraintreeAccessToken": {
    "title": "secrets: detected paypal braintree access token",
    "display_name": "DetectedPaypalBraintreeAccessToken",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "PayPal Braintree Access Token detected"
  },
  "LdapEntryPoisoning": {
    "title": "ldap entry poisoning",
    "display_name": "LdapEntryPoisoning",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "An object-returning LDAP search will allow attackers to control the LDAP response. This could\nlead to Remote Code Execution."
  },
  "RegexInjectionDos": {
    "title": "regex injection dos",
    "display_name": "RegexInjectionDos",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in RegExp() can make the application vulnerable to layer 7 DoS."
  },
  "ExpressCookieSessionNoPath": {
    "title": "express cookie session no path",
    "display_name": "ExpressCookieSessionNoPath",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Default session middleware settings: `path` not set.\nIt indicates the path of the cookie; use it to compare against the request path. If this and domain match, then send the cookie in the request."
  },
  "VmCompilefunctionCodeInjection": {
    "title": "vm compilefunction code injection",
    "display_name": "VmCompilefunctionCodeInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach vm.compileFunction."
  },
  "AvoidZypperUpdate": {
    "title": "dockerfile: avoid zypper update",
    "display_name": "AvoidZypperUpdate",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Packages in base images should be up-to-date, removing the need for\n'zypper update'. If packages are out-of-date, consider contacting the\nbase image maintainer.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "HelmetHeaderReferrerPolicy": {
    "title": "helmet header referrer policy",
    "display_name": "HelmetHeaderReferrerPolicy",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Referrer-Policy header is present. More information: https://helmetjs.github.io/docs/referrer-policy/"
  },
  "ReactNoRefs": {
    "title": "react no refs",
    "display_name": "ReactNoRefs",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "`ref` usage found, refs give direct DOM access and may create a possibility for XSS"
  },
  "LastUserIsRoot": {
    "title": "dockerfile: last user is root",
    "display_name": "LastUserIsRoot",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The last user in the container is 'root'. This is a security hazard because if an attacker gains control of the container they will have root access. Switch back to another user after running commands as 'root'.\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "HostpidPod": {
    "title": "kubernetes: hostpid pod",
    "display_name": "HostpidPod",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Pod is sharing the host process ID namespace. When paired with ptrace\nthis can be used to escalate privileges outside of the container. Remove\nthe 'hostPID' key to disable this functionality."
  },
  "HeaderXssGeneric": {
    "title": "header xss generic",
    "display_name": "HeaderXssGeneric",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "X-XSS-Protection header is set to 0. This will disable the browser's XSS Filter."
  },
  "TofastpropertiesCodeExecution": {
    "title": "tofastproperties code execution",
    "display_name": "TofastpropertiesCodeExecution",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Potential arbitrary code execution, whatever is provided to `toFastProperties` is sent straight to eval()"
  },
  "DetectedTwilioApiKey": {
    "title": "secrets: detected twilio api key",
    "display_name": "DetectedTwilioApiKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Twilio API Key detected"
  },
  "HardcodedPassportSecret": {
    "title": "hardcoded passport secret",
    "display_name": "HardcodedPassportSecret",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Hardcoded plain text secret used for Passport Strategy. Store it properly in an environment variable."
  },
  "SqlInjectionUsingRaw": {
    "title": "sql injection using raw",
    "display_name": "SqlInjectionUsingRaw",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Data from request is passed to raw(). This is a SQL injection and could be exploited. See https://docs.djangoproject.com/en/3.0/topics/security/#sql-injection-protection to learn how to mitigate. See https://cwe.mitre.org/data/definitions/89.html to learn about SQLi."
  },
  "MongoClientBadAuth": {
    "title": "mongo client bad auth",
    "display_name": "MongoClientBadAuth",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Warning MONGODB-CR was deprecated with the release of MongoDB 3.6 and is no longer supported by MongoDB 4.0 (see https://api.mongodb.com/python/current/examples/authentication.html for details)."
  },
  "GrpcInsecureConnection": {
    "title": "grpc insecure connection",
    "display_name": "GrpcInsecureConnection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found an insecure gRPC connection. This creates a connection without encryption to a gRPC client/server. A malicious attacker could  tamper with the gRPC message, which could compromise the machine."
  },
  "TlsWithInsecureCipher": {
    "title": "tls with insecure cipher",
    "display_name": "TlsWithInsecureCipher",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected an insecure CipherSuite via the 'tls' module. This suite is considered weak.\nUse the function 'tls.CipherSuites()' to get a list of good cipher suites.\nSee https://golang.org/pkg/crypto/tls/#InsecureCipherSuites\nfor why and what other cipher suites to use."
  },
  "DetectedFacebookAccessToken": {
    "title": "secrets: detected facebook access token",
    "display_name": "DetectedFacebookAccessToken",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Facebook Access Token detected"
  },
  "JwtGoParseUnverified": {
    "title": "jwt go parse unverified",
    "display_name": "JwtGoParseUnverified",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected the decoding of a JWT token without a verify step.\nDon't use `ParseUnverified` unless you know what you're doing\nThis method parses the token but doesn't validate the signature. It's only ever useful in cases where you know the signature is valid (because it has been checked previously in the stack) and you want to extract values from it."
  },
  "PhantomInjection": {
    "title": "phantom injection",
    "display_name": "PhantomInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `phantom` page methods it can result in Server-Side Request Forgery vulnerabilities"
  },
  "FlaskCacheQueryString": {
    "title": "flask cache query string",
    "display_name": "FlaskCacheQueryString",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Flask-caching doesn't cache query strings by default. You have to use `query_string=True`. Also you shouldn't cache verbs that can mutate state."
  },
  "GlobalsMisuseCodeExecution": {
    "title": "globals misuse code execution",
    "display_name": "GlobalsMisuseCodeExecution",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found request data as an index to 'globals()'. This is extremely\ndangerous because it allows an attacker to execute arbitrary code\non the system. Refactor your code not to use 'globals()'."
  },
  "DjangoCompat2_0SignalsWeak": {
    "title": "django compat 2_0 signals weak",
    "display_name": "DjangoCompat2_0SignalsWeak",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The weak argument to django.dispatch.signals.Signal.disconnect() is removed in Django 2.0."
  },
  "JwtPythonNoneAlg": {
    "title": "jwt python none alg",
    "display_name": "JwtPythonNoneAlg",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected use of the 'none' algorithm in a JWT token.\nThe 'none' algorithm assumes the integrity of the token has already\nbeen verified. This would allow a malicious actor to forge a JWT token\nthat will automatically be verified. Do not explicitly use the 'none'\nalgorithm. Instead, use an algorithm such as 'HS256'."
  },
  "CookieSerialization": {
    "title": "cookie serialization",
    "display_name": "CookieSerialization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Checks if code allows cookies to be deserialized using Marshal. If the attacker can craft a valid cookie, this could lead to\nremote code execution. The hybrid check is just to warn users to migrate to :json for best practice."
  },
  "AllowPrivilegeEscalation": {
    "title": "kubernetes: allow privilege escalation",
    "display_name": "AllowPrivilegeEscalation",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Container allows for privilege escalation via setuid or setgid binaries.\nAdd 'allowPrivilegeEscalation: false' in 'securityContext' to prevent this."
  },
  "RandomFdExhaustion": {
    "title": "random fd exhaustion",
    "display_name": "RandomFdExhaustion",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Call to 'read()' without error checking is susceptible to file descriptor\nexhaustion. Consider using the 'getrandom()' function."
  },
  "DetectNonLiteralRequire": {
    "title": "detect non literal require",
    "display_name": "DetectNonLiteralRequire",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected the use of require(variable). Calling require with a non-literal argument might\nallow an attacker to load an run arbitrary code, or access arbitrary files."
  },
  "ExpressCors": {
    "title": "express cors",
    "display_name": "ExpressCors",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Access-Control-Allow-Origin response header is set to \"*\". This will disable CORS Same Origin Policy restrictions."
  },
  "MissingYumCleanAll": {
    "title": "dockerfile: missing yum clean all",
    "display_name": "MissingYumCleanAll",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This yum command does not end with '&& yum clean all'. Running 'yum clean all' will remove cached data and reduce package size. (This must be performed in the same RUN step.)\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "ReturnInInit": {
    "title": "return in init",
    "display_name": "ReturnInInit",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "`return` should never appear inside a class __init__ function. This will cause a runtime error."
  },
  "NodeXpathInjection": {
    "title": "node xpath injection",
    "display_name": "NodeXpathInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in xpath.parse() can result in XPATH injection vulnerability."
  },
  "DetectedAmazonMwsAuthToken": {
    "title": "secrets: detected amazon mws auth token",
    "display_name": "DetectedAmazonMwsAuthToken",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Amazon MWS Auth Token detected"
  },
  "AvoidShelve": {
    "title": "avoid shelve",
    "display_name": "AvoidShelve",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Avoid using `shelve`, which uses `pickle`, which is known to lead to code execution vulnerabilities.\nWhen unpickling, the serialized data could be manipulated to run arbitrary code.\nInstead, consider serializing the relevant data as JSON or a similar text-based\nserialization format."
  },
  "ForceSslFalse": {
    "title": "force ssl false",
    "display_name": "ForceSslFalse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Checks for configuration setting of force_ssl to false. Force_ssl forces usage of HTTPS, which\ncould lead to network interception of unencrypted application traffic. To fix, set config.force_ssl = true."
  },
  "UnverifiedJwtDecode": {
    "title": "unverified jwt decode",
    "display_name": "UnverifiedJwtDecode",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected JWT token decoded with 'verify=False'. This bypasses any integrity\nchecks for the token which means the token could be tampered with by\nmalicious actors. Ensure that the JWT token is verified."
  },
  "ScriptEngineInjection": {
    "title": "script engine injection",
    "display_name": "ScriptEngineInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected potential code injection using ScriptEngine. Ensure\nuser-controlled data cannot enter '.eval()', otherwise, this is\na code injection vulnerability."
  },
  "ProhibitJqueryHtml": {
    "title": "prohibit jquery html",
    "display_name": "ProhibitJqueryHtml",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "JQuery's html function can lead to XSS. If the string is plain test, use the text function instead.\nOtherwise, use a function that escapes html such as edx's HtmlUtils.setHtml."
  },
  "DebugTemplateTag": {
    "title": "debug template tag",
    "display_name": "DebugTemplateTag",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a debug template tag in a Django template. This dumps\ndebugging information to the page when debug mode is enabled.\nShowing debug information to users is dangerous because it may\nreveal information about your environment that malicious actors\ncan use to gain access to the system. Remove the debug tag."
  },
  "AngularBypasssecuritytrust": {
    "title": "angular bypasssecuritytrust",
    "display_name": "AngularBypasssecuritytrust",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Bypassing the built-in sanitization could expose the application to cross-site scripting (XSS)."
  },
  "HandlerAttributeReadFromMultipleSourcesDict": {
    "title": "handler attribute read from multiple sources dict",
    "display_name": "HandlerAttributeReadFromMultipleSourcesDict",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Attribute $ATT is read from two different sources: '$X[$KEY]' and '$Y.$ATT'. Make sure this is intended, as this could cause logic bugs if they are treated as if they are the same object."
  },
  "JavascriptDebugger": {
    "title": "javascript debugger",
    "display_name": "JavascriptDebugger",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "found debugger call; should this be in production code?"
  },
  "InsecureCipherAlgorithmDes": {
    "title": "insecure cipher algorithm des",
    "display_name": "InsecureCipherAlgorithmDes",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected DES cipher algorithm which is considered insecure. The algorithm is\nconsidered weak and has been deprecated. Use AES instead."
  },
  "NodeSecret": {
    "title": "node secret",
    "display_name": "NodeSecret",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A hardcoded secret is identified. Store it properly in an environment variable."
  },
  "ReactJwtInLocalstorage": {
    "title": "react jwt in localstorage",
    "display_name": "ReactJwtInLocalstorage",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Storing JWT tokens in localStorage known to be a bad practice, consider moving your tokens from localStorage to a HTTP cookie."
  },
  "InsecureFilePermissions": {
    "title": "insecure file permissions",
    "display_name": "InsecureFilePermissions",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Insecure file permissions detected."
  },
  "ReactPropsInState": {
    "title": "react props in state",
    "display_name": "ReactPropsInState",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "It is a bad practice to stop the data flow in rendering by copying props into state."
  },
  "Log4jMessageInjection": {
    "title": "Possible injection into Log4j messages",
    "display_name": "Log4jMessageInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "\u68c0\u67e5log4j\u7c7b\u7684error(\u2026), warn(\u2026), info(\u2026), debug(\u2026), fatal(\u2026), trace(\u2026), log(level, \u2026)\u7b49api\u8c03\u7528\u65b9\u6cd5"
  },
  "DebugEnabled": {
    "title": "debug enabled",
    "display_name": "DebugEnabled",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected Flask app with debug=True. Do not deploy to production with this flag enabled\nas it will leak sensitive information. Instead, consider using Flask configuration\nvariables or setting 'debug' using system environment variables."
  },
  "VmRunincontextContextInjection": {
    "title": "vm runincontext context injection",
    "display_name": "VmRunincontextContextInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach vm.runInContext."
  },
  "DynamicProxyHost": {
    "title": "nginx: dynamic proxy host",
    "display_name": "DynamicProxyHost",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The host for this proxy URL is dynamically determined. This can be dangerous if the host can be injected by an attacker because it may forcibly alter destination of the proxy. Consider hardcoding acceptable destinations and retrieving them with 'map' or something similar.\n{\"include\": [\"*.conf\", \"*.vhost\", \"sites-available/*\", \"sites-enabled/*\"]}"
  },
  "JwtGoNoneAlgorithm": {
    "title": "jwt go none algorithm",
    "display_name": "JwtGoNoneAlgorithm",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected use of the 'none' algorithm in a JWT token.\nThe 'none' algorithm assumes the integrity of the token has already\nbeen verified. This would allow a malicious actor to forge a JWT token\nthat will automatically be verified. Do not explicitly use the 'none'\nalgorithm. Instead, use an algorithm such as 'HS256'."
  },
  "AvoidBindToAllInterfaces": {
    "title": "avoid bind to all interfaces",
    "display_name": "AvoidBindToAllInterfaces",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Listening on 0.0.0.0 or empty string could unexpectedly expose the server publicly as it binds to all available interfaces"
  },
  "MissingNoopener": {
    "title": "missing noopener",
    "display_name": "MissingNoopener",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This anchor tag with 'target=\"_blank\"' is missing 'noopener'. A page opened with 'target=\"_blank\"' can access the window object of the origin page. This means it can manipulate the 'window.opener' property, which could redirect the origin page to a malicious URL. This is called reverse tabnabbing. To prevent this, include 'rel=noopener' on this tag"
  },
  "DetectedArtifactoryPassword": {
    "title": "secrets: detected artifactory password",
    "display_name": "DetectedArtifactoryPassword",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Artifactory token detected"
  },
  "DangerousSubprocessUse": {
    "title": "dangerous subprocess use",
    "display_name": "DangerousSubprocessUse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected subprocess function '$FUNC' without a static string. If this data can be\ncontrolled by a malicious actor, it may be an instance of command injection.\nAudit the use of this call to ensure it is not controllable by an external resource.\nYou may consider using 'shlex.escape()'."
  },
  "DesedeIsDeprecated": {
    "title": "desede is deprecated",
    "display_name": "DesedeIsDeprecated",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Triple DES (3DES or DESede) is considered deprecated. AES is the recommended cipher.\nUpgrade to use AES.\nSee https://csrc.nist.gov/News/2017/Update-to-Current-Use-and-Deprecation-of-TDEA for more information."
  },
  "UseOnetoonefield": {
    "title": "use onetoonefield",
    "display_name": "UseOnetoonefield",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use 'django.db.models.OneToOneField' instead of 'ForeignKey' with unique=True.\n'OneToOneField' is used to create one-to-one relationships."
  },
  "CurlSslVerifypeerOff": {
    "title": "curl ssl verifypeer off",
    "display_name": "CurlSslVerifypeerOff",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "SSL verification is disabled but should not be (currently CURLOPT_SSL_VERIFYPEER= $IS_VERIFIED)"
  },
  "UseRaiseForStatus": {
    "title": "use raise for status",
    "display_name": "UseRaiseForStatus",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "There's an HTTP request made with requests,\nbut the raise_for_status() utility method isn't used.\nThis can result in request errors going unnoticed\nand your code behaving in unexpected ways,\nsuch as if your authorization API returns a 500 error\nwhile you're only checking for a 401."
  },
  "InsecureOpenerdirectorOpen": {
    "title": "insecure openerdirector open",
    "display_name": "InsecureOpenerdirectorOpen",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected an unsecured transmission channel. 'OpenerDirector.open(...)' is\nbeing used with 'http://'. Use 'https://' instead to secure the channel."
  },
  "UnquotedAttributeVar": {
    "title": "html-templates: unquoted attribute var",
    "display_name": "UnquotedAttributeVar",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: \"{{ expr }}\".\n{\"include\": [\"*.html\", \"*.mustache\", \"*.hbs\"]}"
  },
  "InsecureDeserialization": {
    "title": "insecure deserialization",
    "display_name": "InsecureDeserialization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected the use of an insecure deserizliation library in a Flask route. These libraries\nare prone to code execution vulnerabilities. Ensure user data does not enter this function.\nTo fix this, try to avoid serializing whole objects. Consider instead using a serializer\nsuch as JSON."
  },
  "NodeTlsReject": {
    "title": "node tls reject",
    "display_name": "NodeTlsReject",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Setting 'NODE_TLS_REJECT_UNAUTHORIZED' to 0 will allow node server to accept self signed certificates and is not a secure behaviour."
  },
  "GenericErrorDisclosure": {
    "title": "generic error disclosure",
    "display_name": "GenericErrorDisclosure",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Error messages with stack traces may expose sensitive information about the application."
  },
  "ExpressWkhtmltoimageInjection": {
    "title": "express wkhtmltoimage injection",
    "display_name": "ExpressWkhtmltoimageInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `phantom` methods it can result in Server-Side Request Forgery vulnerabilities"
  },
  "JwtDecodeWithoutVerify": {
    "title": "jwt decode without verify",
    "display_name": "JwtDecodeWithoutVerify",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected the decoding of a JWT token without a verify step.\nJWT tokens must be verified before use, otherwise the token's\nintegrity is unknown. This means a malicious actor could forge\na JWT token with any claims. Call '.verify()' before using the token."
  },
  "EvalNodejs": {
    "title": "eval nodejs",
    "display_name": "EvalNodejs",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in eval() or similar functions may result in Server Side Injection or Remote Code Injection"
  },
  "ElInjection": {
    "title": "el injection",
    "display_name": "ElInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "An expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation."
  },
  "FlaskDeprecatedApis": {
    "title": "flask deprecated apis",
    "display_name": "FlaskDeprecatedApis",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "deprecated Flask API"
  },
  "AvoidLatestVersion": {
    "title": "dockerfile: avoid latest version",
    "display_name": "AvoidLatestVersion",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Images should be tagged with an explicit version to produce\ndeterministic container images. The 'latest' tag may change\nthe base container without warning.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "UnencryptedSocket": {
    "title": "unencrypted socket",
    "display_name": "UnencryptedSocket",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This socket is not encrypted.\nThe traffic could be read by an attacker intercepting the network traffic.\nUse an SSLSocket created by 'SSLSocketFactory' or 'SSLServerSocketFactory'\ninstead"
  },
  "ReactHrefVar": {
    "title": "react href var",
    "display_name": "ReactHrefVar",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a variable used in an anchor tag with the 'href' attribute. A malicious actor may be able to input the 'javascript:' URI, which could cause cross-site scripting (XSS). If you are generating a URL to a known host, hardcode the base link (or retrieve it from a configuration) and append the path. You may also consider funneling link generation through a safe method which sanitizes URLs for the 'javascript:' URI."
  },
  "InsecureUrlopenFtp": {
    "title": "insecure urlopen ftp",
    "display_name": "InsecureUrlopenFtp",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected 'urllib.urlopen()' using 'ftp://'. This request will not be\nencrypted. Consider using SFTP instead. urllib does not support SFTP,\nso consider switching to a library which supports SFTP."
  },
  "AvoidRenderInline": {
    "title": "avoid render inline",
    "display_name": "AvoidRenderInline",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "'render inline: ...' renders an entire ERB template inline and is dangerous.\nIf external data can reach here, this exposes your application\nto server-side template injection (SSTI) or cross-site scripting (XSS) attacks.\nInstead, consider using a partial or another safe rendering method."
  },
  "NoStaticInitializationVector": {
    "title": "no static initialization vector",
    "display_name": "NoStaticInitializationVector",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Initialization Vectors (IVs) for block ciphers should be randomly generated\neach time they are used. Using a static IV means the same plaintext\nencrypts to the same ciphertext every time, weakening the strength\nof the encryption."
  },
  "TemplateUnquotedAttributeVar": {
    "title": "template unquoted attribute var",
    "display_name": "TemplateUnquotedAttributeVar",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: \"{{ expr }}\"."
  },
  "CookieSessionNoSecure": {
    "title": "cookie session no secure",
    "display_name": "CookieSessionNoSecure",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Default session middleware settings: `secure` not set. It ensures the browser only sends the cookie over HTTPS."
  },
  "HelmetHeaderIenoopen": {
    "title": "helmet header ienoopen",
    "display_name": "HelmetHeaderIenoopen",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "X-Download-Options header is present. More information: https://helmetjs.github.io/docs/ienoopen/"
  },
  "AdmzipPathOverwrite": {
    "title": "admzip path overwrite",
    "display_name": "AdmzipPathOverwrite",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Insecure ZIP archive extraction using adm-zip can result in arbitrary path over write and can result in code injection."
  },
  "InsecureRequestObject": {
    "title": "insecure request object",
    "display_name": "InsecureRequestObject",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a 'urllib.request.Request()' object using an insecure transport\nprotocol, 'http://'. This connection will not be encrypted. Use\n'https://' instead."
  },
  "SsrfInjectionUrllib": {
    "title": "ssrf injection urllib",
    "display_name": "SsrfInjectionUrllib",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Data from request object is passed to a new server-side request.\nThis could lead to a server-side request forgery (SSRF). To mitigate,\nensure that schemes and hosts are validated against an allowlist,\ndo not forward the response to the user, and ensure proper authentication\nand transport-layer security in the proxied request.\nSee https://owasp.org/www-community/attacks/Server_Side_Request_Forgery\nto learn more about SSRF vulnerabilities."
  },
  "NewFunctionDetected": {
    "title": "new function detected",
    "display_name": "NewFunctionDetected",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected the use of new Function(), which can be dangerous if used to evaluate\ndynamic content. If this content can be input from outside the program, this\nmay be a code injection vulnerability. Ensure evaluated content is not definable\nby external sources."
  },
  "GenericPathTraversal": {
    "title": "generic path traversal",
    "display_name": "GenericPathTraversal",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted user input in readFile()/readFileSync() can endup in Directory Traversal Attacks."
  },
  "AsyncpgSqli": {
    "title": "asyncpg sqli",
    "display_name": "AsyncpgSqli",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected string concatenation with a non-literal variable in a asyncpg\nPython SQL statement. This could lead to SQL injection if the variable is user-controlled\nand not properly sanitized. In order to prevent SQL injection,\nused parameterized queries or prepared statements instead.\nYou can create parameterized queries like so:\n'conn.fetch(\"SELECT $1 FROM table\", value)'.\nYou can also create prepared statements with 'Connection.prepare':\n'stmt = conn.prepare(\"SELECT $1 FROM table\")\n await stmt.fetch(user_value)'"
  },
  "AvoidRaw": {
    "title": "avoid raw",
    "display_name": "AvoidRaw",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "'raw()' bypasses HTML escaping. If external data can reach here, this exposes your application\nto cross-site scripting (XSS) attacks. If you must do this, construct individual strings\nand mark them as safe for HTML rendering with `html_safe()`."
  },
  "JdbcSqli": {
    "title": "jdbc sqli",
    "display_name": "JdbcSqli",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a formatted string in a SQL statement. This could lead to SQL\ninjection if variables in the SQL statement are not properly sanitized.\nUse a prepared statements (java.sql.PreparedStatement) instead. You\ncan obtain a PreparedStatement using 'connection.prepareStatement'."
  },
  "Python37CompatabilityOsModule": {
    "title": "python37 compatability os module",
    "display_name": "Python37CompatabilityOsModule",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "this function is only available on Python 3.7+"
  },
  "CbcPaddingOracle": {
    "title": "cbc padding oracle",
    "display_name": "CbcPaddingOracle",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Using CBC with PKCS5Padding is susceptible to padding orcale attacks. A malicious actor\ncould discern the difference between plaintext with valid or invalid padding. Further,\nCBC mode does not include any integrity checks. See https://find-sec-bugs.github.io/bugs.htm#CIPHER_INTEGRITY.\nUse 'AES/GCM/NoPadding' instead."
  },
  "HeaderRedefinition": {
    "title": "nginx: header redefinition",
    "display_name": "HeaderRedefinition",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The 'add_header' directive is called in a 'location' block after headers have been set at the server block. Calling 'add_header' in the location block will actually overwrite the headers defined in the server block, no matter which headers are set. To fix this, explicitly set all headers or set all headers in the server block.\n{\"include\": [\"*.conf\", \"*.vhost\", \"sites-available/*\", \"sites-enabled/*\"]}"
  },
  "BadHexaConversion": {
    "title": "bad hexa conversion",
    "display_name": "BadHexaConversion",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "'Integer.toHexString()' strips leading zeroes from each byte if read byte-by-byte.\nThis mistake weakens the hash value computed since it introduces more collisions.\nUse 'String.format(\"%02X\", ...)' instead."
  },
  "ExpressPhantomInjection": {
    "title": "express phantom injection",
    "display_name": "ExpressPhantomInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `phantom` methods it can result in Server-Side Request Forgery vulnerabilities"
  },
  "SequelizeWeakTls": {
    "title": "sequelize weak tls",
    "display_name": "SequelizeWeakTls",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The Sequelize connection string indicates that an older version of TLS is in use. TLS1.0 and TLS1.1 are deprecated and should be used. By default, Sequelize use TLSv1.2 but it's recommended to use TLS1.3. Not applicable to SQLite database."
  },
  "ExpressLfr": {
    "title": "express lfr",
    "display_name": "ExpressLfr",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted user input in express render() function can result in arbitrary file read when hbs templating is used."
  },
  "DetectedAwsSessionToken": {
    "title": "secrets: detected aws session token",
    "display_name": "DetectedAwsSessionToken",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "AWS Session Token detected"
  },
  "DetectChildProcess": {
    "title": "detect child process",
    "display_name": "DetectChildProcess",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected non-literal calls to $EXEC(). This could lead to a command\ninjection vulnerability."
  },
  "DetectedGenericSecret": {
    "title": "secrets: detected generic secret",
    "display_name": "DetectedGenericSecret",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Generic Secret detected"
  },
  "RawHtmlConcat": {
    "title": "raw html concat",
    "display_name": "RawHtmlConcat",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in a HTML string may result in XSS"
  },
  "ExpressCookieSessionNoSecure": {
    "title": "express cookie session no secure",
    "display_name": "ExpressCookieSessionNoSecure",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Default session middleware settings: `secure` not set.\nIt ensures the browser only sends the cookie over HTTPS."
  },
  "NodeDeserialize": {
    "title": "node deserialize",
    "display_name": "NodeDeserialize",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in 'unserialize()' or 'deserialize()' function can result in Object Injection or Remote Code Injection."
  },
  "HttpservletPathTraversal": {
    "title": "httpservlet path traversal",
    "display_name": "HttpservletPathTraversal",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a potential path traversal. A malicious actor\ncould control the location of this file, to include going backwards\nin the directory with '../'. To address this, ensure that user-controlled\nvariables in file paths are sanitized. You may aslso consider using a utility\nmethod such as org.apache.commons.io.FilenameUtils.getName(...) to only\nretrieve the file name from the path."
  },
  "ManualTemplateCreation": {
    "title": "manual template creation",
    "display_name": "ManualTemplateCreation",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected manual creation of an ERB template. Manual creation of templates\nmay expose your application to server-side template injection (SSTI) or\ncross-site scripting (XSS) attacks if user input is used to create the\ntemplate. Instead, create a '.erb' template file and use 'render'."
  },
  "NodeUsername": {
    "title": "node username",
    "display_name": "NodeUsername",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A hardcoded username in plain text is identified. Store it properly in an environment variable."
  },
  "NodeSqliInjection": {
    "title": "node sqli injection",
    "display_name": "NodeSqliInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted input concatinated with raw SQL query can result in SQL Injection."
  },
  "UseJstlEscaping": {
    "title": "use jstl escaping",
    "display_name": "UseJstlEscaping",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected an Expression Language segment in a tag that does not escape\noutput. This is dangerous because if any data in this expression\ncan be controlled externally, it is a cross-site scripting\nvulnerability. Instead, use the 'out' tag from the JSTL taglib\nto escape this expression.\nSee https://www.tutorialspoint.com/jsp/jstl_core_out_tag.htm\nfor more information."
  },
  "UnsafeSerializeJavascript": {
    "title": "unsafe serialize javascript",
    "display_name": "UnsafeSerializeJavascript",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "`serialize-javascript` used with `unsafe` parameter, this could be vulnerable to XSS."
  },
  "MissingNoInstallRecommends": {
    "title": "dockerfile: missing no install recommends",
    "display_name": "MissingNoInstallRecommends",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This 'apt-get install' is missing '--no-install-recommends'. This prevents\nunnecessary packages from being installed, thereby reducing image size. Add\n'--no-install-recommends'.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "Python37CompatibilityOs1": {
    "title": "python37 compatibility os1",
    "display_name": "Python37CompatibilityOs1",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "this function is only available on Python 3.7+"
  },
  "UseWorkdir": {
    "title": "dockerfile: use workdir",
    "display_name": "UseWorkdir",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use 'WORKDIR' instead of 'RUN cd ...'. Using 'RUN cd ...' may not work as expected in a conatiner.\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "MissingHashWithEq": {
    "title": "missing hash with eq",
    "display_name": "MissingHashWithEq",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Class `$A` has defined `__eq__` which means it should also have defined `__hash__`;"
  },
  "YamlDeserialize": {
    "title": "yaml deserialize",
    "display_name": "YamlDeserialize",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in 'yaml.load()' function can result in Remote Code Injection."
  },
  "ExpressOpenRedirect2": {
    "title": "express open redirect2",
    "display_name": "ExpressOpenRedirect2",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted user input in response header('Location') can result in Open Redirect vulnerability."
  },
  "EscapeFunctionOverwrite": {
    "title": "escape function overwrite",
    "display_name": "EscapeFunctionOverwrite",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The Mustache escape function is being overwritten. This could bypass\nHTML escaping safety measures built into the rendering engine, exposing\nyour application to cross-site scripting (XSS) vulnerabilities. If you\nneed unescaped HTML, use the triple brace operator in your template:\n'{{{ ... }}}'."
  },
  "Avoid_send_file_without_path_sanitization": {
    "title": "avoid_send_file_without_path_sanitization",
    "display_name": "Avoid_send_file_without_path_sanitization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Looks like `filename` could flow to `flask.send_file()` function. Make sure to properly sanitize filename or use `flask.send_from_directory`"
  },
  "BlowfishInsufficientKeySize": {
    "title": "blowfish insufficient key size",
    "display_name": "BlowfishInsufficientKeySize",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Using less than 128 bits for Blowfish is considered insecure. Use 128 bits\nor more, or switch to use AES instead."
  },
  "DangerousSyscallExec": {
    "title": "dangerous syscall exec",
    "display_name": "DangerousSyscallExec",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected non-static command inside Exec. Audit the input to 'syscall.Exec'.\nIf unverified user data can reach this call site, this is a code injection\nvulnerability. A malicious actor can inject a malicious script to execute\narbitrary code."
  },
  "XxeExpat": {
    "title": "xxe expat",
    "display_name": "XxeExpat",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach the XML Parser, as it can result in XML External or Internal Entity (XXE) Processing vulnerabilities."
  },
  "UrlRewriting": {
    "title": "url rewriting",
    "display_name": "UrlRewriting",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "URL rewriting has significant security risks.\nSince session ID appears in the URL, it may be easily seen by third parties."
  },
  "HostipcPod": {
    "title": "kubernetes: hostipc pod",
    "display_name": "HostipcPod",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Pod is sharing the host IPC namespace. This allows container processes\nto communicate with processes on the host which reduces isolation and\nbypasses container protection models. Remove the 'hostIPC' key to disable\nthis functionality."
  },
  "DetectedAwsAppsyncGraphqlKey": {
    "title": "secrets: detected aws appsync graphql key",
    "display_name": "DetectedAwsAppsyncGraphqlKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "AWS AppSync GraphQL Key detected"
  },
  "ServerDangerousObjectDeserialization": {
    "title": "server dangerous object deserialization",
    "display_name": "ServerDangerousObjectDeserialization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Using an arbitrary object ('Object $PARAM') with Java RMI is an insecure deserialization\nvulnerability. This object can be manipulated by a malicious actor allowing them to execute\ncode on your system. Instead, use an integer ID to look up your object, or consider alternative\nserializiation schemes such as JSON."
  },
  "ReactUnsanitizedProperty": {
    "title": "react unsanitized property",
    "display_name": "ReactUnsanitizedProperty",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in a `$X` is an anti-pattern that can lead to XSS vulnerabilities"
  },
  "PasswordEmptyString": {
    "title": "password empty string",
    "display_name": "PasswordEmptyString",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "'$VAR' is the empty string and is being used to set the password on '$MODEL'.\nIf you meant to set an unusable password, set the password to None or call\n'set_unusable_password()'."
  },
  "HelmetHeaderCheckExpectCt": {
    "title": "helmet header check expect ct",
    "display_name": "HelmetHeaderCheckExpectCt",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Expect-CT header is present. More information: https://helmetjs.github.io/docs/expect-ct/"
  },
  "FileInclusion": {
    "title": "file inclusion",
    "display_name": "FileInclusion",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Non-constant file inclusion. This can lead to LFI or RFI if user\ninput reaches this statement."
  },
  "CommandInjectionOsSystem": {
    "title": "command injection os system",
    "display_name": "CommandInjectionOsSystem",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Request data detected in os.system. This could be vulnerable to a command injection and should be avoided. If this must be done, use the 'subprocess' module instead and pass the arguments as a list. See https://owasp.org/www-community/attacks/Command_Injection for more information."
  },
  "NestjsHeaderCorsAny": {
    "title": "nestjs header cors any",
    "display_name": "NestjsHeaderCorsAny",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Access-Control-Allow-Origin response header is set to \"*\". This will disable CORS Same Origin Policy restrictions."
  },
  "DetectedTelegramBotApiKey": {
    "title": "secrets: detected telegram bot api key",
    "display_name": "DetectedTelegramBotApiKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Telegram Bot API Key detected"
  },
  "DetectedSquareOauthSecret": {
    "title": "secrets: detected square oauth secret",
    "display_name": "DetectedSquareOauthSecret",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Square OAuth Secret detected"
  },
  "CopyFromOwnAlias": {
    "title": "dockerfile: copy from own alias",
    "display_name": "CopyFromOwnAlias",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "COPY instructions cannot copy from its own alias. The '$REF' alias is used before switching to a new image. If you meant to switch to a new image, include a new 'FROM' statement. Otherwise, remove the '--from=$REF' from the COPY statement.\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "Python37CompatibilityIpv6network1": {
    "title": "python37 compatibility ipv6network1",
    "display_name": "Python37CompatibilityIpv6network1",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "this function is only available on Python 3.7+"
  },
  "Python37CompatibilityIpv6network2": {
    "title": "python37 compatibility ipv6network2",
    "display_name": "Python37CompatibilityIpv6network2",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "this function is only available on Python 3.7+"
  },
  "UseEitherWgetOrCurl": {
    "title": "dockerfile: use either wget or curl",
    "display_name": "UseEitherWgetOrCurl",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "'wget' and 'curl' are similar tools. Choose one and do not install the other to decrease image size.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "JwtExposedCredentials": {
    "title": "jwt exposed credentials",
    "display_name": "JwtExposedCredentials",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Password is exposed through JWT token payload. This is not encrypted and  the password could be compromised. Do not store passwords in JWT tokens."
  },
  "FormattedStringBashoperator": {
    "title": "formatted string bashoperator",
    "display_name": "FormattedStringBashoperator",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found a formatted string in BashOperator: $CMD.\nThis could be vulnerable to injection.\nBe extra sure your variables are not controllable by external sources."
  },
  "UseShellInstruction": {
    "title": "dockerfile: use shell instruction",
    "display_name": "UseShellInstruction",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use the SHELL instruction to set the default shell instead of overwriting '/bin/sh'.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "BatchImport": {
    "title": "batch import",
    "display_name": "BatchImport",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Rather than adding one element at a time, consider batch loading to improve performance."
  },
  "PathTraversalFileName": {
    "title": "path traversal file name",
    "display_name": "PathTraversalFileName",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Data from request is passed to a file name `$FILE`.\nThis is a path traversal vulnerability: https://owasp.org/www-community/attacks/Path_Traversal\nTo mitigate, consider using os.path.abspath or os.path.realpath or Path library."
  },
  "DangerousTemplateString": {
    "title": "dangerous template string",
    "display_name": "DangerousTemplateString",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found a template created with string formatting.\nThis is susceptible to server-side template injection\nand cross-site scripting attacks."
  },
  "Ftplib": {
    "title": "ftplib",
    "display_name": "Ftplib",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "FTP does not encrypt communications by default. This can lead to sensitive\ndata being exposed. Ensure use of FTP here does not expose sensitive data."
  },
  "InsecureDocumentMethod": {
    "title": "insecure document method",
    "display_name": "InsecureDocumentMethod",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in methods like `innerHTML`, `outerHTML` or `document.write` is an anti-pattern that can lead to XSS vulnerabilities"
  },
  "HelmetHeaderFeaturePolicy": {
    "title": "helmet header feature policy",
    "display_name": "HelmetHeaderFeaturePolicy",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Feature-Policy header is present. More information: https://helmetjs.github.io/docs/feature-policy/"
  },
  "UserExec": {
    "title": "user exec",
    "display_name": "UserExec",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found user data in a call to 'exec'. This is extremely dangerous because\nit can enable an attacker to execute remote code. See\nhttps://owasp.org/www-community/attacks/Code_Injection for more information."
  },
  "InsecureCipherAlgorithmXor": {
    "title": "insecure cipher algorithm xor",
    "display_name": "InsecureCipherAlgorithmXor",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected XOR cipher algorithm which is considered insecure. This algorithm\nis not cryptographically secure and can be reversed easily. Use AES instead."
  },
  "DetectAngularTrustAsCssMethod": {
    "title": "detect angular trust as css method",
    "display_name": "DetectAngularTrustAsCssMethod",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The use of $sce.trustAsCss can be dangerous if unsantiized user input flows through this API."
  },
  "NodeXxe": {
    "title": "node xxe",
    "display_name": "NodeXxe",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in XML parsers can result in XML External or Internal Entity (XXE) Processing vulnerabilities"
  },
  "RequireEncryption": {
    "title": "require encryption",
    "display_name": "RequireEncryption",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Initializing the a security context for Dask (`distributed`) without \"require_encription\" keyword argument may silently fail to provide security. See https://distributed.dask.org/en/latest/tls.html?highlight=require_encryption#parameters"
  },
  "DetectPseudorandombytes": {
    "title": "detect pseudoRandomBytes",
    "display_name": "DetectPseudorandombytes",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected usage of crypto.pseudoRandomBytes, which does not produce secure random numbers."
  },
  "ChannelGuardedWithMutex": {
    "title": "channel guarded with mutex",
    "display_name": "ChannelGuardedWithMutex",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a channel guarded with a mutex. Channels already have\nan internal mutex, so this is unnecessary. Remove the mutex.\nSee https://hackmongo.com/page/golang-antipatterns/#guarded-channel\nfor more information."
  },
  "Pg8000Sqli": {
    "title": "pg8000 sqli",
    "display_name": "Pg8000Sqli",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected string concatenation with a non-literal variable in a pg8000\nPython SQL statement. This could lead to SQL injection if the variable is user-controlled\nand not properly sanitized. In order to prevent SQL injection,\nused parameterized queries or prepared statements instead.\nYou can create parameterized queries like so:\n'conn.run(\"SELECT :value FROM table\", value=myvalue)'.\nYou can also create prepared statements with 'conn.prepare':\n'conn.prepare(\"SELECT (:v) FROM table\")'"
  },
  "ManualCounterCreate": {
    "title": "manual counter create",
    "display_name": "ManualCounterCreate",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "manually creating a counter - use collections.Counter"
  },
  "DetectedAwsAccessKeyIdValue": {
    "title": "secrets: detected aws access key id value",
    "display_name": "DetectedAwsAccessKeyIdValue",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "AWS Access Key ID Value detected"
  },
  "NodePassword": {
    "title": "node password",
    "display_name": "NodePassword",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A hardcoded password in plain text is identified. Store it properly in an environment variable."
  },
  "NoCsrfExempt": {
    "title": "no csrf exempt",
    "display_name": "NoCsrfExempt",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "There is rarely a good reason to use @csrf_exempt as is used for `$R`."
  },
  "PrivilegedContainer": {
    "title": "kubernetes: privileged container",
    "display_name": "PrivilegedContainer",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Container or pod is running in privileged mode. This grants the\ncontainer the equivalent of root capabilities on the host machine. This\ncan lead to container escapes, privilege escalation, and other security\nconcerns. Remove the 'privileged' key to disable this capability."
  },
  "DangerousLinkTo": {
    "title": "dangerous link to",
    "display_name": "DangerousLinkTo",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a template variable used in 'link_to'. This will\ngenerate dynamic data in the 'href' attribute.\nThis allows a malicious actor to\ninput the 'javascript:' URI and is subject to cross-\nsite scripting (XSS) attacks. If using a relative URL,\nstart with a literal forward slash and concatenate the URL,\nlike this: 'link_to \"Here\", \"/\"+@link'. You may also consider\nsetting the Content Security Policy (CSP) header."
  },
  "JsonEncoding": {
    "title": "json encoding",
    "display_name": "JsonEncoding",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "When a 'Hash' with user-supplied input is encoded in JSPN, Rails doesn't provide adequate escaping.\nIf the JSON string is supplied into HTML, the page will be vulnerable to XXS attacks.\nThe affected ruby versions are 3.0.x, 3.1.x, 3.2.x, 4.1.x, 4.2.x.\nTo fix, either upgrade or add an initializer."
  },
  "UseOfMd5": {
    "title": "use of md5",
    "display_name": "UseOfMd5",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected MD5 hash algorithm which is considered insecure. MD5 is not\ncollision resistant and is therefore not suitable as a cryptographic\nsignature. Use SHA256 or SHA3 instead."
  },
  "NoStringsAsBooleans": {
    "title": "no strings as booleans",
    "display_name": "NoStringsAsBooleans",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Using strings as booleans in Python has unexpected results.\n`\"one\" and \"two\"` will return \"two\".\n`\"one\" or \"two\"` will return \"one\".\n In Python, strings are truthy, and strings with a non-zero length evaluate to True."
  },
  "InsecureUseStrtokFn": {
    "title": "insecure use strtok fn",
    "display_name": "InsecureUseStrtokFn",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Avoid using 'strtok()'. This function directly modifies the first argument buffer, permanently erasing the\ndelimiter character. Use 'strtok_r()' instead."
  },
  "AliasPathTraversal": {
    "title": "nginx: alias path traversal",
    "display_name": "AliasPathTraversal",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The alias in this location block is subject to a path traversal because the location path does not end in a path separator (e.g., '/'). To fix, add a path separator to the end of the path.\n{\"include\": [\"*.conf\", \"*.vhost\", \"sites-available/*\", \"sites-enabled/*\"]}"
  },
  "PassBodyFn": {
    "title": "pass body fn",
    "display_name": "PassBodyFn",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "`pass` is the body of function $X. Consider removing this or raise NotImplementedError() if this is a TODO"
  },
  "SequelizeTlsDisabledCertValidation": {
    "title": "sequelize tls disabled cert validation",
    "display_name": "SequelizeTlsDisabledCertValidation",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Set \"rejectUnauthorized\" to false is a convenient way to resolve certificate error. But this method is unsafe because it disables the server certificate verification, making the Node app open to MITM attack. \"rejectUnauthorized\" option must be alway set to True (default value). With self -signed certificat or custom CA, use \"ca\" option to define Root Certicate. This rule checks TLS configuration only for Postgresql, MariaDB and MySQL. SQLite is not really concerned by TLS configuration. This rule could be extended for MSSQL, but the dialectOptions is specific for Tedious."
  },
  "BadSend": {
    "title": "bad send",
    "display_name": "BadSend",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Checks for unsafe use of Object#send, try, __send__, and public_send. These only account for unsafe\nuse of a method, not target. This can lead to arbitrary calling of exit, along with arbitrary code     execution.\nPlease be sure to sanitize input in order to avoid this."
  },
  "AvoidDill": {
    "title": "avoid dill",
    "display_name": "AvoidDill",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Avoid using `dill`, which uses `pickle`, which is known to lead to code execution vulnerabilities.\nWhen unpickling, the serialized data could be manipulated to run arbitrary code.\nInstead, consider serializing the relevant data as JSON or a similar text-based\nserialization format."
  },
  "DirectResponseWrite": {
    "title": "direct response write",
    "display_name": "DirectResponseWrite",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected direclty writing to a Response object. This bypasses any HTML escaping and may expose your app to a cross-site scripting (XSS) vulnerability. Instead, use 'resp.render()' to render safely escaped HTML."
  },
  "PgOrmSqli": {
    "title": "pg orm sqli",
    "display_name": "PgOrmSqli",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected string concatenation with a non-literal variable in a go-pg ORM\nSQL statement. This could lead to SQL injection if the variable is user-controlled\nand not properly sanitized. In order to prevent SQL injection,\ndo not use strings concatenated with user-controlled input.\nInstead, use parameterized statements."
  },
  "UselessIfBody": {
    "title": "useless if body",
    "display_name": "UselessIfBody",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected identical if-statement bodies. Is this intentional?"
  },
  "DenoDangerousRun": {
    "title": "deno dangerous run",
    "display_name": "DenoDangerousRun",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected non-literal calls to Deno.run(). This could lead to a command\ninjection vulnerability."
  },
  "FlaskViewFuncMatchRouteParams": {
    "title": "flask view func match route params",
    "display_name": "FlaskViewFuncMatchRouteParams",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The view function arguments `$PATH` to `$R` don't match the path defined in @app.route($PATH)"
  },
  "SqlInjectionDbCursorExecute": {
    "title": "sql injection db cursor execute",
    "display_name": "SqlInjectionDbCursorExecute",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Data from request is passed to execute(). This is a SQL injection and could be exploited. See https://docs.djangoproject.com/en/3.0/topics/security/#sql-injection-protection to learn how to mitigate. See https://cwe.mitre.org/data/definitions/89.html to learn about SQLi."
  },
  "ExpressXml2jsonXxe": {
    "title": "express xml2json xxe",
    "display_name": "ExpressXml2jsonXxe",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach the XML Parser,\nas it can result in XML External or Internal Entity (XXE) Processing vulnerabilities"
  },
  "InsufficientRsaKeySize": {
    "title": "insufficient rsa key size",
    "display_name": "InsufficientRsaKeySize",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected an insufficient key size for RSA. NIST recommends\na key size of 2048 or higher."
  },
  "PlaywrightExposedChromeDevtools": {
    "title": "playwright exposed chrome devtools",
    "display_name": "PlaywrightExposedChromeDevtools",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Remote debugging protocol does not perform any authentication, so exposing it too widely can be a security risk."
  },
  "StringIsComparison": {
    "title": "string is comparison",
    "display_name": "StringIsComparison",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found string comparison using 'is' operator. The 'is' operator\nis for reference equality, not value equality, and therefore should\nnot be used to compare strings. For more information, see\nhttps://github.com/satwikkansal/wtfpython#-how-not-to-use-is-operator\""
  },
  "DetectedLogbackCore": {
    "title": "detected logback core",
    "display_name": "DetectedLogbackCore",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "\u68c0\u67e5maven\uff0cgradle\u7b49\u914d\u7f6e\u6587\u4ef6\u4e2d\u4f7f\u7528\u7684logback-core\u7248\u672c\nlogback version < 1.2.9\nlogback version < 1.3.0-alpha11\n\u8bf7\u5347\u7ea7\u52301.2.9\u53ca\u4ee5\u4e0a\u7248\u672c\u3002\n\u6f0f\u6d1e\u8be6\u60c5\u53ef\u4ee5\u770b\uff1ahttps://logback.qos.ch/news.html\nCVE\u8be6\u60c5\uff1ahttps://cve.report/CVE-2021-42550"
  },
  "DjangoDbModelSaveSuper": {
    "title": "django db model save super",
    "display_name": "DjangoDbModelSaveSuper",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a django model `$MODEL` is not calling super().save() inside of the save method."
  },
  "DetectedSlackToken": {
    "title": "secrets: detected slack token",
    "display_name": "DetectedSlackToken",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Slack Token detected"
  },
  "TemplateAutoescapeOff": {
    "title": "template autoescape off",
    "display_name": "TemplateAutoescapeOff",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a segment of a Flask template where autoescaping is explicitly disabled with '{% autoescape off %}'. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability, or turn autoescape on."
  },
  "InsecureUrlretrieveFtp": {
    "title": "insecure urlretrieve ftp",
    "display_name": "InsecureUrlretrieveFtp",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected 'urllib.urlretrieve()' using 'ftp://'. This request will not be\nencrypted. Use SFTP instead. urllib does not support SFTP, so consider\nswitching to a library which supports SFTP."
  },
  "DjangoCompat2_0ExtraForms": {
    "title": "django compat 2_0 extra forms",
    "display_name": "DjangoCompat2_0ExtraForms",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The django.forms.extras package is removed in Django 2.0."
  },
  "TemplateVarUnescapedWithSafeseq": {
    "title": "template var unescaped with safeseq",
    "display_name": "TemplateVarUnescapedWithSafeseq",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a template variable where autoescaping is explicitly\ndisabled with '| safeseq' filter. This allows rendering of raw HTML\nin this segment. Ensure no user data is rendered here, otherwise this\nis a cross-site scripting (XSS) vulnerability. If you must do this,\nuse `mark_safe` in your Python code."
  },
  "MassAssignmentVuln": {
    "title": "mass assignment vuln",
    "display_name": "MassAssignmentVuln",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Checks for calls to without_protection during mass assignment (which allows record creation from hash values).\nThis can lead to users bypassing permissions protections. For Rails 4 and higher, mass protection is on by default.\nFix: Don't use :without_protection => true. Instead, configure attr_acessible to control attribute access."
  },
  "ReactRouterRedirect": {
    "title": "react router redirect",
    "display_name": "ReactRouterRedirect",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in <Redirect /> can lead to unpredicted redirects."
  },
  "Python37CompatibilityPdb": {
    "title": "python37 compatibility pdb",
    "display_name": "Python37CompatibilityPdb",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "this function is only available on Python 3.7+"
  },
  "RequestSessionHttpInWithContext": {
    "title": "request session http in with context",
    "display_name": "RequestSessionHttpInWithContext",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a request using 'http://'. This request will be unencrypted. Use 'https://' instead."
  },
  "ServletresponseWriterXss": {
    "title": "servletresponse writer xss",
    "display_name": "ServletresponseWriterXss",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Cross-site scripting detected in HttpServletResponse writer with variable '$VAR'. User\ninput was detected going directly from the HttpServletRequest into output. Ensure your\ndata is properly encoded using org.owasp.encoder.Encode.forHtml: 'Encode.forHtml($VAR)'."
  },
  "VmCodeInjection": {
    "title": "vm code injection",
    "display_name": "VmCodeInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted user input reaching `vm` can result in code injection."
  },
  "EvalDetected": {
    "title": "eval detected",
    "display_name": "EvalDetected",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected the use of eval(). eval() can be dangerous if used to evaluate\ndynamic content. If this content can be input from outside the program, this\nmay be a code injection vulnerability. Ensure evaluated content is not definable\nby external sources."
  },
  "AccessForeignKeys": {
    "title": "access foreign keys",
    "display_name": "AccessForeignKeys",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "You should use ITEM.user_id rather than ITEM.user.id to prevent running an extra query."
  },
  "DangerousSyscall": {
    "title": "dangerous syscall",
    "display_name": "DangerousSyscall",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "'syscall' is essentially unsafe and unportable. The DL (https://apidock.com/ruby/Fiddle) library is preferred for safer and a bit more portable programming."
  },
  "XssHtmlEmailBody": {
    "title": "xss html email body",
    "display_name": "XssHtmlEmailBody",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found request data in an EmailMessage that is set to use HTML.\nThis is dangerous because HTML emails are susceptible to XSS.\nAn attacker could inject data into this HTML email, causing XSS."
  },
  "InsecureUsePrintfFn": {
    "title": "insecure use printf fn",
    "display_name": "InsecureUsePrintfFn",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Avoid using user-controlled format strings passed into 'sprintf', 'printf' and 'vsprintf'.\nThese functions put you at risk of buffer overflow vulnerabilities through the use of format string exploits.\nInstead, use 'snprintf' and 'vsnprintf'."
  },
  "AntiCsrfControl": {
    "title": "anti csrf control",
    "display_name": "AntiCsrfControl",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This application has anti CSRF protection which prevents cross site request forgery attacks."
  },
  "ShelljsExecInjection": {
    "title": "shelljs exec injection",
    "display_name": "ShelljsExecInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `exec` method it can result in Remote Code Execution"
  },
  "JjwtNoneAlg": {
    "title": "jjwt none alg",
    "display_name": "JjwtNoneAlg",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected use of the 'none' algorithm in a JWT token.\nThe 'none' algorithm assumes the integrity of the token has already\nbeen verified. This would allow a malicious actor to forge a JWT token\nthat will automatically be verified. Do not explicitly use the 'none'\nalgorithm. Instead, use an algorithm such as 'HS256'."
  },
  "DetectedMailgunApiKey": {
    "title": "secrets: detected mailgun api key",
    "display_name": "DetectedMailgunApiKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Mailgun API Key detected"
  },
  "NoReplaceall": {
    "title": "no replaceall",
    "display_name": "NoReplaceall",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The string method replaceAll is not supported in all versions of javascript, and is not supported by older browser versions. Consider using replace() with a regex as the first argument instead like mystring.replace(/bad/g, \"good\") instead of mystring.replaceAll(\"bad\", \"good\") (https://discourse.threejs.org/t/replaceall-is-not-a-function/14585)"
  },
  "NoDirectWriteToResponsewriter": {
    "title": "no direct write to responsewriter",
    "display_name": "NoDirectWriteToResponsewriter",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected directly writing or similar in 'http.ResponseWriter.write()'.\nThis bypasses HTML escaping that prevents cross-site scripting\nvulnerabilities. Instead, use the 'html/template' package\nand render data using 'template.Execute()'."
  },
  "RemovePackageLists": {
    "title": "dockerfile: remove package lists",
    "display_name": "RemovePackageLists",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The package lists were not deleted after running 'apt-get update', which increases the size of the image. Remove the package lists by appending '&& rm -rf /var/lib/apt/lists/*' at the end of apt-get command chain.\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "UserEval": {
    "title": "user eval",
    "display_name": "UserEval",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found user data in a call to 'eval'. This is extremely dangerous because\nit can enable an attacker to execute remote code. See\nhttps://owasp.org/www-community/attacks/Code_Injection for more information"
  },
  "DisabledCertValidation": {
    "title": "disabled cert validation",
    "display_name": "DisabledCertValidation",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Certificate verification has been explicitly disabled. This\npermits insecure connections to insecure servers. Re-enable\ncertification validation."
  },
  "HandlerAssignmentFromMultipleSources": {
    "title": "handler assignment from multiple sources",
    "display_name": "HandlerAssignmentFromMultipleSources",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Variable $VAR is assigned from two different sources: '$X' and '$Y'. Make sure this is intended, as this could cause logic bugs if they are treated as they are the same object."
  },
  "Python37CompatibilityIpv4network2": {
    "title": "python37 compatibility ipv4network2",
    "display_name": "Python37CompatibilityIpv4network2",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "this function is only available on Python 3.7+"
  },
  "Python37CompatibilityIpv4network1": {
    "title": "python37 compatibility ipv4network1",
    "display_name": "Python37CompatibilityIpv4network1",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "this function is only available on Python 3.7+"
  },
  "AvoidApkUpgrade": {
    "title": "dockerfile: avoid apk upgrade",
    "display_name": "AvoidApkUpgrade",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Packages in base images should be up-to-date, removing the need for\n'apk upgrade'. If packages are out-of-date, consider contacting the\nbase image maintainer.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "UselessIfConditional": {
    "title": "useless if conditional",
    "display_name": "UselessIfConditional",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected an if block that checks for the same condition on both branches (`$X`)"
  },
  "InsecureUrlopenerOpenFtp": {
    "title": "insecure urlopener open ftp",
    "display_name": "InsecureUrlopenerOpenFtp",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected an insecure transmission channel. 'URLopener.open(...)' is\nbeing used with 'ftp://'. Use SFTP instead. urllib does not support\nSFTP, so consider using a library which supports SFTP."
  },
  "MissingSslMinversion": {
    "title": "missing ssl minversion",
    "display_name": "MissingSslMinversion",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "`MinVersion` is missing from this TLS configuration. The default\nvalue is TLS1.0 which is considered insecure. Explicitly set the\n`MinVersion` to a secure version of TLS, such as `VersionTLS13`."
  },
  "IsNotIsNot": {
    "title": "is not is not",
    "display_name": "IsNotIsNot",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "In Python 'X is not ...' is different from 'X is (not ...)'.\nIn the latter the 'not' converts the '...' directly to boolean."
  },
  "ReactMarkdownInsecureHtml": {
    "title": "react markdown insecure html",
    "display_name": "ReactMarkdownInsecureHtml",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Overwriting `transformLinkUri` or `transformImageUri` to something insecure or turning `allowDangerousHtml` on, will open code up to XSS vectors."
  },
  "ExtendsCustomExpression": {
    "title": "extends custom expression",
    "display_name": "ExtendsCustomExpression",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found extension of custom expression: $CLASS. Extending expressions\nin this way could inadvertently expose a SQL injection vulnerability.\nSee https://docs.djangoproject.com/en/3.0/ref/models/expressions/#avoiding-sql-injection\nfor more information."
  },
  "DetectedBcryptHash": {
    "title": "secrets: detected bcrypt hash",
    "display_name": "DetectedBcryptHash",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "bcrypt hash detected"
  },
  "InsecureHashAlgorithmSha1": {
    "title": "insecure hash algorithm sha1",
    "display_name": "InsecureHashAlgorithmSha1",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected SHA1 hash algorithm which is considered insecure. SHA1 is not\ncollision resistant and is therefore not suitable as a cryptographic\nsignature. Use SHA256 or SHA3 instead."
  },
  "NodeNosqliInjection": {
    "title": "node nosqli injection",
    "display_name": "NodeNosqliInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Untrusted user input in findOne() function can result in NoSQL Injection."
  },
  "MultiargsCodeExecution": {
    "title": "multiargs code execution",
    "display_name": "MultiargsCodeExecution",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Potential arbitrary code execution, piped to eval"
  },
  "PathJoinResolveTraversal": {
    "title": "path join resolve traversal",
    "display_name": "PathJoinResolveTraversal",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Possible writing outside of the destination,\nmake sure that the target path is nested in the intended destination"
  },
  "JaxRsPathTraversal": {
    "title": "jax rs path traversal",
    "display_name": "JaxRsPathTraversal",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a potential path traversal. A malicious actor\ncould control the location of this file, to include going backwards\nin the directory with '../'. To address this, ensure that user-controlled\nvariables in file paths are sanitized. You may aslso consider using a utility\nmethod such as org.apache.commons.io.FilenameUtils.getName(...) to only\nretrieve the file name from the path."
  },
  "UselessAssignmentKeyed": {
    "title": "useless assignment keyed",
    "display_name": "UselessAssignmentKeyed",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "key `$Y` in `$X` is assigned twice; the first assignment is useless"
  },
  "RubyJwtExposedCredentials": {
    "title": "ruby jwt exposed credentials",
    "display_name": "RubyJwtExposedCredentials",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Password is exposed through JWT token payload. This is not encrypted and\nthe password could be compromised. Do not store passwords in JWT tokens."
  },
  "InsecureHashAlgorithmMd5": {
    "title": "insecure hash algorithm md5",
    "display_name": "InsecureHashAlgorithmMd5",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected MD5 hash algorithm which is considered insecure. MD5 is not\ncollision resistant and is therefore not suitable as a cryptographic\nsignature. Use SHA256 or SHA3 instead."
  },
  "SequelizeRawQuery": {
    "title": "sequelize raw query",
    "display_name": "SequelizeRawQuery",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Avoiding SQL string concatenation: untrusted input concatinated with raw SQL query can result in SQL Injection. Data replacement or data binding should be used. See https://sequelize.org/master/manual/raw-queries.html"
  },
  "UnquotedCsvWriter": {
    "title": "unquoted csv writer",
    "display_name": "UnquotedCsvWriter",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found an unquoted CSV writer. This is susceptible to injection. Use 'quoting=csv.QUOTE_ALL'."
  },
  "ModelAttributesAttrAccessible": {
    "title": "model attributes attr accessible",
    "display_name": "ModelAttributesAttrAccessible",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Checks for models that do not use attr_accessible. This means there is no limiting of which variables can be manipulated\nthrough mass assignment. For newer Rails applications, parameters should be allowlisted using strong parameters.\nFor older Ruby versions, they should be allowlisted using strong_attributes."
  },
  "DjangoCompat2_0AssignmentTag": {
    "title": "django compat 2_0 assignment tag",
    "display_name": "DjangoCompat2_0AssignmentTag",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The assignment_tag helper is removed in Django 2.0."
  },
  "OpenRedirect": {
    "title": "open redirect",
    "display_name": "OpenRedirect",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Data from request is passed to redirect().\nThis is an open redirect and could be exploited.\nConsider using 'url_for()' to generate links to known locations.\nIf you must use a URL to unknown pages, consider using 'urlparse()'\nor similar and checking if the 'netloc' property is the same as\nyour site's host name. See the references for more information."
  },
  "ChromeRemoteInterfaceNavigateInjection": {
    "title": "chrome remote interface navigate injection",
    "display_name": "ChromeRemoteInterfaceNavigateInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `navigate` method it can result in Server-Side Request Forgery vulnerabilities"
  },
  "InsecureHashFunction": {
    "title": "insecure hash function",
    "display_name": "InsecureHashFunction",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected use of an insecure MD4 or MD5 hash function.\nThese functions have known vulnerabilities and are considered deprecated.\nConsider using 'SHA256' or a similar function instead."
  },
  "EcbCipher": {
    "title": "ecb cipher",
    "display_name": "EcbCipher",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Cipher in ECB mode is detected. ECB mode produces the same output for the same input each time\nwhich allows an attacker to intercept and replay the data. Further, ECB mode does not provide\nany integrity checking. See https://find-sec-bugs.github.io/bugs.htm#CIPHER_INTEGRITY."
  },
  "JavaJwtHardcodedSecret": {
    "title": "java jwt hardcoded secret",
    "display_name": "JavaJwtHardcodedSecret",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Hardcoded JWT secret or private key is used.\nThis is a Insufficiently Protected Credentials weakness: https://cwe.mitre.org/data/definitions/522.html\nConsider using an appropriate security mechanism to protect the credentials (e.g. keeping secrets in environment variables)"
  },
  "InsecureSmtpConnection": {
    "title": "insecure smtp connection",
    "display_name": "InsecureSmtpConnection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Insecure SMTP connection detected. This connection will trust any SSL certificate.\nEnable certificate verification by setting 'email.setSSLCheckServerIdentity(true)'."
  },
  "ExpressXml2jsonXxeEvent": {
    "title": "express xml2json xxe event",
    "display_name": "ExpressXml2jsonXxeEvent",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Xml Parser is used inside Request Event.\nMake sure that unverified user data can not reach the XML Parser,\nas it can result in XML External or Internal Entity (XXE) Processing vulnerabilities"
  },
  "JqueryInsecureMethod": {
    "title": "jquery insecure method",
    "display_name": "JqueryInsecureMethod",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in a jQuery's `.$METHOD(...)` is an anti-pattern that can lead to XSS vulnerabilities"
  },
  "AvoidPickle": {
    "title": "avoid pickle",
    "display_name": "AvoidPickle",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Avoid using `pickle`, which is known to lead to code execution vulnerabilities.\nWhen unpickling, the serialized data could be manipulated to run arbitrary code.\nInstead, consider serializing the relevant data as JSON or a similar text-based\nserialization format."
  },
  "SetPipefail": {
    "title": "dockerfile: set pipefail",
    "display_name": "SetPipefail",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Only the exit code from the final command in this RUN instruction will be evaluated unless 'pipefail' is set.\nIf you want to fail the command at any stage in the pipe, set 'pipefail' by including 'SHELL [\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"] before the command.\nIf you're using alpine and don't have bash installed, communicate this explicitly with `SHELL [\"/bin/ash\"]`.\n\n{\"include\": [\"*dockerfile*\", \"*Dockerfile*\"]}"
  },
  "AssignmentComparison": {
    "title": "assignment comparison",
    "display_name": "AssignmentComparison",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The value of `$X` is being ignored and will be used in the conditional test"
  },
  "ChromeRemoteInterfaceSetdocumentcontentInjection": {
    "title": "chrome remote interface setdocumentcontent injection",
    "display_name": "ChromeRemoteInterfaceSetdocumentcontentInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `setDocumentContent` method it can result in Server-Side Request Forgery vulnerabilities"
  },
  "ReactDangerouslysetinnerhtml": {
    "title": "react dangerouslysetinnerhtml",
    "display_name": "ReactDangerouslysetinnerhtml",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Setting HTML from code is risky because it\u2019s easy to inadvertently expose your users to a cross-site scripting (XSS) attack."
  },
  "DetectedPicaticApiKey": {
    "title": "secrets: detected picatic api key",
    "display_name": "DetectedPicaticApiKey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Picatic API Key detected"
  },
  "UnverifiedSslContext": {
    "title": "unverified ssl context",
    "display_name": "UnverifiedSslContext",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Unverified SSL context detected. This will permit insecure connections without verifying\nSSL certificates. Use 'ssl.create_default_context()' instead."
  },
  "DetectedOutlookTeam": {
    "title": "secrets: detected outlook team",
    "display_name": "DetectedOutlookTeam",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Outlook Team detected"
  },
  "DetectedTwitterOauth": {
    "title": "secrets: detected twitter oauth",
    "display_name": "DetectedTwitterOauth",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Twitter OAuth detected"
  },
  "AvoidVHtml": {
    "title": "avoid v html",
    "display_name": "AvoidVHtml",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Dynamically rendering arbitrary HTML on your website can be very dangerous because it can easily lead to XSS vulnerabilities. Only use HTML interpolation on trusted content and never on user-provided content."
  },
  "ReactStyledComponentsInjection": {
    "title": "react styled components injection",
    "display_name": "ReactStyledComponentsInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data in a styled component's css is an anti-pattern that can lead to XSS vulnerabilities"
  },
  "DetectedLog4jCore": {
    "title": "detected log4j core",
    "display_name": "DetectedLog4jCore",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "\u68c0\u67e5maven\uff0cgradle\u7b49\u914d\u7f6e\u6587\u4ef6\u4e2d\u4f7f\u7528\u7684log4j-core\u7248\u672c"
  },
  "SkipTlsVerifyService": {
    "title": "kubernetes: skip tls verify service",
    "display_name": "SkipTlsVerifyService",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Service is disabling TLS certificate verification when communicating with\nthe server. This makes your HTTPS connections insecure. Remove the\n'insecureSkipTLSVerify: true' key to secure communication."
  },
  "FtpUse": {
    "title": "ftp use",
    "display_name": "FtpUse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "FTP allows for unencrypted file transfers. Consider using an encrypted alternative."
  },
  "NonConstantSqlQuery": {
    "title": "non constant sql query",
    "display_name": "NonConstantSqlQuery",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Non-constant SQL query detected. Ensure this is not controlled\nby external data, otherwise this is a SQL injection."
  },
  "MissingSslVersion": {
    "title": "nginx: missing ssl version",
    "display_name": "MissingSslVersion",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This server configuration is missing the 'ssl_protocols' directive. By default, this server will use 'ssl_protocols TLSv1 TLSv1.1 TLSv1.2', and versions older than TLSv1.2 are known to be broken. Explicitly specify 'ssl_protocols TLSv1.2 TLSv1.3' to use secure TLS versions.\n{\"include\": [\"*.conf\", \"*.vhost\", \"sites-available/*\", \"sites-enabled/*\"]}"
  },
  "CustomExpressionAsSql": {
    "title": "custom expression as sql",
    "display_name": "CustomExpressionAsSql",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a Custom Expression ''$EXPRESSION'' calling ''as_sql(...).'' Ensure no user input enters this function because it is susceptible to SQL injection. See https://docs.djangoproject.com/en/3.0/ref/models/expressions/#django.db.models.Func.as_sql for more information."
  },
  "IncorrectDefaultPermission": {
    "title": "incorrect default permission",
    "display_name": "IncorrectDefaultPermission",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Expect permissions to be `0600` or less for os.Chmod, os.Mkdir, os.OpenFile, os.MkdirAll, and ioutil.WriteFile"
  },
  "NodeLogicBypass": {
    "title": "node logic bypass",
    "display_name": "NodeLogicBypass",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled data is used for application business logic decision making. This expose protected data or functionality."
  },
  "SequelizeTlsCertValidation": {
    "title": "sequelize tls cert validation",
    "display_name": "SequelizeTlsCertValidation",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The Sequelize connection string indicates that TLS certificate vailidation of database server is disabled. This is equivalent to not having TLS. An attacker can present any invalid certificate and Sequelize will make database connection ignoring certificate errors. This setting make the connection susceptible to man in the middle (MITM) attacks. Not applicable to SQLite database."
  },
  "VmRuninthiscontextCodeInjection": {
    "title": "vm runinthiscontext code injection",
    "display_name": "VmRuninthiscontextCodeInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach vm.runInThisContext."
  },
  "FormattedTemplateString": {
    "title": "formatted template string",
    "display_name": "FormattedTemplateString",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found a formatted template string passed to 'template.HTML()'.\n'template.HTML()' does not escape contents. Be absolutely sure\nthere is no user-controlled data in this template. If user data\ncan reach this template, you may have a XSS vulnerability."
  },
  "DetectedHockeyapp": {
    "title": "secrets: detected hockeyapp",
    "display_name": "DetectedHockeyapp",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "HockeyApp detected"
  },
  "JoseExposedData": {
    "title": "jose exposed data",
    "display_name": "JoseExposedData",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The object is passed strictly to jose.JWT.sign(...)\nMake sure that sensitive information is not exposed through JWT token payload."
  },
  "MultiprocessingRecv": {
    "title": "multiprocessing recv",
    "display_name": "MultiprocessingRecv",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The Connection.recv() method automatically unpickles the data it receives, which can be a security risk unless you can trust the process which sent the message. Therefore, unless the connection object was produced using Pipe() you should only use the recv() and send() methods after performing some sort of authentication. See more dettails: https://docs.python.org/3/library/multiprocessing.html?highlight=security#multiprocessing.connection.Connection"
  },
  "InsecureSslVersion": {
    "title": "nginx: insecure ssl version",
    "display_name": "InsecureSslVersion",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected use of an insecure SSL version. Secure SSL versions are TLSv1.2 and TLS1.3; older versions are known to be broken and are susceptible to attacks. Prefer use of TLSv1.2 or later.\n{\"include\": [\"*.conf\", \"*.vhost\", \"sites-available/*\", \"sites-enabled/*\"]}"
  },
  "Python37CompatibilityOs2Ok2": {
    "title": "python37 compatibility os2 ok2",
    "display_name": "Python37CompatibilityOs2Ok2",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "this function is only available on Python 3.7+"
  },
  "HelmetHeaderXPoweredBy": {
    "title": "helmet header x powered by",
    "display_name": "HelmetHeaderXPoweredBy",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Default X-Powered-By is removed or modified. More information: https://helmetjs.github.io/docs/hide-powered-by/"
  },
  "ExpressCookieSessionNoHttponly": {
    "title": "express cookie session no httponly",
    "display_name": "ExpressCookieSessionNoHttponly",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Default session middleware settings: `httpOnly` not set.\nIt ensures the cookie is sent only over HTTP(S), not client JavaScript, helping to protect against cross-site scripting attacks."
  },
  "PuppeteerGotoInjection": {
    "title": "puppeteer goto injection",
    "display_name": "PuppeteerGotoInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If unverified user data can reach the `goto` method it can result in Server-Side Request Forgery vulnerabilities"
  },
  "DangerousGlobalsUse": {
    "title": "dangerous globals use",
    "display_name": "DangerousGlobalsUse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Found non static data as an index to 'globals()'. This is extremely\ndangerous because it allows an attacker to execute arbitrary code\non the system. Refactor your code not to use 'globals()'."
  },
  "XxeXml2json": {
    "title": "xxe xml2json",
    "display_name": "XxeXml2json",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach the XML Parser, as it can result in XML External or Internal Entity (XXE) Processing vulnerabilities."
  },
  "FileObjectRedefinedBeforeClose": {
    "title": "file object redefined before close",
    "display_name": "FileObjectRedefinedBeforeClose",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a file object that is redefined and never closed. This\ncould leak file descriptors and unnecessarily consume system resources."
  },
  "StringConcat": {
    "title": "string concat",
    "display_name": "StringConcat",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected string concatenation or formatting in a call to a command via 'sh'.\nThis could be a command injection vulnerability if the data is user-controlled.\nInstead, use a list and append the argument."
  },
  "ExpressVm2ContextInjection": {
    "title": "express vm2 context injection",
    "display_name": "ExpressVm2ContextInjection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that unverified user data can not reach `vm2`."
  },
  "DynamicProxyScheme": {
    "title": "nginx: dynamic proxy scheme",
    "display_name": "DynamicProxyScheme",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The protocol scheme for this proxy is dynamically determined.\nThis can be dangerous if the scheme can be injected by an\nattacker because it may forcibly alter the connection scheme.\nConsider hardcoding a scheme for this proxy.\n\n{\"include\": [\"*.conf\", \"*.vhost\", \"sites-available/*\", \"sites-enabled/*\"]}"
  },
  "MassAssignmentProtectionDisabled": {
    "title": "mass assignment protection disabled",
    "display_name": "MassAssignmentProtectionDisabled",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Mass assignment protection disabled for '$MODEL'. This could\npermit assignment to sensitive model fields without intention. Instead,\nuse 'attr_accessible' for the model or disable mass assigment using\n'config.active_record.whitelist_attributes = true'.\n':without_protection => true' must be removed for this to take effect."
  },
  "SslWrapSocketIsDeprecated": {
    "title": "ssl wrap socket is deprecated",
    "display_name": "SslWrapSocketIsDeprecated",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "'ssl.wrap_socket()' is deprecated. This function creates an insecure socket\nwithout server name indication or hostname matching. Instead, create an SSL\ncontext using 'ssl.SSLContext()' and use that to wrap a socket."
  },
  "DirectlyReturnedFormatString": {
    "title": "directly returned format string",
    "display_name": "DirectlyReturnedFormatString",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected Flask route directly returning a formatted string. This\nis subject to cross-site scripting if user input can reach the string.\nConsider using the template engine instead and rendering pages with\n'render_template()'."
  },
  "NodeSsrf": {
    "title": "node ssrf",
    "display_name": "NodeSsrf",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User controlled URL in http client libraries can result in Server Side Request Forgery (SSRF)."
  },
  "PuppeteerExposedChromeDevtools": {
    "title": "puppeteer exposed chrome devtools",
    "display_name": "PuppeteerExposedChromeDevtools",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Remote debugging protocol does not perform any authentication, so exposing it too widely can be a security risk."
  },
  "CookieSessionNoSamesite": {
    "title": "cookie session no samesite",
    "display_name": "CookieSessionNoSamesite",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Default session middleware settings: `sameSite` attribute is not configured to strict or lax. These configurations provides protection against Cross Site Request Forgery attacks."
  },
  "PermissiveCors": {
    "title": "permissive cors",
    "display_name": "PermissiveCors",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "https://find-sec-bugs.github.io/bugs.htm#PERMISSIVE_CORS\nPermissive CORS policy will allow a malicious application to communicate with the victim application in an inappropriate way, leading to spoofing, data theft, relay and other attacks."
  },
  "DangerousExec": {
    "title": "dangerous exec",
    "display_name": "DangerousExec",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected non-static command inside $EXEC. Audit the input to '$EXEC'.\nIf unverified user data can reach this call site, this is a code injection\nvulnerability. A malicious actor can inject a malicious script to execute\narbitrary code."
  },
  "ExpressCookieSessionDefaultName": {
    "title": "express cookie session default name",
    "display_name": "ExpressCookieSessionDefaultName",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Don\u2019t use the default session cookie name\nUsing the default session cookie name can open your app to attacks.\nThe security issue posed is similar to X-Powered-By: a potential attacker can use it to fingerprint the server and target attacks accordingly."
  },
  "RunAsNonRoot": {
    "title": "kubernetes: run as non root",
    "display_name": "RunAsNonRoot",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Container allows for running applications as root. This can result in\nprivilege escalation attacks. Add 'runAsNonRoot: true' in 'securityContext'\nto prevent this."
  },
  "PdbRemove": {
    "title": "pdb remove",
    "display_name": "PdbRemove",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "pdb is an interactive debugging tool and you may have forgotten to remove it before committing your code"
  },
  "NoSetCiphers": {
    "title": "no set ciphers",
    "display_name": "NoSetCiphers",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The 'ssl' module disables insecure cipher suites by default. Therefore,\nuse of 'set_ciphers()' should only be used when you have very specialized\nrequirements. Otherwise, you risk lowering the security of the SSL channel."
  },
  "CookieSessionDefault": {
    "title": "cookie session default",
    "display_name": "CookieSessionDefault",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Consider changing the default session cookie name. An attacker can use it to fingerprint the server and target attacks accordingly."
  },
  "NoInterpolationInTag": {
    "title": "no interpolation in tag",
    "display_name": "NoInterpolationInTag",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected template variable interpolation in an HTML tag.\nThis is potentially vulnerable to cross-site scripting (XSS)\nattacks because a malicious actor has control over HTML\nbut without the need to use escaped characters. Use explicit\ntags instead."
  },
  "SequelizeEnforceTls": {
    "title": "sequelize enforce tls",
    "display_name": "SequelizeEnforceTls",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If TLS is disabled on server side (Postgresql server), Sequelize establishes connection without TLS and no error will be thrown. To prevent MITN (Man In The Middle) attack, TLS must be enforce by Sequelize. Set \"ssl: true\" or define settings \"ssl: {...}\""
  }
}
