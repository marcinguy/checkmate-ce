# -*- coding: utf-8 -*-


issues_data = {
  "find_sec_bugsHRS_REQUEST_PARAMETER_TO_COOKIE1": {
    "title": "This code constructs an HTTP Cookie using an untrusted HTTP parameter. If this cookie is added\nto an HTTP response, it will allow a HTTP response splitting vulnerability. See\nhttp://en.wikipedia.org/wiki/HTTP_response_splitting for more information.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This code constructs an HTTP Cookie using an untrusted HTTP parameter. If this cookie is added\nto an HTTP response, it will allow a HTTP response splitting vulnerability. See\nhttp://en.wikipedia.org/wiki/HTTP_response_splitting for more information.\n"
  },
  "find_sec_bugsXXE_XMLREADER1": {
    "title": "XML External Entity (XXE) attacks can occur when an XML parser supports XML\nentities while processing XML received from an untrusted source.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "XML External Entity (XXE) attacks can occur when an XML parser supports XML\nentities while processing XML received from an untrusted source.\n"
  },
  "find_sec_bugsDMI_EMPTY_DB_PASSWORD1HARD_CODE_PASSWORD2": {
    "title": "This code creates a database connect using a blank or empty password. This indicates that the\ndatabase is not protected by a password.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This code creates a database connect using a blank or empty password. This indicates that the\ndatabase is not protected by a password.\n"
  },
  "find_sec_bugsSERVLET_PARAMETER1SERVLET_CONTENT_TYPE1SERVLET_SERVER_NAME1SERVLET_SESSION_ID1SERVLET_QUERY_STRING1SERVLET_HEADER1SERVLET_HEADER_REFERER1SERVLET_HEADER_USER_AGENT1": {
    "title": "The Servlet can read GET and POST parameters from various methods. The\nvalue obtained should be considered unsafe.\"\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The Servlet can read GET and POST parameters from various methods. The\nvalue obtained should be considered unsafe.\"\n"
  },
  "find_sec_bugsBLOWFISH_KEY_SIZE1": {
    "title": "A small key size makes the ciphertext vulnerable to brute force attacks. At least 128 bits of\nentropy should be used when generating the key if use of Blowfish is required.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A small key size makes the ciphertext vulnerable to brute force attacks. At least 128 bits of\nentropy should be used when generating the key if use of Blowfish is required.\n"
  },
  "find_sec_bugsSMTP_HEADER_INJECTION1": {
    "title": "Simple Mail Transfer Protocol (SMTP) is a the text based protocol used for\nemail delivery. Like with HTTP, headers are separate by new line separator. If\nkuser input is place in a header line, the application should remove or replace\nnew line characters (CR / LF). You should use a safe wrapper such as Apache\nCommon Email and Simple Java Mail which filter special characters that can lead\nto header injection.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Simple Mail Transfer Protocol (SMTP) is a the text based protocol used for\nemail delivery. Like with HTTP, headers are separate by new line separator. If\nkuser input is place in a header line, the application should remove or replace\nnew line characters (CR / LF). You should use a safe wrapper such as Apache\nCommon Email and Simple Java Mail which filter special characters that can lead\nto header injection.\n"
  },
  "find_sec_bugsSSL_CONTEXT1": {
    "title": "A HostnameVerifier that accept any host are often use because of certificate\nreuse on many hosts. As a consequence, this is vulnerable to Man-in-the-middleattacks\nattacks since the client will trust any certificate.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A HostnameVerifier that accept any host are often use because of certificate\nreuse on many hosts. As a consequence, this is vulnerable to Man-in-the-middleattacks\nattacks since the client will trust any certificate.\n"
  },
  "find_sec_bugsTDES_USAGE1": {
    "title": "Triple DES (also known as 3DES or DESede) is considered strong ciphers for modern\napplications. NIST recommends the usage of AES block ciphers instead of 3DES.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Triple DES (also known as 3DES or DESede) is considered strong ciphers for modern\napplications. NIST recommends the usage of AES block ciphers instead of 3DES.\n"
  },
  "find_sec_bugsXXE_XMLSTREAMREADER1": {
    "title": "XML External Entity (XXE) attacks can occur when an XML parser supports XML\nentities while processing XML received from an untrusted source.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "XML External Entity (XXE) attacks can occur when an XML parser supports XML\nentities while processing XML received from an untrusted source.\n"
  },
  "find_sec_bugsHTTPONLY_COOKIE1": {
    "title": "A new cookie is created without the HttpOnly flag set. The HttpOnly flag is a directive to the\nbrowser to make sure that the cookie can not be red by malicious script. When a user is the\ntarget of a \"Cross-Site Scripting\", the attacker would benefit greatly from getting the session\nid for example.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A new cookie is created without the HttpOnly flag set. The HttpOnly flag is a directive to the\nbrowser to make sure that the cookie can not be red by malicious script. When a user is the\ntarget of a \"Cross-Site Scripting\", the attacker would benefit greatly from getting the session\nid for example.\n"
  },
  "find_sec_bugsUNENCRYPTED_SOCKET1UNENCRYPTED_SERVER_SOCKET1": {
    "title": "Beyond using an SSL socket, you need to make sure your use of SSLSocketFactory\ndoes all the appropriate certificate validation checks to make sure you are not\nsubject to man-in-the-middle attacks. Please read the OWASP Transport Layer\nProtection Cheat Sheet for details on how to do this correctly.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Beyond using an SSL socket, you need to make sure your use of SSLSocketFactory\ndoes all the appropriate certificate validation checks to make sure you are not\nsubject to man-in-the-middle attacks. Please read the OWASP Transport Layer\nProtection Cheat Sheet for details on how to do this correctly.\n"
  },
  "find_sec_bugsXML_DECODER1": {
    "title": "Avoid using XMLDecoder to parse content from an untrusted source.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Avoid using XMLDecoder to parse content from an untrusted source.\n"
  },
  "find_sec_bugsECB_MODE1": {
    "title": "An authentication cipher mode which provides better confidentiality of the encrypted data\nshould be used instead of Electronic Code Book (ECB) mode, which does not provide good\nconfidentiality. Specifically, ECB mode produces the same output for the same input each time.\nThis allows an attacker to intercept and replay the data.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "An authentication cipher mode which provides better confidentiality of the encrypted data\nshould be used instead of Electronic Code Book (ECB) mode, which does not provide good\nconfidentiality. Specifically, ECB mode produces the same output for the same input each time.\nThis allows an attacker to intercept and replay the data.\n"
  },
  "find_sec_bugsLDAP_INJECTION1": {
    "title": "Just like SQL, all inputs passed to an LDAP query need to be passed in safely. Unfortunately,\nLDAP doesn't have prepared statement interfaces like SQL. Therefore, the primary defense\nagainst LDAP injection is strong input validation of any untrusted data before including it in\nan LDAP query.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Just like SQL, all inputs passed to an LDAP query need to be passed in safely. Unfortunately,\nLDAP doesn't have prepared statement interfaces like SQL. Therefore, the primary defense\nagainst LDAP injection is strong input validation of any untrusted data before including it in\nan LDAP query.\n"
  },
  "find_sec_bugsHTTP_PARAMETER_POLLUTION1": {
    "title": "Concatenating unvalidated user input into a URL can allow an attacker to override the value of\na request parameter. Attacker may be able to override existing parameter values, inject a new\nparameter or exploit variables out of a direct reach. HTTP Parameter Pollution (HPP) attacks\nconsist of injecting encoded query string delimiters into other existing parameters. If a web\napplication does not properly sanitize the user input, a malicious user may compromise the\nlogic of the application to perform either client-side or server-side attacks.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Concatenating unvalidated user input into a URL can allow an attacker to override the value of\na request parameter. Attacker may be able to override existing parameter values, inject a new\nparameter or exploit variables out of a direct reach. HTTP Parameter Pollution (HPP) attacks\nconsist of injecting encoded query string delimiters into other existing parameters. If a web\napplication does not properly sanitize the user input, a malicious user may compromise the\nlogic of the application to perform either client-side or server-side attacks.\n"
  },
  "find_sec_bugsINSECURE_COOKIE1": {
    "title": "\"Storing sensitive data in a persistent cookie for an extended period can lead to a breach of\nconfidentiality or account compromise.\"\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "\"Storing sensitive data in a persistent cookie for an extended period can lead to a breach of\nconfidentiality or account compromise.\"\n"
  },
  "find_sec_bugsSQL_INJECTION_SPRING_JDBC1SQL_INJECTION_JPA1SQL_INJECTION_JDO1SQL_INJECTION_JDBC1SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE1": {
    "title": "The input values included in SQL queries need to be passed in safely. Bind\nvariables in prepared statements can be used to easily mitigate the risk of\nSQL injection.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The input values included in SQL queries need to be passed in safely. Bind\nvariables in prepared statements can be used to easily mitigate the risk of\nSQL injection.\n"
  },
  "find_sec_bugsTEMPLATE_INJECTION_PEBBLE1TEMPLATE_INJECTION_FREEMARKER1TEMPLATE_INJECTION_VELOCITY1": {
    "title": "A malicious user in control of a template can run malicious code on the\nserver-side. Velocity templates should be seen as scripts.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A malicious user in control of a template can run malicious code on the\nserver-side. Velocity templates should be seen as scripts.\n"
  },
  "find_sec_bugsXXE_SAXPARSER1": {
    "title": "XML External Entity (XXE) attacks can occur when an XML parser supports XML\nentities while processing XML received from an untrusted source.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "XML External Entity (XXE) attacks can occur when an XML parser supports XML\nentities while processing XML received from an untrusted source.\n"
  },
  "find_sec_bugsURLCONNECTION_SSRF_FD1": {
    "title": "Server-Side Request Forgery occur when a web server executes a request to a\nuser supplied destination parameter that is not validated. Such vulnerabilities\ncould allow an attacker to access internal services or to launch attacks from\nyour web server.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Server-Side Request Forgery occur when a web server executes a request to a\nuser supplied destination parameter that is not validated. Such vulnerabilities\ncould allow an attacker to access internal services or to launch attacks from\nyour web server.\n"
  },
  "find_sec_bugsSTRUTS_FORM_VALIDATION1": {
    "title": "Form inputs should have minimal input validation. Preventive validation helps\nprovide defense in depth against a variety of risks.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Form inputs should have minimal input validation. Preventive validation helps\nprovide defense in depth against a variety of risks.\n"
  },
  "find_sec_bugsBAD_HEXA_CONVERSION1": {
    "title": "When converting a byte array containing a hash signature to a human readable string, a\nconversion mistake can be made if the array is read byte by byte.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "When converting a byte array containing a hash signature to a human readable string, a\nconversion mistake can be made if the array is read byte by byte.\n"
  },
  "find_sec_bugsCUSTOM_MESSAGE_DIGEST1": {
    "title": "Implementing a custom MessageDigest is error-prone. National Institute of Standards and\nTechnology(NIST) recommends the use of SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, or\nSHA-512/256.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Implementing a custom MessageDigest is error-prone. National Institute of Standards and\nTechnology(NIST) recommends the use of SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, or\nSHA-512/256.\n"
  },
  "find_sec_bugsCOMMAND_INJECTION1": {
    "title": "The highlighted API is used to execute a system command. If unfiltered input is passed to this\nAPI, it can lead to arbitrary command execution.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The highlighted API is used to execute a system command. If unfiltered input is passed to this\nAPI, it can lead to arbitrary command execution.\n"
  },
  "find_sec_bugsDEFAULT_HTTP_CLIENT1": {
    "title": "DefaultHttpClient with default constructor is not compatible with TLS 1.2\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "DefaultHttpClient with default constructor is not compatible with TLS 1.2\n"
  },
  "find_sec_bugsBEAN_PROPERTY_INJECTION1": {
    "title": "An attacker can set arbitrary bean properties that can compromise system integrity. An\nattacker can leverage this functionality to access special bean properties like\nclass.classLoader that will allow them to override system properties and potentially execute\narbitrary code.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "An attacker can set arbitrary bean properties that can compromise system integrity. An\nattacker can leverage this functionality to access special bean properties like\nclass.classLoader that will allow them to override system properties and potentially execute\narbitrary code.\n"
  },
  "find_sec_bugsDMI_CONSTANT_DB_PASSWORD1HARD_CODE_PASSWORD3": {
    "title": "This code creates a database connect using a hardcoded, constant password. Anyone with access\nto either the source code or the compiled code can easily learn the password.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This code creates a database connect using a hardcoded, constant password. Anyone with access\nto either the source code or the compiled code can easily learn the password.\n"
  },
  "find_sec_bugsIMPROPER_UNICODE1": {
    "title": "Improper Handling of Unicode Encoding\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Improper Handling of Unicode Encoding\n"
  },
  "find_sec_bugsJAXWS_ENDPOINT1": {
    "title": "This method is part of a SOAP Web Service (JSR224). The security of this web service should be\nanalyzed; Authentication, if enforced, should be tested. Access control, if enforced, should be\ntested. The inputs should be tracked for potential vulnerabilities. The communication should\nideally be over SSL.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This method is part of a SOAP Web Service (JSR224). The security of this web service should be\nanalyzed; Authentication, if enforced, should be tested. Access control, if enforced, should be\ntested. The inputs should be tracked for potential vulnerabilities. The communication should\nideally be over SSL.\n"
  },
  "find_sec_bugsFORMAT_STRING_MANIPULATION1": {
    "title": "Allowing user input to control format parameters could enable an attacker to cause exceptions\nto be thrown or leak information.Attackers may be able to modify the format string argument,\nsuch that an exception is thrown. If this exception is left uncaught, it may crash the\napplication. Alternatively, if sensitive information is used within the unused arguments,\nattackers may change the format string to reveal this information.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Allowing user input to control format parameters could enable an attacker to cause exceptions\nto be thrown or leak information.Attackers may be able to modify the format string argument,\nsuch that an exception is thrown. If this exception is left uncaught, it may crash the\napplication. Alternatively, if sensitive information is used within the unused arguments,\nattackers may change the format string to reveal this information.\n"
  },
  "find_sec_bugsDANGEROUS_PERMISSION_COMBINATION1": {
    "title": "Do not grant dangerous combinations of permissions.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Do not grant dangerous combinations of permissions.\n"
  },
  "find_sec_bugsMALICIOUS_XSLT1": {
    "title": "It is possible to attach malicious behavior to those style sheets. Therefore, if an attacker\ncan control the content or the source of the style sheet, he might be able to trigger remote\ncode execution.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "It is possible to attach malicious behavior to those style sheets. Therefore, if an attacker\ncan control the content or the source of the style sheet, he might be able to trigger remote\ncode execution.\n"
  },
  "find_sec_bugsCOOKIE_PERSISTENT1": {
    "title": "A new cookie is created without the Secure flag set. The Secure flag is a directive to the\nbrowser to make sure that the cookie is not sent for insecure communication (http://)\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A new cookie is created without the Secure flag set. The Secure flag is a directive to the\nbrowser to make sure that the cookie is not sent for insecure communication (http://)\n"
  },
  "find_sec_bugsRPC_ENABLED_EXTENSIONS1": {
    "title": "Enabling extensions in Apache XML RPC server or client can lead to deserialization\nvulnerability which would allow an attacker to execute arbitrary code.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Enabling extensions in Apache XML RPC server or client can lead to deserialization\nvulnerability which would allow an attacker to execute arbitrary code.\n"
  },
  "find_sec_bugsTRUST_BOUNDARY_VIOLATION1": {
    "title": "A trust boundary can be thought of as line drawn through a program. On one side\nof the line, data is untrusted. On the other side of the line, data is assumed\nto be trustworthy. The purpose of validation logic is to allow data to safely\ncross the trust boundary - to move from untrusted to trusted. A trust boundary\nviolation occurs when a program blurs the line between what is trusted and what\nis untrusted. By combining trusted and untrusted data in the same data\nstructure, it becomes easier for programmers to mistakenly trust unvalidated\ndata.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A trust boundary can be thought of as line drawn through a program. On one side\nof the line, data is untrusted. On the other side of the line, data is assumed\nto be trustworthy. The purpose of validation logic is to allow data to safely\ncross the trust boundary - to move from untrusted to trusted. A trust boundary\nviolation occurs when a program blurs the line between what is trusted and what\nis untrusted. By combining trusted and untrusted data in the same data\nstructure, it becomes easier for programmers to mistakenly trust unvalidated\ndata.\n"
  },
  "find_sec_bugsWEAK_FILENAMEUTILS1": {
    "title": "A file is opened to read its content. The filename comes from an input\nparameter. If an unfiltered parameter is passed to this file API, files from an\narbitrary filesystem location could be read.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A file is opened to read its content. The filename comes from an input\nparameter. If an unfiltered parameter is passed to this file API, files from an\narbitrary filesystem location could be read.\n"
  },
  "find_sec_bugsDES_USAGE1": {
    "title": "DES is considered strong ciphers for modern applications. Currently, NIST recommends the usage\nof AES block ciphers instead of DES.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "DES is considered strong ciphers for modern applications. Currently, NIST recommends the usage\nof AES block ciphers instead of DES.\n"
  },
  "find_sec_bugsCRLF_INJECTION_LOGS1": {
    "title": "When data from an untrusted source is put into a logger and not neutralized correctly, an\nattacker could forge log entries or include malicious content. Inserted false entries could be\nused to skew statistics, distract the administrator or even to implicate another party in the\ncommission of a malicious act. If the log file is processed automatically, the attacker can\nrender the file unusable by corrupting the format of the file or injecting unexpected\ncharacters. An attacker may also inject code or other commands into the log file and take\nadvantage of a vulnerability in the log processing utility (e.g. command injection or XSS).\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "When data from an untrusted source is put into a logger and not neutralized correctly, an\nattacker could forge log entries or include malicious content. Inserted false entries could be\nused to skew statistics, distract the administrator or even to implicate another party in the\ncommission of a malicious act. If the log file is processed automatically, the attacker can\nrender the file unusable by corrupting the format of the file or injecting unexpected\ncharacters. An attacker may also inject code or other commands into the log file and take\nadvantage of a vulnerability in the log processing utility (e.g. command injection or XSS).\n"
  },
  "find_sec_bugsHARD_CODE_PASSWORD1": {
    "title": "Passwords should not be kept in the source code. The source code can be widely shared in an\nenterprise environment, and is certainly shared in open source. To be managed safely, passwords\nand secret keys should be stored in separate configuration files or keystores.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Passwords should not be kept in the source code. The source code can be widely shared in an\nenterprise environment, and is certainly shared in open source. To be managed safely, passwords\nand secret keys should be stored in separate configuration files or keystores.\n"
  },
  "find_sec_bugsNORMALIZATION_AFTER_VALIDATION1": {
    "title": "IDS01-J. Normalize strings before validating them\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "IDS01-J. Normalize strings before validating them\n"
  },
  "find_sec_bugsSCRIPT_ENGINE_INJECTION1SPEL_INJECTION1EL_INJECTION2SEAM_LOG_INJECTION1": {
    "title": "The software constructs all or part of a code segment using externally-influenced\ninput from an upstream component, but it does not neutralize or incorrectly\nneutralizes special elements that could modify the syntax or behavior of the\nintended code segment.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The software constructs all or part of a code segment using externally-influenced\ninput from an upstream component, but it does not neutralize or incorrectly\nneutralizes special elements that could modify the syntax or behavior of the\nintended code segment.\n"
  },
  "find_sec_bugsXSS_SERVLET2XSS_SERVLET_PARAMETER1": {
    "title": "The Servlet can read GET and POST parameters from various methods. The value obtained should be\nconsidered unsafe. You may need to validate or sanitize those values before passing them to\nsensitive APIs\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The Servlet can read GET and POST parameters from various methods. The value obtained should be\nconsidered unsafe. You may need to validate or sanitize those values before passing them to\nsensitive APIs\n"
  },
  "find_sec_bugsJAXRS_ENDPOINT1": {
    "title": "This method is part of a REST Web Service (JSR311). The security of this web service should be\nanalyzed; Authentication, if enforced, should be tested. Access control, if enforced, should be\ntested. The inputs should be tracked for potential vulnerabilities. The communication should\nideally be over SSL.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This method is part of a REST Web Service (JSR311). The security of this web service should be\nanalyzed; Authentication, if enforced, should be tested. Access control, if enforced, should be\ntested. The inputs should be tracked for potential vulnerabilities. The communication should\nideally be over SSL.\n"
  },
  "find_sec_bugsPERMISSIVE_CORS2": {
    "title": "Prior to HTML5, Web browsers enforced the Same Origin Policy which ensures that in order for\nJavaScript to access the contents of a Web page, both the JavaScript and the Web page must\noriginate from the same domain. Without the Same Origin Policy, a malicious website could serve\nup JavaScript that loads sensitive information from other websites using a client's\ncredentials, cull through it, and communicate it back to the attacker. HTML5 makes it possible\nfor JavaScript to access data across domains if a new HTTP header called\nAccess-Control-Allow-Origin is defined. With this header, a Web server defines which other\ndomains are allowed to access its domain using cross-origin requests. However, caution should\nbe taken when defining the header because an overly permissive CORS policy will allow a\nmalicious application to communicate with the victim application in an inappropriate way,\nleading to spoofing, data theft, relay and other attacks.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Prior to HTML5, Web browsers enforced the Same Origin Policy which ensures that in order for\nJavaScript to access the contents of a Web page, both the JavaScript and the Web page must\noriginate from the same domain. Without the Same Origin Policy, a malicious website could serve\nup JavaScript that loads sensitive information from other websites using a client's\ncredentials, cull through it, and communicate it back to the attacker. HTML5 makes it possible\nfor JavaScript to access data across domains if a new HTTP header called\nAccess-Control-Allow-Origin is defined. With this header, a Web server defines which other\ndomains are allowed to access its domain using cross-origin requests. However, caution should\nbe taken when defining the header because an overly permissive CORS policy will allow a\nmalicious application to communicate with the victim application in an inappropriate way,\nleading to spoofing, data theft, relay and other attacks.\n"
  },
  "find_sec_bugsPERMISSIVE_CORS1": {
    "title": "Prior to HTML5, Web browsers enforced the Same Origin Policy which ensures that in order for\nJavaScript to access the contents of a Web page, both the JavaScript and the Web page must\noriginate from the same domain. Without the Same Origin Policy, a malicious website could serve\nup JavaScript that loads sensitive information from other websites using a client's\ncredentials, cull through it, and communicate it back to the attacker. HTML5 makes it possible\nfor JavaScript to access data across domains if a new HTTP header called\nAccess-Control-Allow-Origin is defined. With this header, a Web server defines which other\ndomains are allowed to access its domain using cross-origin requests. However, caution should\nbe taken when defining the header because an overly permissive CORS policy will allow a\nmalicious application to communicate with the victim application in an inappropriate way,\nleading to spoofing, data theft, relay and other attacks.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Prior to HTML5, Web browsers enforced the Same Origin Policy which ensures that in order for\nJavaScript to access the contents of a Web page, both the JavaScript and the Web page must\noriginate from the same domain. Without the Same Origin Policy, a malicious website could serve\nup JavaScript that loads sensitive information from other websites using a client's\ncredentials, cull through it, and communicate it back to the attacker. HTML5 makes it possible\nfor JavaScript to access data across domains if a new HTTP header called\nAccess-Control-Allow-Origin is defined. With this header, a Web server defines which other\ndomains are allowed to access its domain using cross-origin requests. However, caution should\nbe taken when defining the header because an overly permissive CORS policy will allow a\nmalicious application to communicate with the victim application in an inappropriate way,\nleading to spoofing, data theft, relay and other attacks.\n"
  },
  "find_sec_bugsSCRIPT_ENGINE_INJECTION2": {
    "title": "The software constructs all or part of a code segment using externally-influenced\ninput from an upstream component, but it does not neutralize or incorrectly\nneutralizes special elements that could modify the syntax or behavior of the\nintended code segment.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The software constructs all or part of a code segment using externally-influenced\ninput from an upstream component, but it does not neutralize or incorrectly\nneutralizes special elements that could modify the syntax or behavior of the\nintended code segment.\n"
  },
  "find_sec_bugsREQUESTDISPATCHER_FILE_DISCLOSURE1STRUTS_FILE_DISCLOSURE1SPRING_FILE_DISCLOSURE1": {
    "title": "Constructing a server-side redirect path with user input could allow an\nattacker to download application binaries (including application classes or\njar files) or view arbitrary files within protected directories.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Constructing a server-side redirect path with user input could allow an\nattacker to download application binaries (including application classes or\njar files) or view arbitrary files within protected directories.\n"
  },
  "find_sec_bugsCOOKIE_USAGE1": {
    "title": "The information stored in a custom cookie should not be sensitive or related to the session.\nIn most cases, sensitive data should only be stored in session and referenced by the user's\nsession cookie.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The information stored in a custom cookie should not be sensitive or related to the session.\nIn most cases, sensitive data should only be stored in session and referenced by the user's\nsession cookie.\n"
  },
  "find_sec_bugsHRS_REQUEST_PARAMETER_TO_HTTP_HEADER1": {
    "title": "This code directly writes an HTTP parameter to an HTTP header, which allows for a HTTP\nresponse splitting vulnerability. See http://en.wikipedia.org/wiki/HTTP_response_splitting for\nmore information.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This code directly writes an HTTP parameter to an HTTP header, which allows for a HTTP\nresponse splitting vulnerability. See http://en.wikipedia.org/wiki/HTTP_response_splitting for\nmore information.\n"
  },
  "find_sec_bugsHAZELCAST_SYMMETRIC_ENCRYPTION1": {
    "title": "The network communications for Hazelcast is configured to use a symmetric cipher (probably DES\nor Blowfish). Those ciphers alone do not provide integrity or secure authentication. The use of\nasymmetric encryption is preferred.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The network communications for Hazelcast is configured to use a symmetric cipher (probably DES\nor Blowfish). Those ciphers alone do not provide integrity or secure authentication. The use of\nasymmetric encryption is preferred.\n"
  },
  "find_sec_bugsPADDING_ORACLE1": {
    "title": "This specific mode of CBC with PKCS5Padding is susceptible to padding oracle attacks. An\nadversary could potentially decrypt the message if the system exposed the difference between\nplaintext with invalid padding or valid padding. The distinction between valid and invalid\npadding is usually revealed through distinct error messages being returned for each condition.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This specific mode of CBC with PKCS5Padding is susceptible to padding oracle attacks. An\nadversary could potentially decrypt the message if the system exposed the difference between\nplaintext with invalid padding or valid padding. The distinction between valid and invalid\npadding is usually revealed through distinct error messages being returned for each condition.\n"
  },
  "find_sec_bugsCUSTOM_INJECTION2": {
    "title": "The method identified is susceptible to injection. The input should be validated and properly\nescaped.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The method identified is susceptible to injection. The input should be validated and properly\nescaped.\n"
  },
  "find_sec_bugsNULL_CIPHER1": {
    "title": "The NullCipher implements the Cipher interface by returning ciphertext identical to the\nsupplied plaintext. In a few contexts, such as testing, a NullCipher may be appropriate. Avoid\nusing the NullCipher. Its accidental use can introduce a significant confidentiality risk.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The NullCipher implements the Cipher interface by returning ciphertext identical to the\nsupplied plaintext. In a few contexts, such as testing, a NullCipher may be appropriate. Avoid\nusing the NullCipher. Its accidental use can introduce a significant confidentiality risk.\n"
  },
  "find_sec_bugsCUSTOM_INJECTION1": {
    "title": "The method identified is susceptible to injection. The input should be validated and properly\nescaped.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The method identified is susceptible to injection. The input should be validated and properly\nescaped.\n"
  },
  "find_sec_bugsHARD_CODE_KEY3": {
    "title": "Cryptographic keys should not be kept in the source code. The source code can be widely shared\nin an enterprise environment, and is certainly shared in open source. To be managed safely,\npasswords and secret keys should be stored in separate configuration files or keystores.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Cryptographic keys should not be kept in the source code. The source code can be widely shared\nin an enterprise environment, and is certainly shared in open source. To be managed safely,\npasswords and secret keys should be stored in separate configuration files or keystores.\n"
  },
  "find_sec_bugsHARD_CODE_KEY2": {
    "title": "Cryptographic keys should not be kept in the source code. The source code can be widely shared\nin an enterprise environment, and is certainly shared in open source. To be managed safely,\npasswords and secret keys should be stored in separate configuration files or keystores.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Cryptographic keys should not be kept in the source code. The source code can be widely shared\nin an enterprise environment, and is certainly shared in open source. To be managed safely,\npasswords and secret keys should be stored in separate configuration files or keystores.\n"
  },
  "find_sec_bugsHARD_CODE_KEY1": {
    "title": "Cryptographic keys should not be kept in the source code. The source code can be widely shared\nin an enterprise environment, and is certainly shared in open source. To be managed safely,\npasswords and secret keys should be stored in separate configuration files or keystores.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Cryptographic keys should not be kept in the source code. The source code can be widely shared\nin an enterprise environment, and is certainly shared in open source. To be managed safely,\npasswords and secret keys should be stored in separate configuration files or keystores.\n"
  },
  "find_sec_bugsOVERLY_PERMISSIVE_FILE_PERMISSION2": {
    "title": "Overly permissive file permission\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Overly permissive file permission\n"
  },
  "find_sec_bugsHARD_CODE_KEY4": {
    "title": "Cryptographic keys should not be kept in the source code. The source code can be widely shared\nin an enterprise environment, and is certainly shared in open source. To be managed safely,\npasswords and secret keys should be stored in separate configuration files or keystores.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Cryptographic keys should not be kept in the source code. The source code can be widely shared\nin an enterprise environment, and is certainly shared in open source. To be managed safely,\npasswords and secret keys should be stored in separate configuration files or keystores.\n"
  },
  "find_sec_bugsPREDICTABLE_RANDOM1": {
    "title": "The use of a predictable random value can lead to vulnerabilities when\nused in certain security critical contexts. A quick fix could be to replace\nthe use of java.util.Random with something stronger, such as java.security.SecureRandom.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The use of a predictable random value can lead to vulnerabilities when\nused in certain security critical contexts. A quick fix could be to replace\nthe use of java.util.Random with something stronger, such as java.security.SecureRandom.\n"
  },
  "find_sec_bugsINSECURE_SMTP_SSL1": {
    "title": "Server identity verification is disabled when making SSL connections.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Server identity verification is disabled when making SSL connections.\n"
  },
  "find_sec_bugsMODIFICATION_AFTER_VALIDATION1": {
    "title": "CERT: IDS11-J. Perform any string modifications before validation\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "CERT: IDS11-J. Perform any string modifications before validation\n"
  },
  "find_sec_bugsXPATH_INJECTION1": {
    "title": "The input values included in SQL queries need to be passed in safely. Bind\nvariables in prepared statements can be used to easily mitigate the risk of\nSQL injection.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The input values included in SQL queries need to be passed in safely. Bind\nvariables in prepared statements can be used to easily mitigate the risk of\nSQL injection.\n"
  },
  "find_sec_bugsEXTERNAL_CONFIG_CONTROL1": {
    "title": "Allowing external control of system settings can disrupt service or cause an application to\nbehave in unexpected, and potentially malicious ways. An attacker could cause an error by\nproviding a nonexistent catalog name or connect to an unauthorized portion of the database.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Allowing external control of system settings can disrupt service or cause an application to\nbehave in unexpected, and potentially malicious ways. An attacker could cause an error by\nproviding a nonexistent catalog name or connect to an unauthorized portion of the database.\n"
  },
  "find_sec_bugsFILE_UPLOAD_FILENAME1": {
    "title": "The filename provided by the FileUpload API can be tampered with by the client to reference\nunauthorized files. The provided filename should be properly validated to ensure it's properly\nstructured, contains no unauthorized path characters (e.g., / \\), and refers to an authorized\nfile.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The filename provided by the FileUpload API can be tampered with by the client to reference\nunauthorized files. The provided filename should be properly validated to ensure it's properly\nstructured, contains no unauthorized path characters (e.g., / \\), and refers to an authorized\nfile.\n"
  },
  "find_sec_bugsOGNL_INJECTION1": {
    "title": "\"A expression is built with a dynamic value. The source of the value(s) should be verified to\navoid that unfiltered values fall into this risky code evaluation.\"\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "\"A expression is built with a dynamic value. The source of the value(s) should be verified to\navoid that unfiltered values fall into this risky code evaluation.\"\n"
  },
  "find_sec_bugsXXE_XPATH1XXE_DOCUMENT1": {
    "title": "XML External Entity (XXE) attacks can occur when an XML parser supports XML\nentities while processing XML received from an untrusted source.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "XML External Entity (XXE) attacks can occur when an XML parser supports XML\nentities while processing XML received from an untrusted source.\n"
  },
  "find_sec_bugsPATH_TRAVERSAL_IN1": {
    "title": "A file is opened to read its content. The filename comes from an input parameter. If an\nunfiltered parameter is passed to this file API, files from an arbitrary filesystem location\ncould be read. This rule identifies potential path traversal vulnerabilities. In many cases,\nthe constructed file path cannot be controlled by the user.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A file is opened to read its content. The filename comes from an input parameter. If an\nunfiltered parameter is passed to this file API, files from an arbitrary filesystem location\ncould be read. This rule identifies potential path traversal vulnerabilities. In many cases,\nthe constructed file path cannot be controlled by the user.\n"
  },
  "find_sec_bugsWICKET_XSS11": {
    "title": "Disabling HTML escaping put the application at risk for Cross-Site Scripting (XSS).\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Disabling HTML escaping put the application at risk for Cross-Site Scripting (XSS).\n"
  },
  "find_sec_bugsHTTP_RESPONSE_SPLITTING1": {
    "title": "When an HTTP request contains unexpected CR and LF characters, the server may respond with an\noutput stream that is interpreted as two different HTTP responses (instead of one). An attacker\ncan control the second response and mount attacks such as cross-site scripting and cache\npoisoning attacks.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "When an HTTP request contains unexpected CR and LF characters, the server may respond with an\noutput stream that is interpreted as two different HTTP responses (instead of one). An attacker\ncan control the second response and mount attacks such as cross-site scripting and cache\npoisoning attacks.\n"
  },
  "find_sec_bugsLDAP_ANONYMOUS1": {
    "title": "Without proper access control, executing an LDAP statement that contains a\nuser-controlled value can allow an attacker to abuse poorly configured LDAP\ncontext\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Without proper access control, executing an LDAP statement that contains a\nuser-controlled value can allow an attacker to abuse poorly configured LDAP\ncontext\n"
  },
  "find_sec_bugsAWS_QUERY_INJECTION1": {
    "title": "Constructing SimpleDB queries containing user input can allow an attacker to view unauthorized\nrecords.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Constructing SimpleDB queries containing user input can allow an attacker to view unauthorized\nrecords.\n"
  },
  "find_sec_bugsXXE_DTD_TRANSFORM_FACTORY1XXE_XSLT_TRANSFORM_FACTORY1": {
    "title": "XML External Entity (XXE) attacks can occur when an XML parser supports XML\nentities while processing XML received from an untrusted source.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "XML External Entity (XXE) attacks can occur when an XML parser supports XML\nentities while processing XML received from an untrusted source.\n"
  },
  "find_sec_bugsWEAK_HOSTNAME_VERIFIER1WEAK_TRUST_MANAGER1": {
    "title": "A HostnameVerifier that accept any host are often use because of certificate\nreuse on many hosts. As a consequence, this is vulnerable to Man-in-the-middle\nattacks since the client will trust any certificate.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A HostnameVerifier that accept any host are often use because of certificate\nreuse on many hosts. As a consequence, this is vulnerable to Man-in-the-middle\nattacks since the client will trust any certificate.\n"
  },
  "find_sec_bugsINFORMATION_EXPOSURE_THROUGH_AN_ERROR_MESSAGE1": {
    "title": "The sensitive information may be valuable information on its own (such as a password), or it\nmay be useful for launching other, more deadly attacks. If an attack fails, an attacker may use\nerror information provided by the server to launch another more focused attack. For example, an\nattempt to exploit a path traversal weakness (CWE-22) might yield the full pathname of the\ninstalled application.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The sensitive information may be valuable information on its own (such as a password), or it\nmay be useful for launching other, more deadly attacks. If an attack fails, an attacker may use\nerror information provided by the server to launch another more focused attack. For example, an\nattempt to exploit a path traversal weakness (CWE-22) might yield the full pathname of the\ninstalled application.\n"
  },
  "find_sec_bugsXSS_SERVLET1": {
    "title": "A potential XSS was found. It could be used to execute unwanted JavaScript in a\nclient's browser.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A potential XSS was found. It could be used to execute unwanted JavaScript in a\nclient's browser.\n"
  },
  "find_sec_bugsPATH_TRAVERSAL_OUT1PATH_TRAVERSAL_OUT1": {
    "title": "A file is opened to write to its contents. The filename comes from an input parameter. If an\nunfiltered parameter is passed to this file API, files at an arbitrary filesystem location\ncould be modified. This rule identifies potential path traversal vulnerabilities. In many\ncases, the constructed file path cannot be controlled by the user.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A file is opened to write to its contents. The filename comes from an input parameter. If an\nunfiltered parameter is passed to this file API, files at an arbitrary filesystem location\ncould be modified. This rule identifies potential path traversal vulnerabilities. In many\ncases, the constructed file path cannot be controlled by the user.\n"
  },
  "find_sec_bugsOVERLY_PERMISSIVE_FILE_PERMISSION1": {
    "title": "Overly permissive file permission\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Overly permissive file permission\n"
  },
  "find_sec_bugsRSA_KEY_SIZE1": {
    "title": "Detected an insufficient key size for DSA. NIST recommends a key size\nof 2048 or higher.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected an insufficient key size for DSA. NIST recommends a key size\nof 2048 or higher.\n"
  },
  "find_sec_bugsPT_ABSOLUTE_PATH_TRAVERSAL1": {
    "title": "\"The software uses an HTTP request parameter to construct a pathname that should be within a\nrestricted directory, but it does not properly neutralize absolute path sequences such as\n\"/abs/path\" that can resolve to a location that is outside of that directory. See\nhttp://cwe.mitre.org/data/definitions/36.html for more information.\"\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "\"The software uses an HTTP request parameter to construct a pathname that should be within a\nrestricted directory, but it does not properly neutralize absolute path sequences such as\n\"/abs/path\" that can resolve to a location that is outside of that directory. See\nhttp://cwe.mitre.org/data/definitions/36.html for more information.\"\n"
  },
  "find_sec_bugsLDAP_ENTRY_POISONING1": {
    "title": "Without proper access control, executing an LDAP statement that contains a\nuser-controlled value can allow an attacker to abuse poorly configured LDAP\ncontext\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Without proper access control, executing an LDAP statement that contains a\nuser-controlled value can allow an attacker to abuse poorly configured LDAP\ncontext\n"
  },
  "find_sec_bugsUNVALIDATED_REDIRECT1URL_REWRITING1": {
    "title": "Unvalidated redirects occur when an application redirects a user to a\ndestination URL specified by a user supplied parameter that is not validated.\nSuch vulnerabilities can be used to facilitate phishing attacks.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Unvalidated redirects occur when an application redirects a user to a\ndestination URL specified by a user supplied parameter that is not validated.\nSuch vulnerabilities can be used to facilitate phishing attacks.\n"
  },
  "find_sec_bugsSAML_IGNORE_COMMENTS1": {
    "title": "Ignoring XML comments in SAML may lead to authentication bypass\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Ignoring XML comments in SAML may lead to authentication bypass\n"
  },
  "find_sec_bugsXSS_REQUEST_PARAMETER_TO_SERVLET_WRITER1": {
    "title": "Servlet reflected cross site scripting vulnerability\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Servlet reflected cross site scripting vulnerability\n"
  },
  "find_sec_bugsWEAK_MESSAGE_DIGEST_MD51WEAK_MESSAGE_DIGEST_SHA11": {
    "title": "DES is considered strong ciphers for modern applications. Currently, NIST recommends the usage\nof AES block ciphers instead of DES.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "DES is considered strong ciphers for modern applications. Currently, NIST recommends the usage\nof AES block ciphers instead of DES.\n"
  },
  "find_sec_bugsRSA_NO_PADDING1": {
    "title": "The software uses the RSA algorithm but does not incorporate Optimal Asymmetric\nEncryption Padding (OAEP), which might weaken the encryption.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The software uses the RSA algorithm but does not incorporate Optimal Asymmetric\nEncryption Padding (OAEP), which might weaken the encryption.\n"
  },
  "find_sec_bugsXSS_REQUEST_WRAPPER1": {
    "title": "Avoid using custom XSS filtering. Please use standard sanitization functions.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Avoid using custom XSS filtering. Please use standard sanitization functions.\n"
  },
  "find_sec_bugsEL_INJECTION1": {
    "title": "An expression is built with a dynamic value. The source of the value(s) should be verified to\navoid that unfiltered values fall into this risky code evaluation.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "An expression is built with a dynamic value. The source of the value(s) should be verified to\navoid that unfiltered values fall into this risky code evaluation.\n"
  },
  "find_sec_bugsCIPHER_INTEGRITY1": {
    "title": "The ciphertext produced is susceptible to alteration by an adversary. This mean that the\ncipher provides no way to detect that the data has been tampered with. If the ciphertext can be\ncontrolled by an attacker, it could be altered without detection.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The ciphertext produced is susceptible to alteration by an adversary. This mean that the\ncipher provides no way to detect that the data has been tampered with. If the ciphertext can be\ncontrolled by an attacker, it could be altered without detection.\n"
  },
  "find_sec_bugsPT_RELATIVE_PATH_TRAVERSAL1": {
    "title": "\"The software uses an HTTP request parameter to construct a pathname that should be within a\nrestricted directory, but it does not properly neutralize sequences such as \"..\" that can\nresolve to a location that is outside of that directory. See\nhttp://cwe.mitre.org/data/definitions/23.html for more information.\"\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "\"The software uses an HTTP request parameter to construct a pathname that should be within a\nrestricted directory, but it does not properly neutralize sequences such as \"..\" that can\nresolve to a location that is outside of that directory. See\nhttp://cwe.mitre.org/data/definitions/23.html for more information.\"\n"
  }
}
