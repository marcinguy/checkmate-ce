# -*- coding: utf-8 -*-


issues_data = {
  "stacktracedisclosure": {
    "title": "Stacktrace Disclosure",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Stacktrace information is displayed in a non-Development environment. Accidentally disclosing sensitive stack trace information in a production environment aids an attacker in reconnaissance and information gathering."
  },
  "xmlreadersettingsunsafeparseroverride": {
    "title": "Xmlreadersettings Unsafe Parser Override",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "XmlReaderSettings found with DtdProcessing.Parse on an XmlReader handling a string argument from a public method.  Enabling Document Type Definition (DTD) parsing may cause XML External Entity (XXE) injection if supplied with user-controllable data."
  },
  "ssrf": {
    "title": "Ssrf",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination. Many different options exist to fix this issue depending the use case (Application can send request only to identified and trusted applications, Application can send requests to ANY external IP address or domain name)."
  },
  "datacontractresolver": {
    "title": "Data Contract Resolver",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Only use DataContractResolver if you are completely sure of what information is being serialized. Malicious types can cause unexpected behavior."
  },
  "missinghstsheader": {
    "title": "Missing Hsts Header",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The HSTS HTTP response security header is missing, allowing interaction and communication to be sent over the insecure HTTP protocol."
  },
  "unsignedsecuritytoken": {
    "title": "Unsigned Security Token",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Accepting unsigned security tokens as valid security tokens allows an attacker to remove its signature and potentially forge an identity. As a fix, set RequireSignedTokens to be true."
  },
  "insecurelosformatterdeserialization": {
    "title": "Insecure Losformatter Deserialization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The LosFormatter type is dangerous and is not recommended for data processing. Applications should stop using LosFormatter as soon as possible, even if they believe the data they're processing to be trustworthy. LosFormatter is insecure and can't be made secure"
  },
  "opendirectorylisting": {
    "title": "Open Directory Listing",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "An open directory listing is potentially exposed, potentially revealing sensitive information to attackers."
  },
  "X509Certificate2privkey": {
    "title": "X509Certificate2 Privkey",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "X509Certificate2.PrivateKey is obsolete. Use a method such as GetRSAPrivateKey() or GetECDsaPrivateKey(). Alternatively, use the CopyWithPrivateKey() method to create a new instance with a private key. Further, if you set X509Certificate2.PrivateKey to `null` or set it to another key without deleting it first, the private key will be left on disk. "
  },
  "insecurejavascriptserializerdeserialization": {
    "title": "Insecure Javascriptserializer Deserialization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The SimpleTypeResolver class is insecure and should not be used. Using SimpleTypeResolver to deserialize JSON could allow the remote client to execute malicious code within the app and take control of the web server."
  },
  "usedeprecatedcipheralgorithm": {
    "title": "Use Deprecated Cipher Algorithm",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Usage of deprecated cipher algorithm detected. Use Aes or ChaCha20Poly1305 instead."
  },
  "openredirect": {
    "title": "Open Redirect",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A query string parameter may contain a URL value that could cause the web application to redirect the request to a malicious website controlled by an attacker. Make sure to sanitize this parameter sufficiently."
  },
  "massassignment": {
    "title": "Mass Assignment",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Mass assignment or Autobinding vulnerability in code allows an attacker to execute over-posting attacks, which could create a new parameter in the binding request and manipulate the underlying object in the application."
  },
  "htmlrawjson": {
    "title": "Html Raw Json",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Unencoded JSON in HTML context is vulnerable to cross-site scripting, because `</script>` is not properly encoded."
  },
  "oscommandinjection": {
    "title": "Os Command Injection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component."
  },
  "netwebconfigdebug": {
    "title": "Net Webconfig Debug",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "ASP.NET applications built with `debug` set to true in production may leak debug information to attackers. Debug mode also affects performance and reliability. Set `debug` to `false` or remove it from `<compilation ... />`"
  },
  "insecurenetdatacontractdeserialization": {
    "title": "Insecure Netdatacontract Deserialization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The NetDataContractSerializer type is dangerous and is not recommended for data processing. Applications should stop using NetDataContractSerializer as soon as possible, even if they believe the data they're processing to be trustworthy. NetDataContractSerializer is insecure and can't be made secure"
  },
  "missingorbrokenauthorization": {
    "title": "Missing Or Broken Authorization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Anonymous access shouldn't be allowed unless explicit by design. Access control checks are missing and potentially can be bypassed. This finding violates the principle of least privilege or deny by default, where access should only be permitted for a specific set of roles or conforms to a custom policy or users."
  },
  "xmltextreaderunsafedefaults": {
    "title": "Xmltextreader Unsafe Defaults",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "XmlReaderSettings found with DtdProcessing.Parse on an XmlReader handling a string argument from a public method.  Enabling Document Type Definition (DTD) parsing may cause XML External Entity (XXE) injection if supplied with user-controllable data."
  },
  "jwttokenvalidationparametersnoexpiryvalidation": {
    "title": "Jwt Tokenvalidationparameters No Expiry Validation",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The TokenValidationParameters.$LIFETIME is set to $FALSE, this means the  JWT tokens lifetime is not validated. This can lead to an  JWT token being used after it has expired, which has security implications.  It is recommended to validate the JWT lifetime to ensure only valid tokens are used."
  },
  "useweakrsaencryptionpadding": {
    "title": "Use Weak Rsa Encryption Padding",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "You are using the outdated PKCS#1 v1.5 encryption padding for your RSA key. Use the OAEP padding instead."
  },
  "razortemplateinjection": {
    "title": "Razor Template Injection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "User-controllable string passed to Razor.Parse.  This leads directly to code execution in the context of the process."
  },
  "xmldocumentunsafeparseroverride": {
    "title": "Xmldocument Unsafe Parser Override",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "XmlReaderSettings found with DtdProcessing.Parse on an XmlReader handling a string argument from a public method.  Enabling Document Type Definition (DTD) parsing may cause XML External Entity (XXE) injection if supplied with user-controllable data."
  },
  "useweakrngforkeygeneration": {
    "title": "Use Weak Rng For Keygeneration",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "You are using an insecure random number generator (RNG) to create a cryptographic key. System.Random must never be used for cryptographic purposes. Use System.Security.Cryptography.RandomNumberGenerator instead."
  },
  "httplistenerwildcardbindings": {
    "title": "Http Listener Wildcard Bindings",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The top level wildcard bindings $PREFIX leaves your application open to security vulnerabilities and give attackers more control over where traffic is routed. If you must use wildcards, consider using subdomain wildcard binding. For example, you can use \"*.asdf.gov\" if you own all of \"asdf.gov\"."
  },
  "X509subjectnamevalidation": {
    "title": "X509 Subject Name Validation",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Validating certificates based on subject name is bad practice. Use the X509Certificate2.Verify() method instead."
  },
  "correctnessdoubleepsilonequality": {
    "title": "Correctness Double Epsilon Equality",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Double.Epsilon is defined by .NET as the smallest value that can be added to or subtracted from a zero-value Double.  It is unsuitable for equality comparisons of non-zero Double values. Furthermore, the value of Double.Epsilon is framework and processor architecture dependent.  Wherever possible, developers should prefer the framework Equals() method over custom equality implementations."
  },
  "insecurefastjsondeserialization": {
    "title": "Insecure Fastjson Deserialization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "$type extension has the potential to be unsafe, so use it with common sense and known json sources and not public facing ones to be safe"
  },
  "webconfiginsecurecookiesettings": {
    "title": "Web Config Insecure Cookie Settings",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Cookie Secure flag is explicitly disabled. You should enforce this value to avoid accidentally presenting sensitive cookie values over plaintext HTTP connections."
  },
  "useecbmode": {
    "title": "Use Ecb Mode",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Usage of the insecure ECB mode detected. You should use an authenticated encryption mode instead, which is implemented by the classes AesGcm or ChaCha20Poly1305."
  },
  "ldapinjection": {
    "title": "Ldap Injection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "LDAP queries are constructed dynamically on user-controlled input. This vulnerability in code could lead to an arbitrary LDAP query execution."
  },
  "regularexpressiondosinfinitetimeout": {
    "title": "Regular Expression Dos Infinite Timeout",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Specifying the regex timeout leaves the system vulnerable to a regex-based Denial of Service (DoS) attack.  Consider setting the timeout to a short amount of time like 2 or 3 seconds. If you are sure you need an infinite timeout, double check that your context meets the conditions outlined in the \"Notes to Callers\" section at the bottom of this page:  https://docs.microsoft.com/en-us/dotnet/api/system.text.regularexpressions.regex.-ctor?view=net-6.0"
  },
  "insecuresoapformatterdeserialization": {
    "title": "Insecure Soapformatter Deserialization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The SoapFormatter type is dangerous and is not recommended for data processing. Applications should stop using SoapFormatter as soon as possible, even if they believe the data they're processing to be trustworthy. SoapFormatter is insecure and can't be made secure"
  },
  "netwebconfigtraceenabled": {
    "title": "Net Webconfig Trace Enabled",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "OWASP guidance recommends disabling tracing for production applications to prevent accidental leakage of sensitive application information."
  },
  "unsafepathcombine": {
    "title": "Unsafe Path Combine",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "String argument $A is used to read or write data from a file via Path.Combine without direct sanitization via Path.GetFileName. If the path is user-supplied data this can lead to path traversal."
  },
  "insecurefspicklerdeserialization": {
    "title": "Insecure Fspickler Deserialization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The FsPickler is dangerous and is not recommended for data processing. Default configuration tend to insecure deserialization vulnerability."
  },
  "insecurebinaryformatterdeserialization": {
    "title": "Insecure Binaryformatter Deserialization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The BinaryFormatter type is dangerous and is not recommended for data processing. Applications should stop using BinaryFormatter as soon as possible, even if they believe the data they're processing to be trustworthy. BinaryFormatter is insecure and can't be made secure"
  },
  "memorymarshalcreatespan": {
    "title": "Memory Marshal Create Span",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "MemoryMarshal.CreateSpan and MemoryMarshal.CreateReadOnlySpan should be used with caution, as the length argument is not checked."
  },
  "razoruseofhtmlstring": {
    "title": "Razor Use Of Htmlstring",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "ASP.NET Core MVC provides an HtmlString class which isn't automatically encoded upon output. This should never be used in combination with untrusted input as this will expose an XSS vulnerability."
  },
  "csharpsqli": {
    "title": "Csharp Sqli",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements instead. You can obtain a PreparedStatement using 'SqlCommand' and 'SqlParameter'."
  },
  "mvcmissingantiforgery": {
    "title": "Mvc Missing Antiforgery",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "$METHOD is a state-changing MVC method that does not validate the antiforgery token or do strict content-type checking. State-changing controller methods should either enforce antiforgery tokens or do strict content-type checking to prevent simple HTTP request types from bypassing CORS preflight controls."
  },
  "correctnessregioninfointerop": {
    "title": "Correctness Regioninfo Interop",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Potential inter-process write of RegionInfo $RI via $PIPESTREAM $P that was instantiated with a two-character culture code $REGION.  Per .NET documentation, if you want to persist a RegionInfo object or communicate it between processes, you should instantiate it by using a full culture name rather than a two-letter ISO region code."
  },
  "misconfiguredlockoutoption": {
    "title": "Misconfigured Lockout Option",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A misconfigured lockout mechanism allows an attacker to execute brute-force attacks. Account lockout must be correctly configured and enabled to prevent these attacks."
  },
  "insecurenewtonsoftdeserialization": {
    "title": "Insecure Newtonsoft Deserialization",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "TypeNameHandling $TYPEHANDLER is unsafe and can lead to arbitrary code execution in the context of the process.  Use a custom SerializationBinder whenever using a setting other than TypeNameHandling.None."
  },
  "xpathinjection": {
    "title": "Xpath Injection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "XPath queries are constructed dynamically on user-controlled input. This vulnerability in code could lead to an XPath Injection exploitation."
  },
  "insecuretypefilterlevelfull": {
    "title": "Insecure Typefilterlevel Full",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Using a .NET remoting service can lead to RCE, even if you try to configure TypeFilterLevel. Recommended to switch from .NET Remoting to WCF https://docs.microsoft.com/en-us/dotnet/framework/wcf/migrating-from-net-remoting-to-wcf"
  },
  "correctnesssslcertificatetrusthandshakenotrust": {
    "title": "Correctness Sslcertificatetrust Handshake No Trust",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Sending the trusted CA list increases the size of the handshake request and can leak system configuration information."
  },
  "regularexpressiondos": {
    "title": "Regular Expression Dos",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "An attacker can then cause a program using a regular expression to enter these extreme situations and then hang for a very long time."
  },
  "structuredlogging": {
    "title": "Structured Logging",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "String interpolation in log message obscures the distinction between variables and the log message. Use structured logging instead, where the variables are passed as additional arguments and the interpolation is performed by the logging library. This reduces the possibility of log injection and makes it easier to search through logs."
  }

}
