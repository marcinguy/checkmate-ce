issues_data = {   'AbstractClassWithoutAbstractMethod': {   'categories': ['security'],
                                              'description': 'The abstract '
                                                             'class does not '
                                                             'contain any '
                                                             'abstract '
                                                             'methods. An '
                                                             'abstract class '
                                                             'suggests an '
                                                             'incomplete '
                                                             'implementation, '
                                                             'which is to be '
                                                             'completed by '
                                                             'subclasses '
                                                             'implementing the '
                                                             'abstract '
                                                             'methods. If the '
                                                             'class is '
                                                             'intended to be '
                                                             'used as a base '
                                                             'class only (not '
                                                             'to be '
                                                             'instantiated '
                                                             'directly) a '
                                                             'protected '
                                                             'constructor can '
                                                             'be provided '
                                                             'prevent direct '
                                                             'instantiation.\n'
                                                             'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#AbstractClassWithoutAbstractMethod\n'
                                                             '\n'
                                                             '\n'
                                                             'public abstract '
                                                             'class Foo {\n'
                                                             '  void int '
                                                             'method1() { ... '
                                                             '}\n'
                                                             '  void int '
                                                             'method2() { ... '
                                                             '}\n'
                                                             '  // consider '
                                                             'using abstract '
                                                             'methods or '
                                                             'removing\n'
                                                             '  // the '
                                                             'abstract '
                                                             'modifier and '
                                                             'adding protected '
                                                             'constructors\n'
                                                             '}\n'
                                                             '\n'
                                                             '      ',
                                              'display_name': 'AbstractClassWithoutAbstractMethod',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '1',
                                              'title': 'This abstract class '
                                                       'does not have any '
                                                       'abstract methods'},
    'AbstractClassWithoutAnyMethod': {   'categories': ['security'],
                                         'description': 'If an abstract class '
                                                        'does not provides any '
                                                        'methods, it may be '
                                                        'acting as a simple '
                                                        'data container that '
                                                        'is not meant to be '
                                                        'instantiated. In this '
                                                        'case, it is probably '
                                                        'better to use a '
                                                        'private or protected '
                                                        'constructor in order '
                                                        'to prevent '
                                                        'instantiation than '
                                                        'make the class '
                                                        'misleadingly '
                                                        'abstract.\n'
                                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#AbstractClassWithoutAnyMethod\n'
                                                        '\n'
                                                        '            \n'
                                                        'public class abstract '
                                                        'Example {\n'
                                                        '\tString field;\n'
                                                        '\tint otherField;\n'
                                                        '}\n'
                                                        '            \n'
                                                        '        ',
                                         'display_name': 'AbstractClassWithoutAnyMethod',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'No abstract method which '
                                                  'means that the keyword is '
                                                  'most likely used to prevent '
                                                  'instantiation. Use a '
                                                  'private or protected '
                                                  'constructor instead.'},
    'AbstractNaming': {   'categories': ['security'],
                          'description': 'Abstract classes should be named '
                                         "'AbstractXXX'.\n"
                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#AbstractNaming\n'
                                         '\n'
                                         '\n'
                                         'public abstract class Foo { // '
                                         'should be AbstractFoo\n'
                                         '}\n'
                                         '\n'
                                         '       ',
                          'display_name': 'AbstractNaming',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'Abstract classes should be named '
                                   "'AbstractXXX'"},
    'AccessorClassGeneration': {   'categories': ['security'],
                                   'description': 'Instantiation by way of '
                                                  'private constructors from '
                                                  'outside of the '
                                                  "constructor's class often "
                                                  'causes the generation of an '
                                                  'accessor. A factory method, '
                                                  'or non-privatization of the '
                                                  'constructor can eliminate '
                                                  'this situation. The '
                                                  'generated class file is '
                                                  'actually an interface. It '
                                                  'gives the accessing class '
                                                  'the ability to invoke a new '
                                                  'hidden package scope '
                                                  'constructor that takes the '
                                                  'interface as a '
                                                  'supplementary parameter. '
                                                  'This turns a private '
                                                  'constructor effectively '
                                                  'into one with package '
                                                  'scope, and is challenging '
                                                  'to discern.\n'
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#AccessorClassGeneration\n'
                                                  '\n'
                                                  '  \n'
                                                  'public class Outer {\n'
                                                  ' void method(){\n'
                                                  '  Inner ic = new '
                                                  'Inner();//Causes generation '
                                                  'of accessor class\n'
                                                  ' }\n'
                                                  ' public class Inner {\n'
                                                  '  private Inner(){}\n'
                                                  ' }\n'
                                                  '}\n'
                                                  '  \n'
                                                  '      ',
                                   'display_name': 'AccessorClassGeneration',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'Avoid instantiation through '
                                            'private constructors from outside '
                                            "of the constructor's class."},
    'AccessorMethodGeneration': {   'categories': ['security'],
                                    'description': 'When accessing a private '
                                                   'field / method from '
                                                   'another class, the Java '
                                                   'compiler will generate a '
                                                   'accessor methods with '
                                                   'package-private '
                                                   'visibility. This adds '
                                                   'overhead, and to the dex '
                                                   'method count on Android. '
                                                   'This situation can be '
                                                   'avoided by changing the '
                                                   'visibility of the field / '
                                                   'method from private to '
                                                   'package-private.\n'
                                                   'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#AccessorMethodGeneration\n'
                                                   '\n'
                                                   '\n'
                                                   'public class OuterClass {\n'
                                                   '    private int counter;\n'
                                                   '    /* package */ int id;\n'
                                                   '\n'
                                                   '    public class '
                                                   'InnerClass {\n'
                                                   '        InnerClass() {\n'
                                                   '            '
                                                   'OuterClass.this.counter++; '
                                                   '// wrong accessor method '
                                                   'will be generated\n'
                                                   '        }\n'
                                                   '\n'
                                                   '        public int '
                                                   'getOuterClassId() {\n'
                                                   '            return '
                                                   'OuterClass.this.id; // id '
                                                   'is package-private, no '
                                                   'accessor method needed\n'
                                                   '        }\n'
                                                   '    }\n'
                                                   '}\n'
                                                   ' \n'
                                                   '        ',
                                    'display_name': 'AccessorMethodGeneration',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'Avoid autogenerated methods to '
                                             'access private fields and '
                                             'methods of inner / outer '
                                             'classes'},
    'AddEmptyString': {   'categories': ['security'],
                          'description': 'The conversion of literals to '
                                         'strings by concatenating them with '
                                         'empty strings is inefficient. It is '
                                         'much better to use one of the '
                                         'type-specific toString() methods '
                                         'instead.\n'
                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/optimizations.html#AddEmptyString\n'
                                         '\n'
                                         '             \n'
                                         'String s = "" + 123; \t\t\t\t// '
                                         'inefficient \n'
                                         'String t = Integer.toString(456); \t'
                                         '// preferred approach\n'
                                         '            \n'
                                         '        ',
                          'display_name': 'AddEmptyString',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'Do not add empty strings'},
    'ApexBadCrypto': {   'categories': ['security'],
                         'description': 'The rule makes sure you are using '
                                        'randomly generated IVs and keys for '
                                        '`Crypto` calls. Hard-wiring these '
                                        'values greatly compromises the '
                                        'security of encrypted data.\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-apex/rules/apex/security.html#ApexBadCrypto\n'
                                        '\n'
                                        '            \n'
                                        'public without sharing class Foo {\n'
                                        '    Blob hardCodedIV = '
                                        "Blob.valueOf('Hardcoded IV 123');\n"
                                        '    Blob hardCodedKey = '
                                        "Blob.valueOf('0000000000000000');\n"
                                        "    Blob data = Blob.valueOf('Data to "
                                        "be encrypted');\n"
                                        '    Blob encrypted = '
                                        "Crypto.encrypt('AES128', "
                                        'hardCodedKey, hardCodedIV, data);\n'
                                        '}\n'
                                        '    \n'
                                        '        ',
                         'display_name': 'ApexBadCrypto',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Apex classes should use random IV/key'},
    'ApexCRUDViolation': {   'categories': ['security'],
                             'description': 'The rule validates you are '
                                            'checking for access permissions '
                                            'before a SOQL/SOSL/DML operation. '
                                            'Since Apex runs in system mode '
                                            'not having proper permissions '
                                            'checks results in escalation of '
                                            'privilege and may produce runtime '
                                            'errors. This check forces you to '
                                            'handle such scenarios.\n'
                                            'https://pmd.github.io/pmd-5.8.1/pmd-apex/rules/apex/security.html#ApexCRUDViolationRule\n'
                                            '\n'
                                            '            \n'
                                            'public class Foo {\n'
                                            '    public Contact foo(String '
                                            'status, String ID) {\n'
                                            '        Contact c = [SELECT '
                                            'Status__c FROM Contact WHERE '
                                            'Id=:ID];\n'
                                            '\n'
                                            '        // Make sure we can '
                                            'update the database before even '
                                            'trying\n'
                                            '        if '
                                            '(!Schema.sObjectType.Contact.fields.Name.isUpdateable()) '
                                            '{\n'
                                            '            return null;\n'
                                            '        }\n'
                                            '\n'
                                            '        c.Status__c = status;\n'
                                            '        update c;\n'
                                            '        return c;\n'
                                            '    }\n'
                                            '}\n'
                                            '    \n'
                                            '        ',
                             'display_name': 'ApexCRUDViolation',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Validate CRUD permission before '
                                      'SOQL/DML operation'},
    'ApexCSRF': {   'categories': ['security'],
                    'description': 'Check to avoid making DML operations in '
                                   'Apex class constructor/init method. This '
                                   'prevents modification of the database just '
                                   'by accessing a page.\n'
                                   'https://pmd.github.io/pmd-5.8.1/pmd-apex/rules/apex/security.html#ApexCSRF\n'
                                   '\n'
                                   '            \n'
                                   'public class Foo {\n'
                                   '    public init() {\n'
                                   '        insert data;\n'
                                   '    }\n'
                                   '\n'
                                   '    public Foo() {\n'
                                   '        insert data;\n'
                                   '    }\n'
                                   '}\n'
                                   '    \n'
                                   '        ',
                    'display_name': 'ApexCSRF',
                    'file': '%(issue.file)s',
                    'line': '%(issue.line)s',
                    'severity': '1',
                    'title': 'Avoid making DML operations in Apex class '
                             'constructor/init method'},
    'ApexDangerousMethods': {   'categories': ['security'],
                                'description': 'Checks against calling '
                                               'dangerous methods. For the '
                                               'time being, it reports: * '
                                               "Against `FinancialForce`'s "
                                               '`Configuration.disableTriggerCRUDSecurity()`. '
                                               'Disabling CRUD security opens '
                                               'the door to several attacks '
                                               'and requires manual '
                                               'validation, which is '
                                               'unreliable. * Calling '
                                               '`System.debug` passing '
                                               'sensitive data as parameter, '
                                               'which could lead to exposure '
                                               'of private data.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-apex/rules/apex/security.html#ApexDangerousMethodsRule\n'
                                               '\n'
                                               '            \n'
                                               'public class Foo {\n'
                                               '    public Foo() {\n'
                                               '        '
                                               'Configuration.disableTriggerCRUDSecurity();\n'
                                               '    }\n'
                                               '}\n'
                                               '    \n'
                                               '        ',
                                'display_name': 'ApexDangerousMethods',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Calling potentially dangerous '
                                         'method'},
    'ApexInsecureEndpoint': {   'categories': ['security'],
                                'description': 'Checks against accessing '
                                               'endpoints under plain '
                                               '**http**. You should always '
                                               'use **https** for security.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-apex/rules/apex/security.html#ApexInsecureEndpoint\n'
                                               '\n'
                                               '            \n'
                                               'public without sharing class '
                                               'Foo {\n'
                                               '    void foo() {\n'
                                               '        HttpRequest req = new '
                                               'HttpRequest();\n'
                                               '        '
                                               "req.setEndpoint('http://localhost:com');\n"
                                               '    }\n'
                                               '}\n'
                                               '    \n'
                                               '        ',
                                'display_name': 'ApexInsecureEndpoint',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Apex callouts should use encrypted '
                                         'communication channels'},
    'ApexOpenRedirect': {   'categories': ['security'],
                            'description': 'Checks against redirects to '
                                           'user-controlled locations. This '
                                           'prevents attackers from '
                                           'redirecting users to phishing '
                                           'sites.\n'
                                           'https://pmd.github.io/pmd-5.8.1/pmd-apex/rules/apex/security.html#ApexOpenRedirect\n'
                                           '\n'
                                           '            \n'
                                           'public without sharing class Foo '
                                           '{\n'
                                           '    String unsafeLocation = '
                                           "ApexPage.getCurrentPage().getParameters.get('url_param');\n"
                                           '    PageReference page() {\n'
                                           '       return new '
                                           'PageReference(unsafeLocation);\n'
                                           '    }\n'
                                           '}\n'
                                           '    \n'
                                           '        ',
                            'display_name': 'ApexOpenRedirect',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'Apex classes should safely redirect to a '
                                     'known location'},
    'ApexSOQLInjection': {   'categories': ['security'],
                             'description': 'Detects the usage of untrusted / '
                                            'unescaped variables in DML '
                                            'queries.\n'
                                            'https://pmd.github.io/pmd-5.8.1/pmd-apex/rules/apex/security.html#ApexSOQLInjection\n'
                                            '\n'
                                            '            \n'
                                            'public class Foo {\n'
                                            '    public void test1(String t1) '
                                            '{\n'
                                            "        Database.query('SELECT Id "
                                            "FROM Account' + t1);\n"
                                            '    }\n'
                                            '}\n'
                                            '    \n'
                                            '        ',
                             'display_name': 'ApexSOQLInjection',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Avoid untrusted/unescaped variables in '
                                      'DML query'},
    'ApexSharingViolations': {   'categories': ['security'],
                                 'description': 'Detect classes declared '
                                                'without explicit sharing mode '
                                                'if DML methods are used. This '
                                                'forces the developer to take '
                                                'access restrictions into '
                                                'account before modifying '
                                                'objects.\n'
                                                'https://pmd.github.io/pmd-5.8.1/pmd-apex/rules/apex/security.html#ApexSharingViolations\n'
                                                '\n'
                                                '            \n'
                                                'public without sharing class '
                                                'Foo {\n'
                                                '// DML operation here\n'
                                                '}\n'
                                                '    \n'
                                                '        ',
                                 'display_name': 'ApexSharingViolations',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'Apex classes should declare a '
                                          'sharing model if DML or SOQL/SOSL '
                                          'is used'},
    'ApexSuggestUsingNamedCred': {   'categories': ['security'],
                                     'description': 'Detects hardcoded '
                                                    'credentials used in '
                                                    'requests to an endpoint. '
                                                    'You should refrain from '
                                                    'hardcoding credentials: * '
                                                    'They are hard to mantain '
                                                    'by being mixed in '
                                                    'application code * '
                                                    'Particularly hard to '
                                                    'update them when used '
                                                    'from different classes * '
                                                    'Granting a developer '
                                                    'access to the codebase '
                                                    'means granting knowledge '
                                                    'of credentials, keeping a '
                                                    'two-level access is not '
                                                    'possible. * Using '
                                                    'different credentials for '
                                                    'different environments is '
                                                    'troublesome and '
                                                    'error-prone. Instead, you '
                                                    'should use *Named '
                                                    'Credentials* and a '
                                                    'callout endpoint. For '
                                                    'more information, you can '
                                                    'check '
                                                    '[this](https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_callouts_named_credentials.htm)\n'
                                                    'https://pmd.github.io/pmd-5.8.1/pmd-apex/rules/apex/security.html#ApexSuggestUsingNamedCredRule\n'
                                                    '\n'
                                                    '            \n'
                                                    'public class Foo {\n'
                                                    '    public void '
                                                    'foo(String username, '
                                                    'String password) {\n'
                                                    '        Blob headerValue '
                                                    '= Blob.valueOf(username + '
                                                    "':' + password);\n"
                                                    '        String '
                                                    'authorizationHeader = '
                                                    "'BASIC ' + "
                                                    'EncodingUtil.base64Encode(headerValue);\n'
                                                    '        '
                                                    "req.setHeader('Authorization', "
                                                    'authorizationHeader);\n'
                                                    '    }\n'
                                                    '}\n'
                                                    '    \n'
                                                    '        ',
                                     'display_name': 'ApexSuggestUsingNamedCred',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'Suggest named credentials for '
                                              'authentication'},
    'ApexUnitTestClassShouldHaveAsserts': {   'categories': ['security'],
                                              'description': 'Apex unit tests '
                                                             'should include '
                                                             'at least one '
                                                             'assertion. This '
                                                             'makes the tests '
                                                             'more robust, and '
                                                             'using assert '
                                                             'with messages '
                                                             'provide the '
                                                             'developer a '
                                                             'clearer idea of '
                                                             'what the test '
                                                             'does.\n'
                                                             'https://pmd.github.io/pmd-5.8.1/pmd-apex/rules/apex/apexunit.html#ApexUnitTestClassShouldHaveAsserts\n'
                                                             '\n'
                                                             '            \n'
                                                             '@isTest\n'
                                                             'public class Foo '
                                                             '{\n'
                                                             '   public static '
                                                             'testMethod void '
                                                             'testSomething() '
                                                             '{\n'
                                                             '      Account a '
                                                             '= null;\n'
                                                             '   // This is '
                                                             'better than '
                                                             'having a '
                                                             'NullPointerException\n'
                                                             '   // '
                                                             'System.assertNotEquals(a, '
                                                             "null, 'account "
                                                             "not found');\n"
                                                             '   '
                                                             'a.toString();\n'
                                                             '   }\n'
                                                             '}\n'
                                                             '    \n'
                                                             '        ',
                                              'display_name': 'ApexUnitTestClassShouldHaveAsserts',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '1',
                                              'title': 'Apex unit tests should '
                                                       'System.assert() or '
                                                       'assertEquals() or '
                                                       'assertNotEquals()'},
    'ApexUnitTestShouldNotUseSeeAllDataTrue': {   'categories': ['security'],
                                                  'description': 'Apex unit '
                                                                 'tests should '
                                                                 'not use '
                                                                 '@isTest(seeAllData=true) '
                                                                 'because it '
                                                                 'opens up the '
                                                                 'existing '
                                                                 'database '
                                                                 'data for '
                                                                 'unexpected '
                                                                 'modification '
                                                                 'by tests.\n'
                                                                 'https://pmd.github.io/pmd-5.8.1/pmd-apex/rules/apex/apexunit.html#ApexUnitTestShouldNotUseSeeAllDataTrue\n'
                                                                 '\n'
                                                                 '            \n'
                                                                 '@isTest(seeAllData '
                                                                 '= true)\n'
                                                                 'public class '
                                                                 'Foo {\n'
                                                                 '   public '
                                                                 'static '
                                                                 'testMethod '
                                                                 'void '
                                                                 'testSomething() '
                                                                 '{\n'
                                                                 '      '
                                                                 'Account a = '
                                                                 'null;\n'
                                                                 '   // This '
                                                                 'is better '
                                                                 'than having '
                                                                 'a '
                                                                 'NullPointerException\n'
                                                                 '   // '
                                                                 'System.assertNotEquals(a, '
                                                                 'null, '
                                                                 "'account not "
                                                                 "found');\n"
                                                                 '   '
                                                                 'a.toString();\n'
                                                                 '   }\n'
                                                                 '}\n'
                                                                 '    \n'
                                                                 '        ',
                                                  'display_name': 'ApexUnitTestShouldNotUseSeeAllDataTrue',
                                                  'file': '%(issue.file)s',
                                                  'line': '%(issue.line)s',
                                                  'severity': '1',
                                                  'title': 'Apex unit tests '
                                                           'should not use '
                                                           '@isTest(seeAllData '
                                                           '= true)'},
    'ApexXSSFromEscapeFalse': {   'categories': ['security'],
                                  'description': 'Reports on calls to '
                                                 '`addError` with disabled '
                                                 'escaping. The message passed '
                                                 'to `addError` will be '
                                                 'displayed directly to the '
                                                 'user in the UI, making it '
                                                 'prime ground for XSS attacks '
                                                 'if unescaped.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-apex/rules/apex/security.html#ApexXSSFromEscapeFalse\n'
                                                 '\n'
                                                 '            \n'
                                                 'public without sharing class '
                                                 'Foo {\n'
                                                 '    '
                                                 'Trigger.new[0].addError(vulnerableHTMLGoesHere, '
                                                 'false);\n'
                                                 '}\n'
                                                 '    \n'
                                                 '        ',
                                  'display_name': 'ApexXSSFromEscapeFalse',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'Apex classes should escape Strings '
                                           'in error messages'},
    'ApexXSSFromURLParam': {   'categories': ['security'],
                               'description': 'Makes sure that all values '
                                              'obtained from URL parameters '
                                              'are properly escaped / '
                                              'sanitized to avoid XSS '
                                              'attacks.\n'
                                              'https://pmd.github.io/pmd-5.8.1/pmd-apex/rules/apex/security.html#ApexXSSFromURLParam\n'
                                              '\n'
                                              '            \n'
                                              'public without sharing class '
                                              'Foo {\n'
                                              '    String unescapedstring = '
                                              "ApexPage.getCurrentPage().getParameters.get('url_param');\n"
                                              '    String usedLater = '
                                              'unescapedstring;\n'
                                              '}\n'
                                              '    \n'
                                              '        ',
                               'display_name': 'ApexXSSFromURLParam',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Apex classes should escape/sanitize '
                                        'Strings obtained from URL parameters'},
    'AppendCharacterWithChar': {   'categories': ['security'],
                                   'description': 'Avoid concatenating '
                                                  'characters as strings in '
                                                  'StringBuffer/StringBuilder.append '
                                                  'methods.\n'
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strings.html#AppendCharacterWithChar\n'
                                                  '\n'
                                                  '\n'
                                                  'StringBuffer sb = new '
                                                  'StringBuffer();\n'
                                                  'sb.append("a");\t\t // '
                                                  'avoid this\n'
                                                  '\n'
                                                  'StringBuffer sb = new '
                                                  'StringBuffer();\n'
                                                  "sb.append('a');\t\t// use "
                                                  'this instead\n'
                                                  '\n'
                                                  '    ',
                                   'display_name': 'AppendCharacterWithChar',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'Avoid appending characters as '
                                            'strings in StringBuffer.append.'},
    'ArrayIsStoredDirectly': {   'categories': ['security'],
                                 'description': 'Constructors and methods '
                                                'receiving arrays should clone '
                                                'objects and store the copy. '
                                                'This prevents future changes '
                                                'from the user from affecting '
                                                'the original array.\n'
                                                'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/sunsecure.html#ArrayIsStoredDirectly\n'
                                                '\n'
                                                '  \n'
                                                'public class Foo {\n'
                                                '  private String [] x;\n'
                                                '    public void foo (String '
                                                '[] param) {\n'
                                                "      // Don't do this, make "
                                                'a copy of the array at least\n'
                                                '      this.x=param;\n'
                                                '    }\n'
                                                '}\n'
                                                '  \n'
                                                '      ',
                                 'display_name': 'ArrayIsStoredDirectly',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': "The user-supplied array ''{0}'' is "
                                          'stored directly.'},
    'AssignmentInOperand': {   'categories': ['security'],
                               'description': 'Avoid assignments in operands; '
                                              'this can make code more '
                                              'complicated and harder to '
                                              'read.\n'
                                              'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#AssignmentInOperand\n'
                                              '\n'
                                              '  \n'
                                              'public void bar() {\n'
                                              '    int x = 2;\n'
                                              '    if ((x = getX()) == 3) {\n'
                                              '      '
                                              'System.out.println("3!");\n'
                                              '    }\n'
                                              '}\n'
                                              '  \n'
                                              '  ',
                               'display_name': 'AssignmentInOperand',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Avoid assignments in operands'},
    'AssignmentToNonFinalStatic': {   'categories': ['security'],
                                      'description': 'Identifies a possible '
                                                     'unsafe usage of a static '
                                                     'field.\n'
                                                     'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#AssignmentToNonFinalStatic\n'
                                                     '\n'
                                                     '   \n'
                                                     'public class StaticField '
                                                     '{\n'
                                                     '   static int x;\n'
                                                     '   public '
                                                     'FinalFields(int y) {\n'
                                                     '    x = y; // unsafe\n'
                                                     '   }\n'
                                                     '}\n'
                                                     '   \n'
                                                     '       ',
                                      'display_name': 'AssignmentToNonFinalStatic',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'Possible unsafe assignment to '
                                               'a non-final static field in a '
                                               'constructor.'},
    'AtLeastOneConstructor': {   'categories': ['security'],
                                 'description': 'Each class should declare at '
                                                'least one constructor.\n'
                                                'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#AtLeastOneConstructor\n'
                                                '\n'
                                                '  \n'
                                                'public class Foo {\n'
                                                '   // missing constructor\n'
                                                '  public void doSomething() { '
                                                '... }\n'
                                                '  public void doOtherThing { '
                                                '... }\n'
                                                '}\n'
                                                '  \n'
                                                '  ',
                                 'display_name': 'AtLeastOneConstructor',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'Each class should declare at least '
                                          'one constructor'},
    'AvoidAccessibilityAlteration': {   'categories': ['security'],
                                        'description': 'Methods such as '
                                                       'getDeclaredConstructors(), '
                                                       'getDeclaredConstructor(Class[]) '
                                                       'and setAccessible(), '
                                                       'as the interface '
                                                       'PrivilegedAction, '
                                                       'allows for the runtime '
                                                       'alteration of '
                                                       'variable, class, or '
                                                       'method visibility, '
                                                       'even if they are '
                                                       'private. This violates '
                                                       'the principle of '
                                                       'encapsulation.\n'
                                                       'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#AvoidAccessibilityAlteration\n'
                                                       '\n'
                                                       '            \n'
                                                       '\n'
                                                       'import '
                                                       'java.lang.reflect.AccessibleObject;\n'
                                                       'import '
                                                       'java.lang.reflect.Method;\n'
                                                       'import '
                                                       'java.security.PrivilegedAction;\n'
                                                       '\n'
                                                       'public class Violation '
                                                       '{\n'
                                                       '  public void '
                                                       'invalidCallsInMethod() '
                                                       'throws '
                                                       'SecurityException, '
                                                       'NoSuchMethodException '
                                                       '{\n'
                                                       '    // Possible call '
                                                       'to forbidden '
                                                       'getDeclaredConstructors\n'
                                                       '    Class[] '
                                                       'arrayOfClass = new '
                                                       'Class[1];\n'
                                                       '    '
                                                       'this.getClass().getDeclaredConstructors();\n'
                                                       '    '
                                                       'this.getClass().getDeclaredConstructor(arrayOfClass);\n'
                                                       '    Class clazz = '
                                                       'this.getClass();\n'
                                                       '    '
                                                       'clazz.getDeclaredConstructor(arrayOfClass);\n'
                                                       '    '
                                                       'clazz.getDeclaredConstructors();\n'
                                                       '      // Possible call '
                                                       'to forbidden '
                                                       'setAccessible\n'
                                                       '    '
                                                       'clazz.getMethod("", '
                                                       'arrayOfClass).setAccessible(false);\n'
                                                       '    '
                                                       'AccessibleObject.setAccessible(null, '
                                                       'false);\n'
                                                       '    '
                                                       'Method.setAccessible(null, '
                                                       'false);\n'
                                                       '    Method[] '
                                                       'methodsArray = '
                                                       'clazz.getMethods();\n'
                                                       '    int nbMethod;\n'
                                                       '    for ( nbMethod = '
                                                       '0; nbMethod < '
                                                       'methodsArray.length; '
                                                       'nbMethod++ ) {\n'
                                                       '      '
                                                       'methodsArray[nbMethod].setAccessible(false);\n'
                                                       '    }\n'
                                                       '\n'
                                                       '      // Possible call '
                                                       'to forbidden '
                                                       'PrivilegedAction\n'
                                                       '    PrivilegedAction '
                                                       'priv = '
                                                       '(PrivilegedAction) new '
                                                       'Object(); priv.run();\n'
                                                       '  }\n'
                                                       '}\n'
                                                       '          \n'
                                                       '      ',
                                        'display_name': 'AvoidAccessibilityAlteration',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'You should modify visibility '
                                                 'of class or methods using '
                                                 'getDeclaredConstructors(), '
                                                 'getDeclaredConstructor(Class[]), '
                                                 'setAccessible() or '
                                                 'PrivilegedAction.'},
    'AvoidArrayLoops': {   'categories': ['security'],
                           'description': 'Instead of manually copying data '
                                          'between two arrays, use the '
                                          'efficient System.arraycopy method '
                                          'instead.\n'
                                          'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/optimizations.html#AvoidArrayLoops\n'
                                          '\n'
                                          '    \n'
                                          'public class Test {\n'
                                          '  public void bar() {\n'
                                          '    int[] a = new int[10];\n'
                                          '    int[] b = new int[10];\n'
                                          '    for (int i=0;i<10;i++) {\n'
                                          '      b[i]=a[i];\n'
                                          '    }\n'
                                          '  }\n'
                                          '}\n'
                                          '     // this will trigger the rule\n'
                                          '     for (int i=0;i<10;i++) {\n'
                                          '       b[i]=a[c[i]];\n'
                                          '     }\n'
                                          '\n'
                                          '  }\n'
                                          '}\n'
                                          '    \n'
                                          '      ',
                           'display_name': 'AvoidArrayLoops',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'System.arraycopy is more efficient'},
    'AvoidAssertAsIdentifier': {   'categories': ['security'],
                                   'description': "Use of the term 'assert' "
                                                  'will conflict with newer '
                                                  'versions of Java since it '
                                                  'is a reserved word.\n'
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/migrating.html#AvoidAssertAsIdentifier\n'
                                                  '\n'
                                                  '  \n'
                                                  'public class A {\n'
                                                  '\tpublic  class foo {\n'
                                                  '\t\tString assert = "foo";\n'
                                                  '\t}\n'
                                                  '}\n'
                                                  '  \n'
                                                  '      ',
                                   'display_name': 'AvoidAssertAsIdentifier',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'Avoid using assert as an '
                                            'identifier; it became a reserved '
                                            'word in JDK 1.4'},
    'AvoidAxisNavigation': {   'categories': ['security'],
                               'description': "Avoid using the 'following' or "
                                              "'preceeding' axes whenever "
                                              'possible, as these can cut '
                                              'through 100% of the document in '
                                              'the worst case. Also, try to '
                                              "avoid using 'descendant' or "
                                              "'descendant-self' axes, as if "
                                              "you're at the top of the "
                                              'Document, it necessarily means '
                                              'cutting through 100% of the '
                                              'document.\n'
                                              'https://pmd.github.io/pmd-5.8.1/pmd-xml/rules/xsl/xpath.html#AvoidAxisNavigation\n'
                                              '\n'
                                              ' \n'
                                              ' <xsl:variable name="var" '
                                              'select="//item/descendant::child"/>\n'
                                              ' \n'
                                              '     ',
                               'display_name': 'AvoidAxisNavigation',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Axis navigation has the largest '
                                        'impact when writing an XPath query.'},
    'AvoidBranchingStatementAsLastInLoop': {   'categories': ['security'],
                                               'description': 'Using a '
                                                              'branching '
                                                              'statement as '
                                                              'the last part '
                                                              'of a loop may '
                                                              'be a bug, '
                                                              'and/or is '
                                                              'confusing. '
                                                              'Ensure that the '
                                                              'usage is not a '
                                                              'bug, or '
                                                              'consider using '
                                                              'another '
                                                              'approach.\n'
                                                              'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#AvoidBranchingStatementAsLastInLoop\n'
                                                              '\n'
                                                              '            \n'
                                                              '  // unusual '
                                                              'use of '
                                                              'branching '
                                                              'statement in a '
                                                              'loop\n'
                                                              'for (int i = 0; '
                                                              'i < 10; i++) {\n'
                                                              '\tif (i*i <= '
                                                              '25) {\n'
                                                              '\t\tcontinue;\n'
                                                              '\t}\n'
                                                              '\tbreak;\n'
                                                              '}\n'
                                                              '\n'
                                                              '  // this makes '
                                                              'more sense...\n'
                                                              'for (int i = 0; '
                                                              'i < 10; i++) {\n'
                                                              '\tif (i*i > 25) '
                                                              '{\n'
                                                              '\t\tbreak;\n'
                                                              '\t}\n'
                                                              '}\n'
                                                              '            \n'
                                                              '        ',
                                               'display_name': 'AvoidBranchingStatementAsLastInLoop',
                                               'file': '%(issue.file)s',
                                               'line': '%(issue.line)s',
                                               'severity': '1',
                                               'title': 'Avoid using a '
                                                        'branching statement '
                                                        'as the last in a '
                                                        'loop.'},
    'AvoidCallingFinalize': {   'categories': ['security'],
                                'description': 'The method Object.finalize() '
                                               'is called by the garbage '
                                               'collector on an object when '
                                               'garbage collection determines '
                                               'that there are no more '
                                               'references to the object. It '
                                               'should not be invoked by '
                                               'application logic.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/finalizers.html#AvoidCallingFinalize\n'
                                               '\n'
                                               '\n'
                                               'void foo() {\n'
                                               '\tBar b = new Bar();\n'
                                               '\tb.finalize();\n'
                                               '}\n'
                                               '\n'
                                               '      ',
                                'display_name': 'AvoidCallingFinalize',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Avoid calling finalize() explicitly'},
    'AvoidCatchingGenericException': {   'categories': ['security'],
                                         'description': 'Avoid catching '
                                                        'generic exceptions '
                                                        'such as '
                                                        'NullPointerException, '
                                                        'RuntimeException, '
                                                        'Exception in '
                                                        'try-catch block\n'
                                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strictexception.html#AvoidCatchingGenericException\n'
                                                        '\n'
                                                        '    \n'
                                                        'package '
                                                        'com.igate.primitive;\n'
                                                        '    \n'
                                                        'public class '
                                                        'PrimitiveType {\n'
                                                        '    \n'
                                                        '  public void '
                                                        'downCastPrimitiveType() '
                                                        '{\n'
                                                        '    try {\n'
                                                        '      '
                                                        'System.out.println(" '
                                                        'i [" + i + "]");\n'
                                                        '    } catch(Exception '
                                                        'e) {\n'
                                                        '      '
                                                        'e.printStackTrace();\n'
                                                        '    } '
                                                        'catch(RuntimeException '
                                                        'e) {\n'
                                                        '      '
                                                        'e.printStackTrace();\n'
                                                        '    } '
                                                        'catch(NullPointerException '
                                                        'e) {\n'
                                                        '      '
                                                        'e.printStackTrace();\n'
                                                        '    }\n'
                                                        '  } \n'
                                                        '}\n'
                                                        '    \n'
                                                        '    ',
                                         'display_name': 'AvoidCatchingGenericException',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'Avoid catching generic '
                                                  'exceptions such as '
                                                  'NullPointerException, '
                                                  'RuntimeException, Exception '
                                                  'in try-catch block'},
    'AvoidCatchingNPE': {   'categories': ['security'],
                            'description': 'Code should never throw '
                                           'NullPointerExceptions under normal '
                                           'circumstances. A catch block may '
                                           'hide the original error, causing '
                                           'other, more subtle problems later '
                                           'on.\n'
                                           'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strictexception.html#AvoidCatchingNPE\n'
                                           '  \n'
                                           'public class Foo {\n'
                                           '  void bar() {\n'
                                           '    try {\n'
                                           '      // do something\n'
                                           '      }  catch '
                                           '(NullPointerException npe) {\n'
                                           '    }\n'
                                           '  }\n'
                                           '}\n'
                                           '\n'
                                           '    ',
                            'display_name': 'AvoidCatchingNPE',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'Avoid catching NullPointerException; '
                                     'consider removing the cause of the NPE.'},
    'AvoidCatchingThrowable': {   'categories': ['security'],
                                  'description': 'Catching Throwable errors is '
                                                 'not recommended since its '
                                                 'scope is very broad. It '
                                                 'includes runtime issues such '
                                                 'as OutOfMemoryError that '
                                                 'should be exposed and '
                                                 'managed separately.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strictexception.html#AvoidCatchingThrowable\n'
                                                 '\n'
                                                 '\t\n'
                                                 'public void bar() {\n'
                                                 '\ttry {\n'
                                                 '     // do something\n'
                                                 '    } catch (Throwable th) '
                                                 '{  // should not catch '
                                                 'Throwable\n'
                                                 '\t\tth.printStackTrace();\n'
                                                 '    }\n'
                                                 '  }\n'
                                                 '\t\n'
                                                 '      ',
                                  'display_name': 'AvoidCatchingThrowable',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'A catch statement should never '
                                           'catch throwable since it includes '
                                           'errors.'},
    'AvoidDecimalLiteralsInBigDecimalConstructor': {   'categories': [   'security'],
                                                       'description': 'One '
                                                                      'might '
                                                                      'assume '
                                                                      'that '
                                                                      'the '
                                                                      'result '
                                                                      'of "new '
                                                                      'BigDecimal(0.1)" '
                                                                      'is '
                                                                      'exactly '
                                                                      'equal '
                                                                      'to 0.1, '
                                                                      'but it '
                                                                      'is '
                                                                      'actually '
                                                                      'equal '
                                                                      'to '
                                                                      '.1000000000000000055511151231257827021181583404541015625. '
                                                                      'This is '
                                                                      'because '
                                                                      '0.1 '
                                                                      'cannot '
                                                                      'be '
                                                                      'represented '
                                                                      'exactly '
                                                                      'as a '
                                                                      'double '
                                                                      '(or as '
                                                                      'a '
                                                                      'binary '
                                                                      'fraction '
                                                                      'of any '
                                                                      'finite '
                                                                      'length). '
                                                                      'Thus, '
                                                                      'the '
                                                                      'long '
                                                                      'value '
                                                                      'that is '
                                                                      'being '
                                                                      'passed '
                                                                      'in to '
                                                                      'the '
                                                                      'constructor '
                                                                      'is not '
                                                                      'exactly '
                                                                      'equal '
                                                                      'to 0.1, '
                                                                      'appearances '
                                                                      'notwithstanding. '
                                                                      'The '
                                                                      '(String) '
                                                                      'constructor, '
                                                                      'on the '
                                                                      'other '
                                                                      'hand, '
                                                                      'is '
                                                                      'perfectly '
                                                                      'predictable: '
                                                                      "'new "
                                                                      'BigDecimal("0.1")\' '
                                                                      'is '
                                                                      'exactly '
                                                                      'equal '
                                                                      'to 0.1, '
                                                                      'as one '
                                                                      'would '
                                                                      'expect. '
                                                                      'Therefore, '
                                                                      'it is '
                                                                      'generally '
                                                                      'recommended '
                                                                      'that '
                                                                      'the '
                                                                      '(String) '
                                                                      'constructor '
                                                                      'be used '
                                                                      'in '
                                                                      'preference '
                                                                      'to this '
                                                                      'one.\n'
                                                                      'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#AvoidDecimalLiteralsInBigDecimalConstructor\n'
                                                                      '\n'
                                                                      '\n'
                                                                      'BigDecimal '
                                                                      'bd = '
                                                                      'new '
                                                                      'BigDecimal(1.123);\t\t'
                                                                      '// loss '
                                                                      'of '
                                                                      'precision, '
                                                                      'this '
                                                                      'would '
                                                                      'trigger '
                                                                      'the '
                                                                      'rule\n'
                                                                      '\n'
                                                                      'BigDecimal '
                                                                      'bd = '
                                                                      'new '
                                                                      'BigDecimal("1.123");   \t'
                                                                      '// '
                                                                      'preferred '
                                                                      'approach\n'
                                                                      '\n'
                                                                      'BigDecimal '
                                                                      'bd = '
                                                                      'new '
                                                                      'BigDecimal(12);     \t'
                                                                      '// '
                                                                      'preferred '
                                                                      'approach, '
                                                                      'ok for '
                                                                      'integer '
                                                                      'values\n'
                                                                      '\n'
                                                                      '  ',
                                                       'display_name': 'AvoidDecimalLiteralsInBigDecimalConstructor',
                                                       'file': '%(issue.file)s',
                                                       'line': '%(issue.line)s',
                                                       'severity': '1',
                                                       'title': 'Avoid '
                                                                'creating '
                                                                'BigDecimal '
                                                                'with a '
                                                                'decimal '
                                                                '(float/double) '
                                                                'literal. Use '
                                                                'a String '
                                                                'literal'},
    'AvoidDeeplyNestedIfStmts': {   'categories': ['security'],
                                    'description': 'Avoid creating deeply '
                                                   'nested if-then statements '
                                                   'since they are harder to '
                                                   'read and error-prone to '
                                                   'maintain.\n'
                                                   'https://pmd.github.io/pmd-5.8.1/pmd-vm/rules/vm/basic.html#AvoidDeeplyNestedIfStmts\n',
                                    'display_name': 'AvoidDeeplyNestedIfStmts',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'Deeply nested if..then '
                                             'statements are hard to read'},
    'AvoidDmlStatementsInLoops': {   'categories': ['security'],
                                     'description': 'Avoid DML statements '
                                                    'inside loops to avoid '
                                                    'hitting the DML governor '
                                                    'limit. Instead, try to '
                                                    'batch up the data into a '
                                                    'list and invoke your DML '
                                                    'once on that list of data '
                                                    'outside the loop.\n'
                                                    'https://pmd.github.io/pmd-5.8.1/pmd-apex/rules/apex/performance.html#AvoidDmlStatementsInLoops\n'
                                                    '\n'
                                                    '\n'
                                                    'public class Something {\n'
                                                    '\tpublic void foo() {  \n'
                                                    '\t\tfor (Integer i = 0; i '
                                                    '< 151; i++) {\n'
                                                    '\t\t    Account account;\n'
                                                    '\t\t    ...\n'
                                                    '\t\t    insert account;\n'
                                                    '\t\t}\n'
                                                    '\t}\n'
                                                    '}\n'
                                                    '\n'
                                                    '    ',
                                     'display_name': 'AvoidDmlStatementsInLoops',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'Avoid DML statements inside '
                                              'loops'},
    'AvoidDollarSigns': {   'categories': ['security'],
                            'description': 'Avoid using dollar signs in '
                                           'variable/method/class/interface '
                                           'names.\n'
                                           'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#AvoidDollarSigns\n'
                                           '\n'
                                           '   \n'
                                           'public class Fo$o {  // not a '
                                           'recommended name\n'
                                           '}\n'
                                           '   \n'
                                           '       ',
                            'display_name': 'AvoidDollarSigns',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'Avoid using dollar signs in '
                                     'variable/method/class/interface names'},
    'AvoidDuplicateLiterals': {   'categories': ['security'],
                                  'description': 'Code containing duplicate '
                                                 'String literals can usually '
                                                 'be improved by declaring the '
                                                 'String as a constant field.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strings.html#AvoidDuplicateLiterals\n'
                                                 '\n'
                                                 '\n'
                                                 'private void bar() {\n'
                                                 '     buz("Howdy");\n'
                                                 '     buz("Howdy");\n'
                                                 '     buz("Howdy");\n'
                                                 '     buz("Howdy");\n'
                                                 ' }\n'
                                                 ' private void buz(String x) '
                                                 '{}\n'
                                                 '\n'
                                                 '    ',
                                  'display_name': 'AvoidDuplicateLiterals',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'The String literal {0} appears {1} '
                                           'times in this file; the first '
                                           'occurrence is on line {2}'},
    'AvoidEnumAsIdentifier': {   'categories': ['security'],
                                 'description': "Use of the term 'enum' will "
                                                'conflict with newer versions '
                                                'of Java since it is a '
                                                'reserved word.\n'
                                                'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/migrating.html#AvoidEnumAsIdentifier\n'
                                                '\n'
                                                '  \n'
                                                'public class A {\n'
                                                '\tpublic  class foo {\n'
                                                '\t\tString enum = "foo";\n'
                                                '\t}\n'
                                                '}\n'
                                                '  \n'
                                                '      ',
                                 'display_name': 'AvoidEnumAsIdentifier',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'Avoid using enum as an identifier; '
                                          "it's a reserved word in JDK 1.5"},
    'AvoidFieldNameMatchingMethodName': {   'categories': ['security'],
                                            'description': 'It can be '
                                                           'confusing to have '
                                                           'a field name with '
                                                           'the same name as a '
                                                           'method. While this '
                                                           'is permitted, '
                                                           'having information '
                                                           '(field) and '
                                                           'actions (method) '
                                                           'is not clear '
                                                           'naming. Developers '
                                                           'versed in '
                                                           'Smalltalk often '
                                                           'prefer this '
                                                           'approach as the '
                                                           'methods denote '
                                                           'accessor methods.\n'
                                                           'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#AvoidFieldNameMatchingMethodName\n'
                                                           '\n'
                                                           '\n'
                                                           'public class Foo '
                                                           '{\n'
                                                           '\tObject bar;\n'
                                                           '\t// bar is data '
                                                           'or an action or '
                                                           'both?\n'
                                                           '\tvoid bar() {\n'
                                                           '\t}\n'
                                                           '}\n'
                                                           '\n'
                                                           '      ',
                                            'display_name': 'AvoidFieldNameMatchingMethodName',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'Field {0} has the same '
                                                     'name as a method'},
    'AvoidFieldNameMatchingTypeName': {   'categories': ['security'],
                                          'description': 'It is somewhat '
                                                         'confusing to have a '
                                                         'field name matching '
                                                         'the declaring class '
                                                         'name. This probably '
                                                         'means that type '
                                                         'and/or field names '
                                                         'should be chosen '
                                                         'more carefully.\n'
                                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#AvoidFieldNameMatchingTypeName\n'
                                                         '\n'
                                                         '\n'
                                                         'public class Foo '
                                                         'extends Bar {\n'
                                                         '\tint foo;\t// There '
                                                         'is probably a better '
                                                         'name that can be '
                                                         'used\n'
                                                         '}\n'
                                                         '\n'
                                                         '      ',
                                          'display_name': 'AvoidFieldNameMatchingTypeName',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'It is somewhat confusing '
                                                   'to have a field name '
                                                   'matching the declaring '
                                                   'class name'},
    'AvoidFinalLocalVariable': {   'categories': ['security'],
                                   'description': 'Avoid using final local '
                                                  'variables, turn them into '
                                                  'fields.\n'
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#AvoidFinalLocalVariable\n'
                                                  '\n'
                                                  'public class MyClass {\n'
                                                  '    public void foo() {\n'
                                                  '        final String '
                                                  'finalLocalVariable;\n'
                                                  '    }\n'
                                                  '}\n'
                                                  '       ',
                                   'display_name': 'AvoidFinalLocalVariable',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'Avoid using final local '
                                            'variables, turn them into fields'},
    'AvoidGlobalModifier': {   'categories': ['security'],
                               'description': 'Global classes should be '
                                              'avoided (especially in managed '
                                              'packages) as they can never be '
                                              'deleted or changed in '
                                              'signature. Always check twice '
                                              'if something needs to be '
                                              'global. Many interfaces (e.g. '
                                              'Batch) required global '
                                              "modifiers in the past but don't "
                                              "require this anymore. Don't "
                                              'lock yourself in.\n'
                                              'https://pmd.github.io/pmd-5.8.1/pmd-apex/rules/apex/style.html#AvoidGlobalModifier\n'
                                              '\n'
                                              'global class Unchangeable {\n'
                                              '\tglobal UndeletableType '
                                              'unchangable(UndeletableType '
                                              'param) {\n'
                                              '\t\t// ...\n'
                                              '\t}\n'
                                              '}\n'
                                              '\n'
                                              '    ',
                               'display_name': 'AvoidGlobalModifier',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Avoid using global modifier'},
    'AvoidInstanceofChecksInCatchClause': {   'categories': ['security'],
                                              'description': 'Each caught '
                                                             'exception type '
                                                             'should be '
                                                             'handled in its '
                                                             'own catch '
                                                             'clause.\n'
                                                             'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#AvoidInstanceofChecksInCatchClause\n'
                                                             '\n'
                                                             '\n'
                                                             'try { // Avoid '
                                                             'this\n'
                                                             ' // do '
                                                             'something\n'
                                                             '} catch '
                                                             '(Exception ee) '
                                                             '{\n'
                                                             ' if (ee '
                                                             'instanceof '
                                                             'IOException) {\n'
                                                             '  cleanup();\n'
                                                             ' }\n'
                                                             '}\n'
                                                             'try {  // Prefer '
                                                             'this:\n'
                                                             ' // do '
                                                             'something\n'
                                                             '} catch '
                                                             '(IOException ee) '
                                                             '{\n'
                                                             ' cleanup();\n'
                                                             '}\n'
                                                             '\n'
                                                             '      ',
                                              'display_name': 'AvoidInstanceofChecksInCatchClause',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '1',
                                              'title': 'An instanceof check is '
                                                       'being performed on the '
                                                       'caught exception.  '
                                                       'Create a separate '
                                                       'catch clause for this '
                                                       'exception type.'},
    'AvoidInstantiatingObjectsInLoops': {   'categories': ['security'],
                                            'description': 'New objects '
                                                           'created within '
                                                           'loops should be '
                                                           'checked to see if '
                                                           'they can created '
                                                           'outside them and '
                                                           'reused.\n'
                                                           'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/optimizations.html#AvoidInstantiatingObjectsInLoops\n'
                                                           '\n'
                                                           '\n'
                                                           'public class '
                                                           'Something {\n'
                                                           '\tpublic static '
                                                           'void main( String '
                                                           'as[] ) {  \n'
                                                           '\t\tfor (int i = '
                                                           '0; i < 10; i++) {\n'
                                                           '\t\t    Foo f = '
                                                           'new Foo(); // '
                                                           'Avoid this '
                                                           'whenever you can '
                                                           "it's really "
                                                           'expensive\n'
                                                           '\t\t}\n'
                                                           '\t}\n'
                                                           '}\n'
                                                           '\n'
                                                           '    ',
                                            'display_name': 'AvoidInstantiatingObjectsInLoops',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'Avoid instantiating new '
                                                     'objects inside loops'},
    'AvoidLiteralsInIfCondition': {   'categories': ['security'],
                                      'description': 'Avoid using hard-coded '
                                                     'literals in conditional '
                                                     'statements. By declaring '
                                                     'them as static variables '
                                                     'or private members with '
                                                     'descriptive names '
                                                     'maintainability is '
                                                     'enhanced. By default, '
                                                     'the literals "-1" and '
                                                     '"0" are ignored. More '
                                                     'exceptions can be '
                                                     'defined with the '
                                                     'property '
                                                     '"ignoreMagicNumbers".\n'
                                                     'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#AvoidLiteralsInIfCondition\n'
                                                     '\n'
                                                     '\n'
                                                     'private static final int '
                                                     'MAX_NUMBER_OF_REQUESTS = '
                                                     '10;\n'
                                                     '\n'
                                                     'public void '
                                                     'checkRequests() {\n'
                                                     '\n'
                                                     '    if (i == 10) '
                                                     '{                        '
                                                     '// magic number, buried '
                                                     'in a method\n'
                                                     '      doSomething();\n'
                                                     '    }\n'
                                                     '\n'
                                                     '    if (i == '
                                                     'MAX_NUMBER_OF_REQUESTS) '
                                                     '{    // preferred '
                                                     'approach\n'
                                                     '      doSomething();\n'
                                                     '    }\n'
                                                     '\n'
                                                     '    if '
                                                     "(aString.indexOf('.') != "
                                                     '-1) {}     // magic '
                                                     'number -1, by default '
                                                     'ignored\n'
                                                     '    if '
                                                     "(aString.indexOf('.') >= "
                                                     '0) { }     // '
                                                     'alternative approach\n'
                                                     '\n'
                                                     '    if (aDouble > 0.0) '
                                                     '{}                  // '
                                                     'magic number 0.0\n'
                                                     '    if (aDouble >= '
                                                     'Double.MIN_VALUE) {}    '
                                                     '// preferred approach\n'
                                                     '}\n'
                                                     '\n'
                                                     '    ',
                                      'display_name': 'AvoidLiteralsInIfCondition',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'Avoid using Literals in '
                                               'Conditional Statements'},
    'AvoidLogicInTrigger': {   'categories': ['security'],
                               'description': 'As triggers do not allow '
                                              'methods like regular classes '
                                              'they are less flexible and '
                                              'suited to apply good '
                                              'encapsulation style. Therefore '
                                              'delegate the triggers work to a '
                                              'regular class (often called '
                                              'Trigger handler class). See '
                                              'more here: '
                                              'https://developer.salesforce.com/page/Trigger_Frameworks_and_Apex_Trigger_Best_Practices\n'
                                              'https://pmd.github.io/pmd-5.8.1/pmd-apex/rules/apex/style.html#AvoidLogicInTrigger\n'
                                              '\n'
                                              'trigger Accounts on Account '
                                              '(before insert, before update, '
                                              'before delete, after insert, '
                                              'after update, after delete, '
                                              'after undelete) {\n'
                                              '\tfor(Account acc : '
                                              'Trigger.new) {           \n'
                                              '\t\tif(Trigger.isInsert) {\n'
                                              '\t\t\t...\n'
                                              '\t\t}\n'
                                              '\t\t\n'
                                              '\t\t...\n'
                                              '\t\t\n'
                                              '\t\tif(Trigger.isDelete) {\n'
                                              '\t\t\t...\n'
                                              '\t\t}\n'
                                              '\t}\n'
                                              '}\n'
                                              '\n'
                                              '    ',
                               'display_name': 'AvoidLogicInTrigger',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Avoid logic in triggers'},
    'AvoidLosingExceptionInformation': {   'categories': ['security'],
                                           'description': 'Statements in a '
                                                          'catch block that '
                                                          'invoke accessors on '
                                                          'the exception '
                                                          'without using the '
                                                          'information only '
                                                          'add to code size. '
                                                          'Either remove the '
                                                          'invocation, or use '
                                                          'the return result.\n'
                                                          'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strictexception.html#AvoidLosingExceptionInformation\n'
                                                          '\n'
                                                          '\n'
                                                          'public void bar() '
                                                          '{\n'
                                                          '\ttry {\n'
                                                          '\t\t// do '
                                                          'something\n'
                                                          '\t} catch '
                                                          '(SomeException se) '
                                                          '{\n'
                                                          '\t\t'
                                                          'se.getMessage();\n'
                                                          '\t}\n'
                                                          '}\n'
                                                          '\n'
                                                          '\t\t',
                                           'display_name': 'AvoidLosingExceptionInformation',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'Avoid statements in a '
                                                    'catch block that invoke '
                                                    'accessors on the '
                                                    'exception without using '
                                                    'the information'},
    'AvoidMultipleUnaryOperators': {   'categories': ['security'],
                                       'description': 'The use of multiple '
                                                      'unary operators may be '
                                                      'problematic, and/or '
                                                      'confusing. Ensure that '
                                                      'the intended usage is '
                                                      'not a bug, or consider '
                                                      'simplifying the '
                                                      'expression.\n'
                                                      'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#AvoidMultipleUnaryOperators\n'
                                                      '\n'
                                                      '            \n'
                                                      '// These are typo bugs, '
                                                      'or at best needlessly '
                                                      'complex and confusing:\n'
                                                      'int i = - -1;\n'
                                                      'int j = + - +1;\n'
                                                      'int z = ~~2;\n'
                                                      'boolean b = !!true;\n'
                                                      'boolean c = !!!true;\n'
                                                      '\n'
                                                      '// These are better:\n'
                                                      'int i = 1;\n'
                                                      'int j = -1;\n'
                                                      'int z = 2;\n'
                                                      'boolean b = true;\n'
                                                      'boolean c = false;\n'
                                                      '\n'
                                                      '// And these just make '
                                                      'your brain hurt:\n'
                                                      'int i = ~-2;\n'
                                                      'int j = -~7;\n'
                                                      '            \n'
                                                      '        ',
                                       'display_name': 'AvoidMultipleUnaryOperators',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'Using multiple unary '
                                                'operators may be a bug, '
                                                'and/or is confusing.'},
    'AvoidPrefixingMethodParameters': {   'categories': ['security'],
                                          'description': 'Prefixing parameters '
                                                         "by 'in' or 'out' "
                                                         'pollutes the name of '
                                                         'the parameters and '
                                                         'reduces code '
                                                         'readability. To '
                                                         'indicate whether or '
                                                         'not a parameter will '
                                                         'be modify in a '
                                                         'method, its better '
                                                         'to document method '
                                                         'behavior with '
                                                         'Javadoc.\n'
                                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#AvoidPrefixingMethodParameters\n'
                                                         '\n'
                                                         '// Not really clear\n'
                                                         'public class Foo {\n'
                                                         '  public void bar(\n'
                                                         '      int '
                                                         'inLeftOperand,\n'
                                                         '      Result '
                                                         'outRightOperand) {\n'
                                                         '      '
                                                         'outRightOperand.setValue(inLeftOperand '
                                                         '* '
                                                         'outRightOperand.getValue());\n'
                                                         '  }\n'
                                                         '}\n'
                                                         '        ',
                                          'display_name': 'AvoidPrefixingMethodParameters',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'Avoid prefixing parameters '
                                                   'by in, out or inOut. Uses '
                                                   'Javadoc to document this '
                                                   'behavior.'},
    'AvoidPrintStackTrace': {   'categories': ['security'],
                                'description': 'Avoid printStackTrace(); use a '
                                               'logger call instead.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/logging-java.html#AvoidPrintStackTrace\n'
                                               '\n'
                                               '\n'
                                               'class Foo {\n'
                                               '  void bar() {\n'
                                               '    try {\n'
                                               '     // do something\n'
                                               '    } catch (Exception e) {\n'
                                               '     e.printStackTrace();\n'
                                               '     }\n'
                                               '   }\n'
                                               '}\n'
                                               '\n'
                                               '           ',
                                'display_name': 'AvoidPrintStackTrace',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Avoid printStackTrace(); use a '
                                         'logger call instead.'},
    'AvoidProtectedFieldInFinalClass': {   'categories': ['security'],
                                           'description': 'Do not use '
                                                          'protected fields in '
                                                          'final classes since '
                                                          'they cannot be '
                                                          'subclassed. Clarify '
                                                          'your intent by '
                                                          'using private or '
                                                          'package access '
                                                          'modifiers instead.\n'
                                                          'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#AvoidProtectedFieldInFinalClass\n'
                                                          '\n'
                                                          '\n'
                                                          'public final class '
                                                          'Bar {\n'
                                                          '  private int x;\n'
                                                          '  protected int y;  '
                                                          '// bar cannot be '
                                                          'subclassed, so is y '
                                                          'really private or '
                                                          'package visible?\n'
                                                          '  Bar() {}\n'
                                                          '}\n'
                                                          ' \n'
                                                          '         ',
                                           'display_name': 'AvoidProtectedFieldInFinalClass',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'Avoid protected fields in '
                                                    'a final class.  Change to '
                                                    'private or package '
                                                    'access.'},
    'AvoidProtectedMethodInFinalClassNotExtending': {   'categories': [   'security'],
                                                        'description': 'Do not '
                                                                       'use '
                                                                       'protected '
                                                                       'methods '
                                                                       'in '
                                                                       'most '
                                                                       'final '
                                                                       'classes '
                                                                       'since '
                                                                       'they '
                                                                       'cannot '
                                                                       'be '
                                                                       'subclassed. '
                                                                       'This '
                                                                       'should '
                                                                       'only '
                                                                       'be '
                                                                       'allowed '
                                                                       'in '
                                                                       'final '
                                                                       'classes '
                                                                       'that '
                                                                       'extend '
                                                                       'other '
                                                                       'classes '
                                                                       'with '
                                                                       'protected '
                                                                       'methods '
                                                                       '(whose '
                                                                       'visibility '
                                                                       'cannot '
                                                                       'be '
                                                                       'reduced). '
                                                                       'Clarify '
                                                                       'your '
                                                                       'intent '
                                                                       'by '
                                                                       'using '
                                                                       'private '
                                                                       'or '
                                                                       'package '
                                                                       'access '
                                                                       'modifiers '
                                                                       'instead.\n'
                                                                       'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#AvoidProtectedMethodInFinalClassNotExtending\n'
                                                                       '\n'
                                                                       '\n'
                                                                       'public '
                                                                       'final '
                                                                       'class '
                                                                       'Foo {\n'
                                                                       '  '
                                                                       'private '
                                                                       'int '
                                                                       'bar() '
                                                                       '{}\n'
                                                                       '  '
                                                                       'protected '
                                                                       'int '
                                                                       'baz() '
                                                                       '{} // '
                                                                       'Foo '
                                                                       'cannot '
                                                                       'be '
                                                                       'subclassed, '
                                                                       'and '
                                                                       "doesn't "
                                                                       'extend '
                                                                       'anything, '
                                                                       'so is '
                                                                       'baz() '
                                                                       'really '
                                                                       'private '
                                                                       'or '
                                                                       'package '
                                                                       'visible?\n'
                                                                       '}\n'
                                                                       ' \n'
                                                                       '         ',
                                                        'display_name': 'AvoidProtectedMethodInFinalClassNotExtending',
                                                        'file': '%(issue.file)s',
                                                        'line': '%(issue.line)s',
                                                        'severity': '1',
                                                        'title': 'Avoid '
                                                                 'protected '
                                                                 'methods in a '
                                                                 'final class '
                                                                 "that doesn't "
                                                                 'extend '
                                                                 'anything '
                                                                 'other than '
                                                                 'Object.  '
                                                                 'Change to '
                                                                 'private or '
                                                                 'package '
                                                                 'access.'},
    'AvoidReassigningParameters': {   'categories': ['security'],
                                      'description': 'Reassigning values to '
                                                     'incoming parameters is '
                                                     'not recommended. Use '
                                                     'temporary local '
                                                     'variables instead.\n'
                                                     'https://pmd.github.io/pmd-5.8.1/pmd-vm/rules/vm/basic.html#AvoidReassigningParameters\n',
                                      'display_name': 'AvoidReassigningParameters',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'Avoid reassigning macro '
                                               "parameters such as ''{0}''"},
    'AvoidRethrowingException': {   'categories': ['security'],
                                    'description': 'Catch blocks that merely '
                                                   'rethrow a caught exception '
                                                   'only add to code size and '
                                                   'runtime complexity.\n'
                                                   'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strictexception.html#AvoidRethrowingException\n'
                                                   '  \n'
                                                   'public void bar() {\n'
                                                   '    try {\n'
                                                   '    // do something\n'
                                                   '    }  catch '
                                                   '(SomeException se) {\n'
                                                   '       throw se;\n'
                                                   '    }\n'
                                                   '}\n'
                                                   '  \n'
                                                   '    ',
                                    'display_name': 'AvoidRethrowingException',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'A catch statement that catches '
                                             'an exception only to rethrow it '
                                             'should be avoided.'},
    'AvoidSoqlInLoops': {   'categories': ['security'],
                            'description': 'New objects created within loops '
                                           'should be checked to see if they '
                                           'can created outside them and '
                                           'reused.\n'
                                           'https://pmd.github.io/pmd-5.8.1/pmd-apex/rules/apex/performance.html#AvoidSoqlInLoops\n'
                                           '\n'
                                           'public class Something {\n'
                                           '\tpublic static void main( String '
                                           'as[] ) {  \n'
                                           '\t\tfor (Integer i = 0; i < 10; '
                                           'i++) {\n'
                                           '\t\t\tList<Account> accounts = '
                                           '[SELECT Id FROM Account];\n'
                                           '\t\t}\n'
                                           '\t}\n'
                                           '}\n'
                                           '\n'
                                           '    ',
                            'display_name': 'AvoidSoqlInLoops',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'Avoid Soql queries inside loops'},
    'AvoidStringBufferField': {   'categories': ['security'],
                                  'description': 'StringBuffers/StringBuilders '
                                                 'can grow considerably, and '
                                                 'so may become a source of '
                                                 'memory leaks if held within '
                                                 'objects with long '
                                                 'lifetimes.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strings.html#AvoidStringBufferField\n'
                                                 '\n'
                                                 '\n'
                                                 'public class Foo {\n'
                                                 '\tprivate StringBuffer '
                                                 'buffer;\t// potential memory '
                                                 'leak as an instance '
                                                 'variable;\n'
                                                 '}\n'
                                                 '\n'
                                                 '\t\t',
                                  'display_name': 'AvoidStringBufferField',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'StringBuffers can grow quite a '
                                           'lot, and so may become a source of '
                                           'memory leak (if the owning class '
                                           'has a long life time).'},
    'AvoidSynchronizedAtMethodLevel': {   'categories': ['security'],
                                          'description': 'Method-level '
                                                         'synchronization can '
                                                         'cause problems when '
                                                         'new code is added to '
                                                         'the method. '
                                                         'Block-level '
                                                         'synchronization '
                                                         'helps to ensure that '
                                                         'only the code that '
                                                         'needs '
                                                         'synchronization gets '
                                                         'it.\n'
                                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#AvoidSynchronizedAtMethodLevel\n'
                                                         '\n'
                                                         '\n'
                                                         'public class Foo {\n'
                                                         '  // Try to avoid '
                                                         'this:\n'
                                                         '  synchronized void '
                                                         'foo() {\n'
                                                         '  }\n'
                                                         '  // Prefer this:\n'
                                                         '  void bar() {\n'
                                                         '    '
                                                         'synchronized(this) '
                                                         '{\n'
                                                         '    }\n'
                                                         '  }\n'
                                                         '\n'
                                                         '  // Try to avoid '
                                                         'this for static '
                                                         'methods:\n'
                                                         '  static '
                                                         'synchronized void '
                                                         'fooStatic() {\n'
                                                         '  }\n'
                                                         '\n'
                                                         '  // Prefer this:\n'
                                                         '  static void '
                                                         'barStatic() {\n'
                                                         '    '
                                                         'synchronized(Foo.class) '
                                                         '{\n'
                                                         '    }\n'
                                                         '  }\n'
                                                         '}\n'
                                                         '\n'
                                                         '      ',
                                          'display_name': 'AvoidSynchronizedAtMethodLevel',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'Use block level rather '
                                                   'than method level '
                                                   'synchronization'},
    'AvoidThreadGroup': {   'categories': ['security'],
                            'description': 'Avoid using java.lang.ThreadGroup; '
                                           'although it is intended to be used '
                                           'in a threaded environment it '
                                           'contains methods that are not '
                                           'thread-safe.\n'
                                           'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#AvoidThreadGroup\n'
                                           '\n'
                                           '    \n'
                                           'public class Bar {\n'
                                           '\tvoid buz() {\n'
                                           '\t\tThreadGroup tg = new '
                                           'ThreadGroup("My threadgroup") ;\n'
                                           '\t\ttg = new ThreadGroup(tg, "my '
                                           'thread group");\n'
                                           '\t\ttg = '
                                           'Thread.currentThread().getThreadGroup();\n'
                                           '\t\ttg = '
                                           'System.getSecurityManager().getThreadGroup();\n'
                                           '\t}\n'
                                           '}\n'
                                           '    \n'
                                           '      ',
                            'display_name': 'AvoidThreadGroup',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'Avoid using java.lang.ThreadGroup; it is '
                                     'not thread safe'},
    'AvoidThrowingNewInstanceOfSameException': {   'categories': ['security'],
                                                   'description': 'Catch '
                                                                  'blocks that '
                                                                  'merely '
                                                                  'rethrow a '
                                                                  'caught '
                                                                  'exception '
                                                                  'wrapped '
                                                                  'inside a '
                                                                  'new '
                                                                  'instance of '
                                                                  'the same '
                                                                  'type only '
                                                                  'add to code '
                                                                  'size and '
                                                                  'runtime '
                                                                  'complexity.\n'
                                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strictexception.html#AvoidThrowingNewInstanceOfSameException\n'
                                                                  '  \n'
                                                                  'public void '
                                                                  'bar() {\n'
                                                                  '      try '
                                                                  '{\n'
                                                                  '       // '
                                                                  'do '
                                                                  'something\n'
                                                                  '      }  '
                                                                  'catch '
                                                                  '(SomeException '
                                                                  'se) {\n'
                                                                  '         // '
                                                                  'harmless '
                                                                  'comment      \n'
                                                                  '           '
                                                                  'throw new '
                                                                  'SomeException(se);\n'
                                                                  '      }\n'
                                                                  '}\n'
                                                                  '  \n'
                                                                  '    ',
                                                   'display_name': 'AvoidThrowingNewInstanceOfSameException',
                                                   'file': '%(issue.file)s',
                                                   'line': '%(issue.line)s',
                                                   'severity': '1',
                                                   'title': 'A catch statement '
                                                            'that catches an '
                                                            'exception only to '
                                                            'wrap it in a new '
                                                            'instance of the '
                                                            'same type of '
                                                            'exception and '
                                                            'throw it should '
                                                            'be avoided'},
    'AvoidThrowingNullPointerException': {   'categories': ['security'],
                                             'description': 'Avoid throwing '
                                                            'NullPointerExceptions. '
                                                            'These are '
                                                            'confusing because '
                                                            'most people will '
                                                            'assume that the '
                                                            'virtual machine '
                                                            'threw it. '
                                                            'Consider using an '
                                                            'IllegalArgumentException '
                                                            'instead; this '
                                                            'will be clearly '
                                                            'seen as a '
                                                            'programmer-initiated '
                                                            'exception.\n'
                                                            'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strictexception.html#AvoidThrowingNullPointerException\n'
                                                            '\n'
                                                            '        \n'
                                                            'public class Foo '
                                                            '{\n'
                                                            '  void bar() {\n'
                                                            '    throw new '
                                                            'NullPointerException();\n'
                                                            '  }\n'
                                                            '}\n'
                                                            '  \n'
                                                            '      ',
                                             'display_name': 'AvoidThrowingNullPointerException',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': 'Avoid throwing null '
                                                      'pointer exceptions.'},
    'AvoidThrowingRawExceptionTypes': {   'categories': ['security'],
                                          'description': 'Avoid throwing '
                                                         'certain exception '
                                                         'types. Rather than '
                                                         'throw a raw '
                                                         'RuntimeException, '
                                                         'Throwable, '
                                                         'Exception, or Error, '
                                                         'use a subclassed '
                                                         'exception or error '
                                                         'instead.\n'
                                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strictexception.html#AvoidThrowingRawExceptionTypes\n'
                                                         '\n'
                                                         '      \n'
                                                         'public class Foo {\n'
                                                         '  public void bar() '
                                                         'throws Exception {\n'
                                                         '    throw new '
                                                         'Exception();\n'
                                                         '   }\n'
                                                         '}\n'
                                                         '\n'
                                                         '    ',
                                          'display_name': 'AvoidThrowingRawExceptionTypes',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'Avoid throwing raw '
                                                   'exception types.'},
    'AvoidTrailingComma': {   'categories': ['security'],
                              'description': 'This rule helps improve code '
                                             'portability due to differences '
                                             'in browser treatment of trailing '
                                             'commas in object or array '
                                             'literals.\n'
                                             'https://pmd.github.io/pmd-5.8.1/pmd-javascript/rules/ecmascript/basic.html#AvoidTrailingComma\n'
                                             '\n'
                                             '\n'
                                             'function(arg) {\n'
                                             '    var obj1 = { a : 1 }; // Ok\n'
                                             '    var arr1 = [ 1, 2 ]; // Ok\n'
                                             '\n'
                                             '    var obj2 = { a : 1, }; // '
                                             'Syntax error in some browsers!\n'
                                             '    var arr2 = [ 1, 2, ]; // '
                                             'Length 2 or 3 depending on the '
                                             'browser!\n'
                                             '}\n'
                                             '\n'
                                             '        ',
                              'display_name': 'AvoidTrailingComma',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'Avoid trailing commas in object or '
                                       'array literals'},
    'AvoidUsingHardCodedIP': {   'categories': ['security'],
                                 'description': 'Application with hard-coded '
                                                'IP addresses can become '
                                                'impossible to deploy in some '
                                                'cases. Externalizing IP '
                                                'adresses is preferable.\n'
                                                'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#AvoidUsingHardCodedIP\n'
                                                '\n'
                                                '\t    \n'
                                                'public class Foo {\n'
                                                '\tprivate String ip = '
                                                '"127.0.0.1"; \t// not '
                                                'recommended\n'
                                                '}\n'
                                                '\t    \n'
                                                '\t    ',
                                 'display_name': 'AvoidUsingHardCodedIP',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'Do not hard code the IP address '
                                          '${variableName}'},
    'AvoidUsingNativeCode': {   'categories': ['security'],
                                'description': 'Unnecessary reliance on Java '
                                               'Native Interface (JNI) calls '
                                               'directly reduces application '
                                               'portability and increases the '
                                               'maintenance burden.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#AvoidUsingNativeCode\n'
                                               '\n'
                                               '            \n'
                                               'public class SomeJNIClass {\n'
                                               '\n'
                                               '     public SomeJNIClass() {\n'
                                               '         '
                                               'System.loadLibrary("nativelib");\n'
                                               '     }\n'
                                               '\n'
                                               '     static {\n'
                                               '         '
                                               'System.loadLibrary("nativelib");\n'
                                               '         }\n'
                                               '\n'
                                               '     public void '
                                               'invalidCallsInMethod() throws '
                                               'SecurityException, '
                                               'NoSuchMethodException {\n'
                                               '         '
                                               'System.loadLibrary("nativelib");\n'
                                               '     }\n'
                                               '}\n'
                                               '            \n'
                                               '        ',
                                'display_name': 'AvoidUsingNativeCode',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'The use of native code is not '
                                         'recommended.'},
    'AvoidUsingOctalValues': {   'categories': ['security'],
                                 'description': 'Integer literals should not '
                                                'start with zero since this '
                                                'denotes that the rest of '
                                                'literal will be interpreted '
                                                'as an octal value.\n'
                                                'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#AvoidUsingOctalValues\n'
                                                '\n'
                                                '\t\t    \n'
                                                'int i = 012;\t// set i with '
                                                '10 not 12\n'
                                                'int j = 010;\t// set j with 8 '
                                                'not 10\n'
                                                'k = i * j;\t\t// set k with '
                                                '80 not 120\n'
                                                '\t\t    \n'
                                                '    ',
                                 'display_name': 'AvoidUsingOctalValues',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'Do not start a literal by 0 unless '
                                          "it's an octal value"},
    'AvoidUsingShortType': {   'categories': ['security'],
                               'description': "Java uses the 'short' type to "
                                              'reduce memory usage, not to '
                                              'optimize calculation. In fact, '
                                              'the JVM does not have any '
                                              'arithmetic capabilities for the '
                                              'short type: the JVM must '
                                              'convert the short into an int, '
                                              'do the proper calculation and '
                                              'convert the int back to a '
                                              'short. Thus any storage gains '
                                              'found through use of the '
                                              "'short' type may be offset by "
                                              'adverse impacts on '
                                              'performance.\n'
                                              'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#AvoidUsingShortType\n'
                                              '\n'
                                              '            \n'
                                              'public class UsingShort {\n'
                                              '   private short doNotUseShort '
                                              '= 0;\n'
                                              '\n'
                                              '   public UsingShort() {\n'
                                              '    short shouldNotBeUsed = 1;\n'
                                              '    doNotUseShort += '
                                              'shouldNotBeUsed;\n'
                                              '  }\n'
                                              '}\n'
                                              '       \n'
                                              '     ',
                               'display_name': 'AvoidUsingShortType',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Do not use the short type'},
    'AvoidUsingVolatile': {   'categories': ['security'],
                              'description': "Use of the keyword 'volatile' is "
                                             'generally used to fine tune a '
                                             'Java application, and therefore, '
                                             'requires a good expertise of the '
                                             'Java Memory Model. Moreover, its '
                                             'range of action is somewhat '
                                             'misknown. Therefore, the '
                                             'volatile keyword should not be '
                                             'used for maintenance purpose and '
                                             'portability.\n'
                                             'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#AvoidUsingVolatile\n'
                                             '\n'
                                             '      \n'
                                             'public class ThrDeux {\n'
                                             '  private volatile String var1;\t'
                                             '// not suggested\n'
                                             '  private          String var2;\t'
                                             '// preferred\n'
                                             '}\n'
                                             '      \n'
                                             '    ',
                              'display_name': 'AvoidUsingVolatile',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'Use of modifier volatile is not '
                                       'recommended.'},
    'AvoidWithStatement': {   'categories': ['security'],
                              'description': "Avoid using with - it's bad "
                                             'news\n'
                                             'https://pmd.github.io/pmd-5.8.1/pmd-javascript/rules/ecmascript/basic.html#AvoidWithStatement\n'
                                             '\n'
                                             'with (object) {\n'
                                             '  property = 3; // Might be on '
                                             'object, might be on window: who '
                                             'knows.\n'
                                             '}\n'
                                             '      ',
                              'display_name': 'AvoidWithStatement',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': "Avoid using with - it's bad news"},
    'BadComparison': {   'categories': ['security'],
                         'description': 'Avoid equality comparisons with '
                                        'Double.NaN. Due to the implicit lack '
                                        'of representation precision when '
                                        'comparing floating point numbers '
                                        'these are likely to cause logic '
                                        'errors.\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#BadComparison\n'
                                        '\n'
                                        '  \n'
                                        'boolean x = (y == Double.NaN);\n'
                                        '  \n'
                                        '      ',
                         'display_name': 'BadComparison',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Avoid equality comparisons with Double.NaN'},
    'BeanMembersShouldSerialize': {   'categories': ['security'],
                                      'description': 'If a class is a bean, or '
                                                     'is referenced by a bean '
                                                     'directly or indirectly '
                                                     'it needs to be '
                                                     'serializable. Member '
                                                     'variables need to be '
                                                     'marked as transient, '
                                                     'static, or have accessor '
                                                     'methods in the class. '
                                                     'Marking variables as '
                                                     'transient is the safest '
                                                     'and easiest '
                                                     'modification. Accessor '
                                                     'methods should follow '
                                                     'the Java naming '
                                                     'conventions, i.e. for a '
                                                     'variable named foo, '
                                                     'getFoo() and setFoo() '
                                                     'accessor methods should '
                                                     'be provided.\n'
                                                     'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/javabeans.html#BeanMembersShouldSerialize\n'
                                                     '\n'
                                                     '\n'
                                                     'private transient int '
                                                     "someFoo;  // good, it's "
                                                     'transient\n'
                                                     'private static int '
                                                     'otherFoo;    // also OK\n'
                                                     'private int '
                                                     'moreFoo;            // '
                                                     'OK, has proper '
                                                     'accessors, see below\n'
                                                     'private int '
                                                     'badFoo;             // '
                                                     'bad, should be marked '
                                                     'transient\n'
                                                     '\n'
                                                     'private void '
                                                     'setMoreFoo(int '
                                                     'moreFoo){\n'
                                                     '      this.moreFoo = '
                                                     'moreFoo;\n'
                                                     '}\n'
                                                     '\n'
                                                     'private int '
                                                     'getMoreFoo(){\n'
                                                     '      return '
                                                     'this.moreFoo;\n'
                                                     '}\n'
                                                     '\n'
                                                     '\n'
                                                     '    ',
                                      'display_name': 'BeanMembersShouldSerialize',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'Found non-transient, '
                                               'non-static member. Please mark '
                                               'as transient or provide '
                                               'accessors.'},
    'BigIntegerInstantiation': {   'categories': ['security'],
                                   'description': "Don't create instances of "
                                                  'already existing BigInteger '
                                                  '(BigInteger.ZERO, '
                                                  'BigInteger.ONE) and for '
                                                  'Java 1.5 onwards, '
                                                  'BigInteger.TEN and '
                                                  'BigDecimal '
                                                  '(BigDecimal.ZERO, '
                                                  'BigDecimal.ONE, '
                                                  'BigDecimal.TEN)\n'
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#BigIntegerInstantiation\n'
                                                  '\n'
                                                  '\n'
                                                  'BigInteger bi = new '
                                                  'BigInteger(1);\t\t// '
                                                  'reference BigInteger.ONE '
                                                  'instead\n'
                                                  'BigInteger bi2 = new '
                                                  'BigInteger("0");\t// '
                                                  'reference BigInteger.ZERO '
                                                  'instead\n'
                                                  'BigInteger bi3 = new '
                                                  'BigInteger(0.0);\t// '
                                                  'reference BigInteger.ZERO '
                                                  'instead\n'
                                                  'BigInteger bi4;\n'
                                                  'bi4 = new '
                                                  'BigInteger(0);\t\t\t\t// '
                                                  'reference BigInteger.ZERO '
                                                  'instead\n'
                                                  '\n'
                                                  '  ',
                                   'display_name': 'BigIntegerInstantiation',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': "Don't create instances of already "
                                            'existing BigInteger and '
                                            'BigDecimal (ZERO, ONE, TEN)'},
    'BooleanGetMethodName': {   'categories': ['security'],
                                'description': 'Methods that return boolean '
                                               'results should be named as '
                                               'predicate statements to denote '
                                               "this. I.e, 'isReady()', "
                                               "'hasValues()', 'canCommit()', "
                                               "'willFail()', etc. Avoid the "
                                               "use of the 'get' prefix for "
                                               'these methods.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#BooleanGetMethodName\n'
                                               '\n'
                                               '            \n'
                                               'public boolean getFoo(); \t// '
                                               'bad\n'
                                               'public boolean isFoo(); \t// '
                                               'ok\n'
                                               'public boolean getFoo(boolean '
                                               'bar); // ok, unless '
                                               'checkParameterizedMethods=true\n'
                                               '     ',
                                'display_name': 'BooleanGetMethodName',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': "A 'getX()' method which returns a "
                                         "boolean should be named 'isX()'"},
    'BooleanInstantiation': {   'categories': ['security'],
                                'description': 'Avoid instantiating Boolean '
                                               'objects; you can reference '
                                               'Boolean.TRUE, Boolean.FALSE, '
                                               'or call Boolean.valueOf() '
                                               'instead.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#BooleanInstantiation\n'
                                               '\n'
                                               '   \n'
                                               'Boolean bar = new '
                                               'Boolean("true");\t\t// '
                                               'unnecessary creation, just '
                                               'reference Boolean.TRUE;\n'
                                               'Boolean buz = '
                                               'Boolean.valueOf(false);\t// '
                                               '...., just reference '
                                               'Boolean.FALSE;\n'
                                               '   \n'
                                               '   ',
                                'display_name': 'BooleanInstantiation',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Avoid instantiating Boolean objects; '
                                         'reference Boolean.TRUE or '
                                         'Boolean.FALSE or call '
                                         'Boolean.valueOf() instead.'},
    'BrokenNullCheck': {   'categories': ['security'],
                           'description': 'The null check is broken since it '
                                          'will throw a NullPointerException '
                                          'itself. It is likely that you used '
                                          '|| instead of && or vice versa.\n'
                                          'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#BrokenNullCheck\n'
                                          '\n'
                                          '\n'
                                          'public String bar(String string) {\n'
                                          '  // should be &&\n'
                                          '\tif (string!=null || '
                                          '!string.equals(""))\n'
                                          '\t\treturn string;\n'
                                          '  // should be ||\n'
                                          '\tif (string==null && '
                                          'string.equals(""))\n'
                                          '\t\treturn string;\n'
                                          '}\n'
                                          '        \n'
                                          '        ',
                           'display_name': 'BrokenNullCheck',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'Method call on object which may be null'},
    'ByteInstantiation': {   'categories': ['security'],
                             'description': 'Calling new Byte() causes memory '
                                            'allocation that can be avoided by '
                                            'the static Byte.valueOf(). It '
                                            'makes use of an internal cache '
                                            'that recycles earlier instances '
                                            'making it more memory efficient.\n'
                                            'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/migrating.html#ByteInstantiation\n'
                                            '\n'
                                            '\n'
                                            'public class Foo {\n'
                                            '\tprivate Byte i = new Byte(0); '
                                            '// change to Byte i =\t'
                                            'Byte.valueOf(0);\n'
                                            '}\n'
                                            '\n'
                                            '     ',
                             'display_name': 'ByteInstantiation',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Avoid instantiating Byte objects. Call '
                                      'Byte.valueOf() instead'},
    'CallSuperFirst': {   'categories': ['security'],
                          'description': 'Super should be called at the start '
                                         'of the method\n'
                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/android.html#CallSuperFirst\n'
                                         '\n'
                                         'public class DummyActivity extends '
                                         'Activity {\n'
                                         '\tpublic void onCreate(Bundle '
                                         'bundle) {\n'
                                         '     // missing call to '
                                         'super.onCreate(bundle)\n'
                                         '\t\tfoo();\n'
                                         '\t}\n'
                                         '}\n'
                                         '\n'
                                         '    ',
                          'display_name': 'CallSuperFirst',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'super should be called at the start of the '
                                   'method'},
    'CallSuperInConstructor': {   'categories': ['security'],
                                  'description': 'It is a good practice to '
                                                 'call super() in a '
                                                 'constructor. If super() is '
                                                 'not called but another '
                                                 'constructor (such as an '
                                                 'overloaded constructor) is '
                                                 'called, this rule will not '
                                                 'report it.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#CallSuperInConstructor\n'
                                                 '\n'
                                                 '\n'
                                                 'public class Foo extends '
                                                 'Bar{\n'
                                                 '  public Foo() {\n'
                                                 '   // call the constructor '
                                                 'of Bar\n'
                                                 '   super();\n'
                                                 '  }\n'
                                                 ' public Foo(int code) {\n'
                                                 '  // do something with code\n'
                                                 '   this();\n'
                                                 '   // no problem with this\n'
                                                 '  }\n'
                                                 '}\n'
                                                 '\n'
                                                 '      ',
                                  'display_name': 'CallSuperInConstructor',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'It is a good practice to call '
                                           'super() in a constructor'},
    'CallSuperLast': {   'categories': ['security'],
                         'description': 'Super should be called at the end of '
                                        'the method\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/android.html#CallSuperLast\n'
                                        '\n'
                                        '      \n'
                                        'public class DummyActivity extends '
                                        'Activity {\n'
                                        '\tpublic void onPause() {\n'
                                        '\t\tfoo();\n'
                                        '\t\t// missing call to '
                                        'super.onPause()\n'
                                        '\t}\n'
                                        '}\n'
                                        '\n'
                                        '    ',
                         'display_name': 'CallSuperLast',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'super should be called at the end of the '
                                  'method'},
    'CheckResultSet': {   'categories': ['security'],
                          'description': 'Always check the return values of '
                                         'navigation methods (next, previous, '
                                         'first, last) of a ResultSet. If the '
                                         "value return is 'false', it should "
                                         'be handled properly.\n'
                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#CheckResultSet\n'
                                         '\n'
                                         '            \n'
                                         'Statement stat = '
                                         'conn.createStatement();\n'
                                         'ResultSet rst = '
                                         'stat.executeQuery("SELECT name FROM '
                                         'person");\n'
                                         'rst.next(); \t// what if it returns '
                                         'false? bad form\n'
                                         'String firstName = '
                                         'rst.getString(1);\n'
                                         '\n'
                                         'Statement stat = '
                                         'conn.createStatement();\n'
                                         'ResultSet rst = '
                                         'stat.executeQuery("SELECT name FROM '
                                         'person");\n'
                                         'if (rst.next()) {\t// result is '
                                         'properly examined and used\n'
                                         '    String firstName = '
                                         'rst.getString(1);\n'
                                         '\t} else  {\n'
                                         '\t\t// handle missing data\n'
                                         '}\n'
                                         '            \n'
                                         '        ',
                          'display_name': 'CheckResultSet',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'Always check the return of one of the '
                                   'navigation method '
                                   '(next,previous,first,last) of a '
                                   'ResultSet.'},
    'CheckSkipResult': {   'categories': ['security'],
                           'description': 'The skip() method may skip a '
                                          'smaller number of bytes than '
                                          'requested. Check the returned value '
                                          'to find out if it was the case or '
                                          'not.\n'
                                          'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#CheckSkipResult\n'
                                          '\n'
                                          '        \n'
                                          'public class Foo {\n'
                                          '\n'
                                          '   private FileInputStream _s = new '
                                          'FileInputStream("file");\n'
                                          '\n'
                                          '   public void skip(int n) throws '
                                          'IOException {\n'
                                          '      _s.skip(n); // You are not '
                                          'sure that exactly n bytes are '
                                          'skipped\n'
                                          '   }\n'
                                          '\n'
                                          '   public void skipExactly(int n) '
                                          'throws IOException {\n'
                                          '      while (n != 0) {\n'
                                          '         long skipped = '
                                          '_s.skip(n);\n'
                                          '         if (skipped == 0)\n'
                                          '            throw new '
                                          'EOFException();\n'
                                          '         n -= skipped;\n'
                                          '      }\n'
                                          '   }\n'
                                          '        \n'
                                          '        ',
                           'display_name': 'CheckSkipResult',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'Check the value returned by the skip() '
                                    'method of an InputStream to see if the '
                                    'requested number of bytes has been '
                                    'skipped.'},
    'ClassCastExceptionWithToArray': {   'categories': ['security'],
                                         'description': 'When deriving an '
                                                        'array of a specific '
                                                        'class from your '
                                                        'Collection, one '
                                                        'should provide an '
                                                        'array of the same '
                                                        'class as the '
                                                        'parameter of the '
                                                        'toArray() method. '
                                                        'Doing otherwise you '
                                                        'will will result in a '
                                                        'ClassCastException.\n'
                                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#ClassCastExceptionWithToArray\n'
                                                        '\n'
                                                        '\n'
                                                        'Collection c = new '
                                                        'ArrayList();\n'
                                                        'Integer obj = new '
                                                        'Integer(1);\n'
                                                        'c.add(obj);\n'
                                                        '\n'
                                                        '    // this would '
                                                        'trigger the rule (and '
                                                        'throw a '
                                                        'ClassCastException if '
                                                        'executed)\n'
                                                        'Integer[] a = '
                                                        '(Integer '
                                                        '[])c.toArray();\n'
                                                        '\n'
                                                        '   // this is fine '
                                                        'and will not trigger '
                                                        'the rule\n'
                                                        'Integer[] b = '
                                                        '(Integer '
                                                        '[])c.toArray(new '
                                                        'Integer[c.size()]);\n'
                                                        '\n'
                                                        '  ',
                                         'display_name': 'ClassCastExceptionWithToArray',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'This usage of the '
                                                  'Collection.toArray() method '
                                                  'will throw a '
                                                  'ClassCastException.'},
    'ClassNamingConventions': {   'categories': ['security'],
                                  'description': 'Class names should always '
                                                 'begin with an upper case '
                                                 'character.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#ClassNamingConventions\n'
                                                 '\n'
                                                 '\n'
                                                 'public class Foo {}\n'
                                                 '\n'
                                                 '      ',
                                  'display_name': 'ClassNamingConventions',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'Class names should begin with an '
                                           'uppercase character'},
    'ClassWithOnlyPrivateConstructorsShouldBeFinal': {   'categories': [   'security'],
                                                         'description': 'A '
                                                                        'class '
                                                                        'with '
                                                                        'only '
                                                                        'private '
                                                                        'constructors '
                                                                        'should '
                                                                        'be '
                                                                        'final, '
                                                                        'unless '
                                                                        'the '
                                                                        'private '
                                                                        'constructor '
                                                                        'is '
                                                                        'invoked '
                                                                        'by a '
                                                                        'inner '
                                                                        'class.\n'
                                                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#ClassWithOnlyPrivateConstructorsShouldBeFinal\n'
                                                                        '\n'
                                                                        'public '
                                                                        'class '
                                                                        'Foo '
                                                                        '{  '
                                                                        '//Should '
                                                                        'be '
                                                                        'final\n'
                                                                        '    '
                                                                        'private '
                                                                        'Foo() '
                                                                        '{ }\n'
                                                                        '}\n'
                                                                        '     ',
                                                         'display_name': 'ClassWithOnlyPrivateConstructorsShouldBeFinal',
                                                         'file': '%(issue.file)s',
                                                         'line': '%(issue.line)s',
                                                         'severity': '1',
                                                         'title': 'A class '
                                                                  'which only '
                                                                  'has private '
                                                                  'constructors '
                                                                  'should be '
                                                                  'final'},
    'CloneMethodMustBePublic': {   'categories': ['security'],
                                   'description': 'The java Manual says "By '
                                                  'convention, classes that '
                                                  'implement this interface '
                                                  'should override '
                                                  'Object.clone (which is '
                                                  'protected) with a public '
                                                  'method."\n'
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/clone.html#CloneMethodMustBePublic\n'
                                                  '\n'
                                                  '            \n'
                                                  'public class Foo implements '
                                                  'Cloneable {\n'
                                                  '    @Override\n'
                                                  '    protected Object '
                                                  'clone() throws '
                                                  'CloneNotSupportedException '
                                                  '{ // Violation, must be '
                                                  'public\n'
                                                  '    }\n'
                                                  '}\n'
                                                  '\n'
                                                  'public class Foo implements '
                                                  'Cloneable {\n'
                                                  '    @Override\n'
                                                  '    protected Foo clone() { '
                                                  '// Violation, must be '
                                                  'public\n'
                                                  '    }\n'
                                                  '}\n'
                                                  '\n'
                                                  'public class Foo implements '
                                                  'Cloneable {\n'
                                                  '    @Override\n'
                                                  '    public Object clone() '
                                                  '// Ok\n'
                                                  '}\n',
                                   'display_name': 'CloneMethodMustBePublic',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'clone() method must be public if '
                                            'the class implements Cloneable'},
    'CloneMethodMustImplementCloneable': {   'categories': ['security'],
                                             'description': 'The method '
                                                            'clone() should '
                                                            'only be '
                                                            'implemented if '
                                                            'the class '
                                                            'implements the '
                                                            'Cloneable '
                                                            'interface with '
                                                            'the exception of '
                                                            'a final method '
                                                            'that only throws '
                                                            'CloneNotSupportedException. '
                                                            'This version uses '
                                                            "PMD's type "
                                                            'resolution '
                                                            'facilities, and '
                                                            'can detect if the '
                                                            'class implements '
                                                            'or extends a '
                                                            'Cloneable class.\n'
                                                            'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/typeresolution.html#CloneMethodMustImplementCloneable\n'
                                                            '\n'
                                                            '            \n'
                                                            'public class '
                                                            'MyClass {\n'
                                                            '\tpublic Object '
                                                            'clone() throws '
                                                            'CloneNotSupportedException '
                                                            '{\n'
                                                            '\t\treturn foo;\n'
                                                            '\t}\n'
                                                            '}\n'
                                                            '   \n'
                                                            '        ',
                                             'display_name': 'CloneMethodMustImplementCloneable',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': 'clone() method should '
                                                      'be implemented only if '
                                                      'implementing Cloneable '
                                                      'interface'},
    'CloneMethodReturnTypeMustMatchClassName': {   'categories': ['security'],
                                                   'description': 'If a class '
                                                                  'implements '
                                                                  'cloneable '
                                                                  'the return '
                                                                  'type of the '
                                                                  'method '
                                                                  'clone() '
                                                                  'must be the '
                                                                  'class name. '
                                                                  'That way, '
                                                                  'the caller '
                                                                  'of the '
                                                                  'clone '
                                                                  'method '
                                                                  "doesn't "
                                                                  'need to '
                                                                  'cast the '
                                                                  'returned '
                                                                  'clone to '
                                                                  'the correct '
                                                                  'type. Note: '
                                                                  'This is '
                                                                  'only '
                                                                  'possible '
                                                                  'with Java '
                                                                  '1.5 or '
                                                                  'higher.\n'
                                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/clone.html#CloneMethodReturnTypeMustMatchClassName\n'
                                                                  '\n'
                                                                  '            \n'
                                                                  'public '
                                                                  'class Foo '
                                                                  'implements '
                                                                  'Cloneable '
                                                                  '{\n'
                                                                  '    '
                                                                  '@Override\n'
                                                                  '    '
                                                                  'protected '
                                                                  'Object '
                                                                  'clone() { '
                                                                  '// '
                                                                  'Violation, '
                                                                  'Object must '
                                                                  'be Foo\n'
                                                                  '    }\n'
                                                                  '}\n'
                                                                  '\n'
                                                                  'public '
                                                                  'class Foo '
                                                                  'implements '
                                                                  'Cloneable '
                                                                  '{\n'
                                                                  '    '
                                                                  '@Override\n'
                                                                  '    public '
                                                                  'Foo clone() '
                                                                  '{ //Ok\n'
                                                                  '    }\n'
                                                                  '}\n'
                                                                  '            \n'
                                                                  '        ',
                                                   'display_name': 'CloneMethodReturnTypeMustMatchClassName',
                                                   'file': '%(issue.file)s',
                                                   'line': '%(issue.line)s',
                                                   'severity': '1',
                                                   'title': 'The return type '
                                                            'of the clone() '
                                                            'method must be '
                                                            'the class name '
                                                            'when implements '
                                                            'Cloneable'},
    'CloneThrowsCloneNotSupportedException': {   'categories': ['security'],
                                                 'description': 'The method '
                                                                'clone() '
                                                                'should throw '
                                                                'a '
                                                                'CloneNotSupportedException.\n'
                                                                'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/clone.html#CloneThrowsCloneNotSupportedException\n'
                                                                '\n'
                                                                '             \n'
                                                                ' public class '
                                                                'MyClass '
                                                                'implements '
                                                                'Cloneable{\n'
                                                                '     public '
                                                                'Object '
                                                                'clone() { // '
                                                                'will cause an '
                                                                'error\n'
                                                                '          '
                                                                'MyClass clone '
                                                                '= '
                                                                '(MyClass)super.clone();\n'
                                                                '          '
                                                                'return '
                                                                'clone;\n'
                                                                '     }\n'
                                                                ' }\n'
                                                                '    \n'
                                                                '         ',
                                                 'display_name': 'CloneThrowsCloneNotSupportedException',
                                                 'file': '%(issue.file)s',
                                                 'line': '%(issue.line)s',
                                                 'severity': '1',
                                                 'title': 'clone() method '
                                                          'should throw '
                                                          'CloneNotSupportedException'},
    'CloseResource': {   'categories': ['security'],
                         'description': 'Ensure that resources (like '
                                        'Connection, Statement, and ResultSet '
                                        'objects) are always closed after '
                                        'use.\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#CloseResource\n'
                                        '\n'
                                        '\n'
                                        'public class Bar {\n'
                                        '  public void foo() {\n'
                                        '    Connection c = '
                                        'pool.getConnection();\n'
                                        '    try {\n'
                                        '      // do stuff\n'
                                        '    } catch (SQLException ex) {\n'
                                        '     // handle exception\n'
                                        '    } finally {\n'
                                        '      // oops, should close the '
                                        "connection using 'close'!\n"
                                        '      // c.close();\n'
                                        '    }\n'
                                        '  }\n'
                                        '}\n'
                                        '\n'
                                        '    ',
                         'display_name': 'CloseResource',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure that resources like this {0} object '
                                  'are closed after use'},
    'CollapsibleIfStatements': {   'categories': ['security'],
                                   'description': 'Sometimes two consecutive '
                                                  "'if' statements can be "
                                                  'consolidated by separating '
                                                  'their conditions with a '
                                                  'boolean short-circuit '
                                                  'operator.\n'
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-vm/rules/vm/basic.html#CollapsibleIfStatements\n',
                                   'display_name': 'CollapsibleIfStatements',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'These nested if statements could '
                                            'be combined'},
    'CommentContent': {   'categories': ['security'],
                          'description': 'A rule for the politically '
                                         "correct... we don't want to offend "
                                         'anyone.\n'
                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/comments.html#CommentContent\n'
                                         '\n'
                                         '      \n'
                                         '//\tOMG, this is horrible, Bob is an '
                                         'idiot !!!\n'
                                         '      \n'
                                         '  ',
                          'display_name': 'CommentContent',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'Invalid words or phrases found'},
    'CommentDefaultAccessModifier': {   'categories': ['security'],
                                        'description': 'To avoid mistakes if '
                                                       'we want that a Method, '
                                                       'Field or Nested class '
                                                       'have a default access '
                                                       'modifier we must add a '
                                                       'comment at the '
                                                       'beginning of the '
                                                       'Method, Field or '
                                                       'Nested class. By '
                                                       'default the comment '
                                                       'must be /* default */, '
                                                       'if you want another, '
                                                       'you have to provide a '
                                                       'regex.\n'
                                                       'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/comments.html#CommentDefaultAccessModifier\n'
                                                       '\n'
                                                       '        \n'
                                                       '        public class '
                                                       'Foo {\n'
                                                       '            final '
                                                       'String stringValue = '
                                                       '"some string";\n'
                                                       '            String '
                                                       'getString() {\n'
                                                       '               return '
                                                       'stringValue;\n'
                                                       '            }\n'
                                                       '\n'
                                                       '            class '
                                                       'NestedFoo {\n'
                                                       '            }\n'
                                                       '        }\n'
                                                       '\n'
                                                       '        // should be\n'
                                                       '        public class '
                                                       'Foo {\n'
                                                       '            /* default '
                                                       '*/ final String '
                                                       'stringValue = "some '
                                                       'string";\n'
                                                       '            /* default '
                                                       '*/ String getString() '
                                                       '{\n'
                                                       '               return '
                                                       'stringValue;\n'
                                                       '            }\n'
                                                       '\n'
                                                       '            /* default '
                                                       '*/ class NestedFoo {\n'
                                                       '            }\n'
                                                       '        }\n'
                                                       '        \n'
                                                       '    ',
                                        'display_name': 'CommentDefaultAccessModifier',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'Missing commented default '
                                                 'access modifier'},
    'CommentRequired': {   'categories': ['security'],
                           'description': 'Denotes whether comments are '
                                          'required (or unwanted) for specific '
                                          'language elements.\n'
                                          'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/comments.html#CommentRequired\n'
                                          '\n'
                                          '\n'
                                          '/**\n'
                                          '* \n'
                                          '*\n'
                                          '* @author George Bush\n'
                                          '*/\n'
                                          '\n'
                                          '    ',
                           'display_name': 'CommentRequired',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'Comment is required'},
    'CommentSize': {   'categories': ['security'],
                       'description': 'Determines whether the dimensions of '
                                      'non-header comments found are within '
                                      'the specified limits.\n'
                                      'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/comments.html#CommentSize\n'
                                      '\n'
                                      '\n'
                                      '/**\n'
                                      '*\n'
                                      '*\ttoo many lines!\n'
                                      '*\n'
                                      '*\n'
                                      '*\n'
                                      '*\n'
                                      '*\n'
                                      '*\n'
                                      '*\n'
                                      '*\n'
                                      '*\n'
                                      '*\n'
                                      '*\n'
                                      '*\n'
                                      '*/\n'
                                      '\n'
                                      '    ',
                       'display_name': 'CommentSize',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Comment is too large'},
    'CompareObjectsWithEquals': {   'categories': ['security'],
                                    'description': 'Use equals() to compare '
                                                   'object references; avoid '
                                                   'comparing them with ==.\n'
                                                   'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#CompareObjectsWithEquals\n'
                                                   '\n'
                                                   '\n'
                                                   'class Foo {\n'
                                                   '  boolean bar(String a, '
                                                   'String b) {\n'
                                                   '    return a == b;\n'
                                                   '  }\n'
                                                   '}\n'
                                                   '\n'
                                                   '\n'
                                                   '  ',
                                    'display_name': 'CompareObjectsWithEquals',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'Use equals() to compare object '
                                             'references.'},
    'ConfusingTernary': {   'categories': ['security'],
                            'description': 'Avoid negation within an "if" '
                                           'expression with an "else" clause. '
                                           'For example, rephrase: if (x != y) '
                                           'diff(); else same(); as: if (x == '
                                           'y) same(); else diff(); Most "if '
                                           '(x != y)" cases without an "else" '
                                           'are often return cases, so '
                                           'consistent use of this rule makes '
                                           'the code easier to read. Also, '
                                           'this resolves trivial ordering '
                                           'problems, such as "does the error '
                                           'case go first?" or "does the '
                                           'common case go first?".\n'
                                           'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#ConfusingTernary\n'
                                           '\n'
                                           '          \n'
                                           'boolean bar(int x, int y) {\n'
                                           '  return (x != y) ? diff : same;\n'
                                           ' }\n'
                                           '          \n'
                                           '        ',
                            'display_name': 'ConfusingTernary',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'Avoid if (x != y) ..; else ..;'},
    'ConsecutiveAppendsShouldReuse': {   'categories': ['security'],
                                         'description': 'Consecutive calls to '
                                                        'StringBuffer/StringBuilder '
                                                        '.append should be '
                                                        'chained, reusing the '
                                                        'target object. This '
                                                        'can improve the '
                                                        'performance by '
                                                        'producing a smaller '
                                                        'bytecode, reducing '
                                                        'overhead and '
                                                        'improving inlining. A '
                                                        'complete analysis can '
                                                        'be found '
                                                        '[here](https://github.com/pmd/pmd/issues/202#issuecomment-274349067)\n'
                                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strings.html#ConsecutiveAppendsShouldReuse\n'
                                                        '\n'
                                                        '\n'
                                                        'String foo = " ";\n'
                                                        '\n'
                                                        'StringBuffer buf = '
                                                        'new StringBuffer();\n'
                                                        'buf.append("Hello"); '
                                                        '// poor\n'
                                                        'buf.append(foo);\n'
                                                        'buf.append("World");\n'
                                                        '\n'
                                                        'StringBuffer buf = '
                                                        'new StringBuffer();\n'
                                                        'buf.append("Hello").append(foo).append("World"); '
                                                        '// good\n'
                                                        '\n'
                                                        '    ',
                                         'display_name': 'ConsecutiveAppendsShouldReuse',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'StringBuffer (or '
                                                  'StringBuilder).append is '
                                                  'called consecutively '
                                                  'without reusing the target '
                                                  'variable.'},
    'ConsecutiveLiteralAppends': {   'categories': ['security'],
                                     'description': 'Consecutively calling '
                                                    'StringBuffer/StringBuilder.append '
                                                    'with String literals\n'
                                                    'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strings.html#ConsecutiveLiteralAppends\n'
                                                    '\n'
                                                    '\n'
                                                    'StringBuffer buf = new '
                                                    'StringBuffer();\n'
                                                    'buf.append("Hello").append(" '
                                                    '").append("World"); // '
                                                    'poor\n'
                                                    'buf.append("Hello '
                                                    'World");        \t\t\t\t '
                                                    '// good\n'
                                                    '\n'
                                                    '    ',
                                     'display_name': 'ConsecutiveLiteralAppends',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'StringBuffer (or '
                                              'StringBuilder).append is called '
                                              '{0} consecutive times with '
                                              'literal Strings. Use a single '
                                              'append with a single combined '
                                              'String.'},
    'ConsistentReturn': {   'categories': ['security'],
                            'description': 'ECMAScript does provide for return '
                                           'types on functions, and therefore '
                                           'there is no solid rule as to their '
                                           'usage. However, when a function '
                                           'does use returns they should all '
                                           'have a value, or all with no '
                                           'value. Mixed return usage is '
                                           'likely a bug, or at best poor '
                                           'style.\n'
                                           'https://pmd.github.io/pmd-5.8.1/pmd-javascript/rules/ecmascript/basic.html#ConsistentReturn\n'
                                           '\n'
                                           '  \n'
                                           '// Ok\n'
                                           'function foo() {\n'
                                           '   if (condition1) {\n'
                                           '      return true;\n'
                                           '   }\n'
                                           '   return false;\n'
                                           '}\n'
                                           '\n'
                                           '// Bad\n'
                                           'function bar() {\n'
                                           '   if (condition1) {\n'
                                           '      return;\n'
                                           '   }\n'
                                           '   return false;\n'
                                           '}\n'
                                           '\n'
                                           '      ',
                            'display_name': 'ConsistentReturn',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': "A function should not mix 'return' "
                                     'statements with and without a result.'},
    'ConstantsInInterface': {   'categories': ['security'],
                                'description': 'Avoid constants in interfaces. '
                                               'Interfaces should define '
                                               'types, constants are '
                                               'implementation details better '
                                               'placed in classes or enums. '
                                               'See Effective Java, item 19.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#ConstantsInInterface\n'
                                               '\n'
                                               '\n'
                                               'public interface '
                                               'ConstantInterface {\n'
                                               '    public static final int '
                                               'CONST1 = 1; // violation, no '
                                               'fields allowed in interface!\n'
                                               '    static final int CONST2 = '
                                               '1; // violation, no fields '
                                               'allowed in interface!\n'
                                               '    final int CONST3 = 1; // '
                                               'violation, no fields allowed '
                                               'in interface!\n'
                                               '    int CONST4 = 1; // '
                                               'violation, no fields allowed '
                                               'in interface!\n'
                                               '}\n'
                                               '\n'
                                               '// with ignoreIfHasMethods = '
                                               'false\n'
                                               'public interface '
                                               'AnotherConstantInterface {\n'
                                               '    public static final int '
                                               'CONST1 = 1; // violation, no '
                                               'fields allowed in interface!\n'
                                               '\n'
                                               '    int anyMethod();\n'
                                               '}\n'
                                               '\n'
                                               '// with ignoreIfHasMethods = '
                                               'true\n'
                                               'public interface '
                                               'YetAnotherConstantInterface {\n'
                                               '    public static final int '
                                               'CONST1 = 1; // no violation\n'
                                               '\n'
                                               '    int anyMethod();\n'
                                               '}\n'
                                               ' \n'
                                               '        ',
                                'display_name': 'ConstantsInInterface',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Avoid constants in interfaces. '
                                         'Interfaces define types, constants '
                                         'are implementation details better '
                                         'placed in classes or enums. See '
                                         'Effective Java, item 19.'},
    'ConstructorCallsOverridableMethod': {   'categories': ['security'],
                                             'description': 'Calling '
                                                            'overridable '
                                                            'methods during '
                                                            'construction '
                                                            'poses a risk of '
                                                            'invoking methods '
                                                            'on an '
                                                            'incompletely '
                                                            'constructed '
                                                            'object and can be '
                                                            'difficult to '
                                                            'debug. It may '
                                                            'leave the '
                                                            'sub-class unable '
                                                            'to construct its '
                                                            'superclass or '
                                                            'forced to '
                                                            'replicate the '
                                                            'construction '
                                                            'process '
                                                            'completely within '
                                                            'itself, losing '
                                                            'the ability to '
                                                            'call super(). If '
                                                            'the default '
                                                            'constructor '
                                                            'contains a call '
                                                            'to an overridable '
                                                            'method, the '
                                                            'subclass may be '
                                                            'completely '
                                                            'uninstantiable. '
                                                            'Note that this '
                                                            'includes method '
                                                            'calls throughout '
                                                            'the control flow '
                                                            'graph - i.e., if '
                                                            'a constructor '
                                                            'Foo() calls a '
                                                            'private method '
                                                            'bar() that calls '
                                                            'a public method '
                                                            'buz(), this '
                                                            'denotes a '
                                                            'problem.\n'
                                                            'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#ConstructorCallsOverridableMethod\n'
                                                            '\n'
                                                            '  \n'
                                                            'public class '
                                                            'SeniorClass {\n'
                                                            '  public '
                                                            'SeniorClass(){\n'
                                                            '      toString(); '
                                                            '//may throw '
                                                            'NullPointerException '
                                                            'if overridden\n'
                                                            '  }\n'
                                                            '  public String '
                                                            'toString(){\n'
                                                            '    return '
                                                            '"IAmSeniorClass";\n'
                                                            '  }\n'
                                                            '}\n'
                                                            'public class '
                                                            'JuniorClass '
                                                            'extends '
                                                            'SeniorClass {\n'
                                                            '  private String '
                                                            'name;\n'
                                                            '  public '
                                                            'JuniorClass(){\n'
                                                            '    super(); '
                                                            '//Automatic call '
                                                            'leads to '
                                                            'NullPointerException\n'
                                                            '    name = '
                                                            '"JuniorClass";\n'
                                                            '  }\n'
                                                            '  public String '
                                                            'toString(){\n'
                                                            '    return '
                                                            'name.toUpperCase();\n'
                                                            '  }\n'
                                                            '}\n'
                                                            '  \n'
                                                            '      ',
                                             'display_name': 'ConstructorCallsOverridableMethod',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': 'Overridable {0} called '
                                                      'during object '
                                                      'construction'},
    'CouplingBetweenObjects': {   'categories': ['security'],
                                  'description': 'This rule counts the number '
                                                 'of unique attributes, local '
                                                 'variables, and return types '
                                                 'within an object. A number '
                                                 'higher than the specified '
                                                 'threshold can indicate a '
                                                 'high degree of coupling.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/coupling.html#CouplingBetweenObjects\n'
                                                 '\n'
                                                 '\n'
                                                 'import com.Blah;\n'
                                                 'import org.Bar;\n'
                                                 'import org.Bardo;\n'
                                                 '\n'
                                                 'public class Foo {\n'
                                                 '   private Blah var1;\n'
                                                 '   private Bar var2;\n'
                                                 ' \n'
                                                 ' \t//followed by many '
                                                 'imports of unique objects\n'
                                                 '   void ObjectC doWork() {\n'
                                                 '     Bardo var55;\n'
                                                 '     ObjectA var44;\n'
                                                 '     ObjectZ var93;\n'
                                                 '     return something;\n'
                                                 '   }\n'
                                                 '}\n'
                                                 '\n'
                                                 '    ',
                                  'display_name': 'CouplingBetweenObjects',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'High amount of different objects '
                                           'as members denotes a high '
                                           'coupling'},
    'CyclomaticComplexity': {   'categories': ['security'],
                                'description': 'Complexity directly affects '
                                               'maintenance costs is '
                                               'determined by the number of '
                                               'decision points in a method '
                                               'plus one for the method entry. '
                                               'The decision points include '
                                               "'if', 'while', 'for', and "
                                               "'case labels' calls. "
                                               'Generally, numbers ranging '
                                               'from 1-4 denote low '
                                               'complexity, 5-7 denote '
                                               'moderate complexity, 8-10 '
                                               'denote high complexity, and '
                                               '11+ is very high complexity.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-plsql/rules/plsql/codesize.html#CyclomaticComplexity\n'
                                               '\n'
                                               '\n'
                                               '-- Cyclomatic Complexity of '
                                               '25 \n'
                                               'CREATE OR REPLACE PACKAGE BODY '
                                               'pkg_pmd_working_sequence  AS \n'
                                               '1 PROCEDURE ty_logger  IS '
                                               'BEGIN\n'
                                               '2        IF true\n'
                                               '         THEN\n'
                                               '              '
                                               "DBMS_OUTPUT.PUT_LINE('IF/THEN "
                                               "l_Integer='||l_integer);         \n"
                                               '3\t\t IF true\n'
                                               '\t\t THEN\n'
                                               '\t\t      '
                                               "DBMS_OUTPUT.PUT_LINE('IF/THEN "
                                               "l_Integer='||l_integer);         \n"
                                               '4\t\t\t IF true\n'
                                               '\t\t\t THEN\n'
                                               '\t\t\t      '
                                               "DBMS_OUTPUT.PUT_LINE('IF/THEN "
                                               "l_Integer='||l_integer);         \n"
                                               '5\t\t\t ELSIF false\n'
                                               '\t\t\t THEN\n'
                                               '\t\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '\t\t\t ELSE\n'
                                               '\t\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '\t\t\t END IF;\n'
                                               '6\t\t ELSIF false\n'
                                               '\t\t THEN\n'
                                               '\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '7\t\t\t IF true\n'
                                               '\t\t\t THEN\n'
                                               '\t\t\t      '
                                               "DBMS_OUTPUT.PUT_LINE('IF/THEN "
                                               "l_Integer='||l_integer);         \n"
                                               '8\t\t\t ELSIF false\n'
                                               '\t\t\t THEN\n'
                                               '\t\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '\t\t\t ELSE\n'
                                               '\t\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '\t\t\t END IF;\n'
                                               '\t\t ELSE\n'
                                               '\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '9\t\t\t IF true\n'
                                               '\t\t\t THEN\n'
                                               '\t\t\t      '
                                               "DBMS_OUTPUT.PUT_LINE('IF/THEN "
                                               "l_Integer='||l_integer);         \n"
                                               '10\t\t\t ELSIF false\n'
                                               '\t\t\t THEN\n'
                                               '\t\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '\t\t\t ELSE\n'
                                               '\t\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '\t\t\t END IF;\n'
                                               '\t\t END IF;\n'
                                               '11         ELSIF false\n'
                                               '         THEN\n'
                                               '\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '12\t\t IF true\n'
                                               '\t\t THEN\n'
                                               '\t\t      '
                                               "DBMS_OUTPUT.PUT_LINE('IF/THEN "
                                               "l_Integer='||l_integer);         \n"
                                               '13\t\t\t IF true\n'
                                               '\t\t\t THEN\n'
                                               '\t\t\t      '
                                               "DBMS_OUTPUT.PUT_LINE('IF/THEN "
                                               "l_Integer='||l_integer);         \n"
                                               '14\t\t\t ELSIF false\n'
                                               '\t\t\t THEN\n'
                                               '\t\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '\t\t\t ELSE\n'
                                               '\t\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '\t\t\t END IF;\n'
                                               '15\t\t ELSIF false\n'
                                               '\t\t THEN\n'
                                               '16\t\t\t IF true\n'
                                               '\t\t\t THEN\n'
                                               '\t\t\t      '
                                               "DBMS_OUTPUT.PUT_LINE('IF/THEN "
                                               "l_Integer='||l_integer);         \n"
                                               '17\t\t\t ELSIF false\n'
                                               '\t\t\t THEN\n'
                                               '\t\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '\t\t\t ELSE\n'
                                               '\t\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '\t\t\t END IF;\n'
                                               '\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '\t\t ELSE\n'
                                               '\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '\t\t END IF;\n'
                                               '\t ELSE\n'
                                               '\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '18\t\t IF true\n'
                                               '\t\t THEN\n'
                                               '\t\t      '
                                               "DBMS_OUTPUT.PUT_LINE('IF/THEN "
                                               "l_Integer='||l_integer);         \n"
                                               '19\t\t\t IF true\n'
                                               '\t\t\t THEN\n'
                                               '\t\t\t      '
                                               "DBMS_OUTPUT.PUT_LINE('IF/THEN "
                                               "l_Integer='||l_integer);         \n"
                                               '20\t\t\t ELSIF false\n'
                                               '\t\t\t THEN\n'
                                               '\t\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '\t\t\t ELSE\n'
                                               '\t\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '\t\t\t END IF;\n'
                                               '21\t\t ELSIF false\n'
                                               '\t\t THEN\n'
                                               '\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '22\t\t\t IF true\n'
                                               '\t\t\t THEN\n'
                                               '\t\t\t      '
                                               "DBMS_OUTPUT.PUT_LINE('IF/THEN "
                                               "l_Integer='||l_integer);         \n"
                                               '23\t\t\t ELSIF false\n'
                                               '\t\t\t THEN\n'
                                               '\t\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '\t\t\t ELSE\n'
                                               '\t\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '\t\t\t END IF;\n'
                                               '\t\t ELSE\n'
                                               '\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '24\t\t\t IF true\n'
                                               '\t\t\t THEN\n'
                                               '\t\t\t      '
                                               "DBMS_OUTPUT.PUT_LINE('IF/THEN "
                                               "l_Integer='||l_integer);         \n"
                                               '25\t\t\t ELSIF false\n'
                                               '\t\t\t THEN\n'
                                               '\t\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '\t\t\t ELSE\n'
                                               '\t\t\t\t'
                                               "DBMS_OUTPUT.PUT_LINE('ELSIF "
                                               "l_Integer='||l_integer);             \n"
                                               '\t\t\t END IF;\n'
                                               '\t\t END IF;\n'
                                               '\t END IF;\n'
                                               'END;\t\t\t\t\t\t\t\t\n'
                                               '\t\t\t\t\t\t\n'
                                               'END;\n'
                                               '\n'
                                               '   ',
                                'display_name': 'CyclomaticComplexity',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': "The {0} ''{1}'' has a Cyclomatic "
                                         'Complexity of {2}.'},
    'DataflowAnomalyAnalysis': {   'categories': ['security'],
                                   'description': 'The dataflow analysis '
                                                  'tracks local definitions, '
                                                  'undefinitions and '
                                                  'references to variables on '
                                                  'different paths on the data '
                                                  'flow. From those '
                                                  'informations there can be '
                                                  'found various problems. 1. '
                                                  'UR - Anomaly: There is a '
                                                  'reference to a variable '
                                                  'that was not defined '
                                                  'before. This is a bug and '
                                                  'leads to an error. 2. DU - '
                                                  'Anomaly: A recently defined '
                                                  'variable is undefined. '
                                                  'These anomalies may appear '
                                                  'in normal source text. 3. '
                                                  'DD - Anomaly: A recently '
                                                  'defined variable is '
                                                  'redefined. This is ominous '
                                                  "but don't have to be a "
                                                  'bug.\n'
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#DataflowAnomalyAnalysis\n'
                                                  '\n'
                                                  '\n'
                                                  'public void foo() {\n'
                                                  '  int buz = 5;\n'
                                                  '  buz = 6; // redefinition '
                                                  'of buz -> dd-anomaly\n'
                                                  '  foo(buz);\n'
                                                  '  buz = 2;\n'
                                                  '} // buz is undefined when '
                                                  'leaving scope -> '
                                                  'du-anomaly\n'
                                                  '\n'
                                                  '          ',
                                   'display_name': 'DataflowAnomalyAnalysis',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': "Found ''{0}''-anomaly for "
                                            "variable ''{1}'' (lines "
                                            "''{2}''-''{3}'')."},
    'DefaultLabelNotLastInSwitchStmt': {   'categories': ['security'],
                                           'description': 'By convention, the '
                                                          'default label '
                                                          'should be the last '
                                                          'label in a switch '
                                                          'statement.\n'
                                                          'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#DefaultLabelNotLastInSwitchStmt\n'
                                                          '\n'
                                                          '   \n'
                                                          'public class Foo {\n'
                                                          '  void bar(int a) '
                                                          '{\n'
                                                          '   switch (a) {\n'
                                                          '    case 1:  // do '
                                                          'something\n'
                                                          '       break;\n'
                                                          '    default:  // '
                                                          'the default case '
                                                          'should be last, by '
                                                          'convention\n'
                                                          '       break;\n'
                                                          '    case 2:\n'
                                                          '       break;\n'
                                                          '   }\n'
                                                          '  }\n'
                                                          '}   \n'
                                                          '       ',
                                           'display_name': 'DefaultLabelNotLastInSwitchStmt',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'The default label should '
                                                    'be the last label in a '
                                                    'switch statement'},
    'DefaultPackage': {   'categories': ['security'],
                          'description': 'Use explicit scoping instead of '
                                         'accidental usage of default package '
                                         'private level. The rule allows '
                                         'methods and fields annotated with '
                                         "Guava's @VisibleForTesting.\n"
                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#DefaultPackage\n',
                          'display_name': 'DefaultPackage',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'Use explicit scoping instead of the '
                                   'default package private level'},
    'DoNotCallGarbageCollectionExplicitly': {   'categories': ['security'],
                                                'description': 'Calls to '
                                                               'System.gc(), '
                                                               'Runtime.getRuntime().gc(), '
                                                               'and '
                                                               'System.runFinalization() '
                                                               'are not '
                                                               'advised. Code '
                                                               'should have '
                                                               'the same '
                                                               'behavior '
                                                               'whether the '
                                                               'garbage '
                                                               'collection is '
                                                               'disabled using '
                                                               'the option '
                                                               '-Xdisableexplicitgc '
                                                               'or not. '
                                                               'Moreover, '
                                                               '"modern" jvms '
                                                               'do a very good '
                                                               'job handling '
                                                               'garbage '
                                                               'collections. '
                                                               'If memory '
                                                               'usage issues '
                                                               'unrelated to '
                                                               'memory leaks '
                                                               'develop within '
                                                               'an '
                                                               'application, '
                                                               'it should be '
                                                               'dealt with JVM '
                                                               'options rather '
                                                               'than within '
                                                               'the code '
                                                               'itself.\n'
                                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#DoNotCallGarbageCollectionExplicitly\n'
                                                               '\n'
                                                               '            \n'
                                                               'public class '
                                                               'GCCall {\n'
                                                               '    public '
                                                               'GCCall() {\n'
                                                               '        // '
                                                               'Explicit gc '
                                                               'call !\n'
                                                               '        '
                                                               'System.gc();\n'
                                                               '    }\n'
                                                               '\n'
                                                               '    public '
                                                               'void '
                                                               'doSomething() '
                                                               '{\n'
                                                               '        // '
                                                               'Explicit gc '
                                                               'call !\n'
                                                               '        '
                                                               'Runtime.getRuntime().gc();\n'
                                                               '    }\n'
                                                               '\n'
                                                               '    public '
                                                               'explicitGCcall() '
                                                               '{\n'
                                                               '        // '
                                                               'Explicit gc '
                                                               'call !\n'
                                                               '        '
                                                               'System.gc();\n'
                                                               '    }\n'
                                                               '\n'
                                                               '    public '
                                                               'void '
                                                               'doSomething() '
                                                               '{\n'
                                                               '        // '
                                                               'Explicit gc '
                                                               'call !\n'
                                                               '        '
                                                               'Runtime.getRuntime().gc();\n'
                                                               '    }\n'
                                                               '}\n'
                                                               '      \n'
                                                               '    ',
                                                'display_name': 'DoNotCallGarbageCollectionExplicitly',
                                                'file': '%(issue.file)s',
                                                'line': '%(issue.line)s',
                                                'severity': '1',
                                                'title': 'Do not explicitly '
                                                         'trigger a garbage '
                                                         'collection.'},
    'DoNotCallSystemExit': {   'categories': ['security'],
                               'description': 'Web applications should not '
                                              'call System.exit(), since only '
                                              'the web container or the '
                                              'application server should stop '
                                              'the JVM. This rule also checks '
                                              'for the equivalent call '
                                              'Runtime.getRuntime().exit().\n'
                                              'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/j2ee.html#DoNotCallSystemExit\n'
                                              '\n'
                                              '    \t\t\n'
                                              'public void bar() {\n'
                                              '    '
                                              'System.exit(0);                 '
                                              '// never call this when running '
                                              'in an application server!\n'
                                              '}\n'
                                              'public void foo() {\n'
                                              '    '
                                              'Runtime.getRuntime().exit(0);   '
                                              '// never stop the JVM manually, '
                                              'the container will do this.\n'
                                              '}\n'
                                              '     ',
                               'display_name': 'DoNotCallSystemExit',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'System.exit() should not be used in '
                                        'J2EE/JEE apps'},
    'DoNotExtendJavaLangError': {   'categories': ['security'],
                                    'description': 'Errors are system '
                                                   'exceptions. Do not extend '
                                                   'them.\n'
                                                   'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strictexception.html#DoNotExtendJavaLangError\n'
                                                   '\n'
                                                   'public class Foo extends '
                                                   'Error { }\n'
                                                   '    ',
                                    'display_name': 'DoNotExtendJavaLangError',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'Exceptions should not extend '
                                             'java.lang.Error'},
    'DoNotHardCodeSDCard': {   'categories': ['security'],
                               'description': 'Use '
                                              'Environment.getExternalStorageDirectory() '
                                              'instead of "/sdcard"\n'
                                              'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/android.html#DoNotHardCodeSDCard\n'
                                              '\n'
                                              '      \n'
                                              'public class MyActivity extends '
                                              'Activity {\n'
                                              '\tprotected void foo() {\n'
                                              '\t\tString storageLocation = '
                                              '"/sdcard/mypackage";\t// '
                                              'hard-coded, poor approach\n'
                                              '\n'
                                              '\t\tstorageLocation = '
                                              'Environment.getExternalStorageDirectory() '
                                              '+ "/mypackage"; // preferred '
                                              'approach\n'
                                              '\t}\n'
                                              '}\n'
                                              '\n'
                                              '    ',
                               'display_name': 'DoNotHardCodeSDCard',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Do not hardcode /sdcard.'},
    'DoNotThrowExceptionInFinally': {   'categories': ['security'],
                                        'description': 'Throwing exceptions '
                                                       "within a 'finally' "
                                                       'block is confusing '
                                                       'since they may mask '
                                                       'other exceptions or '
                                                       'code defects. Note: '
                                                       'This is a PMD '
                                                       'implementation of the '
                                                       'Lint4j rule "A throw '
                                                       'in a finally block"\n'
                                                       'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strictexception.html#DoNotThrowExceptionInFinally\n'
                                                       '\n'
                                                       '    \t\t\n'
                                                       'public class Foo {\n'
                                                       '\tpublic void bar() {\n'
                                                       '\t\ttry {\n'
                                                       '\t\t\t// Here do some '
                                                       'stuff\n'
                                                       '\t\t} catch( Exception '
                                                       'e) {\n'
                                                       '\t\t\t// Handling the '
                                                       'issue\n'
                                                       '\t\t} finally {\n'
                                                       '\t\t\t// is this '
                                                       'really a good idea ?\n'
                                                       '\t\t\tthrow new '
                                                       'Exception();\n'
                                                       '\t\t}\n'
                                                       '\t}\n'
                                                       '}\n'
                                                       '\t    \t\n'
                                                       '    \t',
                                        'display_name': 'DoNotThrowExceptionInFinally',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'A throw statement in a '
                                                 'finally block makes the '
                                                 'control flow hard to '
                                                 'understand.'},
    'DoNotUseThreads': {   'categories': ['security'],
                           'description': 'The J2EE specification explicitly '
                                          'forbids the use of threads.\n'
                                          'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/j2ee.html#DoNotUseThreads\n'
                                          '\n'
                                          '            \t\n'
                                          '            // This is not allowed\n'
                                          'public class UsingThread extends '
                                          'Thread {\n'
                                          '\n'
                                          ' }\n'
                                          '\t// Neither this,\n'
                                          'public class OtherThread implements '
                                          'Runnable {\n'
                                          '\t// Nor this ...\n'
                                          '\tpublic void methode() {\n'
                                          '\t\t\tRunnable thread = new '
                                          'Thread(); thread.run();\n'
                                          '\t}\n'
                                          '}\n'
                                          '\t\t\t\t\n'
                                          '\t\t',
                           'display_name': 'DoNotUseThreads',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'To be compliant to J2EE, a webapp should '
                                    'not use any thread.'},
    'DontCallThreadRun': {   'categories': ['security'],
                             'description': 'Explicitly calling Thread.run() '
                                            'method will execute in the '
                                            "caller's thread of control. "
                                            'Instead, call Thread.start() for '
                                            'the intended behavior.\n'
                                            'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#DontCallThreadRun\n'
                                            '\n'
                                            '\n'
                                            'Thread t = new Thread();\n'
                                            't.run();            // use '
                                            't.start() instead\n'
                                            'new Thread().run(); // same '
                                            'violation\n'
                                            '\n'
                                            '      ',
                             'display_name': 'DontCallThreadRun',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': "Don't call Thread.run() explicitly, use "
                                      'Thread.start()'},
    'DontImportJavaLang': {   'categories': ['security'],
                              'description': 'Avoid importing anything from '
                                             "the package 'java.lang'. These "
                                             'classes are automatically '
                                             'imported (JLS 7.5.3).\n'
                                             'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/imports.html#DontImportJavaLang\n'
                                             '\n'
                                             '\n'
                                             'import java.lang.String;\t// '
                                             'this is unnecessary\n'
                                             '\n'
                                             'public class Foo {}\n'
                                             '\n'
                                             '// --- in another source code '
                                             'file...\n'
                                             '\n'
                                             'import java.lang.*;\t// this is '
                                             'bad\n'
                                             '\n'
                                             'public class Foo {}\n'
                                             '\n'
                                             '    ',
                              'display_name': 'DontImportJavaLang',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'Avoid importing anything from the '
                                       "package 'java.lang'"},
    'DontImportSun': {   'categories': ['security'],
                         'description': 'Avoid importing anything from the '
                                        "'sun.*' packages. These packages are "
                                        'not portable and are likely to '
                                        'change.\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#DontImportSun\n'
                                        '\n'
                                        '\n'
                                        'import sun.misc.foo;\n'
                                        'public class Foo {}\n'
                                        '\n'
                                        '       ',
                         'display_name': 'DontImportSun',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': "Avoid importing anything from the 'sun.*' "
                                  'packages'},
    'DontNestJsfInJstlIteration': {   'categories': ['security'],
                                      'description': 'Do not nest JSF '
                                                     'component custom actions '
                                                     'inside a custom action '
                                                     'that iterates over its '
                                                     'body.\n'
                                                     'https://pmd.github.io/pmd-5.8.1/pmd-jsp/rules/jsp/basic-jsf.html#DontNestJsfInJstlIteration\n'
                                                     '\n'
                                                     ' \n'
                                                     '<html> <body> <ul>\n'
                                                     '\t\t<c:forEach '
                                                     "items='${books}' "
                                                     "var='b'>\n"
                                                     '\t\t\t<li> <h:outputText '
                                                     "value='#{b}' /> </li>\n"
                                                     '\t\t</c:forEach>\n'
                                                     '</ul> </body> </html>\n'
                                                     ' \n'
                                                     '     ',
                                      'display_name': 'DontNestJsfInJstlIteration',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'Do not nest JSF component '
                                               'custom actions inside a custom '
                                               'action that iterates over its '
                                               'body.'},
    'DontUseFloatTypeForLoopIndices': {   'categories': ['security'],
                                          'description': "Don't use floating "
                                                         'point for loop '
                                                         'indices. If you must '
                                                         'use floating point, '
                                                         'use double unless '
                                                         "you're certain that "
                                                         'float provides '
                                                         'enough precision and '
                                                         'you have a '
                                                         'compelling '
                                                         'performance need '
                                                         '(space or time).\n'
                                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#DontUseFloatTypeForLoopIndices\n'
                                                         '\n'
                                                         '\n'
                                                         'public class Count '
                                                         '{\n'
                                                         '  public static void '
                                                         'main(String[] args) '
                                                         '{\n'
                                                         '    final int START '
                                                         '= 2000000000;\n'
                                                         '    int count = 0;\n'
                                                         '    for (float f = '
                                                         'START; f < START + '
                                                         '50; f++)\n'
                                                         '      count++;\n'
                                                         '      //Prints 0 '
                                                         'because (float) '
                                                         'START == (float) '
                                                         '(START + 50).\n'
                                                         '      '
                                                         'System.out.println(count);\n'
                                                         '      //The '
                                                         'termination test '
                                                         'misbehaves due to '
                                                         'floating point '
                                                         'granularity.\n'
                                                         '    }\n'
                                                         '}\n'
                                                         '\n'
                                                         '    ',
                                          'display_name': 'DontUseFloatTypeForLoopIndices',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': "Don't use floating point "
                                                   'for loop indices. If you '
                                                   'must use floating point, '
                                                   'use double.'},
    'DoubleCheckedLocking': {   'categories': ['security'],
                                'description': 'Partially created objects can '
                                               'be returned by the Double '
                                               'Checked Locking pattern when '
                                               'used in Java. An optimizing '
                                               'JRE may assign a reference to '
                                               'the baz variable before it '
                                               'calls the constructor of the '
                                               'object the reference points '
                                               'to. Note: With Java 5, you can '
                                               'make Double checked locking '
                                               'work, if you declare the '
                                               'variable to be `volatile`. For '
                                               'more details refer to: '
                                               'http://www.javaworld.com/javaworld/jw-02-2001/jw-0209-double.html '
                                               'or '
                                               'http://www.cs.umd.edu/~pugh/java/memoryModel/DoubleCheckedLocking.html\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#DoubleCheckedLocking\n'
                                               '\n'
                                               '  \n'
                                               'public class Foo {\n'
                                               '\t/*volatile */ Object baz = '
                                               'null; // fix for Java5 and '
                                               'later: volatile\n'
                                               '\tObject bar() {\n'
                                               '\t\tif (baz == null) { // baz '
                                               'may be non-null yet not fully '
                                               'created\n'
                                               '\t\t\tsynchronized(this) {\n'
                                               '\t\t\t\tif (baz == null) {\n'
                                               '\t\t\t\t\tbaz = new Object();\n'
                                               '        \t\t}\n'
                                               '      \t\t}\n'
                                               '    \t}\n'
                                               '\t\treturn baz;\n'
                                               '\t}\n'
                                               '}\n'
                                               ' \n'
                                               '      ',
                                'display_name': 'DoubleCheckedLocking',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Double checked locking is not thread '
                                         'safe in Java.'},
    'DuplicateImports': {   'categories': ['security'],
                            'description': 'Duplicate or overlapping import '
                                           'statements should be avoided.\n'
                                           'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/imports.html#DuplicateImports\n'
                                           '\n'
                                           '\n'
                                           'import java.lang.String;\n'
                                           'import java.lang.*;\n'
                                           'public class Foo {}\n'
                                           '\n'
                                           '    ',
                            'display_name': 'DuplicateImports',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': "Avoid duplicate imports such as ''{0}''"},
    'DuplicateJspImports': {   'categories': ['security'],
                               'description': 'Avoid duplicate import '
                                              "statements inside JSP's.\n"
                                              'https://pmd.github.io/pmd-5.8.1/pmd-jsp/rules/jsp/basic.html#DuplicateJspImports\n'
                                              '\n'
                                              '\t\t\t \n'
                                              '<%@ page '
                                              'import=\\"com.foo.MyClass,com.foo.MyClass\\"%><html><body><b><img '
                                              'src=\\"<%=Some.get()%>/foo\\">xx</img>text</b></body></html>\n'
                                              '\t\t\t \n'
                                              '\t\t',
                               'display_name': 'DuplicateJspImports',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Avoid duplicate imports such as '
                                        "''{0}''"},
    'EmptyCatchBlock': {   'categories': ['security'],
                           'description': 'Empty Catch Block finds instances '
                                          'where an exception is caught, but '
                                          'nothing is done. In most '
                                          'circumstances, this swallows an '
                                          'exception which should either be '
                                          'acted on or reported.\n'
                                          'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/empty.html#EmptyCatchBlock\n'
                                          '\n'
                                          '  \n'
                                          'public void doSomething() {\n'
                                          '  try {\n'
                                          '    FileInputStream fis = new '
                                          'FileInputStream("/tmp/bugger");\n'
                                          '  } catch (IOException ioe) {\n'
                                          '      // not good\n'
                                          '  }\n'
                                          '}\n'
                                          ' \n'
                                          '      ',
                           'display_name': 'EmptyCatchBlock',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'Avoid empty catch blocks'},
    'EmptyFinalizer': {   'categories': ['security'],
                          'description': 'Empty finalize methods serve no '
                                         'purpose and should be removed.\n'
                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/finalizers.html#EmptyFinalizer\n'
                                         '\n'
                                         '\n'
                                         'public class Foo {\n'
                                         '   protected void finalize() {}\n'
                                         '}\n'
                                         '\n'
                                         '       ',
                          'display_name': 'EmptyFinalizer',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'Avoid empty finalize methods'},
    'EmptyFinallyBlock': {   'categories': ['security'],
                             'description': 'Empty finally blocks serve no '
                                            'purpose and should be removed.\n'
                                            'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/empty.html#EmptyFinallyBlock\n'
                                            '\n'
                                            '  \n'
                                            'public class Foo {\n'
                                            ' public void bar() {\n'
                                            '  try {\n'
                                            '    int x=2;\n'
                                            '   } finally {\n'
                                            '    // empty!\n'
                                            '   }\n'
                                            ' }\n'
                                            '}\n'
                                            ' \n'
                                            '      ',
                             'display_name': 'EmptyFinallyBlock',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Avoid empty finally blocks'},
    'EmptyForeachStmt': {   'categories': ['security'],
                            'description': 'Empty foreach statements should be '
                                           'deleted.\n'
                                           'https://pmd.github.io/pmd-5.8.1/pmd-vm/rules/vm/basic.html#EmptyForeachStmt\n',
                            'display_name': 'EmptyForeachStmt',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'Avoid empty foreach loops'},
    'EmptyIfStmt': {   'categories': ['security'],
                       'description': 'Empty if statements should be deleted.\n'
                                      'https://pmd.github.io/pmd-5.8.1/pmd-vm/rules/vm/basic.html#EmptyIfStmt\n',
                       'display_name': 'EmptyIfStmt',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Avoid empty if statements'},
    'EmptyInitializer': {   'categories': ['security'],
                            'description': 'Empty initializers serve no '
                                           'purpose and should be removed.\n'
                                           'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/empty.html#EmptyInitializer\n'
                                           '\n'
                                           '   \n'
                                           'public class Foo {\n'
                                           '\n'
                                           '   static {} // Why ?\n'
                                           '\n'
                                           '   {} // Again, why ?\n'
                                           '\n'
                                           '}\n'
                                           '    \n'
                                           '    ',
                            'display_name': 'EmptyInitializer',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'Empty initializer was found'},
    'EmptyMethodInAbstractClassShouldBeAbstract': {   'categories': [   'security'],
                                                      'description': 'Empty or '
                                                                     'auto-generated '
                                                                     'methods '
                                                                     'in an '
                                                                     'abstract '
                                                                     'class '
                                                                     'should '
                                                                     'be '
                                                                     'tagged '
                                                                     'as '
                                                                     'abstract. '
                                                                     'This '
                                                                     'helps to '
                                                                     'remove '
                                                                     'their '
                                                                     'inapproprate '
                                                                     'usage by '
                                                                     'developers '
                                                                     'who '
                                                                     'should '
                                                                     'be '
                                                                     'implementing '
                                                                     'their '
                                                                     'own '
                                                                     'versions '
                                                                     'in the '
                                                                     'concrete '
                                                                     'subclasses.\n'
                                                                     'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#EmptyMethodInAbstractClassShouldBeAbstract\n'
                                                                     '\n'
                                                                     '        \t\n'
                                                                     'public '
                                                                     'abstract '
                                                                     'class '
                                                                     'ShouldBeAbstract '
                                                                     '{\n'
                                                                     '    '
                                                                     'public '
                                                                     'Object '
                                                                     'couldBeAbstract() '
                                                                     '{\n'
                                                                     '        '
                                                                     '// '
                                                                     'Should '
                                                                     'be '
                                                                     'abstract '
                                                                     'method '
                                                                     '?\n'
                                                                     '        '
                                                                     'return '
                                                                     'null;\n'
                                                                     '    }\n'
                                                                     '\n'
                                                                     '    '
                                                                     'public '
                                                                     'void '
                                                                     'couldBeAbstract() '
                                                                     '{\n'
                                                                     '    }\n'
                                                                     '}\n'
                                                                     '\t     \t\n'
                                                                     '    \t',
                                                      'display_name': 'EmptyMethodInAbstractClassShouldBeAbstract',
                                                      'file': '%(issue.file)s',
                                                      'line': '%(issue.line)s',
                                                      'severity': '1',
                                                      'title': 'An empty '
                                                               'method in an '
                                                               'abstract class '
                                                               'should be '
                                                               'abstract '
                                                               'instead'},
    'EmptyStatementBlock': {   'categories': ['security'],
                               'description': 'Empty block statements serve no '
                                              'purpose and should be removed.\n'
                                              'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/empty.html#EmptyStatementBlock\n'
                                              '\n'
                                              '    \n'
                                              'public class Foo {\n'
                                              '\n'
                                              '   private int _bar;\n'
                                              '\n'
                                              '   public void setBar(int bar) '
                                              '{\n'
                                              '      { _bar = bar; } // Why '
                                              'not?\n'
                                              '      {} // But remove this.\n'
                                              '   }\n'
                                              '\n'
                                              '}\n'
                                              '    \n'
                                              '    ',
                               'display_name': 'EmptyStatementBlock',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Avoid empty block statements.'},
    'EmptyStatementNotInLoop': {   'categories': ['security'],
                                   'description': 'An empty statement (or a '
                                                  'semicolon by itself) that '
                                                  'is not used as the sole '
                                                  "body of a 'for' or 'while' "
                                                  'loop is probably a bug. It '
                                                  'could also be a double '
                                                  'semicolon, which has no '
                                                  'purpose and should be '
                                                  'removed.\n'
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/empty.html#EmptyStatementNotInLoop\n'
                                                  '\n'
                                                  '\n'
                                                  'public void doit() {\n'
                                                  '      // this is probably '
                                                  'not what you meant to do\n'
                                                  '      ;\n'
                                                  '      // the extra '
                                                  'semicolon here this is not '
                                                  'necessary\n'
                                                  '      '
                                                  'System.out.println("look at '
                                                  'the extra semicolon");;\n'
                                                  '}\n'
                                                  '\n'
                                                  '       ',
                                   'display_name': 'EmptyStatementNotInLoop',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'An empty statement (semicolon) '
                                            'not part of a loop'},
    'EmptyStaticInitializer': {   'categories': ['security'],
                                  'description': 'An empty static initializer '
                                                 'serve no purpose and should '
                                                 'be removed.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/empty.html#EmptyStaticInitializer\n'
                                                 '\n'
                                                 '   \n'
                                                 'public class Foo {\n'
                                                 '\tstatic {\n'
                                                 '\t// empty\n'
                                                 '\t}\n'
                                                 '}\n'
                                                 '\n'
                                                 '       ',
                                  'display_name': 'EmptyStaticInitializer',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'Empty static initializer was '
                                           'found'},
    'EmptySwitchStatements': {   'categories': ['security'],
                                 'description': 'Empty switch statements serve '
                                                'no purpose and should be '
                                                'removed.\n'
                                                'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/empty.html#EmptySwitchStatements\n'
                                                '\n'
                                                '  \n'
                                                'public void bar() {\n'
                                                '\tint x = 2;\n'
                                                '\tswitch (x) {\n'
                                                '\t// once there was code '
                                                'here\n'
                                                "\t// but it's been commented "
                                                'out or something\n'
                                                '\t}\n'
                                                '}\n'
                                                '\n'
                                                '      ',
                                 'display_name': 'EmptySwitchStatements',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'Avoid empty switch statements'},
    'EmptySynchronizedBlock': {   'categories': ['security'],
                                  'description': 'Empty synchronized blocks '
                                                 'serve no purpose and should '
                                                 'be removed.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/empty.html#EmptySynchronizedBlock\n'
                                                 '\n'
                                                 '\n'
                                                 'public class Foo {\n'
                                                 ' public void bar() {\n'
                                                 '  synchronized (this) {\n'
                                                 '   // empty!\n'
                                                 '  }\n'
                                                 ' }\n'
                                                 '}\n'
                                                 '\n'
                                                 '      ',
                                  'display_name': 'EmptySynchronizedBlock',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'Avoid empty synchronized blocks'},
    'EmptyTryBlock': {   'categories': ['security'],
                         'description': "Avoid empty try blocks - what's the "
                                        'point?\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/empty.html#EmptyTryBlock\n'
                                        '\n'
                                        '  \n'
                                        'public class Foo {\n'
                                        ' public void bar() {\n'
                                        '  try {\n'
                                        '  } catch (Exception e) {\n'
                                        '    e.printStackTrace();\n'
                                        '  }\n'
                                        ' }\n'
                                        '}\n'
                                        '\n'
                                        '      ',
                         'display_name': 'EmptyTryBlock',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Avoid empty try blocks'},
    'EmptyWhileStmt': {   'categories': ['security'],
                          'description': 'Empty While Statement finds all '
                                         'instances where a while statement '
                                         'does nothing. If it is a timing '
                                         'loop, then you should use '
                                         'Thread.sleep() for it; if it is a '
                                         'while loop that does a lot in the '
                                         'exit expression, rewrite it to make '
                                         'it clearer.\n'
                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/empty.html#EmptyWhileStmt\n'
                                         '\n'
                                         '  \n'
                                         'void bar(int a, int b) {\n'
                                         '\twhile (a == b) {\n'
                                         '\t// empty!\n'
                                         '\t}\n'
                                         '}\n'
                                         ' \n'
                                         '       ',
                          'display_name': 'EmptyWhileStmt',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': "Avoid empty 'while' statements"},
    'EqualComparison': {   'categories': ['security'],
                           'description': 'Using == in condition may lead to '
                                          'unexpected results, as the '
                                          'variables are automatically casted '
                                          'to be of the same type. The === '
                                          'operator avoids the casting.\n'
                                          'https://pmd.github.io/pmd-5.8.1/pmd-javascript/rules/ecmascript/basic.html#EqualComparison\n'
                                          '\n'
                                          '  \n'
                                          '// Ok\n'
                                          'if (someVar === true) {\n'
                                          '  ...\n'
                                          '}\n'
                                          '// Ok\n'
                                          'if (someVar !== 3) {\n'
                                          '  ...\n'
                                          '}\n'
                                          '// Bad\n'
                                          'if (someVar == true) {\n'
                                          '  ...\n'
                                          '}\n'
                                          '// Bad\n'
                                          'if (someVar != 3) {\n'
                                          '  ...\n'
                                          '}\n'
                                          '\n'
                                          '\n'
                                          '      ',
                           'display_name': 'EqualComparison',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': "Use '==='/'!==' to compare with "
                                    'true/false or Numbers'},
    'EqualsNull': {   'categories': ['security'],
                      'description': 'Tests for null should not use the '
                                     "equals() method. The '==' operator "
                                     'should be used instead.\n'
                                     'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#EqualsNull\n'
                                     '\n'
                                     '       \n'
                                     'String x = "foo";\n'
                                     '\n'
                                     'if (x.equals(null)) { // bad form\n'
                                     '   \tdoSomething();\n'
                                     '\t}\n'
                                     '\n'
                                     'if (x == null) { \t// preferred\n'
                                     '   \tdoSomething();\n'
                                     '\t}\n'
                                     '    \n'
                                     '        ',
                      'display_name': 'EqualsNull',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Avoid using equals() to compare against null'},
    'ExceptionAsFlowControl': {   'categories': ['security'],
                                  'description': 'Using Exceptions as form of '
                                                 'flow control is not '
                                                 'recommended as they obscure '
                                                 'true exceptions when '
                                                 'debugging. Either add the '
                                                 'necessary validation or use '
                                                 'an alternate control '
                                                 'structure.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strictexception.html#ExceptionAsFlowControl\n'
                                                 '\n'
                                                 '  \n'
                                                 'public void bar() {\n'
                                                 '    try {\n'
                                                 '      try {\n'
                                                 '      } catch (Exception e) '
                                                 '{\n'
                                                 '        throw new '
                                                 'WrapperException(e);\n'
                                                 '       // this is '
                                                 'essentially a GOTO to the '
                                                 'WrapperException catch '
                                                 'block\n'
                                                 '       }\n'
                                                 '     } catch '
                                                 '(WrapperException e) {\n'
                                                 '     // do some more stuff\n'
                                                 '    }\n'
                                                 '  }\n'
                                                 '  \n'
                                                 '      ',
                                  'display_name': 'ExceptionAsFlowControl',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'Avoid using exceptions as flow '
                                           'control.'},
    'ExcessiveClassLength': {   'categories': ['security'],
                                'description': 'Excessive class file lengths '
                                               'are usually indications that '
                                               'the class may be burdened with '
                                               'excessive responsibilities '
                                               'that could be provided by '
                                               'external classes or functions. '
                                               'In breaking these methods '
                                               'apart the code becomes more '
                                               'managable and ripe for reuse.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/codesize.html#ExcessiveClassLength\n'
                                               '\n'
                                               '\n'
                                               'public class Foo {\n'
                                               '\tpublic void bar1() {\n'
                                               '    // 1000 lines of code\n'
                                               '\t}\n'
                                               '\tpublic void bar2() {\n'
                                               '    // 1000 lines of code\n'
                                               '\t}\n'
                                               '    public void bar3() {\n'
                                               '    // 1000 lines of code\n'
                                               '\t}\n'
                                               '\t\n'
                                               '\t\n'
                                               '    public void barN() {\n'
                                               '    // 1000 lines of code\n'
                                               '\t}\n'
                                               '}\n'
                                               '\n'
                                               '   ',
                                'display_name': 'ExcessiveClassLength',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Avoid really long classes.'},
    'ExcessiveImports': {   'categories': ['security'],
                            'description': 'A high number of imports can '
                                           'indicate a high degree of coupling '
                                           'within an object. This rule counts '
                                           'the number of unique imports and '
                                           'reports a violation if the count '
                                           'is above the user-specified '
                                           'threshold.\n'
                                           'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/coupling.html#ExcessiveImports\n'
                                           '\n'
                                           '      \n'
                                           'import blah.blah.Baz;\n'
                                           'import blah.blah.Bif;\n'
                                           '// 18 others from the same package '
                                           'elided\n'
                                           'public class Foo {\n'
                                           ' public void doWork() {}\n'
                                           '}\n'
                                           '      \n'
                                           '  ',
                            'display_name': 'ExcessiveImports',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'A high number of imports can indicate a '
                                     'high degree of coupling within an '
                                     'object.'},
    'ExcessiveMethodLength': {   'categories': ['security'],
                                 'description': 'When methods are excessively '
                                                'long this usually indicates '
                                                'that the method is doing more '
                                                'than its name/signature might '
                                                'suggest. They also become '
                                                'challenging for others to '
                                                'digest since excessive '
                                                'scrolling causes readers to '
                                                'lose focus. Try to reduce the '
                                                'method length by creating '
                                                'helper methods and removing '
                                                'any copy/pasted code.\n'
                                                'https://pmd.github.io/pmd-5.8.1/pmd-plsql/rules/plsql/codesize.html#ExcessiveMethodLength\n'
                                                '\n'
                                                '\n'
                                                'CREATE OR REPLACE\n'
                                                'PROCEDURE doSomething BEGIN\n'
                                                '\tDBMS_OUTPUT.PUT_LINE("Hello '
                                                'world!");\n'
                                                '\tDBMS_OUTPUT.PUT_LINE("Hello '
                                                'world!");\n'
                                                '\t\t-- 98 copies omitted for '
                                                'brevity.\n'
                                                'END;\n'
                                                '\n'
                                                '\n'
                                                '   ',
                                 'display_name': 'ExcessiveMethodLength',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'Avoid really long methods ({0} '
                                          'lines found).'},
    'ExcessiveObjectLength': {   'categories': ['security'],
                                 'description': 'Excessive object line lengths '
                                                'are usually indications that '
                                                'the object may be burdened '
                                                'with excessive '
                                                'responsibilities that could '
                                                'be provided by other objects. '
                                                'In breaking these methods '
                                                'apart the code becomes more '
                                                'managable and ripe for '
                                                'reuse.\n'
                                                'https://pmd.github.io/pmd-5.8.1/pmd-plsql/rules/plsql/codesize.html#ExcessiveObjectLength\n'
                                                '\n'
                                                '\n'
                                                'CREATE OR REPLACE\n'
                                                'PACKAGE BODY Foo AS\n'
                                                '\tPROCEDURE bar1 IS BEGIN\n'
                                                '    -- 1000 lines of code\n'
                                                '\tEND bar1;\n'
                                                '\tPROCEDURE bar2 IS BEGIN\n'
                                                '    -- 1000 lines of code\n'
                                                '\tEND bar2;\n'
                                                '    PROCEDURE bar3 IS BEGIN\n'
                                                '    -- 1000 lines of code\n'
                                                '\tEND bar3;\n'
                                                '\t\n'
                                                '\t\n'
                                                '    PROCEDURE barN IS BEGIN\n'
                                                '    -- 1000 lines of code\n'
                                                '\tEND barn;\n'
                                                'END;\n'
                                                '\n'
                                                '   ',
                                 'display_name': 'ExcessiveObjectLength',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'Avoid really long Oracle object '
                                          'specifications and bodies ({0} '
                                          'lines found).'},
    'ExcessivePackageBodyLength': {   'categories': ['security'],
                                      'description': 'Excessive class file '
                                                     'lengths are usually '
                                                     'indications that the '
                                                     'class may be burdened '
                                                     'with excessive '
                                                     'responsibilities that '
                                                     'could be provided by '
                                                     'external classes or '
                                                     'functions. In breaking '
                                                     'these methods apart the '
                                                     'code becomes more '
                                                     'managable and ripe for '
                                                     'reuse.\n'
                                                     'https://pmd.github.io/pmd-5.8.1/pmd-plsql/rules/plsql/codesize.html#ExcessivePackageBodyLength\n'
                                                     '\n'
                                                     '\n'
                                                     'CREATE OR REPLACE\n'
                                                     'PACKAGE BODY Foo AS\n'
                                                     '\tPROCEDURE bar1 IS '
                                                     'BEGIN\n'
                                                     '    -- 1000 lines of '
                                                     'code\n'
                                                     '\tEND bar1;\n'
                                                     '\tPROCEDURE bar2 IS '
                                                     'BEGIN\n'
                                                     '    -- 1000 lines of '
                                                     'code\n'
                                                     '\tEND bar2;\n'
                                                     '    PROCEDURE bar3 IS '
                                                     'BEGIN\n'
                                                     '    -- 1000 lines of '
                                                     'code\n'
                                                     '\tEND bar3;\n'
                                                     '\t\n'
                                                     '\t\n'
                                                     '    PROCEDURE barN IS '
                                                     'BEGIN\n'
                                                     '    -- 1000 lines of '
                                                     'code\n'
                                                     '\tEND barn;\n'
                                                     'END;\n'
                                                     '\n'
                                                     '   ',
                                      'display_name': 'ExcessivePackageBodyLength',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'Avoid really long Object Type '
                                               'and Package bodies ({0} lines '
                                               'found).'},
    'ExcessivePackageSpecificationLength': {   'categories': ['security'],
                                               'description': 'Excessive class '
                                                              'file lengths '
                                                              'are usually '
                                                              'indications '
                                                              'that the class '
                                                              'may be burdened '
                                                              'with excessive '
                                                              'responsibilities '
                                                              'that could be '
                                                              'provided by '
                                                              'external '
                                                              'classes or '
                                                              'functions. In '
                                                              'breaking these '
                                                              'methods apart '
                                                              'the code '
                                                              'becomes more '
                                                              'managable and '
                                                              'ripe for '
                                                              'reuse.\n'
                                                              'https://pmd.github.io/pmd-5.8.1/pmd-plsql/rules/plsql/codesize.html#ExcessivePackageSpecificationLength\n'
                                                              '\n'
                                                              '\n'
                                                              '\n'
                                                              'CREATE OR '
                                                              'REPLACE\n'
                                                              'PACKAGE Foo AS\n'
                                                              '\tPROCEDURE '
                                                              'bar1 ;\n'
                                                              '\tPROCEDURE '
                                                              'bar2 ;\n'
                                                              '        '
                                                              'PROCEDURE bar3 '
                                                              ';\n'
                                                              '\t\n'
                                                              '    ..\n'
                                                              '\t\n'
                                                              '        '
                                                              'PROCEDURE barN '
                                                              ';\n'
                                                              'END;\n'
                                                              '   ',
                                               'display_name': 'ExcessivePackageSpecificationLength',
                                               'file': '%(issue.file)s',
                                               'line': '%(issue.line)s',
                                               'severity': '1',
                                               'title': 'Avoid really long '
                                                        'Package '
                                                        'Specifications ({0} '
                                                        'lines found).'},
    'ExcessiveParameterList': {   'categories': ['security'],
                                  'description': 'Methods with numerous '
                                                 'parameters are a challenge '
                                                 'to maintain, especially if '
                                                 'most of them share the same '
                                                 'datatype. These situations '
                                                 'usually denote the need for '
                                                 'new objects to wrap the '
                                                 'numerous parameters.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-plsql/rules/plsql/codesize.html#ExcessiveParameterList\n'
                                                 '\n'
                                                 '\n'
                                                 'CREATE OR REPLACE\n'
                                                 'PROCEDURE addPerson(\t\t-- '
                                                 'too many arguments liable to '
                                                 'be mixed up\n'
                                                 '\tbirthYear pls_integer, '
                                                 'birthMonth pls_integer, '
                                                 'birthDate pls_integer, '
                                                 'height pls_integer, weight '
                                                 'pls_integer, ssn '
                                                 'pls_integer) {\n'
                                                 '\n'
                                                 '\t. . . .\n'
                                                 'END ADDPERSON;\n'
                                                 ' \n'
                                                 'CREATE OR REPLACE\n'
                                                 'PROCEDURE addPerson(\t\t-- '
                                                 'preferred approach\n'
                                                 '\tbirthdate DATE, '
                                                 'measurements '
                                                 'BodyMeasurements , ssn '
                                                 'INTEGER) BEGIN\n'
                                                 '\n'
                                                 '\t. . . .\n'
                                                 'END;\n'
                                                 '\n'
                                                 '   ',
                                  'display_name': 'ExcessiveParameterList',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'Avoid long parameter lists.'},
    'ExcessivePublicCount': {   'categories': ['security'],
                                'description': 'Classes with large numbers of '
                                               'public methods and attributes '
                                               'require disproportionate '
                                               'testing efforts since '
                                               'combinational side effects '
                                               'grow rapidly and increase '
                                               'risk. Refactoring these '
                                               'classes into smaller ones not '
                                               'only increases testability and '
                                               'reliability but also allows '
                                               'new variations to be developed '
                                               'easily.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/codesize.html#ExcessivePublicCount\n'
                                               '\n'
                                               '    \n'
                                               'public class Foo {\n'
                                               '\tpublic String value;\n'
                                               '\tpublic Bar something;\n'
                                               '\tpublic Variable var;\n'
                                               ' // [... more more public '
                                               'attributes ...]\n'
                                               ' \n'
                                               '\tpublic void doWork() {}\n'
                                               '\tpublic void doMoreWork() {}\n'
                                               '\tpublic void doWorkAgain() '
                                               '{}\n'
                                               ' // [... more more public '
                                               'methods ...]\n'
                                               '}\n'
                                               '    \n'
                                               '    ',
                                'display_name': 'ExcessivePublicCount',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'This class has a bunch of public '
                                         'methods and attributes'},
    'ExcessiveTemplateLength': {   'categories': ['security'],
                                   'description': 'The template is too long. '
                                                  'It should be broken up into '
                                                  'smaller pieces.\n'
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-vm/rules/vm/basic.html#ExcessiveTemplateLength\n',
                                   'display_name': 'ExcessiveTemplateLength',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'Template is too long'},
    'ExcessiveTypeLength': {   'categories': ['security'],
                               'description': 'Excessive class file lengths '
                                              'are usually indications that '
                                              'the class may be burdened with '
                                              'excessive responsibilities that '
                                              'could be provided by external '
                                              'classes or functions. In '
                                              'breaking these methods apart '
                                              'the code becomes more managable '
                                              'and ripe for reuse.\n'
                                              'https://pmd.github.io/pmd-5.8.1/pmd-plsql/rules/plsql/codesize.html#ExcessiveTypeLength\n'
                                              '\n'
                                              '\n'
                                              'CREATE OR REPLACE\n'
                                              'TYPE BODY Foo AS\n'
                                              '\t MEMBER PROCEDURE bar1 IS '
                                              'BEGIN\n'
                                              '    -- 1000 lines of code\n'
                                              '\tEND bar1;\n'
                                              '\t MEMBER PROCEDURE bar2 IS '
                                              'BEGIN\n'
                                              '    -- 1000 lines of code\n'
                                              '\tEND bar2;\n'
                                              '     MEMBER PROCEDURE bar3 IS '
                                              'BEGIN\n'
                                              '    -- 1000 lines of code\n'
                                              '\tEND bar3;\n'
                                              '\t\n'
                                              '\t\n'
                                              '     MEMBER PROCEDURE barN IS '
                                              'BEGIN\n'
                                              '    -- 1000 lines of code\n'
                                              '\tEND barn;\n'
                                              'END;\n'
                                              '\n'
                                              '   ',
                               'display_name': 'ExcessiveTypeLength',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Avoid really long Object Type '
                                        'specifications ({0} lines found).'},
    'ExtendsObject': {   'categories': ['security'],
                         'description': 'No need to explicitly extend Object.\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#ExtendsObject\n'
                                        '\n'
                                        '    \n'
                                        'public class Foo extends Object { \t'
                                        '// not required\n'
                                        '}\n'
                                        '    \n'
                                        '    ',
                         'display_name': 'ExtendsObject',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'No need to explicitly extend Object.'},
    'FieldDeclarationsShouldBeAtStartOfClass': {   'categories': ['security'],
                                                   'description': 'Fields '
                                                                  'should be '
                                                                  'declared at '
                                                                  'the top of '
                                                                  'the class, '
                                                                  'before any '
                                                                  'method '
                                                                  'declarations, '
                                                                  'constructors, '
                                                                  'initializers '
                                                                  'or inner '
                                                                  'classes.\n'
                                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#FieldDeclarationsShouldBeAtStartOfClass\n'
                                                                  '\n'
                                                                  '      \n'
                                                                  'public '
                                                                  'class '
                                                                  'HelloWorldBean '
                                                                  '{\n'
                                                                  '\n'
                                                                  '  // Field '
                                                                  'declared '
                                                                  'before '
                                                                  'methods / '
                                                                  'inner '
                                                                  'classes - '
                                                                  'OK\n'
                                                                  '  private '
                                                                  'String '
                                                                  '_thing;\n'
                                                                  '\n'
                                                                  '  public '
                                                                  'String '
                                                                  'getMessage() '
                                                                  '{\n'
                                                                  '    return '
                                                                  '"Hello '
                                                                  'World!";\n'
                                                                  '  }\n'
                                                                  '\n'
                                                                  '  // Field '
                                                                  'declared '
                                                                  'after '
                                                                  'methods / '
                                                                  'inner '
                                                                  'classes - '
                                                                  'avoid this\n'
                                                                  '  private '
                                                                  'String '
                                                                  '_fieldInWrongLocation;\n'
                                                                  '}\n'
                                                                  '      \n'
                                                                  '    ',
                                                   'display_name': 'FieldDeclarationsShouldBeAtStartOfClass',
                                                   'file': '%(issue.file)s',
                                                   'line': '%(issue.line)s',
                                                   'severity': '1',
                                                   'title': 'Fields should be '
                                                            'declared at the '
                                                            'top of the class, '
                                                            'before any method '
                                                            'declarations, '
                                                            'constructors, '
                                                            'initializers or '
                                                            'inner classes.'},
    'FinalFieldCouldBeStatic': {   'categories': ['security'],
                                   'description': 'If a final field is '
                                                  'assigned to a compile-time '
                                                  'constant, it could be made '
                                                  'static, thus saving '
                                                  'overhead in each object at '
                                                  'runtime.\n'
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#FinalFieldCouldBeStatic\n'
                                                  '\n'
                                                  '  \n'
                                                  'public class Foo {\n'
                                                  '  public final int BAR = '
                                                  '42; // this could be static '
                                                  'and save some space\n'
                                                  '}\n'
                                                  '  \n'
                                                  '      ',
                                   'display_name': 'FinalFieldCouldBeStatic',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'This final field could be made '
                                            'static'},
    'FinalizeDoesNotCallSuperFinalize': {   'categories': ['security'],
                                            'description': 'If the finalize() '
                                                           'is implemented, '
                                                           'its last action '
                                                           'should be to call '
                                                           'super.finalize.\n'
                                                           'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/finalizers.html#FinalizeDoesNotCallSuperFinalize\n'
                                                           '\n'
                                                           '\n'
                                                           'protected void '
                                                           'finalize() {\n'
                                                           '\tsomething();\n'
                                                           '\t// neglected to '
                                                           'call '
                                                           'super.finalize()\n'
                                                           '}\n'
                                                           '\n'
                                                           '       ',
                                            'display_name': 'FinalizeDoesNotCallSuperFinalize',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'Last statement in '
                                                     'finalize method should '
                                                     'be a call to '
                                                     'super.finalize()'},
    'FinalizeOnlyCallsSuperFinalize': {   'categories': ['security'],
                                          'description': 'If the finalize() is '
                                                         'implemented, it '
                                                         'should do something '
                                                         'besides just calling '
                                                         'super.finalize().\n'
                                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/finalizers.html#FinalizeOnlyCallsSuperFinalize\n'
                                                         '\n'
                                                         '           \n'
                                                         'protected void '
                                                         'finalize() {\n'
                                                         '\tsuper.finalize();\n'
                                                         '}\n'
                                                         '           \n'
                                                         '       ',
                                          'display_name': 'FinalizeOnlyCallsSuperFinalize',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'Finalize should do '
                                                   'something besides just '
                                                   'calling super.finalize()'},
    'FinalizeOverloaded': {   'categories': ['security'],
                              'description': 'Methods named finalize() should '
                                             'not have parameters. It is '
                                             'confusing and most likely an '
                                             'attempt to overload '
                                             'Object.finalize(). It will not '
                                             'be called by the VM.\n'
                                             'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/finalizers.html#FinalizeOverloaded\n'
                                             '\n'
                                             '\n'
                                             'public class Foo {\n'
                                             '   // this is confusing and '
                                             'probably a bug\n'
                                             '   protected void finalize(int '
                                             'a) {\n'
                                             '   }\n'
                                             '}\n'
                                             '\n'
                                             '   ',
                              'display_name': 'FinalizeOverloaded',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'Finalize methods should not be '
                                       'overloaded'},
    'FinalizeShouldBeProtected': {   'categories': ['security'],
                                     'description': 'When overriding the '
                                                    'finalize(), the new '
                                                    'method should be set as '
                                                    'protected. If made '
                                                    'public, other classes may '
                                                    'invoke it at '
                                                    'inappropriate times.\n'
                                                    'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/finalizers.html#FinalizeShouldBeProtected\n'
                                                    '\n'
                                                    '  \n'
                                                    'public void finalize() {\n'
                                                    '\t// do something\n'
                                                    '}\n'
                                                    '  \n'
                                                    '      ',
                                     'display_name': 'FinalizeShouldBeProtected',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'If you override finalize(), '
                                              'make it protected'},
    'ForLoopShouldBeWhileLoop': {   'categories': ['security'],
                                    'description': 'Some for loops can be '
                                                   'simplified to while loops, '
                                                   'this makes them more '
                                                   'concise.\n'
                                                   'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#ForLoopShouldBeWhileLoop\n'
                                                   '\n'
                                                   '  \n'
                                                   'public class Foo {\n'
                                                   '\tvoid bar() {\n'
                                                   '\t\tfor (;true;) true; // '
                                                   'No Init or Update part, '
                                                   'may as well be: while '
                                                   '(true)\n'
                                                   '\t}\n'
                                                   '}\n'
                                                   ' \n'
                                                   '      ',
                                    'display_name': 'ForLoopShouldBeWhileLoop',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'This for loop could be '
                                             'simplified to a while loop'},
    'ForLoopsMustUseBraces': {   'categories': ['security'],
                                 'description': "Avoid using 'for' statements "
                                                'without using curly braces. '
                                                'If the code formatting or '
                                                'indentation is lost then it '
                                                'becomes difficult to separate '
                                                'the code being controlled '
                                                'from the rest.\n'
                                                'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/braces.html#ForLoopsMustUseBraces\n'
                                                '\n'
                                                '\n'
                                                'for (int i = 0; i < 42; i++)\n'
                                                '   foo();\n'
                                                '\n'
                                                '       ',
                                 'display_name': 'ForLoopsMustUseBraces',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': "Avoid using 'for' statements "
                                          'without curly braces'},
    'GenericsNaming': {   'categories': ['security'],
                          'description': 'Names for references to generic '
                                         'values should be limited to a single '
                                         'uppercase letter.\n'
                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#GenericsNaming\n'
                                         '\n'
                                         '            \n'
                                         'public interface GenericDao<E '
                                         'extends BaseModel, K extends '
                                         'Serializable> extends BaseDao {\n'
                                         '   // This is ok...\n'
                                         '}\n'
                                         '\n'
                                         'public interface GenericDao<E '
                                         'extends BaseModel, K extends '
                                         'Serializable> {\n'
                                         '   // Also this\n'
                                         '}\n'
                                         '\n'
                                         'public interface GenericDao<e '
                                         'extends BaseModel, K extends '
                                         'Serializable> {\n'
                                         "   // 'e' should be an 'E'\n"
                                         '}\n'
                                         '\n'
                                         'public interface GenericDao<EF '
                                         'extends BaseModel, K extends '
                                         'Serializable> {\n'
                                         "   // 'EF' is not ok.\n"
                                         '}\n'
                                         '     ',
                          'display_name': 'GenericsNaming',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'Generics names should be a one letter long '
                                   'and upper case.'},
    'GlobalVariable': {   'categories': ['security'],
                          'description': 'This rule helps to avoid using '
                                         'accidently global variables by '
                                         'simply missing the "var" '
                                         'declaration. Global variables can '
                                         'lead to side-effects that are hard '
                                         'to debug.\n'
                                         'https://pmd.github.io/pmd-5.8.1/pmd-javascript/rules/ecmascript/basic.html#GlobalVariable\n'
                                         '\n'
                                         '\n'
                                         'function(arg) {\n'
                                         '    notDeclaredVariable = 1; // this '
                                         'will create a global variable and '
                                         'trigger the rule\n'
                                         '\n'
                                         '    var someVar = 1; // this is a '
                                         "local variable, that's ok\n"
                                         '\n'
                                         '    window.otherGlobal = 2; // this '
                                         'will not trigger the rule, although '
                                         'it is a global variable.\n'
                                         '}\n'
                                         '\n'
                                         '        ',
                          'display_name': 'GlobalVariable',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'Avoid using global variables'},
    'GodClass': {   'categories': ['security'],
                    'description': 'The God Class rule detects the God Class '
                                   'design flaw using metrics. God classes do '
                                   'too many things, are very big and overly '
                                   'complex. They should be split apart to be '
                                   'more object-oriented. The rule uses the '
                                   'detection strategy described in '
                                   '"Object-Oriented Metrics in Practice". The '
                                   'violations are reported against the entire '
                                   'class. See also the references: Michele '
                                   'Lanza and Radu Marinescu. Object-Oriented '
                                   'Metrics in Practice: Using Software '
                                   'Metrics to Characterize, Evaluate, and '
                                   'Improve the Design of Object-Oriented '
                                   'Systems. Springer, Berlin, 1 edition, '
                                   'October 2006. Page 80.\n'
                                   'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#GodClass\n',
                    'display_name': 'GodClass',
                    'file': '%(issue.file)s',
                    'line': '%(issue.line)s',
                    'severity': '1',
                    'title': 'Possible God class'},
    'GuardDebugLogging': {   'categories': ['security'],
                             'description': 'When log messages are composed by '
                                            'concatenating strings, the whole '
                                            'section should be guarded by a '
                                            'isDebugEnabled() check to avoid '
                                            'performance and memory issues.\n'
                                            'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/logging-jakarta-commons.html#GuardDebugLogging\n'
                                            '\n'
                                            '            \n'
                                            'public class Test {\n'
                                            '    private static final Log '
                                            '__log = '
                                            'LogFactory.getLog(Test.class);\n'
                                            '    public void test() {\n'
                                            '        // okay:\n'
                                            '        __log.debug("log '
                                            'something");\n'
                                            '\n'
                                            '        // okay:\n'
                                            '        __log.debug("log '
                                            'something with exception", e);\n'
                                            '\n'
                                            '        // bad:\n'
                                            '        __log.debug("log '
                                            'something" + " and " + "concat '
                                            'strings");\n'
                                            '\n'
                                            '        // bad:\n'
                                            '        __log.debug("log '
                                            'something" + " and " + "concat '
                                            'strings", e);\n'
                                            '\n'
                                            '        // good:\n'
                                            '        if '
                                            '(__log.isDebugEnabled()) {\n'
                                            '        __log.debug("bla" + "",e '
                                            ');\n'
                                            '        }\n'
                                            '    }\n'
                                            '}\n'
                                            '            \n'
                                            '        ',
                             'display_name': 'GuardDebugLogging',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'debug logging that involves string '
                                      'concatenation should be guarded with '
                                      'isDebugEnabled() checks'},
    'GuardLogStatement': {   'categories': ['security'],
                             'description': 'Whenever using a log level, one '
                                            'should check if the loglevel is '
                                            'actually enabled, or otherwise '
                                            'skip the associate String '
                                            'creation and manipulation.\n'
                                            'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/logging-jakarta-commons.html#GuardLogStatement\n'
                                            '\n'
                                            ' \n'
                                            '    // Add this for performance\n'
                                            '    if (log.isDebugEnabled() { '
                                            '...\n'
                                            '        log.debug("log something" '
                                            '+ " and " + "concat strings");\n'
                                            '\n'
                                            '     ',
                             'display_name': 'GuardLogStatement',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'There is log block not surrounded by '
                                      'if'},
    'GuardLogStatementJavaUtil': {   'categories': ['security'],
                                     'description': 'Whenever using a log '
                                                    'level, one should check '
                                                    'if the loglevel is '
                                                    'actually enabled, or '
                                                    'otherwise skip the '
                                                    'associate String creation '
                                                    'and manipulation.\n'
                                                    'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/logging-java.html#GuardLogStatementJavaUtil\n'
                                                    '\n'
                                                    ' \n'
                                                    ' \t// Add this for '
                                                    'performance\n'
                                                    '\tif '
                                                    '(log.isLoggable(Level.FINE)) '
                                                    '{ ...\n'
                                                    ' \t    log.fine("log '
                                                    'something" + " and " + '
                                                    '"concat strings");\n'
                                                    '\n'
                                                    '     ',
                                     'display_name': 'GuardLogStatementJavaUtil',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'There is log block not '
                                              'surrounded by if'},
    'IdempotentOperations': {   'categories': ['security'],
                                'description': 'Avoid idempotent operations - '
                                               'they have no effect.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#IdempotentOperations\n'
                                               '\n'
                                               '      \n'
                                               'public class Foo {\n'
                                               ' public void bar() {\n'
                                               '  int x = 2;\n'
                                               '  x = x;\n'
                                               ' }\n'
                                               '}\n'
                                               '      \n'
                                               '      ',
                                'display_name': 'IdempotentOperations',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Avoid idempotent operations (like '
                                         'assigning a variable to itself).'},
    'IfElseStmtsMustUseBraces': {   'categories': ['security'],
                                    'description': 'Avoid using if..else '
                                                   'statements without using '
                                                   'surrounding braces. If the '
                                                   'code formatting or '
                                                   'indentation is lost then '
                                                   'it becomes difficult to '
                                                   'separate the code being '
                                                   'controlled from the rest.\n'
                                                   'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/braces.html#IfElseStmtsMustUseBraces\n'
                                                   '\n'
                                                   '\n'
                                                   '   // this is OK\n'
                                                   'if (foo) x++;\n'
                                                   '   \n'
                                                   '   // but this is not\n'
                                                   'if (foo)\n'
                                                   '       x = x+1;\n'
                                                   '   else\n'
                                                   '       x = x-1;\n'
                                                   '\n'
                                                   '       ',
                                    'display_name': 'IfElseStmtsMustUseBraces',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': "Avoid using 'if...else' "
                                             'statements without curly braces'},
    'IfStmtsMustUseBraces': {   'categories': ['security'],
                                'description': 'Avoid using if statements '
                                               'without using braces to '
                                               'surround the code block. If '
                                               'the code formatting or '
                                               'indentation is lost then it '
                                               'becomes difficult to separate '
                                               'the code being controlled from '
                                               'the rest.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/braces.html#IfStmtsMustUseBraces\n'
                                               '\n'
                                               ' \n'
                                               '\n'
                                               'if (foo)\t// not recommended\n'
                                               '\tx++;\n'
                                               '\n'
                                               'if (foo) {\t// preferred '
                                               'approach\n'
                                               '\tx++;\n'
                                               '}\n'
                                               '\n'
                                               ' \n'
                                               '     ',
                                'display_name': 'IfStmtsMustUseBraces',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Avoid using if statements without '
                                         'curly braces'},
    'IframeMissingSrcAttribute': {   'categories': ['security'],
                                     'description': 'IFrames which are missing '
                                                    'a src element can cause '
                                                    'security information '
                                                    'popups in IE if you are '
                                                    'accessing the page '
                                                    'through SSL. See '
                                                    'http://support.microsoft.com/default.aspx?scid=kb;EN-US;Q261188\n'
                                                    'https://pmd.github.io/pmd-5.8.1/pmd-jsp/rules/jsp/basic.html#IframeMissingSrcAttribute\n'
                                                    '\n'
                                                    '\t\t\t\n'
                                                    '<HTML><title>bad '
                                                    'example><BODY>\n'
                                                    '<iframe></iframe>\n'
                                                    '</BODY> </HTML>\n'
                                                    '\n'
                                                    '<HTML><title>good '
                                                    'example><BODY>\n'
                                                    '<iframe '
                                                    'src="foo"></iframe>\n'
                                                    '</BODY> </HTML>\n'
                                                    '\t\t\t\n'
                                                    '\t\t',
                                     'display_name': 'IframeMissingSrcAttribute',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'IFrames must have a src '
                                              'attribute.'},
    'ImmutableField': {   'categories': ['security'],
                          'description': 'Identifies private fields whose '
                                         'values never change once they are '
                                         'initialized either in the '
                                         'declaration of the field or by a '
                                         'constructor. This helps in '
                                         'converting existing classes to '
                                         'becoming immutable ones.\n'
                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#ImmutableField\n'
                                         '\n'
                                         '  \n'
                                         'public class Foo {\n'
                                         '  private int x; // could be final\n'
                                         '  public Foo() {\n'
                                         '      x = 7;\n'
                                         '  }\n'
                                         '  public void foo() {\n'
                                         '     int a = x + 2;\n'
                                         '  }\n'
                                         '}\n'
                                         '  \n'
                                         '      ',
                          'display_name': 'ImmutableField',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': "Private field ''{0}'' could be made final; "
                                   'it is only initialized in the declaration '
                                   'or constructor.'},
    'ImportFromSamePackage': {   'categories': ['security'],
                                 'description': 'There is no need to import a '
                                                'type that lives in the same '
                                                'package.\n'
                                                'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/imports.html#ImportFromSamePackage\n'
                                                '\n'
                                                ' \n'
                                                ' package foo;\n'
                                                ' \n'
                                                ' import foo.Buz; // no need '
                                                'for this\n'
                                                ' import foo.*; // or this\n'
                                                ' \n'
                                                ' public class Bar{}\n'
                                                ' \n'
                                                '     ',
                                 'display_name': 'ImportFromSamePackage',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'No need to import a type that lives '
                                          'in the same package'},
    'InefficientEmptyStringCheck': {   'categories': ['security'],
                                       'description': 'String.trim().length() '
                                                      'is an inefficient way '
                                                      'to check if a String is '
                                                      'really empty, as it '
                                                      'creates a new String '
                                                      'object just to check '
                                                      'its size. Consider '
                                                      'creating a static '
                                                      'function that loops '
                                                      'through a string, '
                                                      'checking '
                                                      'Character.isWhitespace() '
                                                      'on each character and '
                                                      'returning false if a '
                                                      'non-whitespace '
                                                      'character is found. You '
                                                      "can refer to Apache's "
                                                      'StringUtils#isBlank (in '
                                                      'commons-lang) or '
                                                      "Spring's "
                                                      'StringUtils#hasText (in '
                                                      'the Springs framework) '
                                                      'for existing '
                                                      'implementations.\n'
                                                      'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strings.html#InefficientEmptyStringCheck\n'
                                                      '\n'
                                                      '\n'
                                                      'public void bar(String '
                                                      'string) {\n'
                                                      '\tif (string != null && '
                                                      'string.trim().size() > '
                                                      '0) {\n'
                                                      '\t\tdoSomething();\n'
                                                      '\t}\n'
                                                      '}\n'
                                                      '\n'
                                                      '    ',
                                       'display_name': 'InefficientEmptyStringCheck',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'String.trim().length()==0 is '
                                                'an inefficient way to '
                                                'validate an empty String.'},
    'InefficientStringBuffering': {   'categories': ['security'],
                                      'description': 'Avoid concatenating '
                                                     'non-literals in a '
                                                     'StringBuffer constructor '
                                                     'or append() since '
                                                     'intermediate buffers '
                                                     'will need to be be '
                                                     'created and destroyed by '
                                                     'the JVM.\n'
                                                     'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strings.html#InefficientStringBuffering\n'
                                                     '\n'
                                                     '\n'
                                                     '    // Avoid this, two '
                                                     'buffers are actually '
                                                     'being created here\n'
                                                     'StringBuffer sb = new '
                                                     'StringBuffer("tmp = '
                                                     '"+System.getProperty("java.io.tmpdir"));\n'
                                                     '    \n'
                                                     '    // do this instead\n'
                                                     'StringBuffer sb = new '
                                                     'StringBuffer("tmp = ");\n'
                                                     'sb.append(System.getProperty("java.io.tmpdir"));\n'
                                                     '\n'
                                                     '    ',
                                      'display_name': 'InefficientStringBuffering',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'Avoid concatenating '
                                               'nonliterals in a '
                                               'StringBuffer/StringBuilder '
                                               'constructor or append().'},
    'InnaccurateNumericLiteral': {   'categories': ['security'],
                                     'description': 'The numeric literal will '
                                                    'have at different value '
                                                    'at runtime, which can '
                                                    'happen if you provide too '
                                                    'much precision in a '
                                                    'floating point number. '
                                                    'This may result in '
                                                    'numeric calculations '
                                                    'being in error.\n'
                                                    'https://pmd.github.io/pmd-5.8.1/pmd-javascript/rules/ecmascript/basic.html#InnaccurateNumericLiteral\n'
                                                    '\n'
                                                    '  \n'
                                                    'var a = 9; // Ok\n'
                                                    'var b = 999999999999999; '
                                                    '// Ok\n'
                                                    'var c = '
                                                    '999999999999999999999; // '
                                                    'Not good\n'
                                                    'var w = 1.12e-4; // Ok\n'
                                                    'var x = 1.12; // Ok\n'
                                                    'var y = 1.1234567890123; '
                                                    '// Ok\n'
                                                    'var z = '
                                                    '1.12345678901234567; // '
                                                    'Not good\n'
                                                    '\n'
                                                    '      ',
                                     'display_name': 'InnaccurateNumericLiteral',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': "The numeric literal ''{0}'' "
                                              'will have at different value at '
                                              'runtime.'},
    'InstantiationToGetClass': {   'categories': ['security'],
                                   'description': 'Avoid instantiating an '
                                                  'object just to call '
                                                  'getClass() on it; use the '
                                                  '.class public member '
                                                  'instead.\n'
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#InstantiationToGetClass\n'
                                                  '\n'
                                                  '    \n'
                                                  '  // replace this\n'
                                                  'Class c = new '
                                                  'String().getClass();\n'
                                                  '\n'
                                                  '  // with this:\n'
                                                  'Class c = String.class;\n'
                                                  '\n'
                                                  '    \n'
                                                  '        ',
                                   'display_name': 'InstantiationToGetClass',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'Avoid instantiating an object '
                                            'just to call getClass() on it; '
                                            'use the .class public member '
                                            'instead'},
    'InsufficientStringBufferDeclaration': {   'categories': ['security'],
                                               'description': 'Failing to '
                                                              'pre-size a '
                                                              'StringBuffer or '
                                                              'StringBuilder '
                                                              'properly could '
                                                              'cause it to '
                                                              're-size many '
                                                              'times during '
                                                              'runtime. This '
                                                              'rule attempts '
                                                              'to determine '
                                                              'the total '
                                                              'number the '
                                                              'characters that '
                                                              'are actually '
                                                              'passed into '
                                                              'StringBuffer.append(), '
                                                              'but represents '
                                                              'a best guess '
                                                              '"worst case" '
                                                              'scenario. An '
                                                              'empty '
                                                              'StringBuffer/StringBuilder '
                                                              'constructor '
                                                              'initializes the '
                                                              'object to 16 '
                                                              'characters. '
                                                              'This default is '
                                                              'assumed if the '
                                                              'length of the '
                                                              'constructor can '
                                                              'not be '
                                                              'determined.\n'
                                                              'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strings.html#InsufficientStringBufferDeclaration\n'
                                                              '\n'
                                                              '\n'
                                                              'StringBuffer '
                                                              'bad = new '
                                                              'StringBuffer();\n'
                                                              'bad.append("This '
                                                              'is a long '
                                                              'string that '
                                                              'will exceed the '
                                                              'default 16 '
                                                              'characters");\n'
                                                              '        \n'
                                                              'StringBuffer '
                                                              'good = new '
                                                              'StringBuffer(41);\n'
                                                              'good.append("This '
                                                              'is a long '
                                                              'string, which '
                                                              'is '
                                                              'pre-sized");\n'
                                                              '\n'
                                                              '    ',
                                               'display_name': 'InsufficientStringBufferDeclaration',
                                               'file': '%(issue.file)s',
                                               'line': '%(issue.line)s',
                                               'severity': '1',
                                               'title': 'StringBuffer '
                                                        'constructor is '
                                                        'initialized with size '
                                                        '{0}, but has at least '
                                                        '{1} characters '
                                                        'appended.'},
    'IntegerInstantiation': {   'categories': ['security'],
                                'description': 'Calling new Integer() causes '
                                               'memory allocation that can be '
                                               'avoided by the static '
                                               'Integer.valueOf(). It makes '
                                               'use of an internal cache that '
                                               'recycles earlier instances '
                                               'making it more memory '
                                               'efficient.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/migrating.html#IntegerInstantiation\n'
                                               '\n'
                                               '  \n'
                                               'public class Foo {\n'
                                               '\tprivate Integer i = new '
                                               'Integer(0); // change to '
                                               'Integer i = '
                                               'Integer.valueOf(0);\n'
                                               '}\n'
                                               '   \n'
                                               '      ',
                                'display_name': 'IntegerInstantiation',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Avoid instantiating Integer objects. '
                                         'Call Integer.valueOf() instead.'},
    'InvalidDependencyTypes': {   'categories': ['security'],
                                  'description': 'While Maven will not failed '
                                                 'if you use an invalid type '
                                                 'for a dependency in the '
                                                 'dependency management '
                                                 'section, it will not also '
                                                 'uses the dependency.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-xml/rules/pom/basic.html#InvalidDependencyTypes\n'
                                                 '\n'
                                                 ' \n'
                                                 '<project...>\n'
                                                 '  ...\n'
                                                 '  <dependencyManagement>\n'
                                                 '      ...\n'
                                                 '    <dependency>\n'
                                                 '      '
                                                 '<groupId>org.jboss.arquillian</groupId>\n'
                                                 '      '
                                                 '<artifactId>arquillian-bom</artifactId>\n'
                                                 '      '
                                                 '<version>${arquillian.version}</version>\n'
                                                 '      <type>bom</type> <!-- '
                                                 "not a valid type ! 'pom' is "
                                                 '! -->\n'
                                                 '      <scope>import</scope>\n'
                                                 '    </dependency>\n'
                                                 '    ...\n'
                                                 '  </dependencyManagement>\n'
                                                 '</project>\n'
                                                 ' \n'
                                                 '     ',
                                  'display_name': 'InvalidDependencyTypes',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'By default, Maven only recognized '
                                           'the following types: $validTypes.'},
    'InvalidSlf4jMessageFormat': {   'categories': ['security'],
                                     'description': 'Check for messages in '
                                                    'slf4j loggers with non '
                                                    'matching number of '
                                                    'arguments and '
                                                    'placeholders.\n'
                                                    'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/logging-java.html#InvalidSlf4jMessageFormat\n'
                                                    '\n'
                                                    '                \n'
                                                    'LOGGER.error("forget the '
                                                    'arg {}");\n'
                                                    'LOGGER.error("too many '
                                                    'args {}", "arg1", '
                                                    '"arg2");\n'
                                                    'LOGGER.error("param {}", '
                                                    '"arg1", new '
                                                    'IllegalStateException("arg")); '
                                                    '//The exception is shown '
                                                    'separately, so is '
                                                    'correct.\n'
                                                    '\n'
                                                    '     ',
                                     'display_name': 'InvalidSlf4jMessageFormat',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'Invalid message format'},
    'JUnit4SuitesShouldUseSuiteAnnotation': {   'categories': ['security'],
                                                'description': 'In JUnit 3, '
                                                               'test suites '
                                                               'are indicated '
                                                               'by the suite() '
                                                               'method. In '
                                                               'JUnit 4, '
                                                               'suites are '
                                                               'indicated '
                                                               'through the '
                                                               '@RunWith(Suite.class) '
                                                               'annotation.\n'
                                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/migrating.html#JUnit4SuitesShouldUseSuiteAnnotation\n'
                                                               '\n'
                                                               '\n'
                                                               'public class '
                                                               'BadExample '
                                                               'extends '
                                                               'TestCase{\n'
                                                               '\n'
                                                               '    public '
                                                               'static Test '
                                                               'suite(){\n'
                                                               '    \treturn '
                                                               'new Suite();\n'
                                                               '    }\n'
                                                               '}\n'
                                                               '\n'
                                                               '@RunWith(Suite.class)\n'
                                                               '@SuiteClasses( '
                                                               '{ '
                                                               'TestOne.class, '
                                                               'TestTwo.class '
                                                               '})\n'
                                                               'public class '
                                                               'GoodTest {\n'
                                                               '}\n'
                                                               '      ',
                                                'display_name': 'JUnit4SuitesShouldUseSuiteAnnotation',
                                                'file': '%(issue.file)s',
                                                'line': '%(issue.line)s',
                                                'severity': '1',
                                                'title': 'JUnit 4 indicates '
                                                         'test suites via '
                                                         'annotations, not the '
                                                         'suite method.'},
    'JUnit4TestShouldUseAfterAnnotation': {   'categories': ['security'],
                                              'description': 'In JUnit 3, the '
                                                             'tearDown method '
                                                             'was used to '
                                                             'clean up all '
                                                             'data entities '
                                                             'required in '
                                                             'running tests. '
                                                             'JUnit 4 skips '
                                                             'the tearDown '
                                                             'method and '
                                                             'executes all '
                                                             'methods '
                                                             'annotated with '
                                                             '@After after '
                                                             'running each '
                                                             'test\n'
                                                             'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/migrating.html#JUnit4TestShouldUseAfterAnnotation\n'
                                                             '\n'
                                                             '\n'
                                                             'public class '
                                                             'MyTest {\n'
                                                             '    public void '
                                                             'tearDown() {\n'
                                                             '        bad();\n'
                                                             '    }\n'
                                                             '}\n'
                                                             'public class '
                                                             'MyTest2 {\n'
                                                             '    @After '
                                                             'public void '
                                                             'tearDown() {\n'
                                                             '        good();\n'
                                                             '    }\n'
                                                             '}\n'
                                                             '\n'
                                                             '      ',
                                              'display_name': 'JUnit4TestShouldUseAfterAnnotation',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '1',
                                              'title': 'JUnit 4 tests that '
                                                       'clean up tests should '
                                                       'use the @After '
                                                       'annotation'},
    'JUnit4TestShouldUseBeforeAnnotation': {   'categories': ['security'],
                                               'description': 'In JUnit 3, the '
                                                              'setUp method '
                                                              'was used to set '
                                                              'up all data '
                                                              'entities '
                                                              'required in '
                                                              'running tests. '
                                                              'JUnit 4 skips '
                                                              'the setUp '
                                                              'method and '
                                                              'executes all '
                                                              'methods '
                                                              'annotated with '
                                                              '@Before before '
                                                              'all tests\n'
                                                              'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/migrating.html#JUnit4TestShouldUseBeforeAnnotation\n'
                                                              '\n'
                                                              '\n'
                                                              'public class '
                                                              'MyTest {\n'
                                                              '    public void '
                                                              'setUp() {\n'
                                                              '        bad();\n'
                                                              '    }\n'
                                                              '}\n'
                                                              'public class '
                                                              'MyTest2 {\n'
                                                              '    @Before '
                                                              'public void '
                                                              'setUp() {\n'
                                                              '        '
                                                              'good();\n'
                                                              '    }\n'
                                                              '}\n'
                                                              '\n'
                                                              '      ',
                                               'display_name': 'JUnit4TestShouldUseBeforeAnnotation',
                                               'file': '%(issue.file)s',
                                               'line': '%(issue.line)s',
                                               'severity': '1',
                                               'title': 'JUnit 4 tests that '
                                                        'set up tests should '
                                                        'use the @Before '
                                                        'annotation'},
    'JUnit4TestShouldUseTestAnnotation': {   'categories': ['security'],
                                             'description': 'In JUnit 3, the '
                                                            'framework '
                                                            'executed all '
                                                            'methods which '
                                                            'started with the '
                                                            'word test as a '
                                                            'unit test. In '
                                                            'JUnit 4, only '
                                                            'methods annotated '
                                                            'with the @Test '
                                                            'annotation are '
                                                            'executed.\n'
                                                            'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/migrating.html#JUnit4TestShouldUseTestAnnotation\n'
                                                            '\n'
                                                            '\n'
                                                            'public class '
                                                            'MyTest {\n'
                                                            '    public void '
                                                            'testBad() {\n'
                                                            '        '
                                                            'doSomething();\n'
                                                            '    }\n'
                                                            '\n'
                                                            '\t@Test\n'
                                                            '    public void '
                                                            'testGood() {\n'
                                                            '        '
                                                            'doSomething();\n'
                                                            '    }\n'
                                                            '}\n'
                                                            '\n'
                                                            '      ',
                                             'display_name': 'JUnit4TestShouldUseTestAnnotation',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': 'JUnit 4 tests that '
                                                      'execute tests should '
                                                      'use the @Test '
                                                      'annotation'},
    'JUnitAssertionsShouldIncludeMessage': {   'categories': ['security'],
                                               'description': 'JUnit '
                                                              'assertions '
                                                              'should include '
                                                              'an informative '
                                                              'message - i.e., '
                                                              'use the '
                                                              'three-argument '
                                                              'version of '
                                                              'assertEquals(), '
                                                              'not the '
                                                              'two-argument '
                                                              'version.\n'
                                                              'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/junit.html#JUnitAssertionsShouldIncludeMessage\n'
                                                              '\n'
                                                              '  \n'
                                                              'public class '
                                                              'Foo extends '
                                                              'TestCase {\n'
                                                              ' public void '
                                                              'testSomething() '
                                                              '{\n'
                                                              '  '
                                                              'assertEquals("foo", '
                                                              '"bar");\n'
                                                              '  // Use the '
                                                              'form:\n'
                                                              '  // '
                                                              'assertEquals("Foo '
                                                              'does not equals '
                                                              'bar", "foo", '
                                                              '"bar");\n'
                                                              '  // instead\n'
                                                              ' }\n'
                                                              '}\n'
                                                              '  \n'
                                                              '      ',
                                               'display_name': 'JUnitAssertionsShouldIncludeMessage',
                                               'file': '%(issue.file)s',
                                               'line': '%(issue.line)s',
                                               'severity': '1',
                                               'title': 'JUnit assertions '
                                                        'should include a '
                                                        'message'},
    'JUnitSpelling': {   'categories': ['security'],
                         'description': 'Some JUnit framework methods are easy '
                                        'to misspell.\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/junit.html#JUnitSpelling\n'
                                        '\n'
                                        '\n'
                                        'import junit.framework.*;\n'
                                        '\n'
                                        'public class Foo extends TestCase {\n'
                                        '   public void setup() {}    // oops, '
                                        'should be setUp\n'
                                        '   public void TearDown() {} // oops, '
                                        'should be tearDown\n'
                                        '}\n'
                                        '\n'
                                        '    ',
                         'display_name': 'JUnitSpelling',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'You may have misspelled a JUnit framework '
                                  'method (setUp or tearDown)'},
    'JUnitStaticSuite': {   'categories': ['security'],
                            'description': 'The suite() method in a JUnit test '
                                           'needs to be both public and '
                                           'static.\n'
                                           'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/junit.html#JUnitStaticSuite\n'
                                           '\n'
                                           '  \n'
                                           'import junit.framework.*;\n'
                                           '\n'
                                           'public class Foo extends TestCase '
                                           '{\n'
                                           '   public void suite() {}         '
                                           '// oops, should be static\n'
                                           '   private static void suite() {} '
                                           '// oops, should be public\n'
                                           '}\n'
                                           '  \n'
                                           '      ',
                            'display_name': 'JUnitStaticSuite',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'You have a suite() method that is not '
                                     "both public and static, so JUnit won't "
                                     'call it to get your TestSuite.  Is that '
                                     'what you wanted to do?'},
    'JUnitTestContainsTooManyAsserts': {   'categories': ['security'],
                                           'description': 'JUnit tests should '
                                                          'not contain too '
                                                          'many asserts. Many '
                                                          'asserts are '
                                                          'indicative of a '
                                                          'complex test, for '
                                                          'which it is harder '
                                                          'to verify '
                                                          'correctness. '
                                                          'Consider breaking '
                                                          'the test scenario '
                                                          'into multiple, '
                                                          'shorter test '
                                                          'scenarios. '
                                                          'Customize the '
                                                          'maximum number of '
                                                          'assertions used by '
                                                          'this Rule to suit '
                                                          'your needs.\n'
                                                          'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/junit.html#JUnitTestContainsTooManyAsserts\n'
                                                          '\n'
                                                          '\n'
                                                          'public class '
                                                          'MyTestCase extends '
                                                          'TestCase {\n'
                                                          '\t// Ok\n'
                                                          '\tpublic void '
                                                          'testMyCaseWithOneAssert() '
                                                          '{\n'
                                                          '\t\tboolean myVar = '
                                                          'false;\t\t\n'
                                                          '\t\t'
                                                          'assertFalse("should '
                                                          'be false", myVar);\n'
                                                          '\t}\n'
                                                          '\n'
                                                          '\t// Bad, too many '
                                                          'asserts (assuming '
                                                          'max=1)\n'
                                                          '\tpublic void '
                                                          'testMyCaseWithMoreAsserts() '
                                                          '{\n'
                                                          '\t\tboolean myVar = '
                                                          'false;\t\t\n'
                                                          '\t\t'
                                                          'assertFalse("myVar '
                                                          'should be false", '
                                                          'myVar);\n'
                                                          '\t\t'
                                                          'assertEquals("should '
                                                          'equals false", '
                                                          'false, myVar);\n'
                                                          '\t}\n'
                                                          '}\n'
                                                          '\n'
                                                          '\t\t',
                                           'display_name': 'JUnitTestContainsTooManyAsserts',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'JUnit tests should not '
                                                    'contain more than '
                                                    '${maximumAsserts} '
                                                    'assert(s).'},
    'JUnitTestsShouldIncludeAssert': {   'categories': ['security'],
                                         'description': 'JUnit tests should '
                                                        'include at least one '
                                                        'assertion. This makes '
                                                        'the tests more '
                                                        'robust, and using '
                                                        'assert with messages '
                                                        'provide the developer '
                                                        'a clearer idea of '
                                                        'what the test does.\n'
                                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/junit.html#JUnitTestsShouldIncludeAssert\n'
                                                        '\n'
                                                        '    \n'
                                                        'public class Foo '
                                                        'extends TestCase {\n'
                                                        '   public void '
                                                        'testSomething() {\n'
                                                        '      Bar b = '
                                                        'findBar();\n'
                                                        '   // This is better '
                                                        'than having a '
                                                        'NullPointerException\n'
                                                        '   // '
                                                        'assertNotNull("bar '
                                                        'not found", b);\n'
                                                        '   b.work();\n'
                                                        '   }\n'
                                                        '}\n'
                                                        '    \n'
                                                        '        ',
                                         'display_name': 'JUnitTestsShouldIncludeAssert',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'JUnit tests should include '
                                                  'assert() or fail()'},
    'JUnitUseExpected': {   'categories': ['security'],
                            'description': 'In JUnit4, use the @Test(expected) '
                                           'annotation to denote tests that '
                                           'should throw exceptions.\n'
                                           'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/migrating.html#JUnitUseExpected\n'
                                           '\n'
                                           '\n'
                                           'public class MyTest {\n'
                                           '\t@Test\n'
                                           '    public void testBad() {\n'
                                           '        try {\n'
                                           '            doSomething();\n'
                                           '            fail("should have '
                                           'thrown an exception");\n'
                                           '        } catch (Exception e) {\n'
                                           '        }\n'
                                           '    }\n'
                                           '\n'
                                           '\t@Test(expected=Exception.class)\n'
                                           '    public void testGood() {\n'
                                           '        doSomething();\n'
                                           '    }\n'
                                           '}\n'
                                           '\n'
                                           '      ',
                            'display_name': 'JUnitUseExpected',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'In JUnit4, use the @Test(expected) '
                                     'annotation to denote tests that should '
                                     'throw exceptions'},
    'JspEncoding': {   'categories': ['security'],
                       'description': "A missing 'meta' tag or page directive "
                                      'will trigger this rule, as well as a '
                                      'non-UTF-8 charset.\n'
                                      'https://pmd.github.io/pmd-5.8.1/pmd-jsp/rules/jsp/basic.html#JspEncoding\n'
                                      '\n'
                                      '\t\t\t\n'
                                      '                Most browsers should be '
                                      'able to interpret the following '
                                      'headers:\n'
                                      '                \n'
                                      '                <%@ page '
                                      'contentType="text/html; charset=UTF-8" '
                                      'pageEncoding="UTF-8" %>\n'
                                      '                    \n'
                                      '                <meta '
                                      'http-equiv="Content-Type"  '
                                      'content="text/html; charset=UTF-8" />\n'
                                      '            \n'
                                      '\t\t',
                       'display_name': 'JspEncoding',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'JSP file should use UTF-8 encoding'},
    'JumbledIncrementer': {   'categories': ['security'],
                              'description': 'Avoid jumbled loop incrementers '
                                             '- its usually a mistake, and is '
                                             'confusing even if intentional.\n'
                                             'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#JumbledIncrementer\n'
                                             '\n'
                                             ' \n'
                                             'public class '
                                             'JumbledIncrementerRule1 {\n'
                                             '\tpublic void foo() {\n'
                                             '\t\tfor (int i = 0; i < 10; i++) '
                                             "{\t\t\t// only references 'i'\n"
                                             '\t\t\tfor (int k = 0; k < 20; '
                                             "i++) {\t\t// references both 'i' "
                                             "and 'k'\n"
                                             '\t\t\t\t'
                                             'System.out.println("Hello");\n'
                                             '\t\t\t}\n'
                                             '\t\t}\n'
                                             '\t}\n'
                                             '}\n'
                                             ' \n'
                                             '     ',
                              'display_name': 'JumbledIncrementer',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'Avoid modifying an outer loop '
                                       'incrementer in an inner loop for '
                                       'update expression'},
    'LawOfDemeter': {   'categories': ['security'],
                        'description': 'The Law of Demeter is a simple rule, '
                                       'that says "only talk to friends". It '
                                       'helps to reduce coupling between '
                                       'classes or objects. See also the '
                                       'references: Andrew Hunt, David Thomas, '
                                       'and Ward Cunningham. The Pragmatic '
                                       'Programmer. From Journeyman to Master. '
                                       'Addison-Wesley Longman, Amsterdam, '
                                       'October 1999.; K.J. Lieberherr and '
                                       'I.M. Holland. Assuring good style for '
                                       'object-oriented programs. Software, '
                                       'IEEE, 6(5):38–48, 1989.; '
                                       'http://www.ccs.neu.edu/home/lieber/LoD.html; '
                                       'http://en.wikipedia.org/wiki/Law_of_Demeter\n'
                                       'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/coupling.html#LawOfDemeter\n'
                                       '\n'
                                       '\n'
                                       'public class Foo {\n'
                                       '    /**\n'
                                       '     * This example will result in two '
                                       'violations.\n'
                                       '     */\n'
                                       '    public void example(Bar b) {\n'
                                       '        // this method call is ok, as '
                                       'b is a parameter of "example"\n'
                                       '        C c = b.getC();\n'
                                       '        \n'
                                       '        // this method call is a '
                                       'violation, as we are using c, which we '
                                       'got from B.\n'
                                       '        // We should ask b directly '
                                       'instead, e.g. "b.doItOnC();"\n'
                                       '        c.doIt();\n'
                                       '        \n'
                                       '        // this is also a violation, '
                                       'just expressed differently as a method '
                                       'chain without temporary variables.\n'
                                       '        b.getC().doIt();\n'
                                       '        \n'
                                       '        // a constructor call, not a '
                                       'method call.\n'
                                       '        D d = new D();\n'
                                       '        // this method call is ok, '
                                       'because we have create the new '
                                       'instance of D locally.\n'
                                       '        d.doSomethingElse(); \n'
                                       '    }\n'
                                       '}\n'
                                       '\n'
                                       '        ',
                        'display_name': 'LawOfDemeter',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Potential violation of Law of Demeter'},
    'LocalHomeNamingConvention': {   'categories': ['security'],
                                     'description': 'The Local Home interface '
                                                    'of a Session EJB should '
                                                    'be suffixed by '
                                                    "'LocalHome'.\n"
                                                    'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/j2ee.html#LocalHomeNamingConvention\n'
                                                    '\n'
                                                    '            \n'
                                                    ' public interface '
                                                    'MyBeautifulLocalHome '
                                                    'extends '
                                                    'javax.ejb.EJBLocalHome '
                                                    '{}// proper name\n'
                                                    '\n'
                                                    ' public interface '
                                                    'MissingProperSuffix '
                                                    'extends '
                                                    'javax.ejb.EJBLocalHome '
                                                    '{}\t// non-standard name\n'
                                                    '            \n'
                                                    '        ',
                                     'display_name': 'LocalHomeNamingConvention',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'The Local Home interface of a '
                                              'Session EJB should be suffixed '
                                              "by 'LocalHome'"},
    'LocalInterfaceSessionNamingConvention': {   'categories': ['security'],
                                                 'description': 'The Local '
                                                                'Interface of '
                                                                'a Session EJB '
                                                                'should be '
                                                                'suffixed by '
                                                                "'Local'.\n"
                                                                'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/j2ee.html#LocalInterfaceSessionNamingConvention\n'
                                                                '\n'
                                                                '            \n'
                                                                ' public '
                                                                'interface '
                                                                'MyLocal '
                                                                'extends '
                                                                'javax.ejb.EJBLocalObject '
                                                                '{}\t\t\t\t// '
                                                                'proper name\n'
                                                                '\n'
                                                                ' public '
                                                                'interface '
                                                                'MissingProperSuffix '
                                                                'extends '
                                                                'javax.ejb.EJBLocalObject '
                                                                '{}\t// '
                                                                'non-standard '
                                                                'name\n'
                                                                '            \n'
                                                                '        ',
                                                 'display_name': 'LocalInterfaceSessionNamingConvention',
                                                 'file': '%(issue.file)s',
                                                 'line': '%(issue.line)s',
                                                 'severity': '1',
                                                 'title': 'The Local Interface '
                                                          'of a Session EJB '
                                                          'should be suffixed '
                                                          "by 'Local'"},
    'LocalVariableCouldBeFinal': {   'categories': ['security'],
                                     'description': 'A local variable assigned '
                                                    'only once can be declared '
                                                    'final.\n'
                                                    'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/optimizations.html#LocalVariableCouldBeFinal\n'
                                                    '\n'
                                                    '  \n'
                                                    'public class Bar {\n'
                                                    '\tpublic void foo () {\n'
                                                    '\t\tString txtA = '
                                                    '"a"; \t\t// if txtA will '
                                                    'not be assigned again it '
                                                    'is better to do this:\n'
                                                    '\t\tfinal String txtB = '
                                                    '"b";\n'
                                                    '\t}\n'
                                                    '}\n'
                                                    '  \n'
                                                    '      ',
                                     'display_name': 'LocalVariableCouldBeFinal',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': "Local variable ''{0}'' could be "
                                              'declared final'},
    'LoggerIsNotStaticFinal': {   'categories': ['security'],
                                  'description': 'In most cases, the Logger '
                                                 'reference can be declared as '
                                                 'static and final.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/logging-java.html#LoggerIsNotStaticFinal\n'
                                                 '\n'
                                                 ' \n'
                                                 'public class Foo{\n'
                                                 '    Logger log = '
                                                 'Logger.getLogger(Foo.class.getName());\t\t\t\t\t'
                                                 '// not recommended\n'
                                                 '\n'
                                                 '    static final Logger log '
                                                 '= '
                                                 'Logger.getLogger(Foo.class.getName());\t'
                                                 '// preferred approach\n'
                                                 '}\n'
                                                 '\n'
                                                 '     ',
                                  'display_name': 'LoggerIsNotStaticFinal',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'The Logger variable declaration '
                                           'does not contain the static and '
                                           'final modifiers'},
    'LogicInversion': {   'categories': ['security'],
                          'description': 'Use opposite operator instead of '
                                         'negating the whole expression with a '
                                         'logic complement operator.\n'
                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#LogicInversion\n'
                                         '\n'
                                         '    \n'
                                         'public boolean bar(int a, int b) {\n'
                                         '\n'
                                         '    if (!(a == b)) { // use !=\n'
                                         '         return false;\n'
                                         '     }\n'
                                         '\n'
                                         '    if (!(a < b)) { // use >=\n'
                                         '         return false;\n'
                                         '    }\n'
                                         '\n'
                                         '    return true;\n'
                                         '}\n'
                                         '    \n'
                                         '    ',
                          'display_name': 'LogicInversion',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'Use opposite operator instead of the logic '
                                   'complement operator.'},
    'LongInstantiation': {   'categories': ['security'],
                             'description': 'Calling new Long() causes memory '
                                            'allocation that can be avoided by '
                                            'the static Long.valueOf(). It '
                                            'makes use of an internal cache '
                                            'that recycles earlier instances '
                                            'making it more memory efficient.\n'
                                            'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/migrating.html#LongInstantiation\n'
                                            '\n'
                                            '\n'
                                            'public class Foo {\n'
                                            '\tprivate Long i = new Long(0); '
                                            '// change to Long i = '
                                            'Long.valueOf(0);\n'
                                            '}\n'
                                            '\n'
                                            '    ',
                             'display_name': 'LongInstantiation',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Avoid instantiating Long objects.Call '
                                      'Long.valueOf() instead'},
    'LongVariable': {   'categories': ['security'],
                        'description': 'Fields, formal arguments, or local '
                                       'variable names that are too long can '
                                       'make the code difficult to follow.\n'
                                       'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#LongVariable\n'
                                       '\n'
                                       '\n'
                                       'public class Something {\n'
                                       '\tint reallyLongIntName = -3;  \t\t\t'
                                       '// VIOLATION - Field\n'
                                       '\tpublic static void main( String '
                                       'argumentsList[] ) { // VIOLATION - '
                                       'Formal\n'
                                       '\t\tint otherReallyLongName = -5; \t\t'
                                       '// VIOLATION - Local\n'
                                       '\t\tfor (int interestingIntIndex = 0;\t'
                                       '// VIOLATION - For\n'
                                       '             interestingIntIndex < '
                                       '10;\n'
                                       '             interestingIntIndex ++ ) '
                                       '{\n'
                                       '    }\n'
                                       '}\n'
                                       '\n'
                                       '    ',
                        'display_name': 'LongVariable',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Avoid excessively long variable names like '
                                 '{0}'},
    'LooseCoupling': {   'categories': ['security'],
                         'description': 'Avoid using implementation types '
                                        '(i.e., HashSet); use the interface '
                                        '(i.e, Set) instead\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/typeresolution.html#LooseCoupling\n'
                                        '\n'
                                        '\n'
                                        'import java.util.ArrayList;\n'
                                        'import java.util.HashSet;\n'
                                        '\n'
                                        'public class Bar {\n'
                                        '\t\t// Use List instead\n'
                                        '\tprivate ArrayList list = new '
                                        'ArrayList();\n'
                                        '\t\t// Use Set instead\n'
                                        '\tpublic HashSet getFoo() {\n'
                                        '    return new HashSet();\n'
                                        '  }\n'
                                        '}\n'
                                        '  \n'
                                        '      ',
                         'display_name': 'LooseCoupling',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Avoid using implementation types like '
                                  "''{0}''; use the interface instead"},
    'LoosePackageCoupling': {   'categories': ['security'],
                                'description': 'Avoid using classes from the '
                                               'configured package hierarchy '
                                               'outside of the package '
                                               'hierarchy, except when using '
                                               'one of the configured allowed '
                                               'classes.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/coupling.html#LoosePackageCoupling\n'
                                               '\n'
                                               '\n'
                                               'package some.package;\n'
                                               '\n'
                                               'import '
                                               'some.other.package.subpackage.subsubpackage.DontUseThisClass;\n'
                                               '\n'
                                               'public class Bar {\n'
                                               '   DontUseThisClass boo = new '
                                               'DontUseThisClass();\n'
                                               '}\n'
                                               '  \n'
                                               '      ',
                                'display_name': 'LoosePackageCoupling',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': "Use of ''{0}'' outside of package "
                                         "hierarchy ''{1}'' is not "
                                         'recommended; use recommended classes '
                                         'instead'},
    'MDBAndSessionBeanNamingConvention': {   'categories': ['security'],
                                             'description': 'The EJB '
                                                            'Specification '
                                                            'states that any '
                                                            'MessageDrivenBean '
                                                            'or SessionBean '
                                                            'should be '
                                                            'suffixed by '
                                                            "'Bean'.\n"
                                                            'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/j2ee.html#MDBAndSessionBeanNamingConvention\n'
                                                            '\n'
                                                            '            \n'
                                                            'public class '
                                                            'SomeBean '
                                                            'implements '
                                                            'SessionBean{}\t\t\t\t\t'
                                                            '// proper name\n'
                                                            '\n'
                                                            'public class '
                                                            'MissingTheProperSuffix '
                                                            'implements '
                                                            'SessionBean {}  \t'
                                                            '// non-standard '
                                                            'name\n'
                                                            '            \n'
                                                            '        ',
                                             'display_name': 'MDBAndSessionBeanNamingConvention',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': 'SessionBean or '
                                                      'MessageBean should be '
                                                      'suffixed by Bean'},
    'MethodArgumentCouldBeFinal': {   'categories': ['security'],
                                      'description': 'A method argument that '
                                                     'is never re-assigned '
                                                     'within the method can be '
                                                     'declared final.\n'
                                                     'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/optimizations.html#MethodArgumentCouldBeFinal\n'
                                                     '\n'
                                                     '  \n'
                                                     'public void foo1 (String '
                                                     'param) {\t// do stuff '
                                                     'with param never '
                                                     'assigning it\n'
                                                     '  \n'
                                                     '}\n'
                                                     '\n'
                                                     'public void foo2 (final '
                                                     'String param) {\t// '
                                                     'better, do stuff with '
                                                     'param never assigning '
                                                     'it\n'
                                                     '  \n'
                                                     '}\n'
                                                     '  \n'
                                                     '      ',
                                      'display_name': 'MethodArgumentCouldBeFinal',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': "Parameter ''{0}'' is not "
                                               'assigned and could be declared '
                                               'final'},
    'MethodNamingConventions': {   'categories': ['security'],
                                   'description': 'Method names should always '
                                                  'begin with a lower case '
                                                  'character, and should not '
                                                  'contain underscores.\n'
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#MethodNamingConventions\n'
                                                  '\n'
                                                  '\n'
                                                  'public class Foo {\n'
                                                  '\tpublic void fooStuff() {\n'
                                                  '\t}\n'
                                                  '}\n'
                                                  '\n'
                                                  '          ',
                                   'display_name': 'MethodNamingConventions',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'Method name does not begin with a '
                                            'lower case character.'},
    'MethodReturnsInternalArray': {   'categories': ['security'],
                                      'description': 'Exposing internal arrays '
                                                     'to the caller violates '
                                                     'object encapsulation '
                                                     'since elements can be '
                                                     'removed or replaced '
                                                     'outside of the object '
                                                     'that owns it. It is '
                                                     'safer to return a copy '
                                                     'of the array.\n'
                                                     'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/sunsecure.html#MethodReturnsInternalArray\n'
                                                     '\n'
                                                     '  \n'
                                                     'public class '
                                                     'SecureSystem {\n'
                                                     '  UserData [] ud;\n'
                                                     '  public UserData [] '
                                                     'getUserData() {\n'
                                                     "      // Don't return "
                                                     'directly the internal '
                                                     'array, return a copy\n'
                                                     '      return ud;\n'
                                                     '  }\n'
                                                     '}\n'
                                                     '  \n'
                                                     '      ',
                                      'display_name': 'MethodReturnsInternalArray',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': "Returning ''{0}'' may expose "
                                               'an internal array.'},
    'MethodWithSameNameAsEnclosingClass': {   'categories': ['security'],
                                              'description': 'Non-constructor '
                                                             'methods should '
                                                             'not have the '
                                                             'same name as the '
                                                             'enclosing '
                                                             'class.\n'
                                                             'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#MethodWithSameNameAsEnclosingClass\n'
                                                             '\n'
                                                             '    \n'
                                                             'public class '
                                                             'MyClass {\n'
                                                             '\n'
                                                             '\tpublic '
                                                             'MyClass() '
                                                             '{}\t\t\t// this '
                                                             'is OK because it '
                                                             'is a '
                                                             'constructor\n'
                                                             '\t\n'
                                                             '\tpublic void '
                                                             'MyClass() {}\t// '
                                                             'this is bad '
                                                             'because it is a '
                                                             'method\n'
                                                             '}\n'
                                                             '    \n'
                                                             '       ',
                                              'display_name': 'MethodWithSameNameAsEnclosingClass',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '1',
                                              'title': 'Classes should not '
                                                       'have non-constructor '
                                                       'methods with the same '
                                                       'name as the class'},
    'MisleadingVariableName': {   'categories': ['security'],
                                  'description': 'Detects when a non-field has '
                                                 "a name starting with 'm_'. "
                                                 'This usually denotes a field '
                                                 'and could be confusing.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#MisleadingVariableName\n'
                                                 '\n'
                                                 '  \n'
                                                 'public class Foo {\n'
                                                 '    private int m_foo; // '
                                                 'OK\n'
                                                 '    public void bar(String '
                                                 'm_baz) {  // Bad\n'
                                                 '      int m_boz = 42; // '
                                                 'Bad\n'
                                                 '    }\n'
                                                 '}\n'
                                                 '  \n'
                                                 '      ',
                                  'display_name': 'MisleadingVariableName',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'Avoid naming non-fields with the '
                                           "prefix 'm_'"},
    'MisplacedNullCheck': {   'categories': ['security'],
                              'description': 'The null check here is '
                                             'misplaced. If the variable is '
                                             'null a NullPointerException will '
                                             'be thrown. Either the check is '
                                             'useless (the variable will never '
                                             'be "null") or it is incorrect.\n'
                                             'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#MisplacedNullCheck\n'
                                             '\n'
                                             '    \n'
                                             'public class Foo {\n'
                                             '\tvoid bar() {\n'
                                             '\t\tif (a.equals(baz) && a != '
                                             'null) {}\n'
                                             '\t\t}\n'
                                             '}\n'
                                             '    \n'
                                             '      ',
                              'display_name': 'MisplacedNullCheck',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'The null check here is misplaced; if '
                                       'the variable is null there will be a '
                                       'NullPointerException'},
    'MisplacedPragma': {   'categories': ['security'],
                           'description': 'Oracle states that the PRAQMA '
                                          'AUTONOMOUS_TRANSACTION must be in '
                                          'the declaration block, but the code '
                                          'does not complain, when being '
                                          'compiled on the 11g DB. '
                                          'https://docs.oracle.com/cd/B28359_01/appdev.111/b28370/static.htm#BABIIHBJ\n'
                                          'https://pmd.github.io/pmd-5.8.1/pmd-plsql/rules/plsql/strictsyntax.html#MisplacedPragma\n'
                                          '\n'
                                          'create or replace package '
                                          'inline_pragma_error is\n'
                                          '\n'
                                          'end;\n'
                                          '/\n'
                                          '\n'
                                          'create or replace package body '
                                          'inline_pragma_error is\n'
                                          '  procedure '
                                          'do_transaction(p_input_token        '
                                          'in varchar(200)) is\n'
                                          '  PRAGMA AUTONOMOUS_TRANSACTION; /* '
                                          'this is correct place for PRAGMA '
                                          '*/\n'
                                          '  begin\n'
                                          '    PRAGMA AUTONOMOUS_TRANSACTION; '
                                          '/* this is the wrong place for '
                                          'PRAGMA -> violation */\n'
                                          '    /* do something */\n'
                                          '    COMMIT;\n'
                                          '   end do_transaction;\n'
                                          '\n'
                                          'end inline_pragma_error;\n'
                                          '/\n'
                                          '\n'
                                          '    ',
                           'display_name': 'MisplacedPragma',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'Pragma should be used only inside the '
                                    "declaration block before 'BEGIN'."},
    'MissingBreakInSwitch': {   'categories': ['security'],
                                'description': 'Switch statements without '
                                               'break or return statements for '
                                               'each case option may indicate '
                                               'problematic behaviour. Empty '
                                               'cases are ignored as these '
                                               'indicate an intentional '
                                               'fall-through.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#MissingBreakInSwitch\n'
                                               '\n'
                                               '\n'
                                               'public void bar(int status) {\n'
                                               '    switch(status) {\n'
                                               '      case CANCELLED:\n'
                                               '        doCancelled();\n'
                                               '        // break; hm, should '
                                               'this be commented out?\n'
                                               '      case NEW:\n'
                                               '        doNew();\n'
                                               '        // is this really a '
                                               'fall-through?\n'
                                               '      case REMOVED:\n'
                                               '        doRemoved();\n'
                                               '        // what happens if you '
                                               'add another case after this '
                                               'one?\n'
                                               '      case OTHER: // empty '
                                               'case - this is interpreted as '
                                               'an intentional fall-through\n'
                                               '      case ERROR:\n'
                                               '        doErrorHandling();\n'
                                               '        break;\n'
                                               '    }\n'
                                               '}\n'
                                               '\n'
                                               '      ',
                                'display_name': 'MissingBreakInSwitch',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'A switch statement does not contain '
                                         'a break'},
    'MissingSerialVersionUID': {   'categories': ['security'],
                                   'description': 'Serializable classes should '
                                                  'provide a serialVersionUID '
                                                  'field.\n'
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/javabeans.html#MissingSerialVersionUID\n'
                                                  '\n'
                                                  '\n'
                                                  'public class Foo implements '
                                                  'java.io.Serializable {\n'
                                                  ' String name;\n'
                                                  ' // Define serialization id '
                                                  'to avoid serialization '
                                                  'related bugs\n'
                                                  ' // i.e., public static '
                                                  'final long serialVersionUID '
                                                  '= 4328743;\n'
                                                  '}\n'
                                                  '\n'
                                                  '\n'
                                                  '          ',
                                   'display_name': 'MissingSerialVersionUID',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'Classes implementing Serializable '
                                            'should set a serialVersionUID'},
    'MissingStaticMethodInNonInstantiatableClass': {   'categories': [   'security'],
                                                       'description': 'A class '
                                                                      'that '
                                                                      'has '
                                                                      'private '
                                                                      'constructors '
                                                                      'and '
                                                                      'does '
                                                                      'not '
                                                                      'have '
                                                                      'any '
                                                                      'static '
                                                                      'methods '
                                                                      'or '
                                                                      'fields '
                                                                      'cannot '
                                                                      'be '
                                                                      'used.\n'
                                                                      'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#MissingStaticMethodInNonInstantiatableClass\n'
                                                                      '\n'
                                                                      '\n'
                                                                      '// This '
                                                                      'class '
                                                                      'is '
                                                                      'unusable, '
                                                                      'since '
                                                                      'it '
                                                                      'cannot '
                                                                      'be\n'
                                                                      '// '
                                                                      'instantiated '
                                                                      '(private '
                                                                      'constructor),\n'
                                                                      '// and '
                                                                      'no '
                                                                      'static '
                                                                      'method '
                                                                      'can be '
                                                                      'called.\n'
                                                                      '\n'
                                                                      'public '
                                                                      'class '
                                                                      'Foo {\n'
                                                                      '  '
                                                                      'private '
                                                                      'Foo() '
                                                                      '{}\n'
                                                                      '  void '
                                                                      'foo() '
                                                                      '{}\n'
                                                                      '}\n'
                                                                      '\n'
                                                                      '\n'
                                                                      '      ',
                                                       'display_name': 'MissingStaticMethodInNonInstantiatableClass',
                                                       'file': '%(issue.file)s',
                                                       'line': '%(issue.line)s',
                                                       'severity': '1',
                                                       'title': 'Class cannot '
                                                                'be '
                                                                'instantiated '
                                                                'and does not '
                                                                'provide any '
                                                                'static '
                                                                'methods or '
                                                                'fields'},
    'MistypedCDATASection': {   'categories': ['security'],
                                'description': 'An XML CDATA section begins '
                                               'with a <!CDATA[ marker, which '
                                               'has only one [, and ends with '
                                               'a ]]> marker, which has only '
                                               'two ].\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-xml/rules/xml/basic.html#MistypedCDATASection\n'
                                               '\n'
                                               ' \n'
                                               'An extra [ looks like '
                                               '&lt;!CDATA[[]]&gt;, and an '
                                               'extra ] looks like '
                                               '&lt;!CDATA[]]]&gt;.\n'
                                               ' \n'
                                               '     ',
                                'display_name': 'MistypedCDATASection',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Potentialy mistyped CDATA section '
                                         'with extra [ at beginning or ] at '
                                         'the end.'},
    'ModifiedCyclomaticComplexity': {   'categories': ['security'],
                                        'description': 'Complexity directly '
                                                       'affects maintenance '
                                                       'costs is determined by '
                                                       'the number of decision '
                                                       'points in a method '
                                                       'plus one for the '
                                                       'method entry. The '
                                                       'decision points '
                                                       "include 'if', 'while', "
                                                       "'for', and 'case "
                                                       "labels' calls. "
                                                       'Generally, numbers '
                                                       'ranging from 1-4 '
                                                       'denote low complexity, '
                                                       '5-7 denote moderate '
                                                       'complexity, 8-10 '
                                                       'denote high '
                                                       'complexity, and 11+ is '
                                                       'very high complexity. '
                                                       'Modified complexity '
                                                       'treats switch '
                                                       'statements as a single '
                                                       'decision point.\n'
                                                       'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/codesize.html#ModifiedCyclomaticComplexity\n'
                                                       '\n'
                                                       '\n'
                                                       'public class Foo {    '
                                                       '// This has a '
                                                       'Cyclomatic Complexity '
                                                       '= 9\n'
                                                       '1   public void '
                                                       'example()  {\n'
                                                       '2       if (a == b)  '
                                                       '{\n'
                                                       '3           if (a1 == '
                                                       'b1) {\n'
                                                       '                '
                                                       'fiddle();\n'
                                                       '4           } else if '
                                                       'a2 == b2) {\n'
                                                       '                '
                                                       'fiddle();\n'
                                                       '            }  else {\n'
                                                       '                '
                                                       'fiddle();\n'
                                                       '            }\n'
                                                       '5       } else if (c '
                                                       '== d) {\n'
                                                       '6           while (c '
                                                       '== d) {\n'
                                                       '                '
                                                       'fiddle();\n'
                                                       '            }\n'
                                                       '7        } else if (e '
                                                       '== f) {\n'
                                                       '8           for (int n '
                                                       '= 0; n < h; n++) {\n'
                                                       '                '
                                                       'fiddle();\n'
                                                       '            }\n'
                                                       '        } else{\n'
                                                       '9           switch (z) '
                                                       '{\n'
                                                       '                case '
                                                       '1:\n'
                                                       '                    '
                                                       'fiddle();\n'
                                                       '                    '
                                                       'break;\n'
                                                       '                case '
                                                       '2:\n'
                                                       '                    '
                                                       'fiddle();\n'
                                                       '                    '
                                                       'break;\n'
                                                       '                case '
                                                       '3:\n'
                                                       '                    '
                                                       'fiddle();\n'
                                                       '                    '
                                                       'break;\n'
                                                       '                '
                                                       'default:\n'
                                                       '                    '
                                                       'fiddle();\n'
                                                       '                    '
                                                       'break;\n'
                                                       '            }\n'
                                                       '        }\n'
                                                       '    }\n'
                                                       '}\n'
                                                       '\n'
                                                       '   ',
                                        'display_name': 'ModifiedCyclomaticComplexity',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': "The {0} ''{1}'' has a "
                                                 'Modified Cyclomatic '
                                                 'Complexity of {2}.'},
    'MoreThanOneLogger': {   'categories': ['security'],
                             'description': 'Normally only one logger is used '
                                            'in each class.\n'
                                            'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/logging-java.html#MoreThanOneLogger\n'
                                            '\n'
                                            ' \n'
                                            'public class Foo {\n'
                                            '    Logger log = '
                                            'Logger.getLogger(Foo.class.getName());\n'
                                            '    // It is very rare to see two '
                                            'loggers on a class, normally\n'
                                            '    // log information is '
                                            'multiplexed by levels\n'
                                            '    Logger log2= '
                                            'Logger.getLogger(Foo.class.getName());\n'
                                            '}\n'
                                            '\n'
                                            '     ',
                             'display_name': 'MoreThanOneLogger',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Class contains more than one logger.'},
    'NPathComplexity': {   'categories': ['security'],
                           'description': 'The NPath complexity of a method is '
                                          'the number of acyclic execution '
                                          'paths through that method. A '
                                          'threshold of 200 is generally '
                                          'considered the point where measures '
                                          'should be taken to reduce '
                                          'complexity and increase '
                                          'readability.\n'
                                          'https://pmd.github.io/pmd-5.8.1/pmd-plsql/rules/plsql/codesize.html#NPathComplexity\n'
                                          '\n'
                                          ' \n'
                                          'CREATE OR REPLACE\n'
                                          'PROCEDURE bar AS BEGIN\t-- this is '
                                          'something more complex than it '
                                          'needs to be,\n'
                                          '\tif (y) THEN\t-- it should be '
                                          'broken down into smaller methods or '
                                          'functions\n'
                                          '\t\tfor j IN 0 .. j-1 LOOP\n'
                                          '\t\t\tif (j > r) THEN\n'
                                          '\t\t\t\tdoSomething;\n'
                                          '\t\t\t\twhile (f < 5 ) LOOP\n'
                                          '\t\t\t\t\tanotherThing;\n'
                                          '\t\t\t\t\tf := f - 27;\n'
                                          '\t\t\t\t\tEND LOOP;\n'
                                          '\t\t\telse\n'
                                          '\t\t\t\t\ttryThis();\n'
                                          '\t\t\tEND IF;\n'
                                          '\t\tEND LOOP;\n'
                                          '\tEND IF;\n'
                                          '\tif ( r - n > 45) THEN\n'
                                          '\t\twhile (doMagic) LOOP\n'
                                          '\t\t\tfindRabbits;\n'
                                          '\t\tEND LOOP;\n'
                                          '\tEND IF;\n'
                                          '\tBEGIN\n'
                                          '\t\tdoSomethingDangerous();\n'
                                          '\tEXCEPTION WHEN FooException THEN\n'
                                          '\t\tmakeAmends;\n'
                                          '\t\tBEGIN\n'
                                          '\t\t\tdontDoItAgain;\n'
                                          '\t\tEXCEPTION\n'
                                          '\t\tWHEN OTHERS THEN\n'
                                          '\t\t\t\tlog_problem;\n'
                                          '\t\tEND;\n'
                                          '\tEND;\n'
                                          'END;\n'
                                          '\n'
                                          ' \n'
                                          '    ',
                           'display_name': 'NPathComplexity',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'The method {0}() has an NPath complexity '
                                    'of {1}'},
    'NcssConstructorCount': {   'categories': ['security'],
                                'description': 'This rule uses the NCSS '
                                               '(Non-Commenting Source '
                                               'Statements) algorithm to '
                                               'determine the number of lines '
                                               'of code for a given '
                                               'constructor. NCSS ignores '
                                               'comments, and counts actual '
                                               'statements. Using this '
                                               'algorithm, lines of code that '
                                               'are split are counted as one.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/codesize.html#NcssConstructorCount\n'
                                               '\n'
                                               '\n'
                                               'public class Foo extends Bar '
                                               '{\n'
                                               ' public Foo() {\n'
                                               '     super();\n'
                                               '\n'
                                               '\n'
                                               '\n'
                                               '\n'
                                               '\n'
                                               ' //this constructor only has 1 '
                                               'NCSS lines\n'
                                               '      super.foo();\n'
                                               ' }\n'
                                               '}\n'
                                               '\n'
                                               '   ',
                                'display_name': 'NcssConstructorCount',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'The constructor with {0} parameters '
                                         'has an NCSS line count of {1}'},
    'NcssMethodCount': {   'categories': ['security'],
                           'description': 'This rule uses the NCSS '
                                          '(Non-Commenting Source Statements) '
                                          'algorithm to determine the number '
                                          'of lines of code for a given '
                                          'method. NCSS ignores comments, and '
                                          'counts actual statements. Using '
                                          'this algorithm, lines of code that '
                                          'are split are counted as one.\n'
                                          'https://pmd.github.io/pmd-5.8.1/pmd-plsql/rules/plsql/codesize.html#NcssMethodCount\n'
                                          '\n'
                                          '\n'
                                          'CREATE OR REPLACE PACKAGE BODY AS\n'
                                          ' FUNCTION methd RETURN INTEGER IS\n'
                                          ' BEGIN\n'
                                          '   RETURN 1;;\n'
                                          ' END;\n'
                                          'END;\n'
                                          '\n'
                                          '   ',
                           'display_name': 'NcssMethodCount',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'The method {0}() has an NCSS line count '
                                    'of {1}'},
    'NcssObjectCount': {   'categories': ['security'],
                           'description': 'This rule uses the NCSS '
                                          '(Non-Commenting Source Statements) '
                                          'algorithm to determine the number '
                                          'of lines of code for a given Oracle '
                                          'object. NCSS ignores comments, and '
                                          'counts actual statements. Using '
                                          'this algorithm, lines of code that '
                                          'are split are counted as one.\n'
                                          'https://pmd.github.io/pmd-5.8.1/pmd-plsql/rules/plsql/codesize.html#NcssObjectCount\n'
                                          '\n'
                                          '\n'
                                          'CREATE OR REPLACE PACKAGE pkg_\n'
                                          ' PROCEDURE Foo IS\n'
                                          ' BEGIN\n'
                                          ' --this class only has 6 NCSS '
                                          'lines\n'
                                          '     super();\n'
                                          '     super();\n'
                                          ' END;\n'
                                          '}\n'
                                          '\n'
                                          '   ',
                           'display_name': 'NcssObjectCount',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'The Oracle object has an NCSS line count '
                                    'of {0}'},
    'NcssTypeCount': {   'categories': ['security'],
                         'description': 'This rule uses the NCSS '
                                        '(Non-Commenting Source Statements) '
                                        'algorithm to determine the number of '
                                        'lines of code for a given type. NCSS '
                                        'ignores comments, and counts actual '
                                        'statements. Using this algorithm, '
                                        'lines of code that are split are '
                                        'counted as one.\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/codesize.html#NcssTypeCount\n'
                                        '\n'
                                        '\n'
                                        'public class Foo extends Bar {\n'
                                        ' public Foo() {\n'
                                        ' //this class only has 6 NCSS lines\n'
                                        '     super();\n'
                                        '\n'
                                        '\n'
                                        '\n'
                                        '\n'
                                        '\n'
                                        '      super.foo();\n'
                                        ' }\n'
                                        '}\n'
                                        '\n'
                                        '   ',
                         'display_name': 'NcssTypeCount',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'The type has an NCSS line count of {0}'},
    'NoClassAttribute': {   'categories': ['security'],
                            'description': 'Do not use an attribute called '
                                           '\'class\'. Use "styleclass" for '
                                           'CSS styles.\n'
                                           'https://pmd.github.io/pmd-5.8.1/pmd-jsp/rules/jsp/basic.html#NoClassAttribute\n'
                                           '\n'
                                           '\t\t\t\n'
                                           '<HTML> <BODY>\n'
                                           '<P class="MajorHeading">Some '
                                           'text</P>\n'
                                           '</BODY> </HTML>\n'
                                           '\t\t\t\n'
                                           '\t\t',
                            'display_name': 'NoClassAttribute',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': "Do not use an attribute called 'class'."},
    'NoElseReturn': {   'categories': ['security'],
                        'description': 'The else block in a if-else-construct '
                                       'is unnecessary if the `if` block '
                                       'contains a return. Then the content of '
                                       'the else block can be put outside. See '
                                       'also: '
                                       'http://eslint.org/docs/rules/no-else-return\n'
                                       'https://pmd.github.io/pmd-5.8.1/pmd-javascript/rules/ecmascript/unnecessary.html#NoElseReturn\n'
                                       '\n'
                                       '// Bad:\n'
                                       'if (x) {\n'
                                       '  return y;\n'
                                       '} else {\n'
                                       '  return z;\n'
                                       '}\n'
                                       '\n'
                                       '// Good:\n'
                                       'if (x) {\n'
                                       '  return y;\n'
                                       '}\n'
                                       'return z;\n'
                                       '    ',
                        'display_name': 'NoElseReturn',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'The else block is unnecessary'},
    'NoHtmlComments': {   'categories': ['security'],
                          'description': 'In a production system, HTML '
                                         'comments increase the payload '
                                         'between the application server to '
                                         'the client, and serve little other '
                                         'purpose. Consider switching to JSP '
                                         'comments.\n'
                                         'https://pmd.github.io/pmd-5.8.1/pmd-jsp/rules/jsp/basic.html#NoHtmlComments\n'
                                         '\n'
                                         '\t\t\t\n'
                                         '<HTML><title>bad example><BODY>\n'
                                         '<!-- HTML comment -->\n'
                                         '</BODY> </HTML>\n'
                                         '\n'
                                         '<HTML><title>good example><BODY>\n'
                                         '<%-- JSP comment --%>\n'
                                         '</BODY> </HTML>\n'
                                         '\t\t\t\n'
                                         '\t\t',
                          'display_name': 'NoHtmlComments',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'Use JSP comments instead of HTML comments'},
    'NoInlineJavaScript': {   'categories': ['security'],
                              'description': 'Avoid inline JavaScript. Import '
                                             '.js files instead.\n'
                                             'https://pmd.github.io/pmd-5.8.1/pmd-vm/rules/vm/basic.html#NoInlineJavaScript\n',
                              'display_name': 'NoInlineJavaScript',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'Avoid inline JavaScript'},
    'NoInlineScript': {   'categories': ['security'],
                          'description': 'Avoid inlining HTML script content. '
                                         'Consider externalizing the HTML '
                                         "script using the 'src' attribute on "
                                         'the "script" element. Externalized '
                                         'script could be reused between '
                                         'pages. Browsers can also cache the '
                                         'script, reducing overall download '
                                         'bandwidth.\n'
                                         'https://pmd.github.io/pmd-5.8.1/pmd-jsp/rules/jsp/basic.html#NoInlineScript\n'
                                         '\n'
                                         '            \n'
                                         '                Most browsers should '
                                         'be able to interpret the following '
                                         'headers:\n'
                                         '                \n'
                                         '                <%@ page '
                                         'contentType="text/html; '
                                         'charset=UTF-8" pageEncoding="UTF-8" '
                                         '%>\n'
                                         '                    \n'
                                         '                <meta '
                                         'http-equiv="Content-Type"  '
                                         'content="text/html; charset=UTF-8" '
                                         '/>\n'
                                         '            \n'
                                         '        ',
                          'display_name': 'NoInlineScript',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'Avoiding inlining HTML script content'},
    'NoInlineStyleInformation': {   'categories': ['security'],
                                    'description': 'Style information should '
                                                   'be put in CSS files, not '
                                                   "in JSPs. Therefore, don't "
                                                   'use &lt;B> or &lt;FONT> '
                                                   'tags, or attributes like '
                                                   '"align=\'center\'".\n'
                                                   'https://pmd.github.io/pmd-5.8.1/pmd-jsp/rules/jsp/basic.html#NoInlineStyleInformation\n'
                                                   '\n'
                                                   '\t\t\t\n'
                                                   '<html><body><p '
                                                   "align='center'><b>text</b></p></body></html>\n"
                                                   '\t\t\t\n'
                                                   '\t\t',
                                    'display_name': 'NoInlineStyleInformation',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'Avoid having style information '
                                             'in JSP files.'},
    'NoInlineStyles': {   'categories': ['security'],
                          'description': 'Avoid inline styles. Use css classes '
                                         'instead.\n'
                                         'https://pmd.github.io/pmd-5.8.1/pmd-vm/rules/vm/basic.html#NoInlineStyles\n',
                          'display_name': 'NoInlineStyles',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'Avoid inline styles'},
    'NoJspForward': {   'categories': ['security'],
                        'description': 'Do not do a forward from within a JSP '
                                       'file.\n'
                                       'https://pmd.github.io/pmd-5.8.1/pmd-jsp/rules/jsp/basic.html#NoJspForward\n'
                                       '\n'
                                       '\t\t\t\n'
                                       '<jsp:forward '
                                       "page='UnderConstruction.jsp'/>\n"
                                       '\t\t\t\n'
                                       '\t\t',
                        'display_name': 'NoJspForward',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Do not do a forward from within a JSP file.'},
    'NoLongScripts': {   'categories': ['security'],
                         'description': 'Scripts should be part of Tag '
                                        'Libraries, rather than part of JSP '
                                        'pages.\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-jsp/rules/jsp/basic.html#NoLongScripts\n'
                                        '\n'
                                        '\t\t\t\n'
                                        '<HTML>\n'
                                        '<BODY>\n'
                                        '<!--Java Script-->\n'
                                        '<SCRIPT language="JavaScript" '
                                        'type="text/javascript">\n'
                                        '<!--\n'
                                        'function calcDays(){\n'
                                        '  var date1 = '
                                        "document.getElementById('d1').lastChild.data;\n"
                                        '  var date2 = '
                                        "document.getElementById('d2').lastChild.data;\n"
                                        '  date1 = date1.split("-");\n'
                                        '  date2 = date2.split("-");\n'
                                        '  var sDate = new '
                                        'Date(date1[0]+"/"+date1[1]+"/"+date1[2]);\n'
                                        '  var eDate = new '
                                        'Date(date2[0]+"/"+date2[1]+"/"+date2[2]);\n'
                                        '  var daysApart = '
                                        'Math.abs(Math.round((sDate-eDate)/86400000));\n'
                                        '  '
                                        "document.getElementById('diffDays').lastChild.data "
                                        '= daysApart;\n'
                                        '}\n'
                                        '\n'
                                        'onload=calcDays;\n'
                                        '//-->\n'
                                        '</SCRIPT>\n'
                                        '</BODY>\n'
                                        '</HTML>\n'
                                        '\t\t\t\n'
                                        '\t\t',
                         'display_name': 'NoLongScripts',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Avoid having long scripts (e.g. Javascript) '
                                  'inside a JSP file.'},
    'NoPackage': {   'categories': ['security'],
                     'description': 'Detects when a class or interface does '
                                    'not have a package definition.\n'
                                    'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#NoPackage\n'
                                    '\n'
                                    '\n'
                                    '// no package declaration\n'
                                    'public class ClassInDefaultPackage {\n'
                                    '}\n'
                                    '\n'
                                    '    ',
                     'display_name': 'NoPackage',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'All classes and interfaces must belong to a '
                              'named package'},
    'NoScriptlets': {   'categories': ['security'],
                        'description': 'Scriptlets should be factored into Tag '
                                       'Libraries or JSP declarations, rather '
                                       'than being part of JSP pages.\n'
                                       'https://pmd.github.io/pmd-5.8.1/pmd-jsp/rules/jsp/basic.html#NoScriptlets\n'
                                       '\n'
                                       '\t\t\t \n'
                                       '<HTML>\n'
                                       '<HEAD>\n'
                                       '<%\n'
                                       'response.setHeader("Pragma", '
                                       '"No-cache");\n'
                                       '%>\n'
                                       '</HEAD>\n'
                                       '\t<BODY>\n'
                                       '\t\t<jsp:scriptlet>String title = '
                                       '"Hello world!";</jsp:scriptlet>\n'
                                       '\t</BODY>\n'
                                       '</HTML>\n'
                                       '\t\t\t\t\t \n'
                                       '\t\t',
                        'display_name': 'NoScriptlets',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Avoid having scriptlets inside a JSP file.'},
    'NoUnsanitizedJSPExpression': {   'categories': ['security'],
                                      'description': 'Avoid using expressions '
                                                     'without escaping / '
                                                     'sanitizing. This could '
                                                     'lead to cross site '
                                                     'scripting - as the '
                                                     'expression would be '
                                                     'interpreted by the '
                                                     'browser directly (e.g. '
                                                     '"<script>alert(\'hello\');</script>").\n'
                                                     'https://pmd.github.io/pmd-5.8.1/pmd-jsp/rules/jsp/basic.html#NoUnsanitizedJSPExpression\n'
                                                     '\n'
                                                     '            \n'
                                                     '<%@ page '
                                                     'contentType="text/html; '
                                                     'charset=UTF-8" %>\n'
                                                     '<%@ taglib prefix="fn" '
                                                     'uri="http://java.sun.com/jsp/jstl/functions" '
                                                     '%>\n'
                                                     '${expression}                    '
                                                     "<!-- don't use this -->\n"
                                                     '${fn:escapeXml(expression)}      '
                                                     '<!-- instead, escape it '
                                                     '-->\n'
                                                     '<c:out '
                                                     'value="${expression}" '
                                                     '/>  <!-- or use c:out '
                                                     '-->\n'
                                                     '            \n'
                                                     '        ',
                                      'display_name': 'NoUnsanitizedJSPExpression',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'Using unsanitized JSP '
                                               'expression can lead to Cross '
                                               'Site Scripting (XSS) attacks'},
    'NonCaseLabelInSwitchStatement': {   'categories': ['security'],
                                         'description': 'A non-case label '
                                                        '(e.g. a named '
                                                        'break/continue label) '
                                                        'was present in a '
                                                        'switch statement. '
                                                        'This legal, but '
                                                        'confusing. It is easy '
                                                        'to mix up the case '
                                                        'labels and the '
                                                        'non-case labels.\n'
                                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#NonCaseLabelInSwitchStatement\n'
                                                        '\n'
                                                        '   \n'
                                                        'public class Foo {\n'
                                                        '  void bar(int a) {\n'
                                                        '   switch (a) {\n'
                                                        '     case 1:\n'
                                                        '       // do '
                                                        'something\n'
                                                        '       break;\n'
                                                        '     mylabel: // this '
                                                        'is legal, but '
                                                        'confusing!\n'
                                                        '       break;\n'
                                                        '     default:\n'
                                                        '       break;\n'
                                                        '    }\n'
                                                        '  }\n'
                                                        '}\n'
                                                        '   \n'
                                                        '       ',
                                         'display_name': 'NonCaseLabelInSwitchStatement',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'A non-case label was '
                                                  'present in a switch '
                                                  'statement'},
    'NonStaticInitializer': {   'categories': ['security'],
                                'description': 'A non-static initializer block '
                                               'will be called any time a '
                                               'constructor is invoked (just '
                                               'prior to invoking the '
                                               'constructor). While this is a '
                                               'valid language construct, it '
                                               'is rarely used and is '
                                               'confusing.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#NonStaticInitializer\n'
                                               '\n'
                                               '   \n'
                                               'public class MyClass {\n'
                                               ' // this block gets run before '
                                               'any call to a constructor\n'
                                               '  {\n'
                                               '   System.out.println("I am '
                                               'about to construct myself");\n'
                                               '  }\n'
                                               '}\n'
                                               '   \n'
                                               '       ',
                                'display_name': 'NonStaticInitializer',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Non-static initializers are '
                                         'confusing'},
    'NonThreadSafeSingleton': {   'categories': ['security'],
                                  'description': 'Non-thread safe singletons '
                                                 'can result in bad state '
                                                 'changes. Eliminate static '
                                                 'singletons if possible by '
                                                 'instantiating the object '
                                                 'directly. Static singletons '
                                                 'are usually not needed as '
                                                 'only a single instance '
                                                 'exists anyway. Other '
                                                 'possible fixes are to '
                                                 'synchronize the entire '
                                                 'method or to use an '
                                                 '[initialize-on-demand holder '
                                                 'class](https://en.wikipedia.org/wiki/Initialization-on-demand_holder_idiom). '
                                                 'Refrain from using the '
                                                 'double-checked locking '
                                                 'pattern. The Java Memory '
                                                 "Model doesn't guarantee it "
                                                 'to work unless the variable '
                                                 'is declared as `volatile`, '
                                                 'adding an uneeded '
                                                 'performance penalty. '
                                                 '[Reference](http://www.cs.umd.edu/~pugh/java/memoryModel/DoubleCheckedLocking.html) '
                                                 'See Effective Java, item '
                                                 '48.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#NonThreadSafeSingleton\n'
                                                 '\n'
                                                 'private static Foo foo = '
                                                 'null;\n'
                                                 '\n'
                                                 '//multiple simultaneous '
                                                 'callers may see partially '
                                                 'initialized objects\n'
                                                 'public static Foo getFoo() '
                                                 '{\n'
                                                 '    if (foo==null) {\n'
                                                 '        foo = new Foo();\n'
                                                 '    }\n'
                                                 '    return foo;\n'
                                                 '}\n'
                                                 '        ',
                                  'display_name': 'NonThreadSafeSingleton',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'Singleton is not thread safe'},
    'NullAssignment': {   'categories': ['security'],
                          'description': 'Assigning a "null" to a variable '
                                         '(outside of its declaration) is '
                                         'usually bad form. Sometimes, this '
                                         'type of assignment is an indication '
                                         "that the programmer doesn't "
                                         'completely understand what is going '
                                         'on in the code. NOTE: This sort of '
                                         'assignment may used in some cases to '
                                         'dereference objects and encourage '
                                         'garbage collection.\n'
                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#NullAssignment\n'
                                         '\n'
                                         ' \n'
                                         'public void bar() {\n'
                                         '  Object x = null; // this is OK\n'
                                         '  x = new Object();\n'
                                         '     // big, complex piece of code '
                                         'here\n'
                                         '  x = null; // this is not required\n'
                                         '     // big, complex piece of code '
                                         'here\n'
                                         '}\n'
                                         '\n'
                                         ' \n'
                                         '      ',
                          'display_name': 'NullAssignment',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'Assigning an Object to null is a code '
                                   'smell.  Consider refactoring.'},
    'OneDeclarationPerLine': {   'categories': ['security'],
                                 'description': 'Java allows the use of '
                                                'several variables declaration '
                                                'of the same type on one line. '
                                                'However, it can lead to quite '
                                                'messy code. This rule looks '
                                                'for several declarations on '
                                                'the same line.\n'
                                                'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#OneDeclarationPerLine\n'
                                                '\n'
                                                '          \n'
                                                'String name;            // '
                                                'separate declarations\n'
                                                'String lastname;\n'
                                                '\n'
                                                'String name, lastname;  // '
                                                'combined declaration, a '
                                                'violation\n'
                                                '\n'
                                                'String name,\n'
                                                '       lastname;        // '
                                                'combined declaration on '
                                                'multiple lines, no violation '
                                                'by default.\n'
                                                '                        // '
                                                'Set property strictMode to '
                                                'true to mark this as '
                                                'violation.\n'
                                                '          \n'
                                                '        ',
                                 'display_name': 'OneDeclarationPerLine',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'Use one line for each declaration, '
                                          'it enhances code readability.'},
    'OnlyOneReturn': {   'categories': ['security'],
                         'description': 'A method should have only one exit '
                                        'point, and that should be the last '
                                        'statement in the method.\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#OnlyOneReturn\n'
                                        '\n'
                                        ' \n'
                                        'public class OneReturnOnly1 {\n'
                                        '  public void foo(int x) {\n'
                                        '    if (x > 0) {\n'
                                        '      return "hey";   // first exit\n'
                                        '    }\n'
                                        '    return "hi";\t// second exit\n'
                                        '  }\n'
                                        '}\n'
                                        ' \n'
                                        '     ',
                         'display_name': 'OnlyOneReturn',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'A method should have only one exit point, '
                                  'and that should be the last statement in '
                                  'the method'},
    'OptimizableToArrayCall': {   'categories': ['security'],
                                  'description': "Calls to a collection's "
                                                 'toArray() method should '
                                                 'specify target arrays sized '
                                                 'to match the size of the '
                                                 'collection. Initial arrays '
                                                 'that are too small are '
                                                 'discarded in favour of new '
                                                 'ones that have to be created '
                                                 'that are the proper size.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#OptimizableToArrayCall\n'
                                                 '\n'
                                                 '  \n'
                                                 'List foos = getFoos();\n'
                                                 '\n'
                                                 '    // inefficient, the '
                                                 'array will be discarded\n'
                                                 'Foo[] fooArray = '
                                                 'foos.toArray(new Foo[0]);\n'
                                                 '\n'
                                                 '    // much better; this one '
                                                 'sizes the destination '
                                                 'array,\n'
                                                 '    // avoiding of a new one '
                                                 'via reflection\n'
                                                 'Foo[] fooArray = '
                                                 'foos.toArray(new '
                                                 'Foo[foos.size()]);\n'
                                                 '  \n'
                                                 '      ',
                                  'display_name': 'OptimizableToArrayCall',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'This call to Collection.toArray() '
                                           'may be optimizable'},
    'OverrideBothEqualsAndHashcode': {   'categories': ['security'],
                                         'description': 'Override both public '
                                                        'boolean '
                                                        'Object.equals(Object '
                                                        'other), and public '
                                                        'int '
                                                        'Object.hashCode(), or '
                                                        'override neither. '
                                                        'Even if you are '
                                                        'inheriting a '
                                                        'hashCode() from a '
                                                        'parent class, '
                                                        'consider implementing '
                                                        'hashCode and '
                                                        'explicitly delegating '
                                                        'to your superclass.\n'
                                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#OverrideBothEqualsAndHashcode\n'
                                                        '\n'
                                                        '  \n'
                                                        'public class Bar {\t\t'
                                                        '// poor, missing a '
                                                        'hashcode() method\n'
                                                        '\tpublic boolean '
                                                        'equals(Object o) {\n'
                                                        '      // do some '
                                                        'comparison\n'
                                                        '\t}\n'
                                                        '}\n'
                                                        '\n'
                                                        'public class Baz {\t\t'
                                                        '// poor, missing an '
                                                        'equals() method\n'
                                                        '\tpublic int '
                                                        'hashCode() {\n'
                                                        '      // return some '
                                                        'hash value\n'
                                                        '\t}\n'
                                                        '}\n'
                                                        '\n'
                                                        'public class Foo {\t\t'
                                                        '// perfect, both '
                                                        'methods provided\n'
                                                        '\tpublic boolean '
                                                        'equals(Object other) '
                                                        '{\n'
                                                        '      // do some '
                                                        'comparison\n'
                                                        '\t}\n'
                                                        '\tpublic int '
                                                        'hashCode() {\n'
                                                        '      // return some '
                                                        'hash value\n'
                                                        '\t}\n'
                                                        '}\n'
                                                        ' \n'
                                                        '      ',
                                         'display_name': 'OverrideBothEqualsAndHashcode',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'Ensure you override both '
                                                  'equals() and hashCode()'},
    'PackageCase': {   'categories': ['security'],
                       'description': 'Detects when a package definition '
                                      'contains uppercase characters.\n'
                                      'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#PackageCase\n'
                                      '\n'
                                      '    \n'
                                      'package com.MyCompany;  // should be '
                                      'lowercase name\n'
                                      '\n'
                                      'public class SomeClass {\n'
                                      '}\n'
                                      '    \n'
                                      '        ',
                       'display_name': 'PackageCase',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Package name contains upper case characters'},
    'PositionLiteralsFirstInCaseInsensitiveComparisons': {   'categories': [   'security'],
                                                             'description': 'Position '
                                                                            'literals '
                                                                            'first '
                                                                            'in '
                                                                            'comparisons, '
                                                                            'if '
                                                                            'the '
                                                                            'second '
                                                                            'argument '
                                                                            'is '
                                                                            'null '
                                                                            'then '
                                                                            'NullPointerExceptions '
                                                                            'can '
                                                                            'be '
                                                                            'avoided, '
                                                                            'they '
                                                                            'will '
                                                                            'just '
                                                                            'return '
                                                                            'false.\n'
                                                                            'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#PositionLiteralsFirstInCaseInsensitiveComparisons\n'
                                                                            '\n'
                                                                            '\n'
                                                                            'class '
                                                                            'Foo '
                                                                            '{\n'
                                                                            '  '
                                                                            'boolean '
                                                                            'bar(String '
                                                                            'x) '
                                                                            '{\n'
                                                                            '    '
                                                                            'return '
                                                                            'x.equalsIgnoreCase("2"); '
                                                                            '// '
                                                                            'should '
                                                                            'be '
                                                                            '"2".equalsIgnoreCase(x)\n'
                                                                            '  '
                                                                            '}\n'
                                                                            '}\n'
                                                                            '\n'
                                                                            '\n'
                                                                            '  ',
                                                             'display_name': 'PositionLiteralsFirstInCaseInsensitiveComparisons',
                                                             'file': '%(issue.file)s',
                                                             'line': '%(issue.line)s',
                                                             'severity': '1',
                                                             'title': 'Position '
                                                                      'literals '
                                                                      'first '
                                                                      'in '
                                                                      'String '
                                                                      'comparisons '
                                                                      'for '
                                                                      'EqualsIgnoreCase'},
    'PositionLiteralsFirstInComparisons': {   'categories': ['security'],
                                              'description': 'Position '
                                                             'literals first '
                                                             'in comparisons, '
                                                             'if the second '
                                                             'argument is null '
                                                             'then '
                                                             'NullPointerExceptions '
                                                             'can be avoided, '
                                                             'they will just '
                                                             'return false.\n'
                                                             'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#PositionLiteralsFirstInComparisons\n'
                                                             '\n'
                                                             '\n'
                                                             'class Foo {\n'
                                                             '  boolean '
                                                             'bar(String x) {\n'
                                                             '    return '
                                                             'x.equals("2"); '
                                                             '// should be '
                                                             '"2".equals(x)\n'
                                                             '  }\n'
                                                             '}\n'
                                                             '\n'
                                                             '\n'
                                                             '  ',
                                              'display_name': 'PositionLiteralsFirstInComparisons',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '1',
                                              'title': 'Position literals '
                                                       'first in String '
                                                       'comparisons'},
    'PrematureDeclaration': {   'categories': ['security'],
                                'description': 'Checks for variables that are '
                                               'defined before they might be '
                                               'used. A reference is deemed to '
                                               'be premature if it is created '
                                               'right before a block of code '
                                               "that doesn't use it that also "
                                               'has the ability to return or '
                                               'throw an exception.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/optimizations.html#PrematureDeclaration\n'
                                               '\n'
                                               '              \n'
                                               'public int getLength(String[] '
                                               'strings) {\n'
                                               '  \n'
                                               '  int length = 0;\t// declared '
                                               'prematurely\n'
                                               '\n'
                                               '  if (strings == null || '
                                               'strings.length == 0) return '
                                               '0;\n'
                                               '  \n'
                                               '  for (String str : strings) '
                                               '{\n'
                                               '    length += str.length();\n'
                                               '    }\n'
                                               '\n'
                                               '  return length;\n'
                                               '}\n'
                                               '              \n'
                                               '              ',
                                'display_name': 'PrematureDeclaration',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Avoid declaring a variable if it is '
                                         'unreferenced before a possible exit '
                                         'point.'},
    'PreserveStackTrace': {   'categories': ['security'],
                              'description': 'Throwing a new exception from a '
                                             'catch block without passing the '
                                             'original exception into the new '
                                             'exception will cause the '
                                             'original stack trace to be lost '
                                             'making it difficult to debug '
                                             'effectively.\n'
                                             'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#PreserveStackTrace\n'
                                             '\n'
                                             '    \n'
                                             'public class Foo {\n'
                                             '    void good() {\n'
                                             '        try{\n'
                                             '            '
                                             'Integer.parseInt("a");\n'
                                             '        } catch (Exception e) {\n'
                                             '            throw new '
                                             'Exception(e); // first '
                                             'possibility to create exception '
                                             'chain\n'
                                             '        }\n'
                                             '        try {\n'
                                             '            '
                                             'Integer.parseInt("a");\n'
                                             '        } catch (Exception e) {\n'
                                             '            throw '
                                             '(IllegalStateException)new '
                                             'IllegalStateException().initCause(e); '
                                             '// second possibility to create '
                                             'exception chain.\n'
                                             '        }\n'
                                             '    }\n'
                                             '    void bad() {\n'
                                             '        try{\n'
                                             '            '
                                             'Integer.parseInt("a");\n'
                                             '        } catch (Exception e) {\n'
                                             '            throw new '
                                             'Exception(e.getMessage());\n'
                                             '        }\n'
                                             '    }\n'
                                             '}\n'
                                             '    \n'
                                             '      ',
                              'display_name': 'PreserveStackTrace',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'New exception is thrown in catch '
                                       'block, original stack trace may be '
                                       'lost'},
    'ProjectVersionAsDependencyVersion': {   'categories': ['security'],
                                             'description': 'Using that '
                                                            'expression in '
                                                            'dependency '
                                                            'declarations '
                                                            'seems like a '
                                                            'shortcut, but it '
                                                            'can go wrong. By '
                                                            'far the most '
                                                            'common problem is '
                                                            'the use of '
                                                            '${project.version} '
                                                            'in a BOM or '
                                                            'parent POM.\n'
                                                            'https://pmd.github.io/pmd-5.8.1/pmd-xml/rules/pom/basic.html#ProjectVersionAsDependencyVersion\n'
                                                            '\n'
                                                            ' \n'
                                                            '<project...>\n'
                                                            '  ...\n'
                                                            '  <dependency>\n'
                                                            '    ...\n'
                                                            '    '
                                                            '<version>${project.dependency}</version>\n'
                                                            '  </dependency>\n'
                                                            '</project>\n'
                                                            ' \n'
                                                            '     ',
                                             'display_name': 'ProjectVersionAsDependencyVersion',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': "Do not use project's "
                                                      'version to express a '
                                                      "dependency's version."},
    'ProperCloneImplementation': {   'categories': ['security'],
                                     'description': 'Object clone() should be '
                                                    'implemented with '
                                                    'super.clone().\n'
                                                    'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/clone.html#ProperCloneImplementation\n'
                                                    '\n'
                                                    ' \n'
                                                    'class Foo{\n'
                                                    '    public Object '
                                                    'clone(){\n'
                                                    '        return new Foo(); '
                                                    '// This is bad\n'
                                                    '    }\n'
                                                    '}\n'
                                                    '\n'
                                                    '     ',
                                     'display_name': 'ProperCloneImplementation',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'Object clone() should be '
                                              'implemented with super.clone()'},
    'ProperLogger': {   'categories': ['security'],
                        'description': 'A logger should normally be defined '
                                       'private static final and be associated '
                                       'with the correct class. Private final '
                                       'Log log; is also allowed for rare '
                                       'cases where loggers need to be passed '
                                       'around, with the restriction that the '
                                       'logger needs to be passed into the '
                                       'constructor.\n'
                                       'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/logging-jakarta-commons.html#ProperLogger\n'
                                       '\n'
                                       ' \n'
                                       'public class Foo {\n'
                                       '\n'
                                       '   private static final Log LOG = '
                                       'LogFactory.getLog(Foo.class);\t   // '
                                       'proper way\n'
                                       '\n'
                                       '   protected Log LOG = '
                                       'LogFactory.getLog(Testclass.class);\t\t\t'
                                       '// wrong approach\n'
                                       '}\n'
                                       ' \n'
                                       '            ',
                        'display_name': 'ProperLogger',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Logger should be defined private static '
                                 'final and have the correct class'},
    'RedundantFieldInitializer': {   'categories': ['security'],
                                     'description': 'Java will initialize '
                                                    'fields with known default '
                                                    'values so any explicit '
                                                    'initialization of those '
                                                    'same defaults is '
                                                    'redundant and results in '
                                                    'a larger class file '
                                                    '(approximately three '
                                                    'additional bytecode '
                                                    'instructions per field).\n'
                                                    'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/optimizations.html#RedundantFieldInitializer\n'
                                                    '\n'
                                                    '              \n'
                                                    'public class C {\n'
                                                    '\tboolean b\t= false;\t// '
                                                    'examples of redundant '
                                                    'initializers\n'
                                                    '\tbyte by\t\t= 0;\n'
                                                    '\tshort s\t\t= 0;\n'
                                                    '\tchar c\t\t= 0;\n'
                                                    '\tint i\t\t= 0;\n'
                                                    '\tlong l\t\t= 0;\n'
                                                    '\t\n'
                                                    '\tfloat f\t\t= .0f;    // '
                                                    'all possible float '
                                                    'literals\n'
                                                    '\tdoable d\t= 0d;     // '
                                                    'all possible double '
                                                    'literals\n'
                                                    '\tObject o\t= null;\n'
                                                    '\t\n'
                                                    '\tMyClass mca[] = null;\n'
                                                    '\tint i1 = 0, ia1[] = '
                                                    'null;\n'
                                                    '\t\n'
                                                    '\tclass Nested {\n'
                                                    '\t\tboolean b = false;\n'
                                                    '\t}\n'
                                                    '}\n'
                                                    '              \n'
                                                    '              ',
                                     'display_name': 'RedundantFieldInitializer',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'Avoid using redundant field '
                                              'initializer for '
                                              "''${variableName}''"},
    'RemoteInterfaceNamingConvention': {   'categories': ['security'],
                                           'description': 'Remote Interface of '
                                                          'a Session EJB '
                                                          'should not have a '
                                                          'suffix.\n'
                                                          'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/j2ee.html#RemoteInterfaceNamingConvention\n'
                                                          '\n'
                                                          '            \n'
                                                          ' /* Poor Session '
                                                          'suffix */\n'
                                                          ' public interface '
                                                          'BadSuffixSession '
                                                          'extends '
                                                          'javax.ejb.EJBObject '
                                                          '{}\n'
                                                          '\n'
                                                          ' /* Poor EJB suffix '
                                                          '*/\n'
                                                          ' public interface '
                                                          'BadSuffixEJB '
                                                          'extends '
                                                          'javax.ejb.EJBObject '
                                                          '{}\n'
                                                          '\n'
                                                          ' /* Poor Bean '
                                                          'suffix */\n'
                                                          ' public interface '
                                                          'BadSuffixBean '
                                                          'extends '
                                                          'javax.ejb.EJBObject '
                                                          '{}\n'
                                                          '            \n'
                                                          '        ',
                                           'display_name': 'RemoteInterfaceNamingConvention',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'Remote Interface of a '
                                                    'Session EJB should NOT be '
                                                    'suffixed'},
    'RemoteSessionInterfaceNamingConvention': {   'categories': ['security'],
                                                  'description': 'A Remote '
                                                                 'Home '
                                                                 'interface '
                                                                 'type of a '
                                                                 'Session EJB '
                                                                 'should be '
                                                                 'suffixed by '
                                                                 "'Home'.\n"
                                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/j2ee.html#RemoteSessionInterfaceNamingConvention\n'
                                                                 '\n'
                                                                 '            \n'
                                                                 'public '
                                                                 'interface '
                                                                 'MyBeautifulHome '
                                                                 'extends '
                                                                 'javax.ejb.EJBHome '
                                                                 '{}\t\t// '
                                                                 'proper name\n'
                                                                 '\n'
                                                                 'public '
                                                                 'interface '
                                                                 'MissingProperSuffix '
                                                                 'extends '
                                                                 'javax.ejb.EJBHome '
                                                                 '{}\t// '
                                                                 'non-standard '
                                                                 'name\n'
                                                                 '            \n'
                                                                 '        ',
                                                  'display_name': 'RemoteSessionInterfaceNamingConvention',
                                                  'file': '%(issue.file)s',
                                                  'line': '%(issue.line)s',
                                                  'severity': '1',
                                                  'title': 'Remote Home '
                                                           'interface of a '
                                                           'Session EJB should '
                                                           'be suffixed by '
                                                           "'Home'"},
    'ReplaceEnumerationWithIterator': {   'categories': ['security'],
                                          'description': 'Consider replacing '
                                                         'Enumeration usages '
                                                         'with the newer '
                                                         'java.util.Iterator\n'
                                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/migrating.html#ReplaceEnumerationWithIterator\n'
                                                         '\n'
                                                         '    \n'
                                                         'public class Foo '
                                                         'implements '
                                                         'Enumeration {\n'
                                                         '    private int x = '
                                                         '42;\n'
                                                         '    public boolean '
                                                         'hasMoreElements() {\n'
                                                         '        return '
                                                         'true;\n'
                                                         '    }\n'
                                                         '    public Object '
                                                         'nextElement() {\n'
                                                         '        return '
                                                         'String.valueOf(i++);\n'
                                                         '    }\n'
                                                         '}\n'
                                                         '    \n'
                                                         '      ',
                                          'display_name': 'ReplaceEnumerationWithIterator',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'Consider replacing this '
                                                   'Enumeration with the newer '
                                                   'java.util.Iterator'},
    'ReplaceHashtableWithMap': {   'categories': ['security'],
                                   'description': 'Consider replacing '
                                                  'Hashtable usage with the '
                                                  'newer java.util.Map if '
                                                  'thread safety is not '
                                                  'required.\n'
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/migrating.html#ReplaceHashtableWithMap\n'
                                                  '\n'
                                                  '    \n'
                                                  'public class Foo {\n'
                                                  '\tvoid bar() {\n'
                                                  '\t\tHashtable h = new '
                                                  'Hashtable();\n'
                                                  '\t}\n'
                                                  '}\n'
                                                  '    \n'
                                                  '      ',
                                   'display_name': 'ReplaceHashtableWithMap',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'Consider replacing this Hashtable '
                                            'with the newer java.util.Map'},
    'ReplaceVectorWithList': {   'categories': ['security'],
                                 'description': 'Consider replacing Vector '
                                                'usages with the newer '
                                                'java.util.ArrayList if '
                                                'expensive thread-safe '
                                                'operations are not required.\n'
                                                'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/migrating.html#ReplaceVectorWithList\n'
                                                '\n'
                                                '\n'
                                                'public class Foo {\n'
                                                ' void bar() {\n'
                                                '    Vector v = new Vector();\n'
                                                ' }\n'
                                                '}\n'
                                                '\n'
                                                '  ',
                                 'display_name': 'ReplaceVectorWithList',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'Consider replacing this Vector with '
                                          'the newer java.util.List'},
    'ReturnEmptyArrayRatherThanNull': {   'categories': ['security'],
                                          'description': 'For any method that '
                                                         'returns an array, it '
                                                         'is a better to '
                                                         'return an empty '
                                                         'array rather than a '
                                                         'null reference. This '
                                                         'removes the need for '
                                                         'null checking all '
                                                         'results and avoids '
                                                         'inadvertent '
                                                         'NullPointerExceptions.\n'
                                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#ReturnEmptyArrayRatherThanNull\n'
                                                         '\n'
                                                         'public class Example '
                                                         '{\n'
                                                         '    // Not a good '
                                                         'idea...\n'
                                                         '    public int[] '
                                                         'badBehavior() {\n'
                                                         '                   '
                                                         '// ...\n'
                                                         '        return '
                                                         'null;\n'
                                                         '    }\n'
                                                         '\n'
                                                         '    // Good '
                                                         'behavior\n'
                                                         '    public String[] '
                                                         'bonnePratique() {\n'
                                                         '      //...\n'
                                                         '     return new '
                                                         'String[0];\n'
                                                         '    }\n'
                                                         '}\n'
                                                         '            ',
                                          'display_name': 'ReturnEmptyArrayRatherThanNull',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'Return an empty array '
                                                   "rather than 'null'."},
    'ReturnFromFinallyBlock': {   'categories': ['security'],
                                  'description': 'Avoid returning from a '
                                                 'finally block, this can '
                                                 'discard exceptions.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#ReturnFromFinallyBlock\n'
                                                 '\n'
                                                 '  \n'
                                                 'public class Bar {\n'
                                                 '\tpublic String foo() {\n'
                                                 '\t\ttry {\n'
                                                 '\t\t\tthrow new Exception( '
                                                 '"My Exception" );\n'
                                                 '\t\t} catch (Exception e) {\n'
                                                 '\t\t\tthrow e;\n'
                                                 '\t\t} finally {\n'
                                                 '\t\t\treturn "A. O. K."; // '
                                                 'return not recommended here\n'
                                                 '\t\t}\n'
                                                 '\t}\n'
                                                 '}\n'
                                                 '\n'
                                                 '      ',
                                  'display_name': 'ReturnFromFinallyBlock',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'Avoid returning from a finally '
                                           'block'},
    'ScopeForInVariable': {   'categories': ['security'],
                              'description': 'A for-in loop in which the '
                                             'variable name is not explicitly '
                                             'scoped to the enclosing scope '
                                             "with the 'var' keyword can refer "
                                             'to a variable in an enclosing '
                                             'scope outside the nearest '
                                             'enclosing scope. This will '
                                             'overwrite the existing value of '
                                             'the variable in the outer scope '
                                             'when the body of the for-in is '
                                             'evaluated. When the for-in loop '
                                             'has finished, the variable will '
                                             'contain the last value used in '
                                             'the for-in, and the original '
                                             'value from before the for-in '
                                             'loop will be gone. Since the '
                                             'for-in variable name is most '
                                             'likely intended to be a '
                                             'temporary name, it is better to '
                                             'explicitly scope the variable '
                                             'name to the nearest enclosing '
                                             "scope with 'var'.\n"
                                             'https://pmd.github.io/pmd-5.8.1/pmd-javascript/rules/ecmascript/basic.html#ScopeForInVariable\n'
                                             '\n'
                                             '  \n'
                                             '// Ok\n'
                                             'function foo() {\n'
                                             "   var p = 'clean';\n"
                                             '   function() {\n'
                                             "\t   var obj = { dirty: 'dirty' "
                                             '};\n'
                                             '\t   for (var p in obj) { // Use '
                                             "'var' here.\n"
                                             '\t     obj[p] = obj[p];\n'
                                             '\t   }\n'
                                             '\t   return x;\n'
                                             '   }();\n'
                                             '\n'
                                             "   // 'p' still has value of "
                                             "'clean'.\n"
                                             '}\n'
                                             '// Bad\n'
                                             'function bar() {\n'
                                             "   var p = 'clean';\n"
                                             '   function() {\n'
                                             "\t   var obj = { dirty: 'dirty' "
                                             '};\n'
                                             '\t   for (p in obj) { // Oh no, '
                                             "missing 'var' here!\n"
                                             '\t     obj[p] = obj[p];\n'
                                             '\t   }\n'
                                             '\t   return x;\n'
                                             '   }();\n'
                                             '\n'
                                             "   // 'p' is trashed and has "
                                             "value of 'dirty'!\n"
                                             '}\n'
                                             '\n'
                                             '      ',
                              'display_name': 'ScopeForInVariable',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': "The for-in loop variable ''{0}'' "
                                       "should be explicitly scoped with 'var' "
                                       'to avoid pollution.'},
    'ShortClassName': {   'categories': ['security'],
                          'description': 'Short Classnames with fewer than '
                                         'e.g. five characters are not '
                                         'recommended.\n'
                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#ShortClassName\n'
                                         '\n'
                                         '    \n'
                                         'public class Foo {\n'
                                         '}\n'
                                         '    \n'
                                         '        ',
                          'display_name': 'ShortClassName',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'Avoid short class names like {0}'},
    'ShortInstantiation': {   'categories': ['security'],
                              'description': 'Calling new Short() causes '
                                             'memory allocation that can be '
                                             'avoided by the static '
                                             'Short.valueOf(). It makes use of '
                                             'an internal cache that recycles '
                                             'earlier instances making it more '
                                             'memory efficient.\n'
                                             'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/migrating.html#ShortInstantiation\n'
                                             '\n'
                                             '\n'
                                             'public class Foo {\n'
                                             '\tprivate Short i = new '
                                             'Short(0); // change to Short i = '
                                             'Short.valueOf(0);\n'
                                             '}\n'
                                             '\n'
                                             '          ',
                              'display_name': 'ShortInstantiation',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'Avoid instantiating Short objects. '
                                       'Call Short.valueOf() instead'},
    'ShortMethodName': {   'categories': ['security'],
                           'description': 'Method names that are very short '
                                          'are not helpful to the reader.\n'
                                          'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#ShortMethodName\n'
                                          '\n'
                                          '\n'
                                          'public class ShortMethod {\n'
                                          '\tpublic void a( int i ) { // '
                                          'Violation\n'
                                          '\t}\n'
                                          '}\n'
                                          '\n'
                                          '     ',
                           'display_name': 'ShortMethodName',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'Avoid using short method names'},
    'ShortVariable': {   'categories': ['security'],
                         'description': 'Fields, local variables, or parameter '
                                        'names that are very short are not '
                                        'helpful to the reader.\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#ShortVariable\n'
                                        '\n'
                                        '\n'
                                        'public class Something {\n'
                                        '    private int q = '
                                        '15;                         // field '
                                        '- too short\n'
                                        '    public static void main( String '
                                        'as[] ) {    // formal arg - too '
                                        'short\n'
                                        '        int r = 20 + '
                                        'q;                         // local '
                                        'var - too short\n'
                                        '        for (int i = 0; i < 10; i++) '
                                        '{          // not a violation (inside '
                                        "'for' loop)\n"
                                        '            r += q;\n'
                                        '        }\n'
                                        '        for (Integer i : numbers) '
                                        '{             // not a violation '
                                        "(inside 'for-each' loop)\n"
                                        '            r += q;\n'
                                        '        }\n'
                                        '    }\n'
                                        '}\n'
                                        '\n'
                                        '    ',
                         'display_name': 'ShortVariable',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Avoid variables with short names like {0}'},
    'SignatureDeclareThrowsException': {   'categories': ['security'],
                                           'description': 'It is unclear which '
                                                          'exceptions that can '
                                                          'be thrown from the '
                                                          'methods. It might '
                                                          'be difficult to '
                                                          'document and '
                                                          'understand the '
                                                          'vague interfaces. '
                                                          'Use either a class '
                                                          'derived from '
                                                          'RuntimeException or '
                                                          'a checked '
                                                          'exception. JUnit '
                                                          'classes are '
                                                          'excluded.\n'
                                                          'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/typeresolution.html#SignatureDeclareThrowsException\n'
                                                          '\n'
                                                          '      \t\n'
                                                          'public void '
                                                          'methodThrowingException() '
                                                          'throws Exception {\n'
                                                          '}\n'
                                                          '      \t\n'
                                                          '      ',
                                           'display_name': 'SignatureDeclareThrowsException',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'A method/constructor '
                                                    "shouldn't explicitly "
                                                    'throw '
                                                    'java.lang.Exception'},
    'SimpleDateFormatNeedsLocale': {   'categories': ['security'],
                                       'description': 'Be sure to specify a '
                                                      'Locale when creating '
                                                      'SimpleDateFormat '
                                                      'instances to ensure '
                                                      'that locale-appropriate '
                                                      'formatting is used.\n'
                                                      'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#SimpleDateFormatNeedsLocale\n'
                                                      '\n'
                                                      '        \n'
                                                      'public class Foo {\n'
                                                      '  // Should specify '
                                                      'Locale.US (or '
                                                      'whatever)\n'
                                                      '  private '
                                                      'SimpleDateFormat sdf = '
                                                      'new '
                                                      'SimpleDateFormat("pattern");\n'
                                                      '}\n'
                                                      '        \n'
                                                      '        ',
                                       'display_name': 'SimpleDateFormatNeedsLocale',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'When instantiating a '
                                                'SimpleDateFormat object, '
                                                'specify a Locale'},
    'SimplifiedTernary': {   'categories': ['security'],
                             'description': 'Look for ternary operators with '
                                            'the form `condition ? '
                                            'literalBoolean : foo` or '
                                            '`condition ? foo : '
                                            'literalBoolean`. These '
                                            'expressions can be simplified '
                                            'respectively to `condition || '
                                            'foo` when the literalBoolean is '
                                            'true `!condition && foo` when the '
                                            'literalBoolean is false or '
                                            '`!condition || foo` when the '
                                            'literalBoolean is true `condition '
                                            '&& foo` when the literalBoolean '
                                            'is false\n'
                                            'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#SimplifiedTernary\n'
                                            '\n'
                                            '        \n'
                                            'public class Foo {\n'
                                            '    public boolean test() {\n'
                                            '        return condition ? true : '
                                            'something(); // can be as simple '
                                            'as return condition || '
                                            'something();\n'
                                            '    }\n'
                                            '\n'
                                            '    public void test2() {\n'
                                            '        final boolean value = '
                                            'condition ? false : something(); '
                                            '// can be as simple as value = '
                                            '!condition && something();\n'
                                            '    }\n'
                                            '\n'
                                            '    public boolean test3() {\n'
                                            '        return condition ? '
                                            'something() : true; // can be as '
                                            'simple as return !condition || '
                                            'something();\n'
                                            '    }\n'
                                            '\n'
                                            '    public void test4() {\n'
                                            '        final boolean otherValue '
                                            '= condition ? something() : '
                                            'false; // can be as simple as '
                                            'condition && something();\n'
                                            '    }\n'
                                            '}\n'
                                            '        \n'
                                            '    ',
                             'display_name': 'SimplifiedTernary',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Ternary operators that can be '
                                      'simplified with || or &&'},
    'SimplifyBooleanAssertion': {   'categories': ['security'],
                                    'description': 'Avoid negation in an '
                                                   'assertTrue or assertFalse '
                                                   'test. For example, '
                                                   'rephrase: '
                                                   'assertTrue(!expr); as: '
                                                   'assertFalse(expr);\n'
                                                   'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/junit.html#SimplifyBooleanAssertion\n'
                                                   '\n'
                                                   '\n'
                                                   'public class SimpleTest '
                                                   'extends TestCase {\n'
                                                   '   public void testX() {\n'
                                                   '     assertTrue("not '
                                                   'empty", !r.isEmpty()); // '
                                                   'replace with '
                                                   'assertFalse("not empty", '
                                                   'r.isEmpty())\n'
                                                   '     '
                                                   'assertFalse(!r.isEmpty()); '
                                                   '// replace with '
                                                   'assertTrue(r.isEmpty())\n'
                                                   '   }\n'
                                                   '}\n'
                                                   '\n'
                                                   '          ',
                                    'display_name': 'SimplifyBooleanAssertion',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'assertTrue(!expr) can be '
                                             'replaced by assertFalse(expr)'},
    'SimplifyBooleanExpressions': {   'categories': ['security'],
                                      'description': 'Avoid unnecessary '
                                                     'comparisons in boolean '
                                                     'expressions, they serve '
                                                     'no purpose and impacts '
                                                     'readability.\n'
                                                     'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#SimplifyBooleanExpressions\n'
                                                     '\n'
                                                     '  \n'
                                                     'public class Bar {\n'
                                                     '  // can be simplified '
                                                     'to\n'
                                                     '  // bar = isFoo();\n'
                                                     '  private boolean bar = '
                                                     '(isFoo() == true);\n'
                                                     '\n'
                                                     '  public isFoo() { '
                                                     'return false;}\n'
                                                     '}\n'
                                                     '  \n'
                                                     '      ',
                                      'display_name': 'SimplifyBooleanExpressions',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'Avoid unnecessary comparisons '
                                               'in boolean expressions'},
    'SimplifyBooleanReturns': {   'categories': ['security'],
                                  'description': 'Avoid unnecessary '
                                                 'if-then-else statements when '
                                                 'returning a boolean. The '
                                                 'result of the conditional '
                                                 'test can be returned '
                                                 'instead.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#SimplifyBooleanReturns\n'
                                                 '\n'
                                                 '\n'
                                                 'public boolean '
                                                 'isBarEqualTo(int x) {\n'
                                                 '\n'
                                                 '\tif (bar == x) {\t\t // '
                                                 'this bit of code...\n'
                                                 '\t\treturn true;\n'
                                                 '\t} else {\n'
                                                 '\t\treturn false;\n'
                                                 '    }\n'
                                                 '}\n'
                                                 '\n'
                                                 'public boolean '
                                                 'isBarEqualTo(int x) {\n'
                                                 '\n'
                                                 '   \treturn bar == x;\t// '
                                                 'can be replaced with this\n'
                                                 '}\n'
                                                 '\n'
                                                 '    ',
                                  'display_name': 'SimplifyBooleanReturns',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'Avoid unnecessary if..then..else '
                                           'statements when returning '
                                           'booleans'},
    'SimplifyConditional': {   'categories': ['security'],
                               'description': 'No need to check for null '
                                              'before an instanceof; the '
                                              'instanceof keyword returns '
                                              'false when given a null '
                                              'argument.\n'
                                              'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#SimplifyConditional\n'
                                              '\n'
                                              '      \n'
                                              'class Foo {\n'
                                              '  void bar(Object x) {\n'
                                              '    if (x != null && x '
                                              'instanceof Bar) {\n'
                                              '      // just drop the "x != '
                                              'null" check\n'
                                              '    }\n'
                                              '  }\n'
                                              '}      \n'
                                              '           ',
                               'display_name': 'SimplifyConditional',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'No need to check for null before an '
                                        'instanceof'},
    'SimplifyStartsWith': {   'categories': ['security'],
                              'description': 'Since it passes in a literal of '
                                             'length 1, calls to '
                                             '(string).startsWith can be '
                                             'rewritten using '
                                             '(string).charAt(0) at the '
                                             'expense of some readability.\n'
                                             'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/optimizations.html#SimplifyStartsWith\n'
                                             '\n'
                                             '  \n'
                                             'public class Foo {\n'
                                             '\n'
                                             '\tboolean checkIt(String x) {\n'
                                             '\t\treturn x.startsWith("a");\t'
                                             '// suboptimal\n'
                                             '\t}\n'
                                             '  \n'
                                             '\tboolean fasterCheckIt(String '
                                             'x) {\n'
                                             "\t\treturn x.charAt(0) == 'a';\t"
                                             '//\tfaster approach\n'
                                             '\t}\n'
                                             '}\n'
                                             '\n'
                                             '      ',
                              'display_name': 'SimplifyStartsWith',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'This call to String.startsWith can be '
                                       'rewritten using String.charAt(0)'},
    'SingleMethodSingleton': {   'categories': ['security'],
                                 'description': 'Some classes contain '
                                                'overloaded getInstance. The '
                                                'problem with overloaded '
                                                'getInstance methods is that '
                                                'the instance created using '
                                                'the overloaded method is not '
                                                'cached and so, for each call '
                                                'and new objects will be '
                                                'created for every '
                                                'invocation.\n'
                                                'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#SingleMethodSingleton\n'
                                                '\n'
                                                'public class Singleton {\n'
                                                '\n'
                                                '   private static Singleton '
                                                'singleton = new Singleton( '
                                                ');\n'
                                                '\n'
                                                '  private Singleton(){ }\n'
                                                '\n'
                                                'public static Singleton '
                                                'getInstance( ) {\n'
                                                '\t  return singleton;\n'
                                                '}\n'
                                                'public static Singleton '
                                                'getInstance(Object obj){\n'
                                                '\tSingleton singleton = '
                                                '(Singleton) obj;\n'
                                                '\treturn singleton;\t\t\t'
                                                '//violation\n'
                                                '}\n'
                                                '}\n'
                                                '\n',
                                 'display_name': 'SingleMethodSingleton',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'Class contains multiple getInstance '
                                          'methods. Please review.'},
    'SingletonClassReturningNewInstance': {   'categories': ['security'],
                                              'description': 'Some classes '
                                                             'contain '
                                                             'overloaded '
                                                             'getInstance. The '
                                                             'problem with '
                                                             'overloaded '
                                                             'getInstance '
                                                             'methods is that '
                                                             'the instance '
                                                             'created using '
                                                             'the overloaded '
                                                             'method is not '
                                                             'cached and so, '
                                                             'for each call '
                                                             'and new objects '
                                                             'will be created '
                                                             'for every '
                                                             'invocation.\n'
                                                             'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#SingletonClassReturningNewInstance\n'
                                                             '\n'
                                                             'class Singleton '
                                                             '{\n'
                                                             '\tprivate static '
                                                             'Singleton '
                                                             'instance = '
                                                             'null;\n'
                                                             '\tpublic static '
                                                             'Singleton '
                                                             'getInstance() {\n'
                                                             '\t'
                                                             'synchronized(Singleton.class){\n'
                                                             '\t\treturn new '
                                                             'Singleton();\n'
                                                             '\t}\n'
                                                             '\t}\n'
                                                             '}\n'
                                                             '\n',
                                              'display_name': 'SingletonClassReturningNewInstance',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '1',
                                              'title': 'getInstance method '
                                                       'always creates a new '
                                                       'object and hence does '
                                                       'not comply to '
                                                       'Singleton Design '
                                                       'Pattern behaviour. '
                                                       'Please review'},
    'SingularField': {   'categories': ['security'],
                         'description': 'Fields whose scopes are limited to '
                                        'just single methods do not rely on '
                                        'the containing object to provide them '
                                        'to other methods. They may be better '
                                        'implemented as local variables within '
                                        'those methods.\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#SingularField\n'
                                        '\n'
                                        'public class Foo {\n'
                                        '    private int x;  // no reason to '
                                        'exist at the Foo instance level\n'
                                        '    public void foo(int y) {\n'
                                        '     x = y + 5;\n'
                                        '     return x;\n'
                                        '    }\n'
                                        '}\n'
                                        '   ',
                         'display_name': 'SingularField',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': "Perhaps ''{0}'' could be replaced by a "
                                  'local variable.'},
    'StaticEJBFieldShouldBeFinal': {   'categories': ['security'],
                                       'description': 'According to the J2EE '
                                                      'specification, an EJB '
                                                      'should not have any '
                                                      'static fields with '
                                                      'write access. However, '
                                                      'static read-only fields '
                                                      'are allowed. This '
                                                      'ensures proper behavior '
                                                      'especially when '
                                                      'instances are '
                                                      'distributed by the '
                                                      'container on several '
                                                      'JREs.\n'
                                                      'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/j2ee.html#StaticEJBFieldShouldBeFinal\n'
                                                      '\n'
                                                      'public class SomeEJB '
                                                      'extends EJBObject '
                                                      'implements EJBLocalHome '
                                                      '{\n'
                                                      '\n'
                                                      '\tprivate static int '
                                                      'CountA;\t\t\t// poor, '
                                                      'field can be edited\n'
                                                      '\n'
                                                      '\tprivate static final '
                                                      'int CountB;\t// '
                                                      'preferred, read-only '
                                                      'access\n'
                                                      '}\n'
                                                      '     ',
                                       'display_name': 'StaticEJBFieldShouldBeFinal',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': "EJB's shouldn't have "
                                                'non-final static fields'},
    'StdCyclomaticComplexity': {   'categories': ['security'],
                                   'description': 'Complexity directly affects '
                                                  'maintenance costs is '
                                                  'determined by the number of '
                                                  'decision points in a method '
                                                  'plus one for the method '
                                                  'entry. The decision points '
                                                  "include 'if', 'while', "
                                                  "'for', and 'case labels' "
                                                  'calls. Generally, numbers '
                                                  'ranging from 1-4 denote low '
                                                  'complexity, 5-7 denote '
                                                  'moderate complexity, 8-10 '
                                                  'denote high complexity, and '
                                                  '11+ is very high '
                                                  'complexity.\n'
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/codesize.html#StdCyclomaticComplexity\n'
                                                  '\n'
                                                  '\n'
                                                  'public class Foo {    // '
                                                  'This has a Cyclomatic '
                                                  'Complexity = 12\n'
                                                  '1   public void example()  '
                                                  '{\n'
                                                  '2       if (a == b || (c == '
                                                  'd && e == f))  { // Only '
                                                  'one\n'
                                                  '3           if (a1 == b1) '
                                                  '{\n'
                                                  '                fiddle();\n'
                                                  '4           } else if a2 == '
                                                  'b2) {\n'
                                                  '                fiddle();\n'
                                                  '            }  else {\n'
                                                  '                fiddle();\n'
                                                  '            }\n'
                                                  '5       } else if (c == d) '
                                                  '{\n'
                                                  '6           while (c == d) '
                                                  '{\n'
                                                  '                fiddle();\n'
                                                  '            }\n'
                                                  '7        } else if (e == f) '
                                                  '{\n'
                                                  '8           for (int n = 0; '
                                                  'n < h; n++) {\n'
                                                  '                fiddle();\n'
                                                  '            }\n'
                                                  '        } else{\n'
                                                  '            switch (z) {\n'
                                                  '9               case 1:\n'
                                                  '                    '
                                                  'fiddle();\n'
                                                  '                    break;\n'
                                                  '10              case 2:\n'
                                                  '                    '
                                                  'fiddle();\n'
                                                  '                    break;\n'
                                                  '11              case 3:\n'
                                                  '                    '
                                                  'fiddle();\n'
                                                  '                    break;\n'
                                                  '12              default:\n'
                                                  '                    '
                                                  'fiddle();\n'
                                                  '                    break;\n'
                                                  '            }\n'
                                                  '        }\n'
                                                  '    }\n'
                                                  '}\n'
                                                  '\n'
                                                  '   ',
                                   'display_name': 'StdCyclomaticComplexity',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': "The {0} ''{1}'' has a Standard "
                                            'Cyclomatic Complexity of {2}.'},
    'StringBufferInstantiationWithChar': {   'categories': ['security'],
                                             'description': 'Individual '
                                                            'character values '
                                                            'provided as '
                                                            'initialization '
                                                            'arguments will be '
                                                            'converted into '
                                                            'integers. This '
                                                            'can lead to '
                                                            'internal buffer '
                                                            'sizes that are '
                                                            'larger than '
                                                            'expected. Some '
                                                            'examples: new '
                                                            'StringBuffer() // '
                                                            '16 new '
                                                            'StringBuffer(6) '
                                                            '// 6 new '
                                                            'StringBuffer("hello '
                                                            'world") // 11 + '
                                                            '16 = 27 new '
                                                            "StringBuffer('A') "
                                                            '// chr(A) = 65 '
                                                            'new '
                                                            'StringBuffer("A") '
                                                            '// 1 + 16 = 17 '
                                                            'new '
                                                            'StringBuilder() '
                                                            '// 16 new '
                                                            'StringBuilder(6) '
                                                            '// 6 new '
                                                            'StringBuilder("hello '
                                                            'world") // 11 + '
                                                            '16 = 27 new '
                                                            "StringBuilder('C') "
                                                            '// chr(C) = 67 '
                                                            'new '
                                                            'StringBuilder("A") '
                                                            '// 1 + 16 = 17\n'
                                                            'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strings.html#StringBufferInstantiationWithChar\n'
                                                            '\n'
                                                            '\n'
                                                            '\t// misleading '
                                                            'instantiation, '
                                                            'these buffers\n'
                                                            '\t// are actually '
                                                            'sized to 99 '
                                                            'characters long\n'
                                                            'StringBuffer  sb1 '
                                                            '= new '
                                                            "StringBuffer('c');   \n"
                                                            'StringBuilder sb2 '
                                                            '= new '
                                                            "StringBuilder('c');\n"
                                                            '  \n'
                                                            '// in these '
                                                            'forms, just '
                                                            'single characters '
                                                            'are allocated\n'
                                                            'StringBuffer  sb3 '
                                                            '= new '
                                                            'StringBuffer("c");\n'
                                                            'StringBuilder sb4 '
                                                            '= new '
                                                            'StringBuilder("c");\n'
                                                            '\n'
                                                            '    ',
                                             'display_name': 'StringBufferInstantiationWithChar',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': 'Do not instantiate a '
                                                      'StringBuffer or '
                                                      'StringBuilder with a '
                                                      'char'},
    'StringInstantiation': {   'categories': ['security'],
                               'description': 'Avoid instantiating String '
                                              'objects; this is usually '
                                              'unnecessary since they are '
                                              'immutable and can be safely '
                                              'shared.\n'
                                              'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strings.html#StringInstantiation\n'
                                              '\n'
                                              '\n'
                                              'private String bar = new '
                                              'String("bar"); // just do a '
                                              'String bar = "bar";\n'
                                              '\n'
                                              '    ',
                               'display_name': 'StringInstantiation',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Avoid instantiating String objects; '
                                        'this is usually unnecessary.'},
    'StringToString': {   'categories': ['security'],
                          'description': 'Avoid calling toString() on objects '
                                         'already known to be string '
                                         'instances; this is unnecessary.\n'
                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strings.html#StringToString\n'
                                         '\n'
                                         '\n'
                                         'private String baz() {\n'
                                         '    String bar = "howdy";\n'
                                         '    return bar.toString();\n'
                                         '}\n'
                                         '\n'
                                         '    ',
                          'display_name': 'StringToString',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'Avoid calling toString() on String '
                                   'objects; this is unnecessary.'},
    'SuspiciousConstantFieldName': {   'categories': ['security'],
                                       'description': 'Field names using all '
                                                      'uppercase characters - '
                                                      "Sun's Java naming "
                                                      'conventions indicating '
                                                      'constants - should be '
                                                      'declared as final.\n'
                                                      'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#SuspiciousConstantFieldName\n'
                                                      '\n'
                                                      '    \n'
                                                      'public class Foo {\n'
                                                      ' // this is bad, since '
                                                      'someone could '
                                                      'accidentally\n'
                                                      ' // do PI = 2.71828; '
                                                      'which is actually e\n'
                                                      ' // final double PI = '
                                                      '3.16; is ok\n'
                                                      '  double PI = 3.16;\n'
                                                      '}\n'
                                                      '    \n'
                                                      '       ',
                                       'display_name': 'SuspiciousConstantFieldName',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'The field name indicates a '
                                                'constant but its modifiers do '
                                                'not'},
    'SuspiciousEqualsMethodName': {   'categories': ['security'],
                                      'description': 'The method name and '
                                                     'parameter number are '
                                                     'suspiciously close to '
                                                     'equals(Object), which '
                                                     'can denote an intention '
                                                     'to override the '
                                                     'equals(Object) method.\n'
                                                     'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#SuspiciousEqualsMethodName\n'
                                                     '\n'
                                                     'public class Foo {\n'
                                                     '   public int '
                                                     'equals(Object o) {\n'
                                                     '     // oops, this '
                                                     'probably was supposed to '
                                                     'be boolean equals\n'
                                                     '   }\n'
                                                     '   public boolean '
                                                     'equals(String s) {\n'
                                                     '     // oops, this '
                                                     'probably was supposed to '
                                                     'be equals(Object)\n'
                                                     '   }\n'
                                                     '   public boolean '
                                                     'equals(Object o1, Object '
                                                     'o2) {\n'
                                                     '     // oops, this '
                                                     'probably was supposed to '
                                                     'be equals(Object)\n'
                                                     '   }\n'
                                                     '}\n'
                                                     '        ',
                                      'display_name': 'SuspiciousEqualsMethodName',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'The method name and parameter '
                                               'number are suspiciously close '
                                               'to equals(Object)'},
    'SuspiciousHashcodeMethodName': {   'categories': ['security'],
                                        'description': 'The method name and '
                                                       'return type are '
                                                       'suspiciously close to '
                                                       'hashCode(), which may '
                                                       'denote an intention to '
                                                       'override the '
                                                       'hashCode() method.\n'
                                                       'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#SuspiciousHashcodeMethodName\n'
                                                       '\n'
                                                       '    \n'
                                                       'public class Foo {\n'
                                                       '\tpublic int '
                                                       'hashcode() {\t// oops, '
                                                       'this probably was '
                                                       'supposed to be '
                                                       "'hashCode'\n"
                                                       '\t\n'
                                                       '\t}\n'
                                                       '}\n'
                                                       '    \n'
                                                       '       ',
                                        'display_name': 'SuspiciousHashcodeMethodName',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'The method name and return '
                                                 'type are suspiciously close '
                                                 'to hashCode()'},
    'SuspiciousOctalEscape': {   'categories': ['security'],
                                 'description': 'A suspicious octal escape '
                                                'sequence was found inside a '
                                                'String literal. The Java '
                                                'language specification '
                                                '(section 3.10.6) says an '
                                                'octal escape sequence inside '
                                                'a literal String shall '
                                                'consist of a backslash '
                                                'followed by: OctalDigit | '
                                                'OctalDigit OctalDigit | '
                                                'ZeroToThree OctalDigit '
                                                'OctalDigit Any octal escape '
                                                'sequence followed by '
                                                'non-octal digits can be '
                                                'confusing, e.g. "\\038" is '
                                                'interpreted as the octal '
                                                'escape sequence "\\03" '
                                                'followed by the literal '
                                                'character "8".\n'
                                                'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#SuspiciousOctalEscape\n'
                                                '\n'
                                                '\n'
                                                'public void foo() {\n'
                                                '  // interpreted as octal 12, '
                                                "followed by character '8'\n"
                                                '  '
                                                'System.out.println("suspicious: '
                                                '\\128");\n'
                                                '}\n'
                                                '\n'
                                                '      ',
                                 'display_name': 'SuspiciousOctalEscape',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'Suspicious decimal characters '
                                          'following octal escape in string '
                                          'literal'},
    'SwitchDensity': {   'categories': ['security'],
                         'description': 'A high ratio of statements to labels '
                                        'in a switch statement implies that '
                                        'the switch statement is overloaded. '
                                        'Consider moving the statements into '
                                        'new methods or creating subclasses '
                                        'based on the switch variable.\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#SwitchDensity\n'
                                        '\n'
                                        ' \n'
                                        'public class Foo {\n'
                                        '  public void bar(int x) {\n'
                                        '    switch (x) {\n'
                                        '      case 1: {\n'
                                        '        // lots of statements\n'
                                        '        break;\n'
                                        '      } case 2: {\n'
                                        '        // lots of statements\n'
                                        '        break;\n'
                                        '      }\n'
                                        '    }\n'
                                        '  }\n'
                                        '}\n'
                                        ' \n'
                                        '      ',
                         'display_name': 'SwitchDensity',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'A high ratio of statements to labels in a '
                                  'switch statement.  Consider refactoring.'},
    'SwitchStmtsShouldHaveDefault': {   'categories': ['security'],
                                        'description': 'All switch statements '
                                                       'should include a '
                                                       'default option to '
                                                       'catch any unspecified '
                                                       'values.\n'
                                                       'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#SwitchStmtsShouldHaveDefault\n'
                                                       '\n'
                                                       '\n'
                                                       'public void bar() {\n'
                                                       '    int x = 2;\n'
                                                       '    switch (x) {\n'
                                                       '      case 1: int j = '
                                                       '6;\n'
                                                       '      case 2: int j = '
                                                       '8;\n'
                                                       '      \t\t\t\t// '
                                                       'missing default: here\n'
                                                       '    }\n'
                                                       '}\n'
                                                       '\n'
                                                       '    ',
                                        'display_name': 'SwitchStmtsShouldHaveDefault',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'Switch statements should '
                                                 'have a default label'},
    'SystemPrintln': {   'categories': ['security'],
                         'description': 'References to System.(out|err).print '
                                        'are usually intended for debugging '
                                        'purposes and can remain in the '
                                        'codebase even in production code. By '
                                        'using a logger one can enable/disable '
                                        'this behaviour at will (and by '
                                        'priority) and avoid clogging the '
                                        'Standard out log.\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/logging-java.html#SystemPrintln\n'
                                        '\n'
                                        ' \n'
                                        'class Foo{\n'
                                        '    Logger log = '
                                        'Logger.getLogger(Foo.class.getName());\n'
                                        '    public void testA () {\n'
                                        '        System.out.println("Entering '
                                        'test");\n'
                                        '        // Better use this\n'
                                        '        log.fine("Entering test");\n'
                                        '    }\n'
                                        '}\n'
                                        '\n'
                                        '     ',
                         'display_name': 'SystemPrintln',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': '{0} is used'},
    'TO_DATEWithoutDateFormat': {   'categories': ['security'],
                                    'description': 'TO_DATE without date '
                                                   'format- use '
                                                   'TO_DATE(expression, '
                                                   'date-format)\n'
                                                   'https://pmd.github.io/pmd-5.8.1/pmd-plsql/rules/plsql/dates.html#TO_DATEWithoutDateFormat\n'
                                                   '\n'
                                                   '\n'
                                                   'CREATE OR REPLACE PACKAGE '
                                                   'BODY date_utilities\n'
                                                   'IS\n'
                                                   ' \n'
                                                   '-- Take single parameter, '
                                                   'relyimg on current default '
                                                   'NLS date format \n'
                                                   'FUNCTION '
                                                   'to_date_single_parameter '
                                                   '(p_date_string IN '
                                                   'VARCHAR2) RETURN DATE\n'
                                                   'IS\n'
                                                   'BEGIN\n'
                                                   '   RETURN '
                                                   'TO_DATE(p_date_string); \n'
                                                   'END '
                                                   'to_date_single_parameter '
                                                   ';\n'
                                                   '\n'
                                                   '-- Take 2 parameters, '
                                                   'using an explicit date '
                                                   'format string  \n'
                                                   'FUNCTION '
                                                   'to_date_two_parameters '
                                                   '(p_date_string IN '
                                                   'VARCHAR2, p_format_mask IN '
                                                   'VARCHAR2) RETURN DATE\n'
                                                   'IS\n'
                                                   'BEGIN\n'
                                                   '   TO_DATE(p_date_string, '
                                                   'p_date_format); \n'
                                                   'END to_date_two_parameters '
                                                   ';\n'
                                                   '\n'
                                                   '-- Take 3 parameters, '
                                                   'using an explicit date '
                                                   'format string and an '
                                                   'explicit language    \n'
                                                   'FUNCTION '
                                                   'to_date_three_parameters '
                                                   '(p_date_string IN '
                                                   'VARCHAR2, p_format_mask IN '
                                                   'VARCHAR2, p_nls_language '
                                                   'VARCHAR2 ) RETURN DATE\n'
                                                   'IS\n'
                                                   'BEGIN\n'
                                                   '   TO_DATE(p_date_string, '
                                                   'p_format_mask, '
                                                   'p_nls_language); \n'
                                                   'END '
                                                   'to_date_three_parameters '
                                                   ';\n'
                                                   '\n'
                                                   'END date_utilities ;\n'
                                                   '/\n'
                                                   '\n'
                                                   '  ',
                                    'display_name': 'TO_DATEWithoutDateFormat',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'TO_DATE without date format'},
    'TO_DATE_TO_CHAR': {   'categories': ['security'],
                           'description': 'TO_DATE(TO_CHAR(date-variable)) '
                                          'used to remove time component - use '
                                          'TRUNC(date-veriable)\n'
                                          'https://pmd.github.io/pmd-5.8.1/pmd-plsql/rules/plsql/dates.html#TO_DATE_TO_CHAR\n'
                                          '\n'
                                          '\n'
                                          'CREATE OR REPLACE PACKAGE BODY '
                                          'date_utilities\n'
                                          'IS\n'
                                          ' \n'
                                          '-- Take single parameter, relyimg '
                                          'on current default NLS date '
                                          'format \n'
                                          'FUNCTION strip_time (p_date IN '
                                          'DATE) RETURN DATE\n'
                                          'IS\n'
                                          'BEGIN\n'
                                          '   RETURN '
                                          'TO_DATE(TO_CHAR(p_date)); \n'
                                          'END strip_time ;\n'
                                          '\n'
                                          '\n'
                                          'END date_utilities ;\n'
                                          '/\n'
                                          '\n'
                                          '  ',
                           'display_name': 'TO_DATE_TO_CHAR',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'TO_DATE(TO_CHAR(variable)) instead of '
                                    'TRUNC(variable)'},
    'TO_TIMESTAMPWithoutDateFormat': {   'categories': ['security'],
                                         'description': 'TO_TIMESTAMP without '
                                                        'date format- use '
                                                        'TO_TIMESTAMP(expression, '
                                                        'date-format)\n'
                                                        'https://pmd.github.io/pmd-5.8.1/pmd-plsql/rules/plsql/dates.html#TO_TIMESTAMPWithoutDateFormat\n'
                                                        '\n'
                                                        '\n'
                                                        'CREATE OR REPLACE '
                                                        'PACKAGE BODY '
                                                        'date_utilities\n'
                                                        'IS\n'
                                                        ' \n'
                                                        '-- Take single '
                                                        'parameter, relyimg on '
                                                        'current default NLS '
                                                        'date format \n'
                                                        'FUNCTION '
                                                        'to_timestamp_single_parameter '
                                                        '(p_date_string IN '
                                                        'VARCHAR2) RETURN '
                                                        'DATE\n'
                                                        'IS\n'
                                                        'BEGIN\n'
                                                        '   RETURN '
                                                        'TO_TIMESTAMP(p_date_string); \n'
                                                        'END '
                                                        'to_timestamp_single_parameter '
                                                        ';\n'
                                                        '\n'
                                                        '-- Take 2 parameters, '
                                                        'using an explicit '
                                                        'date format string  \n'
                                                        'FUNCTION '
                                                        'to_timestamp_two_parameters '
                                                        '(p_date_string IN '
                                                        'VARCHAR2, '
                                                        'p_format_mask IN '
                                                        'VARCHAR2) RETURN '
                                                        'DATE\n'
                                                        'IS\n'
                                                        'BEGIN\n'
                                                        '   '
                                                        'TO_TIMESTAMP(p_date_string, '
                                                        'p_date_format); \n'
                                                        'END '
                                                        'to_timestamp_two_parameters '
                                                        ';\n'
                                                        '\n'
                                                        '-- Take 3 parameters, '
                                                        'using an explicit '
                                                        'date format string '
                                                        'and an explicit '
                                                        'language    \n'
                                                        'FUNCTION '
                                                        'to_timestamp_three_parameters '
                                                        '(p_date_string IN '
                                                        'VARCHAR2, '
                                                        'p_format_mask IN '
                                                        'VARCHAR2, '
                                                        'p_nls_language '
                                                        'VARCHAR2 ) RETURN '
                                                        'DATE\n'
                                                        'IS\n'
                                                        'BEGIN\n'
                                                        '   '
                                                        'TO_TIMESTAMP(p_date_string, '
                                                        'p_format_mask, '
                                                        'p_nls_language); \n'
                                                        'END '
                                                        'to_timestamp_three_parameters '
                                                        ';\n'
                                                        '\n'
                                                        'END date_utilities ;\n'
                                                        '/\n'
                                                        '\n'
                                                        '  ',
                                         'display_name': 'TO_TIMESTAMPWithoutDateFormat',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'TO_TIMESTAMP without date '
                                                  'format'},
    'TestClassWithoutTestCases': {   'categories': ['security'],
                                     'description': 'Test classes end with the '
                                                    'suffix Test. Having a '
                                                    'non-test class with that '
                                                    'name is not a good '
                                                    'practice, since most '
                                                    'people will assume it is '
                                                    'a test case. Test classes '
                                                    'have test methods named '
                                                    'testXXX.\n'
                                                    'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/junit.html#TestClassWithoutTestCases\n'
                                                    '\n'
                                                    '\n'
                                                    '//Consider changing the '
                                                    'name of the class if it '
                                                    'is not a test\n'
                                                    '//Consider adding test '
                                                    'methods if it is a test\n'
                                                    'public class CarTest {\n'
                                                    '   public static void '
                                                    'main(String[] args) {\n'
                                                    '    // do something\n'
                                                    '   }\n'
                                                    '   // code\n'
                                                    '}\n'
                                                    '\n'
                                                    '      ',
                                     'display_name': 'TestClassWithoutTestCases',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'This class name ends with '
                                              "'Test' but contains no test "
                                              'cases'},
    'TomKytesDespair': {   'categories': ['security'],
                           'description': '"WHEN OTHERS THEN NULL" hides all '
                                          'errors - (Re)RAISE an exception or '
                                          'call RAISE_APPLICATION_ERROR\n'
                                          'https://pmd.github.io/pmd-5.8.1/pmd-plsql/rules/plsql/TomKytesDespair.html#TomKytesDespair\n'
                                          '\n'
                                          '\n'
                                          'CREATE OR REPLACE PACKAGE BODY '
                                          'update_planned_hrs\n'
                                          'IS\n'
                                          ' \n'
                                          'PROCEDURE set_new_planned (p_emp_id '
                                          'IN NUMBER, p_project_id IN NUMBER, '
                                          'p_hours IN NUMBER)\n'
                                          'IS\n'
                                          'BEGIN\n'
                                          '   UPDATE employee_on_activity ea\n'
                                          '   SET ea.ea_planned_hours = '
                                          'p_hours\n'
                                          '   WHERE\n'
                                          '            ea.ea_emp_id = '
                                          'p_emp_id            \n'
                                          '            AND ea.ea_proj_id = '
                                          'p_project_id;\n'
                                          ' \n'
                                          'EXCEPTION\n'
                                          '          WHEN NO_DATA_FOUND THEN\n'
                                          '           RAISE_APPLICATION_ERROR '
                                          "(-20100, 'No such employee or "
                                          "project');\n"
                                          ' \n'
                                          'END set_new_planned;\n'
                                          ' \n'
                                          'FUNCTION existing_planned (p_emp_id '
                                          'IN NUMBER, p_project_id IN NUMBER) '
                                          'RETURN NUMBER\n'
                                          ' \n'
                                          'IS\n'
                                          ' \n'
                                          'existing_hours NUMBER(4);\n'
                                          ' \n'
                                          'BEGIN\n'
                                          '   SELECT ea.ea_planned_hours INTO '
                                          'existing_hours \n'
                                          '   FROM employee_on_activity ea\n'
                                          '   WHERE\n'
                                          '            ea.ea_emp_id = '
                                          'p_emp_id     \n'
                                          '            AND ea.ea_proj_id = '
                                          'p_project_id; \n'
                                          ' \n'
                                          '   RETURN (existing_hours);\n'
                                          ' \n'
                                          '   EXCEPTION\n'
                                          '          WHEN OTHERS THEN NULL;\n'
                                          ' \n'
                                          '   END existing_planned;\n'
                                          ' \n'
                                          'END update_planned_hrs;\n'
                                          '/\n'
                                          '\n'
                                          '  ',
                           'display_name': 'TomKytesDespair',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'WHEN OTHERS THEN NULL - when you do this, '
                                    'Tom Kyte cries'},
    'TooFewBranchesForASwitchStatement': {   'categories': ['security'],
                                             'description': 'Switch statements '
                                                            'are indended to '
                                                            'be used to '
                                                            'support complex '
                                                            'branching '
                                                            'behaviour. Using '
                                                            'a switch for only '
                                                            'a few cases is '
                                                            'ill-advised, '
                                                            'since switches '
                                                            'are not as easy '
                                                            'to understand as '
                                                            'if-then '
                                                            'statements. In '
                                                            'these cases use '
                                                            'the if-then '
                                                            'statement to '
                                                            'increase code '
                                                            'readability.\n'
                                                            'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#TooFewBranchesForASwitchStatement\n'
                                                            '\n'
                                                            '            \n'
                                                            '// With a '
                                                            'minimumNumberCaseForASwitch '
                                                            'of 3\n'
                                                            'public class Foo '
                                                            '{\n'
                                                            '    public void '
                                                            'bar() {\n'
                                                            '        switch '
                                                            '(condition) {\n'
                                                            '            case '
                                                            'ONE:\n'
                                                            '                '
                                                            'instruction;\n'
                                                            '                '
                                                            'break;\n'
                                                            '            '
                                                            'default:\n'
                                                            '                '
                                                            'break; // not '
                                                            'enough for a '
                                                            "'switch' stmt, a "
                                                            "simple 'if' stmt "
                                                            'would have been '
                                                            'more appropriate\n'
                                                            '        }\n'
                                                            '    }\n'
                                                            '}\n'
                                                            '            \n'
                                                            '        ',
                                             'display_name': 'TooFewBranchesForASwitchStatement',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': 'A switch with less than '
                                                      'three branches is '
                                                      "inefficient, use a 'if "
                                                      "statement' instead."},
    'TooManyFields': {   'categories': ['security'],
                         'description': 'Classes that have too many fields can '
                                        'become unwieldy and could be '
                                        'redesigned to have fewer fields, '
                                        'possibly through grouping related '
                                        'fields in new objects. For example, a '
                                        'class with individual city/state/zip '
                                        'fields could park them within a '
                                        'single Address field.\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-plsql/rules/plsql/codesize.html#TooManyFields\n'
                                        '\n'
                                        '   \n'
                                        'CREATE OR REPLACE PACKAGE '
                                        'pkg_too_many_fields AS\n'
                                        '    C_CHAR_A CONSTANT CHAR(1 CHAR) := '
                                        "'A';\n"
                                        '    C_CHAR_B CONSTANT CHAR(1 CHAR) := '
                                        "'B';\n"
                                        '    ...\n'
                                        '    C_CHAR_Z CONSTANT CHAR(1 CHAR) := '
                                        "'Z';\n"
                                        'END pkg_too_many_fields;\n'
                                        '\n'
                                        '   \n'
                                        '      ',
                         'display_name': 'TooManyFields',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Too many fields'},
    'TooManyMethods': {   'categories': ['security'],
                          'description': 'A package or type with too many '
                                         'methods is probably a good suspect '
                                         'for refactoring, in order to reduce '
                                         'its complexity and find a way to '
                                         'have more fine grained objects.\n'
                                         'https://pmd.github.io/pmd-5.8.1/pmd-plsql/rules/plsql/codesize.html#TooManyMethods\n',
                          'display_name': 'TooManyMethods',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'This object has too many methods, consider '
                                   'refactoring it.'},
    'TooManyStaticImports': {   'categories': ['security'],
                                'description': 'If you overuse the static '
                                               'import feature, it can make '
                                               'your program unreadable and '
                                               'unmaintainable, polluting its '
                                               'namespace with all the static '
                                               'members you import. Readers of '
                                               'your code (including you, a '
                                               'few months after you wrote it) '
                                               'will not know which class a '
                                               'static member comes from (Sun '
                                               '1.5 Language Guide).\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/imports.html#TooManyStaticImports\n'
                                               '\n'
                                               'import static Lennon;\n'
                                               'import static Ringo;\n'
                                               'import static George;\n'
                                               'import static Paul;\n'
                                               'import static Yoko; // Too '
                                               'much !\n'
                                               '\t\t  ',
                                'display_name': 'TooManyStaticImports',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Too many static imports may lead to '
                                         'messy code'},
    'UncommentedEmptyConstructor': {   'categories': ['security'],
                                       'description': 'Uncommented Empty '
                                                      'Constructor finds '
                                                      'instances where a '
                                                      'constructor does not '
                                                      'contain statements, but '
                                                      'there is no comment. By '
                                                      'explicitly commenting '
                                                      'empty constructors it '
                                                      'is easier to '
                                                      'distinguish between '
                                                      'intentional (commented) '
                                                      'and unintentional empty '
                                                      'constructors.\n'
                                                      'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#UncommentedEmptyConstructor\n'
                                                      '\n'
                                                      '  \n'
                                                      'public Foo() {\n'
                                                      '  // This constructor '
                                                      'is intentionally empty. '
                                                      'Nothing special is '
                                                      'needed here.\n'
                                                      '}\n'
                                                      ' \n'
                                                      '      ',
                                       'display_name': 'UncommentedEmptyConstructor',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'Document empty constructor'},
    'UncommentedEmptyMethodBody': {   'categories': ['security'],
                                      'description': 'Uncommented Empty Method '
                                                     'Body finds instances '
                                                     'where a method body does '
                                                     'not contain statements, '
                                                     'but there is no comment. '
                                                     'By explicitly commenting '
                                                     'empty method bodies it '
                                                     'is easier to distinguish '
                                                     'between intentional '
                                                     '(commented) and '
                                                     'unintentional empty '
                                                     'methods.\n'
                                                     'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#UncommentedEmptyMethodBody\n'
                                                     '\n'
                                                     '  \n'
                                                     'public void '
                                                     'doSomething() {\n'
                                                     '}\n'
                                                     ' \n'
                                                     '      ',
                                      'display_name': 'UncommentedEmptyMethodBody',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'Document empty method body'},
    'UnconditionalIfStatement': {   'categories': ['security'],
                                    'description': 'Do not use "if" statements '
                                                   'whose conditionals are '
                                                   'always true or always '
                                                   'false.\n'
                                                   'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/basic.html#UnconditionalIfStatement\n'
                                                   '\n'
                                                   '  \n'
                                                   'public class Foo {\n'
                                                   '\tpublic void close() {\n'
                                                   '\t\tif (true) {\t\t// '
                                                   'fixed conditional, not '
                                                   'recommended\n'
                                                   '\t\t\t// ...\n'
                                                   '\t\t}\n'
                                                   '\t}\n'
                                                   '}\n'
                                                   '\n'
                                                   '      ',
                                    'display_name': 'UnconditionalIfStatement',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': "Do not use 'if' statements that "
                                             'are always true or always false'},
    'UnnecessaryBlock': {   'categories': ['security'],
                            'description': 'An unnecessary Block is present. '
                                           'Such Blocks are often used in '
                                           'other languages to introduce a new '
                                           'variable scope. Blocks do not '
                                           'behave like this in ECMAScipt, and '
                                           'using them can be misleading. '
                                           'Considering removing this '
                                           'unnecessary Block.\n'
                                           'https://pmd.github.io/pmd-5.8.1/pmd-javascript/rules/ecmascript/unnecessary.html#UnnecessaryBlock\n'
                                           '\n'
                                           '    \n'
                                           'if (foo) {\n'
                                           '   // Ok\n'
                                           '}\n'
                                           'if (bar) {\n'
                                           '   {\n'
                                           '      // Bad\n'
                                           '   }\n'
                                           '}\n'
                                           '    \n'
                                           '    ',
                            'display_name': 'UnnecessaryBlock',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'Unnecessary block.'},
    'UnnecessaryBooleanAssertion': {   'categories': ['security'],
                                       'description': 'A JUnit test assertion '
                                                      'with a boolean literal '
                                                      'is unnecessary since it '
                                                      'always will evaluate to '
                                                      'the same thing. '
                                                      'Consider using flow '
                                                      'control (in case of '
                                                      'assertTrue(false) or '
                                                      'similar) or simply '
                                                      'removing statements '
                                                      'like assertTrue(true) '
                                                      'and assertFalse(false). '
                                                      'If you just want a test '
                                                      'to halt after finding '
                                                      'an error, use the '
                                                      'fail() method and '
                                                      'provide an indication '
                                                      'message of why it did.\n'
                                                      'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/junit.html#UnnecessaryBooleanAssertion\n'
                                                      '\n'
                                                      '\n'
                                                      'public class SimpleTest '
                                                      'extends TestCase {\n'
                                                      '\tpublic void testX() '
                                                      '{\n'
                                                      '\t\t'
                                                      'assertTrue(true);\t\t '
                                                      '// serves no real '
                                                      'purpose\n'
                                                      '\t}\n'
                                                      '}\n'
                                                      '\n'
                                                      '          ',
                                       'display_name': 'UnnecessaryBooleanAssertion',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'assertTrue(true) or similar '
                                                'statements are unnecessary'},
    'UnnecessaryCaseChange': {   'categories': ['security'],
                                 'description': 'Using equalsIgnoreCase() is '
                                                'faster than using '
                                                'toUpperCase/toLowerCase().equals()\n'
                                                'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strings.html#UnnecessaryCaseChange\n'
                                                '\n'
                                                '       \n'
                                                'boolean answer1 = '
                                                'buz.toUpperCase().equals("baz");\t \t\t'
                                                '// should be '
                                                'buz.equalsIgnoreCase("baz")\n'
                                                '    \n'
                                                'boolean answer2 = '
                                                'buz.toUpperCase().equalsIgnoreCase("baz");\t '
                                                '// another unnecessary '
                                                'toUpperCase()\n'
                                                ' \n'
                                                '       ',
                                 'display_name': 'UnnecessaryCaseChange',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'Using equalsIgnoreCase() is cleaner '
                                          'than using '
                                          'toUpperCase/toLowerCase().equals().'},
    'UnnecessaryConstructor': {   'categories': ['security'],
                                  'description': 'This rule detects when a '
                                                 'constructor is not '
                                                 'necessary; i.e., when there '
                                                 'is only one constructor, its '
                                                 'public, has an empty body, '
                                                 'and takes no arguments.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#UnnecessaryConstructor\n'
                                                 '\n'
                                                 '  \n'
                                                 'public class Foo {\n'
                                                 '  public Foo() {}\n'
                                                 '}\n'
                                                 '  \n'
                                                 '      ',
                                  'display_name': 'UnnecessaryConstructor',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'Avoid unnecessary constructors - '
                                           'the compiler will generate these '
                                           'for you'},
    'UnnecessaryConversionTemporary': {   'categories': ['security'],
                                          'description': 'Avoid the use '
                                                         'temporary objects '
                                                         'when converting '
                                                         'primitives to '
                                                         'Strings. Use the '
                                                         'static conversion '
                                                         'methods on the '
                                                         'wrapper classes '
                                                         'instead.\n'
                                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/unnecessary.html#UnnecessaryConversionTemporary\n'
                                                         '\n'
                                                         '  \n'
                                                         'public String '
                                                         'convert(int x) {\n'
                                                         '\tString foo = new '
                                                         'Integer(x).toString();\t'
                                                         '// this wastes an '
                                                         'object\n'
                                                         '\t\n'
                                                         '\treturn '
                                                         'Integer.toString(x);\t\t\t\t'
                                                         '// preferred '
                                                         'approach\n'
                                                         '}\n'
                                                         ' \n'
                                                         '      ',
                                          'display_name': 'UnnecessaryConversionTemporary',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'Avoid unnecessary '
                                                   'temporaries when '
                                                   'converting primitives to '
                                                   'Strings'},
    'UnnecessaryFinalModifier': {   'categories': ['security'],
                                    'description': 'When a class has the final '
                                                   'modifier, all the methods '
                                                   'are automatically final '
                                                   'and do not need to be '
                                                   'tagged as such. Similarly, '
                                                   "private methods can't be "
                                                   'overriden, and therefore '
                                                   'do not need to be tagged '
                                                   'either.\n'
                                                   'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/unnecessary.html#UnnecessaryFinalModifier\n'
                                                   '\n'
                                                   '\n'
                                                   'public final class Foo {\n'
                                                   '    // This final modifier '
                                                   'is not necessary, since '
                                                   'the class is final\n'
                                                   '    // and thus, all '
                                                   'methods are final\n'
                                                   '    private final void '
                                                   'foo() {\n'
                                                   '    }\n'
                                                   '}\n'
                                                   '\n'
                                                   '\n'
                                                   '      ',
                                    'display_name': 'UnnecessaryFinalModifier',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'Unnecessary final modifier in '
                                             'final class / private methods'},
    'UnnecessaryFullyQualifiedName': {   'categories': ['security'],
                                         'description': 'Import statements '
                                                        'allow the use of '
                                                        'non-fully qualified '
                                                        'names. The use of a '
                                                        'fully qualified name '
                                                        'which is covered by '
                                                        'an import statement '
                                                        'is redundant. '
                                                        'Consider using the '
                                                        'non-fully qualified '
                                                        'name.\n'
                                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/imports.html#UnnecessaryFullyQualifiedName\n'
                                                        '\n'
                                                        'import '
                                                        'java.util.List;\n'
                                                        '\n'
                                                        'public class Foo {\n'
                                                        '   private '
                                                        'java.util.List list1; '
                                                        '// Unnecessary FQN\n'
                                                        '   private List '
                                                        'list2; // More '
                                                        'appropriate given '
                                                        'import of '
                                                        "'java.util.List'\n"
                                                        '}\n'
                                                        '\t\t  ',
                                         'display_name': 'UnnecessaryFullyQualifiedName',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'Unnecessary use of fully '
                                                  "qualified name ''{0}'' due "
                                                  'to existing {2}import '
                                                  "''{1}''"},
    'UnnecessaryLocalBeforeReturn': {   'categories': ['security'],
                                        'description': 'Avoid the creation of '
                                                       'unnecessary local '
                                                       'variables\n'
                                                       'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#UnnecessaryLocalBeforeReturn\n'
                                                       '\n'
                                                       '  \n'
                                                       'public class Foo {\n'
                                                       '   public int foo() {\n'
                                                       '     int x = '
                                                       'doSomething();\n'
                                                       '     return x;  // '
                                                       "instead, just 'return "
                                                       "doSomething();'\n"
                                                       '   }\n'
                                                       '}\n'
                                                       '  \n'
                                                       '      ',
                                        'display_name': 'UnnecessaryLocalBeforeReturn',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'Consider simply returning '
                                                 'the value vs storing it in '
                                                 "local variable ''{0}''"},
    'UnnecessaryModifier': {   'categories': ['security'],
                               'description': 'Fields in interfaces and '
                                              'annotations are automatically '
                                              '`public static final`, and '
                                              'methods are `public abstract`. '
                                              'Classes, interfaces or '
                                              'annotations nested in an '
                                              'interface or annotation are '
                                              'automatically `public static` '
                                              '(all nested interfaces and '
                                              'annotations are automatically '
                                              'static). Nested enums are '
                                              'automatically `static`. For '
                                              'historical reasons, modifiers '
                                              'which are implied by the '
                                              'context are accepted by the '
                                              'compiler, but are superfluous.\n'
                                              'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/unnecessary.html#UnnecessaryModifier\n'
                                              '\n'
                                              ' \n'
                                              ' public @interface Annotation '
                                              '{\n'
                                              '  public abstract void '
                                              'bar(); \t\t// both abstract and '
                                              'public are ignored by the '
                                              'compiler\n'
                                              '  public static final int X = '
                                              '0; \t// public, static, and '
                                              'final all ignored\n'
                                              '  public static class Bar '
                                              '{} \t\t// public, static '
                                              'ignored\n'
                                              '  public static interface Baz '
                                              '{} \t// ditto\n'
                                              '}\n'
                                              'public interface Foo {\n'
                                              '  public abstract void '
                                              'bar(); \t\t// both abstract and '
                                              'public are ignored by the '
                                              'compiler\n'
                                              '  public static final int X = '
                                              '0; \t// public, static, and '
                                              'final all ignored\n'
                                              '  public static class Bar '
                                              '{} \t\t// public, static '
                                              'ignored\n'
                                              '  public static interface Baz '
                                              '{} \t// ditto\n'
                                              '}\n'
                                              'public class Bar {\n'
                                              '  public static interface Baz '
                                              '{} // static ignored\n'
                                              '  public static enum FoorBar { '
                                              '// static ignored\n'
                                              '    FOO;\n'
                                              '  }\n'
                                              '}\n'
                                              ' \n'
                                              '     ',
                               'display_name': 'UnnecessaryModifier',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Avoid modifiers which are implied by '
                                        'the context'},
    'UnnecessaryParentheses': {   'categories': ['security'],
                                  'description': 'Sometimes expressions are '
                                                 'wrapped in unnecessary '
                                                 'parentheses, making them '
                                                 'look like function calls.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#UnnecessaryParentheses\n'
                                                 '\n'
                                                 '  \n'
                                                 'public class Foo {\n'
                                                 '   boolean bar() {\n'
                                                 '      return (true);\n'
                                                 '      }\n'
                                                 '}\n'
                                                 '  \n'
                                                 '      ',
                                  'display_name': 'UnnecessaryParentheses',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'This statement may have some '
                                           'unnecessary parentheses'},
    'UnnecessaryReturn': {   'categories': ['security'],
                             'description': 'Avoid the use of unnecessary '
                                            'return statements.\n'
                                            'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/unnecessary.html#UnnecessaryReturn\n'
                                            '\n'
                                            '\t\t\n'
                                            'public class Foo {\n'
                                            '  public void bar() {\n'
                                            '    int x = 42;\n'
                                            '    return;\n'
                                            '  }\n'
                                            '}\n'
                                            '\t\t\n'
                                            '      ',
                             'display_name': 'UnnecessaryReturn',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Avoid unnecessary return statements'},
    'UnnecessaryWrapperObjectCreation': {   'categories': ['security'],
                                            'description': 'Most wrapper '
                                                           'classes provide '
                                                           'static conversion '
                                                           'methods that avoid '
                                                           'the need to create '
                                                           'intermediate '
                                                           'objects just to '
                                                           'create the '
                                                           'primitive forms. '
                                                           'Using these avoids '
                                                           'the cost of '
                                                           'creating objects '
                                                           'that also need to '
                                                           'be '
                                                           'garbage-collected '
                                                           'later.\n'
                                                           'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/optimizations.html#UnnecessaryWrapperObjectCreation\n'
                                                           '\n'
                                                           '\n'
                                                           'public int '
                                                           'convert(String s) '
                                                           '{\n'
                                                           '  int i, i2;\n'
                                                           '\n'
                                                           '  i = '
                                                           'Integer.valueOf(s).intValue(); '
                                                           '// this wastes an '
                                                           'object\n'
                                                           '  i = '
                                                           'Integer.parseInt(s); \t\t\t '
                                                           '// this is better\n'
                                                           '\n'
                                                           '  i2 = '
                                                           'Integer.valueOf(i).intValue(); '
                                                           '// this wastes an '
                                                           'object\n'
                                                           '  i2 = i; // this '
                                                           'is better\n'
                                                           '\n'
                                                           '  String s3 = '
                                                           'Integer.valueOf(i2).toString(); '
                                                           '// this wastes an '
                                                           'object\n'
                                                           '  s3 = '
                                                           'Integer.toString(i2); \t\t'
                                                           '// this is better\n'
                                                           '\n'
                                                           '  return i2;\n'
                                                           '}\n'
                                                           '\n'
                                                           '          ',
                                            'display_name': 'UnnecessaryWrapperObjectCreation',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'Unnecessary wrapper '
                                                     'object creation'},
    'UnreachableCode': {   'categories': ['security'],
                           'description': "A 'return', 'break', 'continue', or "
                                          "'throw' statement should be the "
                                          'last in a block. Statements after '
                                          'these will never execute. This is a '
                                          'bug, or extremely poor style.\n'
                                          'https://pmd.github.io/pmd-5.8.1/pmd-javascript/rules/ecmascript/basic.html#UnreachableCode\n'
                                          '\n'
                                          '  \n'
                                          '// Ok\n'
                                          'function foo() {\n'
                                          '   return 1;\n'
                                          '}\n'
                                          '// Bad\n'
                                          'function bar() {\n'
                                          '   var x = 1;\n'
                                          '   return x;\n'
                                          '   x = 2;\n'
                                          '}\n'
                                          '\n'
                                          '      ',
                           'display_name': 'UnreachableCode',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': "A ''return'', ''break'', ''continue'', or "
                                    "''throw'' statement should be the last in "
                                    'a block.'},
    'UnsynchronizedStaticDateFormatter': {   'categories': ['security'],
                                             'description': 'SimpleDateFormat '
                                                            'instances are not '
                                                            'synchronized. Sun '
                                                            'recommends using '
                                                            'separate format '
                                                            'instances for '
                                                            'each thread. If '
                                                            'multiple threads '
                                                            'must access a '
                                                            'static formatter, '
                                                            'the formatter '
                                                            'must be '
                                                            'synchronized '
                                                            'either on method '
                                                            'or block level.\n'
                                                            'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#UnsynchronizedStaticDateFormatter\n'
                                                            '\n'
                                                            '    \n'
                                                            'public class Foo '
                                                            '{\n'
                                                            '    private '
                                                            'static final '
                                                            'SimpleDateFormat '
                                                            'sdf = new '
                                                            'SimpleDateFormat();\n'
                                                            '    void bar() {\n'
                                                            '        '
                                                            'sdf.format(); // '
                                                            'poor, no '
                                                            'thread-safety\n'
                                                            '    }\n'
                                                            '    synchronized '
                                                            'void foo() {\n'
                                                            '        '
                                                            'sdf.format(); // '
                                                            'preferred\n'
                                                            '    }\n'
                                                            '}\n'
                                                            '    \n'
                                                            '      ',
                                             'display_name': 'UnsynchronizedStaticDateFormatter',
                                             'file': '%(issue.file)s',
                                             'line': '%(issue.line)s',
                                             'severity': '1',
                                             'title': 'Static DateFormatter '
                                                      'objects should be '
                                                      'accessed in a '
                                                      'synchronized manner'},
    'UnusedFormalParameter': {   'categories': ['security'],
                                 'description': 'Avoid passing parameters to '
                                                'methods or constructors '
                                                'without actually referencing '
                                                'them in the method body.\n'
                                                'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/unusedcode.html#UnusedFormalParameter\n'
                                                '\n'
                                                '\n'
                                                'public class Foo {\n'
                                                '\tprivate void bar(String '
                                                'howdy) {\n'
                                                '\t// howdy is not used\n'
                                                '\t}\n'
                                                '}\n'
                                                '\n'
                                                '    ',
                                 'display_name': 'UnusedFormalParameter',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'Avoid unused {0} parameters such as '
                                          "''{1}''."},
    'UnusedImports': {   'categories': ['security'],
                         'description': 'Avoid unused import statements. This '
                                        'rule will find unused on demand '
                                        'imports, i.e. import com.foo.*.\r\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/typeresolution.html#UnusedImports\r\n'
                                        '\r\n'
                                        '\r\n'
                                        'import java.io.*;\t// not referenced '
                                        'or required\r\n'
                                        '\r\n'
                                        'public class Foo {}\r\n'
                                        '\r\n'
                                        '    ',
                         'display_name': 'UnusedImports',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': "Avoid unused imports such as ''{0}''"},
    'UnusedLocalVariable': {   'categories': ['security'],
                               'description': 'Detects when a local variable '
                                              'is declared and/or assigned, '
                                              'but not used.\r\n'
                                              'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/unusedcode.html#UnusedLocalVariable\r\n'
                                              '\r\n'
                                              '\r\n'
                                              'public class Foo {\r\n'
                                              '\tpublic void doSomething() '
                                              '{\r\n'
                                              '\t\tint i = 5; // Unused\r\n'
                                              '\t}\r\n'
                                              '}\r\n'
                                              '\r\n'
                                              '    ',
                               'display_name': 'UnusedLocalVariable',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Avoid unused local variables such as '
                                        "''{0}''."},
    'UnusedMacroParameter': {   'categories': ['security'],
                                'description': 'Avoid unused macro parameters. '
                                               'They should be deleted.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-vm/rules/vm/basic.html#UnusedMacroParameter\n',
                                'display_name': 'UnusedMacroParameter',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Avoid unused macro parameters such '
                                         "as ''{0}''"},
    'UnusedNullCheckInEquals': {   'categories': ['security'],
                                   'description': 'After checking an object '
                                                  'reference for null, you '
                                                  'should invoke equals() on '
                                                  'that object rather than '
                                                  'passing it to another '
                                                  "object's equals() method.\n"
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/unnecessary.html#UnusedNullCheckInEquals\n'
                                                  '\n'
                                                  '\t\t\n'
                                                  'public class Test {\n'
                                                  '\n'
                                                  '  public String method1() { '
                                                  'return "ok";}\n'
                                                  '  public String method2() { '
                                                  'return null;}\n'
                                                  '\n'
                                                  '  public void method(String '
                                                  'a) {\n'
                                                  '    String b;\n'
                                                  "\t// I don't know it "
                                                  'method1() can be "null"\n'
                                                  '\t// but I know "a" is not '
                                                  'null..\n'
                                                  "\t// I'd better write "
                                                  'a.equals(method1())\n'
                                                  '\t\n'
                                                  '\tif (a!=null && '
                                                  'method1().equals(a)) { // '
                                                  'will trigger the rule\n'
                                                  '\t//whatever\n'
                                                  '\t}\n'
                                                  '\t\n'
                                                  '\tif (method1().equals(a) '
                                                  "&& a != null) { // won't "
                                                  'trigger the rule\n'
                                                  '\t//whatever\n'
                                                  '\t}\n'
                                                  '\t\n'
                                                  '\tif (a!=null && '
                                                  'method1().equals(b)) { // '
                                                  "won't trigger the rule\n"
                                                  '\t//whatever\n'
                                                  '\t}\n'
                                                  '\t\n'
                                                  '\tif (a!=null && '
                                                  '"LITERAL".equals(a)) { // '
                                                  "won't trigger the rule\n"
                                                  '\t//whatever\n'
                                                  '\t}\n'
                                                  '\t\n'
                                                  '\tif (a!=null && '
                                                  '!a.equals("go")) { // '
                                                  "won't trigger the rule\n"
                                                  '\ta=method2();\n'
                                                  '\tif (method1().equals(a)) '
                                                  '{\n'
                                                  '\t//whatever\n'
                                                  '\t}\n'
                                                  '  }\n'
                                                  '}\n'
                                                  '}\n'
                                                  '\t\t\t\t\n'
                                                  '\t\t\t',
                                   'display_name': 'UnusedNullCheckInEquals',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'Invoke equals() on the object '
                                            "you''ve already ensured is not "
                                            'null'},
    'UnusedPrivateField': {   'categories': ['security'],
                              'description': 'Detects when a private field is '
                                             'declared and/or assigned a '
                                             'value, but not used.\r\n'
                                             'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/unusedcode.html#UnusedPrivateField\r\n'
                                             '\r\n'
                                             '\r\n'
                                             'public class Something {\r\n'
                                             '  private static int FOO = 2; // '
                                             'Unused\r\n'
                                             '  private int i = 5; // '
                                             'Unused\r\n'
                                             '  private int j = 6;\r\n'
                                             '  public int addOne() {\r\n'
                                             '    return j++;\r\n'
                                             '  }\r\n'
                                             '}\r\n'
                                             '\r\n'
                                             '    ',
                              'display_name': 'UnusedPrivateField',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'Avoid unused private fields such as '
                                       "''{0}''."},
    'UnusedPrivateMethod': {   'categories': ['security'],
                               'description': 'Unused Private Method detects '
                                              'when a private method is '
                                              'declared but is unused.\r\n'
                                              'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/unusedcode.html#UnusedPrivateMethod\r\n'
                                              '\r\n'
                                              '\r\n'
                                              'public class Something {\r\n'
                                              '\tprivate void foo() {} // '
                                              'unused\r\n'
                                              '}\r\n'
                                              '\r\n'
                                              '    ',
                               'display_name': 'UnusedPrivateMethod',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Avoid unused private methods such as '
                                        "''{0}''."},
    'UseArrayListInsteadOfVector': {   'categories': ['security'],
                                       'description': 'ArrayList is a much '
                                                      'better Collection '
                                                      'implementation than '
                                                      'Vector if thread-safe '
                                                      'operation is not '
                                                      'required.\n'
                                                      'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/optimizations.html#UseArrayListInsteadOfVector\n'
                                                      '\n'
                                                      '\n'
                                                      'public class SimpleTest '
                                                      'extends TestCase {\n'
                                                      '\tpublic void testX() '
                                                      '{\n'
                                                      '\t\tCollection c1 = new '
                                                      'Vector();\t\t\n'
                                                      '\t\tCollection c2 = new '
                                                      'ArrayList();\t// '
                                                      'achieves the same with '
                                                      'much better '
                                                      'performance\n'
                                                      '\t}\n'
                                                      '}\n'
                                                      '\n'
                                                      '          ',
                                       'display_name': 'UseArrayListInsteadOfVector',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'Use ArrayList instead of '
                                                'Vector'},
    'UseArraysAsList': {   'categories': ['security'],
                           'description': 'The java.util.Arrays class has a '
                                          '"asList" method that should be used '
                                          'when you want to create a new List '
                                          'from an array of objects. It is '
                                          'faster than executing a loop to '
                                          'copy all the elements of the array '
                                          'one by one.\n'
                                          'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/optimizations.html#UseArraysAsList\n'
                                          '\n'
                                          '   \n'
                                          'public class Test {\n'
                                          '  public void foo(Integer[] ints) '
                                          '{\n'
                                          '    // could just use '
                                          'Arrays.asList(ints)\n'
                                          '     List l= new ArrayList(10);\n'
                                          '     for (int i=0; i< 100; i++) {\n'
                                          '       l.add(ints[i]);\n'
                                          '     }\n'
                                          '     for (int i=0; i< 100; i++) {\n'
                                          '       l.add(a[i].toString()); // '
                                          "won't trigger the rule\n"
                                          '     }\n'
                                          '  }\n'
                                          '}\n'
                                          '   \n'
                                          '     ',
                           'display_name': 'UseArraysAsList',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'Use asList instead of tight loops'},
    'UseAssertEqualsInsteadOfAssertTrue': {   'categories': ['security'],
                                              'description': 'This rule '
                                                             'detects JUnit '
                                                             'assertions in '
                                                             'object equality. '
                                                             'These assertions '
                                                             'should be made '
                                                             'by more specific '
                                                             'methods, like '
                                                             'assertEquals.\n'
                                                             'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/junit.html#UseAssertEqualsInsteadOfAssertTrue\n'
                                                             '\n'
                                                             '\n'
                                                             'public class '
                                                             'FooTest extends '
                                                             'TestCase {\n'
                                                             '\tvoid '
                                                             'testCode() {\n'
                                                             '\t\tObject a, '
                                                             'b;\n'
                                                             '\t\t'
                                                             'assertTrue(a.equals(b)); \t\t\t\t\t'
                                                             '// bad usage\n'
                                                             '\t\t'
                                                             'assertEquals(?a '
                                                             'should equals '
                                                             'b?, a, b);\t// '
                                                             'good usage\n'
                                                             '\t}\n'
                                                             '}\n'
                                                             '\n'
                                                             '      ',
                                              'display_name': 'UseAssertEqualsInsteadOfAssertTrue',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '1',
                                              'title': 'Use assertEquals(x, y) '
                                                       'instead of '
                                                       'assertTrue(x.equals(y))'},
    'UseAssertNullInsteadOfAssertTrue': {   'categories': ['security'],
                                            'description': 'This rule detects '
                                                           'JUnit assertions '
                                                           'in object '
                                                           'references '
                                                           'equality. These '
                                                           'assertions should '
                                                           'be made by more '
                                                           'specific methods, '
                                                           'like assertNull, '
                                                           'assertNotNull.\n'
                                                           'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/junit.html#UseAssertNullInsteadOfAssertTrue\n'
                                                           '\n'
                                                           ' \n'
                                                           ' public class '
                                                           'FooTest extends '
                                                           'TestCase {\n'
                                                           '  void testCode() '
                                                           '{\n'
                                                           '   Object a = '
                                                           'doSomething();\n'
                                                           '   '
                                                           'assertTrue(a==null); '
                                                           '// bad usage\n'
                                                           '   assertNull(a);  '
                                                           '// good usage\n'
                                                           '   assertTrue(a != '
                                                           'null); // bad '
                                                           'usage\n'
                                                           '   '
                                                           'assertNotNull(a);  '
                                                           '// good usage\n'
                                                           '  }\n'
                                                           ' }\n'
                                                           ' \n'
                                                           '       ',
                                            'display_name': 'UseAssertNullInsteadOfAssertTrue',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'Use assertNull(x) '
                                                     'instead of '
                                                     'assertTrue(x==null), or '
                                                     'assertNotNull(x) vs '
                                                     'assertFalse(x==null)'},
    'UseAssertSameInsteadOfAssertTrue': {   'categories': ['security'],
                                            'description': 'This rule detects '
                                                           'JUnit assertions '
                                                           'in object '
                                                           'references '
                                                           'equality. These '
                                                           'assertions should '
                                                           'be made by more '
                                                           'specific methods, '
                                                           'like assertSame, '
                                                           'assertNotSame.\n'
                                                           'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/junit.html#UseAssertSameInsteadOfAssertTrue\n'
                                                           '\n'
                                                           '\n'
                                                           'public class '
                                                           'FooTest extends '
                                                           'TestCase {\n'
                                                           ' void testCode() '
                                                           '{\n'
                                                           '  Object a, b;\n'
                                                           '  assertTrue(a == '
                                                           'b); // bad usage\n'
                                                           '  assertSame(a, '
                                                           'b);  // good '
                                                           'usage\n'
                                                           ' }\n'
                                                           '}\n'
                                                           '\n'
                                                           '      ',
                                            'display_name': 'UseAssertSameInsteadOfAssertTrue',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '1',
                                            'title': 'Use assertSame(x, y) '
                                                     'instead of '
                                                     'assertTrue(x==y), or '
                                                     'assertNotSame(x,y) vs '
                                                     'assertFalse(x==y)'},
    'UseAssertTrueInsteadOfAssertEquals': {   'categories': ['security'],
                                              'description': 'When asserting a '
                                                             'value is the '
                                                             'same as a '
                                                             'literal or Boxed '
                                                             'boolean, use '
                                                             'assertTrue/assertFalse, '
                                                             'instead of '
                                                             'assertEquals.\n'
                                                             'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/junit.html#UseAssertTrueInsteadOfAssertEquals\n'
                                                             '\n'
                                                             '\n'
                                                             'public class '
                                                             'MyTestCase '
                                                             'extends TestCase '
                                                             '{\n'
                                                             '\tpublic void '
                                                             'testMyCase() {\n'
                                                             '\t\tboolean '
                                                             'myVar = true;\n'
                                                             '\t\t// Ok\n'
                                                             '\t\t'
                                                             'assertTrue("myVar '
                                                             'is true", '
                                                             'myVar);\n'
                                                             '\t\t// Bad\n'
                                                             '\t\t'
                                                             'assertEquals("myVar '
                                                             'is true", true, '
                                                             'myVar);\n'
                                                             '\t\t// Bad\n'
                                                             '\t\t'
                                                             'assertEquals("myVar '
                                                             'is false", '
                                                             'false, myVar);\n'
                                                             '\t\t// Bad\n'
                                                             '\t\t'
                                                             'assertEquals("myVar '
                                                             'is true", '
                                                             'Boolean.TRUE, '
                                                             'myVar);\n'
                                                             '\t\t// Bad\n'
                                                             '\t\t'
                                                             'assertEquals("myVar '
                                                             'is false", '
                                                             'Boolean.FALSE, '
                                                             'myVar);\n'
                                                             '\t}\n'
                                                             '}\n'
                                                             '\n'
                                                             '\t\t',
                                              'display_name': 'UseAssertTrueInsteadOfAssertEquals',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '1',
                                              'title': 'Use '
                                                       'assertTrue(x)/assertFalse(x) '
                                                       'instead of '
                                                       'assertEquals(true, '
                                                       'x)/assertEquals(false, '
                                                       'x)   or '
                                                       'assertEquals(Boolean.TRUE, '
                                                       'x)/assertEquals(Boolean.FALSE, '
                                                       'x).'},
    'UseBaseWithParseInt': {   'categories': ['security'],
                               'description': 'TODO\n'
                                              'https://pmd.github.io/pmd-5.8.1/pmd-javascript/rules/ecmascript/basic.html#UseBaseWithParseInt\n'
                                              '\n'
                                              'parseInt("10",base);\n'
                                              '  ',
                               'display_name': 'UseBaseWithParseInt',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Always provide a base when using '
                                        'parseInt() functions'},
    'UseCollectionIsEmpty': {   'categories': ['security'],
                                'description': 'The isEmpty() method on '
                                               'java.util.Collection is '
                                               'provided to determine if a '
                                               'collection has any elements. '
                                               'Comparing the value of size() '
                                               'to 0 does not convey intent as '
                                               'well as the isEmpty() method.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#UseCollectionIsEmpty\n'
                                               '\n'
                                               '    \n'
                                               'public class Foo {\n'
                                               '\tvoid good() {\n'
                                               '       \tList foo = '
                                               'getList();\n'
                                               '\t\tif (foo.isEmpty()) {\n'
                                               '\t\t\t// blah\n'
                                               '\t\t}\n'
                                               '   \t}\n'
                                               '\n'
                                               '    void bad() {\n'
                                               '   \t    List foo = '
                                               'getList();\n'
                                               '\t\t\tif (foo.size() == 0) {\n'
                                               '\t\t\t\t// blah\n'
                                               '\t\t\t}\n'
                                               '    \t}\n'
                                               '}\n'
                                               '    \n'
                                               '      ',
                                'display_name': 'UseCollectionIsEmpty',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Substitute calls to size() == 0 (or '
                                         'size() != 0, size() > 0, size() < 1) '
                                         'with calls to isEmpty()'},
    'UseConcatOnce': {   'categories': ['security'],
                         'description': 'The XPath concat() functions accepts '
                                        'as many arguments as required so you '
                                        'can have "concat($a,\'b\',$c)" rather '
                                        'than "concat($a,concat(\'b\',$c)".\n'
                                        'https://pmd.github.io/pmd-5.8.1/pmd-xml/rules/xsl/xpath.html#UseConcatOnce\n'
                                        '\n'
                                        ' \n'
                                        ' <xsl:variable name="var" '
                                        'select="concat("Welcome",concat("to '
                                        'you ",$name))"/>\n'
                                        ' <xsl:variable name="var" '
                                        'select="concat("Welcome","to you '
                                        '",$name))">\n'
                                        ' \n'
                                        '     ',
                         'display_name': 'UseConcatOnce',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'The xpath concat() function accepts as many '
                                  'arguments as required, you may be able to '
                                  'factorize this expression'},
    'UseConcurrentHashMap': {   'categories': ['security'],
                                'description': 'Since Java5 brought a new '
                                               'implementation of the Map '
                                               'designed for multi-threaded '
                                               'access, you can perform '
                                               'efficient map reads without '
                                               'blocking other threads.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#UseConcurrentHashMap\n'
                                               '\n'
                                               '\n'
                                               'public class ConcurrentApp {\n'
                                               '  public void getMyInstance() '
                                               '{\n'
                                               '    Map map1 = new '
                                               'HashMap(); \t// fine for '
                                               'single-threaded access\n'
                                               '    Map map2 = new '
                                               'ConcurrentHashMap();  // '
                                               'preferred for use with '
                                               'multiple threads\n'
                                               '\n'
                                               '    // the following case will '
                                               'be ignored by this rule\n'
                                               '    Map map3 = '
                                               'someModule.methodThatReturnMap(); '
                                               '// might be OK, if the '
                                               'returned map is already '
                                               'thread-safe\n'
                                               '  }\n'
                                               '}\n'
                                               '\n'
                                               '    ',
                                'display_name': 'UseConcurrentHashMap',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'If you run in Java5 or newer and '
                                         'have concurrent access, you should '
                                         'use the ConcurrentHashMap '
                                         'implementation'},
    'UseCorrectExceptionLogging': {   'categories': ['security'],
                                      'description': 'To make sure the full '
                                                     'stacktrace is printed '
                                                     'out, use the logging '
                                                     'statement with two '
                                                     'arguments: a String and '
                                                     'a Throwable.\n'
                                                     'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/logging-jakarta-commons.html#UseCorrectExceptionLogging\n'
                                                     '\n'
                                                     'public class Main {\n'
                                                     '   private static final '
                                                     'Log _LOG = '
                                                     'LogFactory.getLog( '
                                                     'Main.class );\n'
                                                     '   void bar() {\n'
                                                     '     try {\n'
                                                     '     } catch( Exception '
                                                     'e ) {\n'
                                                     '      _LOG.error( e ); '
                                                     '//Wrong!\n'
                                                     '     } catch( '
                                                     'OtherException oe ) {\n'
                                                     '      _LOG.error( '
                                                     'oe.getMessage(), oe ); '
                                                     '//Correct\n'
                                                     '     }\n'
                                                     '   }\n'
                                                     '}\n',
                                      'display_name': 'UseCorrectExceptionLogging',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'Use the correct logging '
                                               'statement for logging '
                                               'exceptions'},
    'UseEqualsToCompareStrings': {   'categories': ['security'],
                                     'description': "Using '==' or '!=' to "
                                                    'compare strings only '
                                                    'works if intern version '
                                                    'is used on both sides. '
                                                    'Use the equals() method '
                                                    'instead.\n'
                                                    'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strings.html#UseEqualsToCompareStrings\n'
                                                    '\n'
                                                    '\n'
                                                    'public boolean '
                                                    'test(String s) {\n'
                                                    '    if (s == "one") '
                                                    'return true; \t\t// '
                                                    'unreliable\n'
                                                    '    if ("two".equals(s)) '
                                                    'return true; \t// better\n'
                                                    '    return false;\n'
                                                    '}\n'
                                                    '\n'
                                                    '    ',
                                     'display_name': 'UseEqualsToCompareStrings',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'Use equals() to compare strings '
                                              "instead of ''=='' or ''!=''"},
    'UseIndexOfChar': {   'categories': ['security'],
                          'description': 'Use String.indexOf(char) when '
                                         'checking for the index of a single '
                                         'character; it executes faster.\n'
                                         'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strings.html#UseIndexOfChar\n'
                                         '\n'
                                         '\n'
                                         'String s = "hello world";\n'
                                         '  // avoid this\n'
                                         'if (s.indexOf("d") {}\n'
                                         '  // instead do this\n'
                                         "if (s.indexOf('d') {}\n"
                                         '\n'
                                         '    ',
                          'display_name': 'UseIndexOfChar',
                          'file': '%(issue.file)s',
                          'line': '%(issue.line)s',
                          'severity': '1',
                          'title': 'String.indexOf(char) is faster than '
                                   'String.indexOf(String).'},
    'UseLocaleWithCaseConversions': {   'categories': ['security'],
                                        'description': 'When doing '
                                                       'String.toLowerCase()/toUpperCase() '
                                                       'conversions, use '
                                                       'Locales to avoids '
                                                       'problems with '
                                                       'languages that have '
                                                       'unusual conventions, '
                                                       'i.e. Turkish.\n'
                                                       'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#UseLocaleWithCaseConversions\n'
                                                       '\n'
                                                       '    \n'
                                                       'class Foo {\n'
                                                       ' // BAD\n'
                                                       ' if '
                                                       '(x.toLowerCase().equals("list")) '
                                                       '{ }\n'
                                                       ' /*\n'
                                                       ' This will not match '
                                                       '"LIST" when in Turkish '
                                                       'locale\n'
                                                       ' The above could be\n'
                                                       ' if '
                                                       '(x.toLowerCase(Locale.US).equals("list")) '
                                                       '{ }\n'
                                                       ' or simply\n'
                                                       ' if '
                                                       '(x.equalsIgnoreCase("list")) '
                                                       '{ }\n'
                                                       ' */\n'
                                                       ' // GOOD\n'
                                                       ' String z = '
                                                       'a.toLowerCase(Locale.EN);\n'
                                                       '}\n'
                                                       '    \n'
                                                       '        ',
                                        'display_name': 'UseLocaleWithCaseConversions',
                                        'file': '%(issue.file)s',
                                        'line': '%(issue.line)s',
                                        'severity': '1',
                                        'title': 'When doing a '
                                                 'String.toLowerCase()/toUpperCase() '
                                                 'call, use a Locale'},
    'UseNotifyAllInsteadOfNotify': {   'categories': ['security'],
                                       'description': 'Thread.notify() awakens '
                                                      'a thread monitoring the '
                                                      'object. If more than '
                                                      'one thread is '
                                                      'monitoring, then only '
                                                      'one is chosen. The '
                                                      'thread chosen is '
                                                      'arbitrary; thus its '
                                                      'usually safer to call '
                                                      'notifyAll() instead.\n'
                                                      'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#UseNotifyAllInsteadOfNotify\n'
                                                      '\n'
                                                      '\n'
                                                      '  void bar() {\n'
                                                      '    x.notify();\n'
                                                      '    // If many threads '
                                                      'are monitoring x, only '
                                                      "one (and you won't know "
                                                      'which) will be '
                                                      'notified.\n'
                                                      '    // use instead:\n'
                                                      '    x.notifyAll();\n'
                                                      '  }\n'
                                                      '\n'
                                                      '      ',
                                       'display_name': 'UseNotifyAllInsteadOfNotify',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'Call Thread.notifyAll() '
                                                'rather than Thread.notify()'},
    'UseObjectForClearerAPI': {   'categories': ['security'],
                                  'description': 'When you write a public '
                                                 'method, you should be '
                                                 'thinking in terms of an API. '
                                                 'If your method is public, it '
                                                 'means other class will use '
                                                 'it, therefore, you want (or '
                                                 'need) to offer a '
                                                 'comprehensive and evolutive '
                                                 'API. If you pass a lot of '
                                                 'information as a simple '
                                                 'series of Strings, you may '
                                                 'think of using an Object to '
                                                 'represent all those '
                                                 "information. You'll get a "
                                                 'simpler API (such as '
                                                 'doWork(Workload workload), '
                                                 'rather than a tedious series '
                                                 'of Strings) and more '
                                                 'importantly, if you need at '
                                                 'some point to pass extra '
                                                 "data, you'll be able to do "
                                                 'so by simply modifying or '
                                                 'extending Workload without '
                                                 'any modification to your '
                                                 'API.\n'
                                                 'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/controversial.html#UseObjectForClearerAPI\n'
                                                 '\n'
                                                 '\n'
                                                 'public class MyClass {\n'
                                                 '  public void connect(String '
                                                 'username,\n'
                                                 '    String pssd,\n'
                                                 '    String databaseName,\n'
                                                 '    String databaseAdress)\n'
                                                 '    // Instead of those '
                                                 'parameters object\n'
                                                 '    // would ensure a '
                                                 'cleaner API and permit\n'
                                                 '    // to add extra data '
                                                 'transparently (no code '
                                                 'change):\n'
                                                 '    // void connect(UserData '
                                                 'data);\n'
                                                 '    {\n'
                                                 '\n'
                                                 '  }\n'
                                                 '}\n'
                                                 '\n'
                                                 '    ',
                                  'display_name': 'UseObjectForClearerAPI',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'Rather than using a lot of String '
                                           'arguments, consider using a '
                                           'container object for those '
                                           'values.'},
    'UseProperClassLoader': {   'categories': ['security'],
                                'description': 'In J2EE, the getClassLoader() '
                                               'method might not work as '
                                               'expected. Use '
                                               'Thread.currentThread().getContextClassLoader() '
                                               'instead.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/j2ee.html#UseProperClassLoader\n'
                                               '\n'
                                               '\n'
                                               'public class Foo {\n'
                                               ' ClassLoader cl = '
                                               'Bar.class.getClassLoader();\n'
                                               '}\n'
                                               '\n'
                                               '  ',
                                'display_name': 'UseProperClassLoader',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'In J2EE, getClassLoader() might not '
                                         'work as expected.  Use '
                                         'Thread.currentThread().getContextClassLoader() '
                                         'instead.'},
    'UseStringBufferForStringAppends': {   'categories': ['security'],
                                           'description': "The use of the '+=' "
                                                          'operator for '
                                                          'appending strings '
                                                          'causes the JVM to '
                                                          'create and use an '
                                                          'internal '
                                                          'StringBuffer. If a '
                                                          'non-trivial number '
                                                          'of these '
                                                          'concatenations are '
                                                          'being used then the '
                                                          'explicit use of a '
                                                          'StringBuilder or '
                                                          'threadsafe '
                                                          'StringBuffer is '
                                                          'recommended to '
                                                          'avoid this.\n'
                                                          'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/optimizations.html#UseStringBufferForStringAppends\n'
                                                          '\n'
                                                          '      \n'
                                                          'public class Foo {\n'
                                                          '  void bar() {\n'
                                                          '    String a;\n'
                                                          '    a = "foo";\n'
                                                          '    a += " bar";\n'
                                                          '   // better would '
                                                          'be:\n'
                                                          '   // StringBuilder '
                                                          'a = new '
                                                          'StringBuilder("foo");\n'
                                                          '   // a.append(" '
                                                          'bar);\n'
                                                          '  }\n'
                                                          '}\n'
                                                          '      \n'
                                                          '           ',
                                           'display_name': 'UseStringBufferForStringAppends',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '1',
                                           'title': 'Prefer StringBuffer over '
                                                    '+= for concatenating '
                                                    'strings'},
    'UseStringBufferLength': {   'categories': ['security'],
                                 'description': 'Use StringBuffer.length() to '
                                                'determine StringBuffer length '
                                                'rather than using '
                                                'StringBuffer.toString().equals("") '
                                                'or '
                                                'StringBuffer.toString().length() '
                                                '== ...\n'
                                                'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strings.html#UseStringBufferLength\n'
                                                '\n'
                                                '  \n'
                                                'StringBuffer sb = new '
                                                'StringBuffer();\n'
                                                '    \n'
                                                'if (sb.toString().equals("")) '
                                                '{}\t    // inefficient \n'
                                                '    \n'
                                                'if (sb.length() == 0) '
                                                '{}\t    \t\t// preferred\n'
                                                '  \n'
                                                '      ',
                                 'display_name': 'UseStringBufferLength',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'This is an inefficient use of '
                                          'StringBuffer.toString; call '
                                          'StringBuffer.length instead.'},
    'UseUtilityClass': {   'categories': ['security'],
                           'description': 'For classes that only have static '
                                          'methods, consider making them '
                                          'utility classes. Note that this '
                                          "doesn't apply to abstract classes, "
                                          'since their subclasses may well '
                                          'include non-static methods. Also, '
                                          'if you want this class to be a '
                                          'utility class, remember to add a '
                                          'private constructor to prevent '
                                          'instantiation. (Note, that this use '
                                          'was known before PMD 5.1.0 as '
                                          'UseSingleton).\n'
                                          'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#UseUtilityClass\n'
                                          '\n'
                                          '\n'
                                          'public class MaybeAUtility {\n'
                                          '  public static void foo() {}\n'
                                          '  public static void bar() {}\n'
                                          '}\n'
                                          '\n'
                                          '    ',
                           'display_name': 'UseUtilityClass',
                           'file': '%(issue.file)s',
                           'line': '%(issue.line)s',
                           'severity': '1',
                           'title': 'All methods are static.  Consider using a '
                                    'utility class instead. Alternatively, you '
                                    'could add a private constructor or make '
                                    'the class abstract to silence this '
                                    'warning.'},
    'UseVarargs': {   'categories': ['security'],
                      'description': 'Java 5 introduced the varargs parameter '
                                     'declaration for methods and '
                                     'constructors. This syntactic sugar '
                                     'provides flexibility for users of these '
                                     'methods and constructors, allowing them '
                                     'to avoid having to deal with the '
                                     'creation of an array.\n'
                                     'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/design.html#UseVarargs\n'
                                     '\n'
                                     'public class Foo {\n'
                                     '   public void foo(String s, Object[] '
                                     'args) {\n'
                                     '      // Do something here...\n'
                                     '   }\n'
                                     '\n'
                                     '   public void bar(String s, Object... '
                                     'args) {\n'
                                     '      // Ahh, varargs tastes much '
                                     'better...\n'
                                     '   }\n'
                                     '}\n'
                                     '        ',
                      'display_name': 'UseVarargs',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Consider using varargs for methods or '
                               'constructors which take an array the last '
                               'parameter.'},
    'UselessOperationOnImmutable': {   'categories': ['security'],
                                       'description': 'An operation on an '
                                                      'Immutable object '
                                                      '(String, BigDecimal or '
                                                      "BigInteger) won't "
                                                      'change the object '
                                                      'itself since the result '
                                                      'of the operation is a '
                                                      'new object. Therefore, '
                                                      'ignoring the operation '
                                                      'result is an error.\n'
                                                      'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/unnecessary.html#UselessOperationOnImmutable\n'
                                                      '\n'
                                                      '    \n'
                                                      'import java.math.*;\n'
                                                      '\n'
                                                      'class Test {\n'
                                                      '  void method1() {\n'
                                                      '    BigDecimal bd=new '
                                                      'BigDecimal(10);\n'
                                                      '    bd.add(new '
                                                      'BigDecimal(5)); \t\t// '
                                                      'this will trigger the '
                                                      'rule\n'
                                                      '  }\n'
                                                      '  void method2() {\n'
                                                      '    BigDecimal bd=new '
                                                      'BigDecimal(10);\n'
                                                      '    bd = bd.add(new '
                                                      'BigDecimal(5)); // this '
                                                      "won't trigger the rule\n"
                                                      '  }\n'
                                                      '}\n'
                                                      '    \n'
                                                      '      ',
                                       'display_name': 'UselessOperationOnImmutable',
                                       'file': '%(issue.file)s',
                                       'line': '%(issue.line)s',
                                       'severity': '1',
                                       'title': 'An operation on an Immutable '
                                                'object (String, BigDecimal or '
                                                "BigInteger) won't change the "
                                                'object itself'},
    'UselessOverridingMethod': {   'categories': ['security'],
                                   'description': 'The overriding method '
                                                  'merely calls the same '
                                                  'method defined in a '
                                                  'superclass.\n'
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/unnecessary.html#UselessOverridingMethod\n'
                                                  '\n'
                                                  'public void foo(String bar) '
                                                  '{\n'
                                                  '  super.foo(bar);      // '
                                                  'why bother overriding?\n'
                                                  '}\n'
                                                  '\n'
                                                  'public String foo() {\n'
                                                  '\treturn super.foo();  // '
                                                  'why bother overriding?\n'
                                                  '}\n'
                                                  '\n'
                                                  '@Id\n'
                                                  'public Long getId() {\n'
                                                  '  return super.getId();  // '
                                                  "OK if 'ignoreAnnotations' "
                                                  'is false, which is the '
                                                  'default behavior\n'
                                                  '}\n'
                                                  '        ',
                                   'display_name': 'UselessOverridingMethod',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': 'Overriding method merely calls '
                                            'super'},
    'UselessParentheses': {   'categories': ['security'],
                              'description': 'Useless parentheses should be '
                                             'removed.\n'
                                             'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/unnecessary.html#UselessParentheses\n'
                                             '\n'
                                             '    \n'
                                             'public class Foo {\n'
                                             '\n'
                                             '   private int _bar1;\n'
                                             '   private Integer _bar2;\n'
                                             '\n'
                                             '   public void setBar(int n) {\n'
                                             '      _bar1 = '
                                             'Integer.valueOf((n)); // here\n'
                                             '      _bar2 = (n); // and here\n'
                                             '   }\n'
                                             '\n'
                                             '}\n'
                                             '    \n'
                                             '    ',
                              'display_name': 'UselessParentheses',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'Useless parentheses.'},
    'UselessQualifiedThis': {   'categories': ['security'],
                                'description': 'Look for qualified this usages '
                                               'in the same class.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/unnecessary.html#UselessQualifiedThis\n'
                                               '\n'
                                               '    \n'
                                               'public class Foo {\n'
                                               '    final Foo otherFoo = '
                                               'Foo.this;  // use "this" '
                                               'directly\n'
                                               '\n'
                                               '    public void doSomething() '
                                               '{\n'
                                               '         final Foo anotherFoo '
                                               '= Foo.this;  // use "this" '
                                               'directly\n'
                                               '    }\n'
                                               '\n'
                                               '    private ActionListener '
                                               'returnListener() {\n'
                                               '        return new '
                                               'ActionListener() {\n'
                                               '            @Override\n'
                                               '            public void '
                                               'actionPerformed(ActionEvent e) '
                                               '{\n'
                                               '                '
                                               'doSomethingWithQualifiedThis(Foo.this);  '
                                               '// This is fine\n'
                                               '            }\n'
                                               '        };\n'
                                               '    }\n'
                                               '\n'
                                               '    private class Foo3 {\n'
                                               '        final Foo myFoo = '
                                               'Foo.this;  // This is fine\n'
                                               '    }\n'
                                               '\n'
                                               '    private class Foo2 {\n'
                                               '        final Foo2 myFoo2 = '
                                               'Foo2.this;  // Use "this" '
                                               'direclty\n'
                                               '    }\n'
                                               '}\n'
                                               '    \n'
                                               '    ',
                                'display_name': 'UselessQualifiedThis',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'Useless qualified this usage in the '
                                         'same class.'},
    'UselessStringValueOf': {   'categories': ['security'],
                                'description': 'No need to call String.valueOf '
                                               'to append to a string; just '
                                               'use the valueOf() argument '
                                               'directly.\n'
                                               'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/strings.html#UselessStringValueOf\n'
                                               '\n'
                                               '\n'
                                               'public String convert(int i) '
                                               '{\n'
                                               '\tString s;\n'
                                               '\ts = "a" + '
                                               'String.valueOf(i);\t// not '
                                               'required\n'
                                               '\ts = "a" + i; \t\t\t\t\t// '
                                               'preferred approach\n'
                                               '\treturn s;\n'
                                               '}\n'
                                               '\n'
                                               '          ',
                                'display_name': 'UselessStringValueOf',
                                'file': '%(issue.file)s',
                                'line': '%(issue.line)s',
                                'severity': '1',
                                'title': 'No need to call String.valueOf to '
                                         'append to a string.'},
    'VariableNamingConventions': {   'categories': ['security'],
                                     'description': 'A variable naming '
                                                    'conventions rule - '
                                                    'customize this to your '
                                                    'liking. Currently, it '
                                                    'checks for final '
                                                    'variables that should be '
                                                    'fully capitalized and '
                                                    'non-final variables that '
                                                    'should not include '
                                                    'underscores.\n'
                                                    'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/naming.html#VariableNamingConventions\n'
                                                    '\n'
                                                    '\n'
                                                    'public class Foo {\n'
                                                    '   public static final '
                                                    'int MY_NUM = 0;\n'
                                                    '   public String myTest = '
                                                    '"";\n'
                                                    '   DataModule dmTest = '
                                                    'new DataModule();\n'
                                                    '}\n'
                                                    '\n'
                                                    '        ',
                                     'display_name': 'VariableNamingConventions',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': '{0} variable {1} should begin '
                                              'with {2}'},
    'VfCsrf': {   'categories': ['security'],
                  'description': 'Avoid calling VF action upon page load as '
                                 'the action becomes vulnerable to CSRF.\n'
                                 'https://pmd.github.io/pmd-5.8.1/pmd-visualforce/rules/vf/security.html#VfCsrfRule\n'
                                 '\n'
                                 '\t\t\t \n'
                                 '<apex:page '
                                 'controller="AcRestActionsController" '
                                 'action="{!csrfInitMethod}" >\t\n'
                                 '\t\t \n'
                                 '\t\t',
                  'display_name': 'VfCsrf',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Avoid calling VF action upon page load'},
    'VfUnescapeEl': {   'categories': ['security'],
                        'description': 'Avoid unescaped user controlled '
                                       'content in EL as it results in XSS.\n'
                                       'https://pmd.github.io/pmd-5.8.1/pmd-visualforce/rules/vf/security.html#VfUnescapeElRule\n'
                                       '\n'
                                       '\t\t\t \n'
                                       '<apex:outputText value="Potential XSS '
                                       'is {! here }" escape="false" />\n'
                                       '\t\t\t \n'
                                       '\t\t',
                        'display_name': 'VfUnescapeEl',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Avoid unescaped user controlled content in '
                                 'EL'},
    'WhileLoopsMustUseBraces': {   'categories': ['security'],
                                   'description': "Avoid using 'while' "
                                                  'statements without using '
                                                  'braces to surround the code '
                                                  'block. If the code '
                                                  'formatting or indentation '
                                                  'is lost then it becomes '
                                                  'difficult to separate the '
                                                  'code being controlled from '
                                                  'the rest.\n'
                                                  'https://pmd.github.io/pmd-5.8.1/pmd-java/rules/java/braces.html#WhileLoopsMustUseBraces\n'
                                                  '\n'
                                                  '\n'
                                                  'while (true)\t// not '
                                                  'recommended\n'
                                                  '      x++;\n'
                                                  '      \n'
                                                  'while (true) {\t// '
                                                  'preferred approach\n'
                                                  '      x++;\n'
                                                  '}\n'
                                                  '\n'
                                                  '      ',
                                   'display_name': 'WhileLoopsMustUseBraces',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '1',
                                   'title': "Avoid using 'while' statements "
                                            'without curly braces'}}
