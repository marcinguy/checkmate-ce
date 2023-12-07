issues_data = {   'flawfinderAddAccessAllowedAce1': {   'categories': ['security'],
                                          'description': 'Make sure that you '
                                                         'set inheritance by '
                                                         'hand if you wish it '
                                                         'to inherit.\n',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'Make sure that you set '
                                                   'inheritance by hand if you '
                                                   'wish it to inherit.\n'},
    'flawfinderCreateProcess1': {   'categories': ['security'],
                                    'description': 'Specify the application '
                                                   'path in the first '
                                                   'argument, NOT as part of '
                                                   'the second, or embedded\n'
                                                   'spaces could allow an '
                                                   'attacker to force a '
                                                   'different program to '
                                                   'run.\n',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'Specify the application path in '
                                             'the first argument, NOT as part '
                                             'of the second, or embedded\n'
                                             'spaces could allow an attacker '
                                             'to force a different program to '
                                             'run.\n'},
    'flawfinderCreateProcessAsUser1CreateProcessWithLogon1': {   'categories': [   'security'],
                                                                 'description': 'Especially '
                                                                                'watch '
                                                                                'out '
                                                                                'for '
                                                                                'embedded '
                                                                                'spaces.\n',
                                                                 'file': '%(issue.file)s',
                                                                 'line': '%(issue.line)s',
                                                                 'severity': '1',
                                                                 'title': 'Especially '
                                                                          'watch '
                                                                          'out '
                                                                          'for '
                                                                          'embedded '
                                                                          'spaces.\n'},
    'flawfinderEVP_des_ecb1EVP_des_cbc1EVP_des_cfb1EVP_des_ofb1EVP_desx_cbc1': {   'categories': [   'security'],
                                                                                   'description': 'Use '
                                                                                                  'a '
                                                                                                  'different '
                                                                                                  'patent-free '
                                                                                                  'encryption '
                                                                                                  'algorithm '
                                                                                                  'with '
                                                                                                  'a '
                                                                                                  'larger '
                                                                                                  'keysize, '
                                                                                                  'such '
                                                                                                  'as '
                                                                                                  '3DES '
                                                                                                  'or '
                                                                                                  'AES.\n',
                                                                                   'file': '%(issue.file)s',
                                                                                   'line': '%(issue.line)s',
                                                                                   'severity': '1',
                                                                                   'title': 'Use '
                                                                                            'a '
                                                                                            'different '
                                                                                            'patent-free '
                                                                                            'encryption '
                                                                                            'algorithm '
                                                                                            'with '
                                                                                            'a '
                                                                                            'larger '
                                                                                            'keysize, '
                                                                                            'such '
                                                                                            'as '
                                                                                            '3DES '
                                                                                            'or '
                                                                                            'AES.\n'},
    'flawfinderEVP_rc4_401EVP_rc2_40_cbc1EVP_rc2_64_cbc1': {   'categories': [   'security'],
                                                               'description': 'Use '
                                                                              'a '
                                                                              'different '
                                                                              'patent-free '
                                                                              'encryption '
                                                                              'algorithm '
                                                                              'with '
                                                                              'a '
                                                                              'larger '
                                                                              'keysize, '
                                                                              'such '
                                                                              'as '
                                                                              '3DES '
                                                                              'or '
                                                                              'AES.\n',
                                                               'file': '%(issue.file)s',
                                                               'line': '%(issue.line)s',
                                                               'severity': '1',
                                                               'title': 'Use a '
                                                                        'different '
                                                                        'patent-free '
                                                                        'encryption '
                                                                        'algorithm '
                                                                        'with '
                                                                        'a '
                                                                        'larger '
                                                                        'keysize, '
                                                                        'such '
                                                                        'as '
                                                                        '3DES '
                                                                        'or '
                                                                        'AES.\n'},
    'flawfinderGetTempFileName1': {   'categories': ['security'],
                                      'description': 'Temporary file race '
                                                     'condition in certain '
                                                     'cases.\n',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'Temporary file race condition '
                                               'in certain cases.\n'},
    'flawfinderInitializeCriticalSection1': {   'categories': ['security'],
                                                'description': 'Use '
                                                               'InitializeCriticalSectionAndSpinCount '
                                                               'instead.\n',
                                                'file': '%(issue.file)s',
                                                'line': '%(issue.line)s',
                                                'severity': '1',
                                                'title': 'Use '
                                                         'InitializeCriticalSectionAndSpinCount '
                                                         'instead.\n'},
    'flawfinderLoadLibrary1': {   'categories': ['security'],
                                  'description': 'Use LoadLibraryEx with one '
                                                 'of the search flags, or call '
                                                 'SetSearchPathMode to use a '
                                                 'safe search\n'
                                                 'path, or pass a full path to '
                                                 'the library.\n',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'Use LoadLibraryEx with one of the '
                                           'search flags, or call '
                                           'SetSearchPathMode to use a safe '
                                           'search\n'
                                           'path, or pass a full path to the '
                                           'library.\n'},
    'flawfinderLoadLibraryEx1': {   'categories': ['security'],
                                    'description': 'Use a flag like '
                                                   'LOAD_LIBRARY_SEARCH_SYSTEM32 '
                                                   'or '
                                                   'LOAD_LIBRARY_SEARCH_APPLICATION_DIR '
                                                   'to search\n'
                                                   'only desired folders.\n',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'Use a flag like '
                                             'LOAD_LIBRARY_SEARCH_SYSTEM32 or '
                                             'LOAD_LIBRARY_SEARCH_APPLICATION_DIR '
                                             'to search\n'
                                             'only desired folders.\n'},
    'flawfinderMultiByteToWideChar1': {   'categories': ['security'],
                                          'description': 'The software does '
                                                         'not properly handle '
                                                         'when an input '
                                                         'contains Unicode '
                                                         'encoding.\n',
                                          'file': '%(issue.file)s',
                                          'line': '%(issue.line)s',
                                          'severity': '1',
                                          'title': 'The software does not '
                                                   'properly handle when an '
                                                   'input contains Unicode '
                                                   'encoding.\n'},
    'flawfinderRpcImpersonateClient1ImpersonateLoggedOnUser1CoImpersonateClient1ImpersonateNamedPipeClient1ImpersonateDdeClientWindow1ImpersonateSecurityContext1SetThreadToken1': {   'categories': [   'security'],
                                                                                                                                                                                       'description': 'Make '
                                                                                                                                                                                                      'sure '
                                                                                                                                                                                                      'the '
                                                                                                                                                                                                      'return '
                                                                                                                                                                                                      'value '
                                                                                                                                                                                                      'is '
                                                                                                                                                                                                      'checked, '
                                                                                                                                                                                                      'and '
                                                                                                                                                                                                      'do '
                                                                                                                                                                                                      'not '
                                                                                                                                                                                                      'continue '
                                                                                                                                                                                                      'if '
                                                                                                                                                                                                      'a '
                                                                                                                                                                                                      'failure '
                                                                                                                                                                                                      'is '
                                                                                                                                                                                                      'reported.\n',
                                                                                                                                                                                       'file': '%(issue.file)s',
                                                                                                                                                                                       'line': '%(issue.line)s',
                                                                                                                                                                                       'severity': '1',
                                                                                                                                                                                       'title': 'Make '
                                                                                                                                                                                                'sure '
                                                                                                                                                                                                'the '
                                                                                                                                                                                                'return '
                                                                                                                                                                                                'value '
                                                                                                                                                                                                'is '
                                                                                                                                                                                                'checked, '
                                                                                                                                                                                                'and '
                                                                                                                                                                                                'do '
                                                                                                                                                                                                'not '
                                                                                                                                                                                                'continue '
                                                                                                                                                                                                'if '
                                                                                                                                                                                                'a '
                                                                                                                                                                                                'failure '
                                                                                                                                                                                                'is '
                                                                                                                                                                                                'reported.\n'},
    'flawfinderSetSecurityDescriptorDacl1': {   'categories': ['security'],
                                                'description': 'Never create '
                                                               'NULL ACLs; an '
                                                               'attacker can '
                                                               'set it to '
                                                               'Everyone '
                                                               '(Deny\n'
                                                               'All Access)\n',
                                                'file': '%(issue.file)s',
                                                'line': '%(issue.line)s',
                                                'severity': '1',
                                                'title': 'Never create NULL '
                                                         'ACLs; an attacker '
                                                         'can set it to '
                                                         'Everyone (Deny\n'
                                                         'All Access)\n'},
    'flawfinderStrCat1StrCatA1StrcatW1lstrcatA1lstrcatW1strCatBuff1StrCatBuffA1StrCatBuffW1StrCatChainW1_tccat1_mbccat1_ftcscat1StrCatN1StrCatNA1StrCatNW1StrNCat1StrNCatA1StrNCatW1lstrncat1lstrcatnA1lstrcatnW1': {   'categories': [   'security'],
                                                                                                                                                                                                                        'description': 'Buffer '
                                                                                                                                                                                                                                       'overflow '
                                                                                                                                                                                                                                       'is '
                                                                                                                                                                                                                                       'not '
                                                                                                                                                                                                                                       'checked.\n',
                                                                                                                                                                                                                        'file': '%(issue.file)s',
                                                                                                                                                                                                                        'line': '%(issue.line)s',
                                                                                                                                                                                                                        'severity': '1',
                                                                                                                                                                                                                        'title': 'Buffer '
                                                                                                                                                                                                                                 'overflow '
                                                                                                                                                                                                                                 'is '
                                                                                                                                                                                                                                 'not '
                                                                                                                                                                                                                                 'checked.\n'},
    'flawfinderaccess1': {   'categories': ['security'],
                             'description': 'Set up the correct permissions '
                                            '(e.g., using setuid()) and try to '
                                            'open the file directly.\n',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Set up the correct permissions (e.g., '
                                      'using setuid()) and try to open the '
                                      'file directly.\n'},
    'flawfinderatoi1atol1_wtoi1_wtoi641': {   'categories': ['security'],
                                              'description': 'If source '
                                                             'untrusted, check '
                                                             'both minimum and '
                                                             'maximum, even if '
                                                             'the input had no '
                                                             'minus sign '
                                                             '(large\n'
                                                             'numbers can roll '
                                                             'over into '
                                                             'negative number; '
                                                             'consider saving '
                                                             'to an unsigned '
                                                             'value if that '
                                                             'is\n'
                                                             'intended).\n',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '1',
                                              'title': 'If source untrusted, '
                                                       'check both minimum and '
                                                       'maximum, even if the '
                                                       'input had no minus '
                                                       'sign (large\n'
                                                       'numbers can roll over '
                                                       'into negative number; '
                                                       'consider saving to an '
                                                       'unsigned value if that '
                                                       'is\n'
                                                       'intended).\n'},
    'flawfinderchar1TCHAR1wchar_t1': {   'categories': ['security'],
                                         'description': 'Perform bounds '
                                                        'checking, use '
                                                        'functions that limit '
                                                        'length, or ensure '
                                                        'that the size is '
                                                        'larger\n'
                                                        'than the maximum '
                                                        'possible length.\n',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'Perform bounds checking, '
                                                  'use functions that limit '
                                                  'length, or ensure that the '
                                                  'size is larger\n'
                                                  'than the maximum possible '
                                                  'length.\n'},
    'flawfinderchgrp1': {   'categories': ['security'],
                            'description': 'Use fchgrp( ) instead.\n',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'Use fchgrp( ) instead.\n'},
    'flawfinderchmod1': {   'categories': ['security'],
                            'description': 'Use fchmod( ) instead.\n',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'Use fchmod( ) instead.\n'},
    'flawfinderchown1': {   'categories': ['security'],
                            'description': 'Use fchown( ) instead.\n',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'Use fchown( ) instead.\n'},
    'flawfinderchroot1': {   'categories': ['security'],
                             'description': 'Make sure the program immediately '
                                            'chdir("/"), closes file '
                                            'descriptors, and drops root\n'
                                            'privileges, and that all '
                                            'necessary files (and no more!) '
                                            'are in the new root.\n',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Make sure the program immediately '
                                      'chdir("/"), closes file descriptors, '
                                      'and drops root\n'
                                      'privileges, and that all necessary '
                                      'files (and no more!) are in the new '
                                      'root.\n'},
    'flawfindercrypt1crypt_r1': {   'categories': ['security'],
                                    'description': 'Use a different algorithm, '
                                                   'such as SHA-256, with a '
                                                   'larger, non-repeating '
                                                   'salt.\n',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'Use a different algorithm, such '
                                             'as SHA-256, with a larger, '
                                             'non-repeating salt.\n'},
    'flawfindercuserid1': {   'categories': ['security'],
                              'description': 'Use getpwuid(geteuid()) and '
                                             'extract the desired information '
                                             'instead.\n',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'Use getpwuid(geteuid()) and extract '
                                       'the desired information instead.\n'},
    'flawfinderdrand481erand481jrand481lcong481lrand481mrand481nrand481random1seed481setstate1srand1strfry1srandom1g_rand_boolean1g_rand_int1g_rand_int_range1g_rand_double1g_rand_double_range1g_random_boolean1g_random_int1g_random_int_range1g_random_double1g_random_double_range1': {   'categories': [   'security'],
                                                                                                                                                                                                                                                                                              'description': 'Use '
                                                                                                                                                                                                                                                                                                             'a '
                                                                                                                                                                                                                                                                                                             'more '
                                                                                                                                                                                                                                                                                                             'secure '
                                                                                                                                                                                                                                                                                                             'technique '
                                                                                                                                                                                                                                                                                                             'for '
                                                                                                                                                                                                                                                                                                             'acquiring '
                                                                                                                                                                                                                                                                                                             'random '
                                                                                                                                                                                                                                                                                                             'values.\n',
                                                                                                                                                                                                                                                                                              'file': '%(issue.file)s',
                                                                                                                                                                                                                                                                                              'line': '%(issue.line)s',
                                                                                                                                                                                                                                                                                              'severity': '1',
                                                                                                                                                                                                                                                                                              'title': 'Use '
                                                                                                                                                                                                                                                                                                       'a '
                                                                                                                                                                                                                                                                                                       'more '
                                                                                                                                                                                                                                                                                                       'secure '
                                                                                                                                                                                                                                                                                                       'technique '
                                                                                                                                                                                                                                                                                                       'for '
                                                                                                                                                                                                                                                                                                       'acquiring '
                                                                                                                                                                                                                                                                                                       'random '
                                                                                                                                                                                                                                                                                                       'values.\n'},
    'flawfinderequal1mismatch1is_permutation1': {   'categories': ['security'],
                                                    'description': 'This '
                                                                   'function '
                                                                   'is often '
                                                                   'discouraged '
                                                                   'by most '
                                                                   'C++ coding '
                                                                   'standards '
                                                                   'in favor '
                                                                   'of its '
                                                                   'safer\n'
                                                                   'alternatives '
                                                                   'provided '
                                                                   'since '
                                                                   'C++14. '
                                                                   'Consider '
                                                                   'using a '
                                                                   'form of '
                                                                   'this '
                                                                   'function '
                                                                   'that '
                                                                   'checks '
                                                                   'the\n'
                                                                   'second '
                                                                   'iterator '
                                                                   'before '
                                                                   'potentially '
                                                                   'overflowing '
                                                                   'it.\n',
                                                    'file': '%(issue.file)s',
                                                    'line': '%(issue.line)s',
                                                    'severity': '1',
                                                    'title': 'This function is '
                                                             'often '
                                                             'discouraged by '
                                                             'most C++ coding '
                                                             'standards in '
                                                             'favor of its '
                                                             'safer\n'
                                                             'alternatives '
                                                             'provided since '
                                                             'C++14. Consider '
                                                             'using a form of '
                                                             'this function '
                                                             'that checks the\n'
                                                             'second iterator '
                                                             'before '
                                                             'potentially '
                                                             'overflowing '
                                                             'it.\n'},
    'flawfinderexecl1execlp1execle1execv1execvp1popen1WinExec1ShellExecute1': {   'categories': [   'security'],
                                                                                  'description': 'try '
                                                                                                 'using '
                                                                                                 'a '
                                                                                                 'library '
                                                                                                 'call '
                                                                                                 'that '
                                                                                                 'implements '
                                                                                                 'the '
                                                                                                 'same '
                                                                                                 'functionality '
                                                                                                 'if '
                                                                                                 'available.\n',
                                                                                  'file': '%(issue.file)s',
                                                                                  'line': '%(issue.line)s',
                                                                                  'severity': '1',
                                                                                  'title': 'try '
                                                                                           'using '
                                                                                           'a '
                                                                                           'library '
                                                                                           'call '
                                                                                           'that '
                                                                                           'implements '
                                                                                           'the '
                                                                                           'same '
                                                                                           'functionality '
                                                                                           'if '
                                                                                           'available.\n'},
    'flawfinderfopen1open1': {   'categories': ['security'],
                                 'description': 'Check when opening files - '
                                                'can an attacker redirect it '
                                                '(via symlinks).\n',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '1',
                                 'title': 'Check when opening files - can an '
                                          'attacker redirect it (via '
                                          'symlinks).\n'},
    'flawfinderfprintf1vfprintf1_ftprintf1_vftprintf1fwprintf1fvwprintf1': {   'categories': [   'security'],
                                                                               'description': 'Use '
                                                                                              'a '
                                                                                              'constant '
                                                                                              'for '
                                                                                              'the '
                                                                                              'format '
                                                                                              'specification.\n',
                                                                               'file': '%(issue.file)s',
                                                                               'line': '%(issue.line)s',
                                                                               'severity': '1',
                                                                               'title': 'Use '
                                                                                        'a '
                                                                                        'constant '
                                                                                        'for '
                                                                                        'the '
                                                                                        'format '
                                                                                        'specification.\n'},
    'flawfinderfscanf1sscanf1vsscanf1vfscanf1_ftscanf1fwscanf1vfwscanf1vswscanf1': {   'categories': [   'security'],
                                                                                       'description': 'Specify '
                                                                                                      'a '
                                                                                                      'limit '
                                                                                                      'to '
                                                                                                      '%s, '
                                                                                                      'or '
                                                                                                      'use '
                                                                                                      'a '
                                                                                                      'different '
                                                                                                      'input '
                                                                                                      'function.\n',
                                                                                       'file': '%(issue.file)s',
                                                                                       'line': '%(issue.line)s',
                                                                                       'severity': '1',
                                                                                       'title': 'Specify '
                                                                                                'a '
                                                                                                'limit '
                                                                                                'to '
                                                                                                '%s, '
                                                                                                'or '
                                                                                                'use '
                                                                                                'a '
                                                                                                'different '
                                                                                                'input '
                                                                                                'function.\n'},
    'flawfinderg_get_home_dir1': {   'categories': ['security'],
                                     'description': 'Check environment '
                                                    'variables carefully '
                                                    'before using them.\n',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'Check environment variables '
                                              'carefully before using them.\n'},
    'flawfinderg_get_tmp_dir1': {   'categories': ['security'],
                                    'description': 'Check environment '
                                                   'variables carefully before '
                                                   'using them.\n',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '1',
                                    'title': 'Check environment variables '
                                             'carefully before using them.\n'},
    'flawfindergetchar1fgetc1getc1read1_gettc1': {   'categories': ['security'],
                                                     'description': 'CWE-20: '
                                                                    'Check '
                                                                    'buffer '
                                                                    'boundaries '
                                                                    'if used '
                                                                    'in a loop '
                                                                    'including '
                                                                    'recursive '
                                                                    'loops\n',
                                                     'file': '%(issue.file)s',
                                                     'line': '%(issue.line)s',
                                                     'severity': '1',
                                                     'title': 'CWE-20: Check '
                                                              'buffer '
                                                              'boundaries if '
                                                              'used in a loop '
                                                              'including '
                                                              'recursive '
                                                              'loops\n'},
    'flawfindergetenv1curl_getenv1': {   'categories': ['security'],
                                         'description': 'Check environment '
                                                        'variables carefully '
                                                        'before using them.\n',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'Check environment variables '
                                                  'carefully before using '
                                                  'them.\n'},
    'flawfindergetlogin1': {   'categories': ['security'],
                               'description': 'Use getpwuid(geteuid()) and '
                                              'extract the desired information '
                                              'instead.\n',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Use getpwuid(geteuid()) and extract '
                                        'the desired information instead.\n'},
    'flawfindergetopt1getopt_long1': {   'categories': ['security'],
                                         'description': 'Check implementation '
                                                        'on installation, or '
                                                        'limit the size of all '
                                                        'string inputs.\n',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '1',
                                         'title': 'Check implementation on '
                                                  'installation, or limit the '
                                                  'size of all string '
                                                  'inputs.\n'},
    'flawfindergetpass1': {   'categories': ['security'],
                              'description': 'Make the specific calls to do '
                                             'exactly what you want.  If you '
                                             'continue to use it, or write '
                                             'your\n'
                                             'own, be sure to zero the '
                                             'password as soon as possible to '
                                             'avoid leaving the cleartext '
                                             'password\n'
                                             "visible in the process' address "
                                             'space.\n',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'Make the specific calls to do exactly '
                                       'what you want.  If you continue to use '
                                       'it, or write your\n'
                                       'own, be sure to zero the password as '
                                       'soon as possible to avoid leaving the '
                                       'cleartext password\n'
                                       "visible in the process' address "
                                       'space.\n'},
    'flawfindergetpw1': {   'categories': ['security'],
                            'description': 'Use getpwuid() instead.\n',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'Use getpwuid() instead.\n'},
    'flawfindergets1_getts1': {   'categories': ['security'],
                                  'description': 'Use fgets() instead.\n',
                                  'file': '%(issue.file)s',
                                  'line': '%(issue.line)s',
                                  'severity': '1',
                                  'title': 'Use fgets() instead.\n'},
    'flawfindergetwd1': {   'categories': ['security'],
                            'description': 'Use getcwd instead.\n',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'Use getcwd instead.\n'},
    'flawfindergsignal1ssignal1': {   'categories': ['security'],
                                      'description': 'Switch to raise/signal, '
                                                     'or some other signalling '
                                                     'approach.\n',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'Switch to raise/signal, or '
                                               'some other signalling '
                                               'approach.\n'},
    'flawfinderlstrcat1wcscat1_tcscat1_mbscat1': {   'categories': ['security'],
                                                     'description': 'Buffer '
                                                                    'overflows '
                                                                    'is not '
                                                                    'checked\n',
                                                     'file': '%(issue.file)s',
                                                     'line': '%(issue.line)s',
                                                     'severity': '1',
                                                     'title': 'Buffer '
                                                              'overflows is '
                                                              'not checked\n'},
    'flawfinderlstrcatn1wcsncat1_tcsncat1_mbsnbcat1': {   'categories': [   'security'],
                                                          'description': 'Consider '
                                                                         'strcat_s, '
                                                                         'strlcat, '
                                                                         'or '
                                                                         'automatically '
                                                                         'resizing '
                                                                         'strings.\n',
                                                          'file': '%(issue.file)s',
                                                          'line': '%(issue.line)s',
                                                          'severity': '1',
                                                          'title': 'Consider '
                                                                   'strcat_s, '
                                                                   'strlcat, '
                                                                   'or '
                                                                   'automatically '
                                                                   'resizing '
                                                                   'strings.\n'},
    'flawfinderlstrcpy1wcscpy1_tcscpy1_mbscpy1': {   'categories': ['security'],
                                                     'description': 'Consider '
                                                                    'using a '
                                                                    'function '
                                                                    'version '
                                                                    'that '
                                                                    'stops '
                                                                    'copying '
                                                                    'at the '
                                                                    'end of '
                                                                    'the '
                                                                    'buffer.\n',
                                                     'file': '%(issue.file)s',
                                                     'line': '%(issue.line)s',
                                                     'severity': '1',
                                                     'title': 'Consider using '
                                                              'a function '
                                                              'version that '
                                                              'stops copying '
                                                              'at the end of '
                                                              'the buffer.\n'},
    'flawfinderlstrcpyn1wcsncpy1_tcsncpy1_mbsnbcpy1': {   'categories': [   'security'],
                                                          'description': 'Easily '
                                                                         'used '
                                                                         'incorrectly\n',
                                                          'file': '%(issue.file)s',
                                                          'line': '%(issue.line)s',
                                                          'severity': '1',
                                                          'title': 'Easily '
                                                                   'used '
                                                                   'incorrectly\n'},
    'flawfindermemalign1': {   'categories': ['security'],
                               'description': 'Use posix_memalign instead '
                                              "(defined in POSIX's 1003.1d).  "
                                              "Don't switch to valloc(); it "
                                              'is\n'
                                              'marked as obsolete in BSD 4.3, '
                                              'as legacy in SUSv2, and is no '
                                              'longer defined in SUSv3.  In '
                                              'some\n'
                                              "cases, malloc()'s alignment may "
                                              'be sufficient.\n',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Use posix_memalign instead (defined '
                                        "in POSIX's 1003.1d).  Don't switch to "
                                        'valloc(); it is\n'
                                        'marked as obsolete in BSD 4.3, as '
                                        'legacy in SUSv2, and is no longer '
                                        'defined in SUSv3.  In some\n'
                                        "cases, malloc()'s alignment may be "
                                        'sufficient.\n'},
    'flawfindermemcpy1CopyMemory1bcopy1': {   'categories': ['security'],
                                              'description': 'Make sure '
                                                             'destination can '
                                                             'always hold the '
                                                             'source data.\n',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '1',
                                              'title': 'Make sure destination '
                                                       'can always hold the '
                                                       'source data.\n'},
    'flawfindermkstemp1': {   'categories': ['security'],
                              'description': 'Some older Unix-like systems '
                                             'create temp files with '
                                             'permission to write by\n'
                                             'all by default, so be sure to '
                                             'set the umask to override this. '
                                             'Also, some older\n'
                                             'Unix systems might fail to use '
                                             'O_EXCL when opening the file, so '
                                             'make sure that\n'
                                             'O_EXCL is used by the library.\n',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'Some older Unix-like systems create '
                                       'temp files with permission to write '
                                       'by\n'
                                       'all by default, so be sure to set the '
                                       'umask to override this. Also, some '
                                       'older\n'
                                       'Unix systems might fail to use O_EXCL '
                                       'when opening the file, so make sure '
                                       'that\n'
                                       'O_EXCL is used by the library.\n'},
    'flawfindermktemp1': {   'categories': ['security'],
                             'description': 'Creating and using insecure '
                                            'temporary files can leave '
                                            'application and system data '
                                            'vulnerable to\n'
                                            'attack (CWE-377).\n',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Creating and using insecure temporary '
                                      'files can leave application and system '
                                      'data vulnerable to\n'
                                      'attack (CWE-377).\n'},
    'flawfinderprintf1vprintf1vwprintf1vfwprintf1_vtprintf1wprintf1': {   'categories': [   'security'],
                                                                          'description': 'Use '
                                                                                         'a '
                                                                                         'constant '
                                                                                         'for '
                                                                                         'the '
                                                                                         'format '
                                                                                         'specification.\n',
                                                                          'file': '%(issue.file)s',
                                                                          'line': '%(issue.line)s',
                                                                          'severity': '1',
                                                                          'title': 'Use '
                                                                                   'a '
                                                                                   'constant '
                                                                                   'for '
                                                                                   'the '
                                                                                   'format '
                                                                                   'specification.\n'},
    'flawfinderreadlink1': {   'categories': ['security'],
                               'description': 'Reconsider approach.\n',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Reconsider approach.\n'},
    'flawfinderrealpath1': {   'categories': ['security'],
                               'description': 'Ensure that the destination '
                                              'buffer is at least of size '
                                              'MAXPATHLEN, andto protect '
                                              'against\n'
                                              'implementation problems, the '
                                              'input argument should also be '
                                              'checked to ensure it is no '
                                              'larger\n'
                                              'than MAXPATHLEN.\n',
                               'file': '%(issue.file)s',
                               'line': '%(issue.line)s',
                               'severity': '1',
                               'title': 'Ensure that the destination buffer is '
                                        'at least of size MAXPATHLEN, andto '
                                        'protect against\n'
                                        'implementation problems, the input '
                                        'argument should also be checked to '
                                        'ensure it is no larger\n'
                                        'than MAXPATHLEN.\n'},
    'flawfinderscanf1vscanf1wscanf1_tscanf1vwscanf1': {   'categories': [   'security'],
                                                          'description': 'Specify '
                                                                         'a '
                                                                         'limit '
                                                                         'to '
                                                                         '%s, '
                                                                         'or '
                                                                         'use '
                                                                         'a '
                                                                         'different '
                                                                         'input '
                                                                         'function.\n',
                                                          'file': '%(issue.file)s',
                                                          'line': '%(issue.line)s',
                                                          'severity': '1',
                                                          'title': 'Specify a '
                                                                   'limit to '
                                                                   '%s, or use '
                                                                   'a '
                                                                   'different '
                                                                   'input '
                                                                   'function.\n'},
    'flawfindersnprintf1vsnprintf1_snprintf1_sntprintf1_vsntprintf1': {   'categories': [   'security'],
                                                                          'description': 'Use '
                                                                                         'a '
                                                                                         'constant '
                                                                                         'for '
                                                                                         'the '
                                                                                         'format '
                                                                                         'specification.\n',
                                                                          'file': '%(issue.file)s',
                                                                          'line': '%(issue.line)s',
                                                                          'severity': '1',
                                                                          'title': 'Use '
                                                                                   'a '
                                                                                   'constant '
                                                                                   'for '
                                                                                   'the '
                                                                                   'format '
                                                                                   'specification.\n'},
    'flawfindersprintf1vsprintf1swprintf1vswprintf1_stprintf1_vstprintf1': {   'categories': [   'security'],
                                                                               'description': 'Use '
                                                                                              'sprintf_s, '
                                                                                              'snprintf, '
                                                                                              'or '
                                                                                              'vsnprintf.\n',
                                                                               'file': '%(issue.file)s',
                                                                               'line': '%(issue.line)s',
                                                                               'severity': '1',
                                                                               'title': 'Use '
                                                                                        'sprintf_s, '
                                                                                        'snprintf, '
                                                                                        'or '
                                                                                        'vsnprintf.\n'},
    'flawfinderstrcat1': {   'categories': ['security'],
                             'description': 'Consider using strcat_s, strncat, '
                                            'strlcat, or snprintf (warning: '
                                            'strncat is easily misused).\n',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Consider using strcat_s, strncat, '
                                      'strlcat, or snprintf (warning: strncat '
                                      'is easily misused).\n'},
    'flawfinderstrccpy1strcadd1': {   'categories': ['security'],
                                      'description': 'Ensure that destination '
                                                     'buffer is sufficiently '
                                                     'large.\n',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'Ensure that destination buffer '
                                               'is sufficiently large.\n'},
    'flawfinderstrcpy1': {   'categories': ['security'],
                             'description': 'Consider using snprintf, '
                                            'strcpy_s, or strlcpy (warning: '
                                            'strncpy easily misused).\n',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Consider using snprintf, strcpy_s, or '
                                      'strlcpy (warning: strncpy easily '
                                      'misused).\n'},
    'flawfinderstrcpyA1strcpyW1StrCpy1StrCpyA1lstrcpyA1lstrcpyW1_tccpy1_mbccpy1_ftcscpy1_mbsncpy1StrCpyN1StrCpyNA1StrCpyNW1StrNCpy1strcpynA1StrNCpyA1StrNCpyW1lstrcpynA1lstrcpynW1': {   'categories': [   'security'],
                                                                                                                                                                                         'description': 'Consider '
                                                                                                                                                                                                        'using '
                                                                                                                                                                                                        'snprintf, '
                                                                                                                                                                                                        'strcpy_s, '
                                                                                                                                                                                                        'or '
                                                                                                                                                                                                        'strlcpy '
                                                                                                                                                                                                        '(warning: '
                                                                                                                                                                                                        'strncpy '
                                                                                                                                                                                                        'easily '
                                                                                                                                                                                                        'misused).\n',
                                                                                                                                                                                         'file': '%(issue.file)s',
                                                                                                                                                                                         'line': '%(issue.line)s',
                                                                                                                                                                                         'severity': '1',
                                                                                                                                                                                         'title': 'Consider '
                                                                                                                                                                                                  'using '
                                                                                                                                                                                                  'snprintf, '
                                                                                                                                                                                                  'strcpy_s, '
                                                                                                                                                                                                  'or '
                                                                                                                                                                                                  'strlcpy '
                                                                                                                                                                                                  '(warning: '
                                                                                                                                                                                                  'strncpy '
                                                                                                                                                                                                  'easily '
                                                                                                                                                                                                  'misused).\n'},
    'flawfinderstreadd1strecpy1': {   'categories': ['security'],
                                      'description': 'Ensure the destination '
                                                     'has 4 times the size of '
                                                     'the source, to leave '
                                                     'room for expansion.\n',
                                      'file': '%(issue.file)s',
                                      'line': '%(issue.line)s',
                                      'severity': '1',
                                      'title': 'Ensure the destination has 4 '
                                               'times the size of the source, '
                                               'to leave room for '
                                               'expansion.\n'},
    'flawfinderstrlen1wcslen1_tcslen1_mbslen1': {   'categories': ['security'],
                                                    'description': 'Does not '
                                                                   'handle '
                                                                   'strings '
                                                                   'that are '
                                                                   'not '
                                                                   '\\\\0-terminated.\n',
                                                    'file': '%(issue.file)s',
                                                    'line': '%(issue.line)s',
                                                    'severity': '1',
                                                    'title': 'Does not handle '
                                                             'strings that are '
                                                             'not '
                                                             '\\\\0-terminated.\n'},
    'flawfinderstrncat1': {   'categories': ['security'],
                              'description': 'Consider strcat_s, strlcat, '
                                             'snprintf, or automatically '
                                             'resizing strings.\n',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'Consider strcat_s, strlcat, snprintf, '
                                       'or automatically resizing strings.\n'},
    'flawfinderstrncpy1': {   'categories': ['security'],
                              'description': 'Easily used incorrectly\n',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'Easily used incorrectly\n'},
    'flawfinderstrtrns1': {   'categories': ['security'],
                              'description': 'Ensure that destination is at '
                                             'least as long as the source.\n',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'Ensure that destination is at least as '
                                       'long as the source.\n'},
    'flawfindersyslog1': {   'categories': ['security'],
                             'description': 'Use a constant format string for '
                                            'syslog.\n',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Use a constant format string for '
                                      'syslog.\n'},
    'flawfindersystem1': {   'categories': ['security'],
                             'description': 'try using a library call that '
                                            'implements the same functionality '
                                            'if available.\n',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'try using a library call that '
                                      'implements the same functionality if '
                                      'available.\n'},
    'flawfindertmpfile1': {   'categories': ['security'],
                              'description': 'Creating and using insecure '
                                             'temporary files can leave '
                                             'application and system data '
                                             'vulnerable to\n'
                                             'attack\n',
                              'file': '%(issue.file)s',
                              'line': '%(issue.line)s',
                              'severity': '1',
                              'title': 'Creating and using insecure temporary '
                                       'files can leave application and system '
                                       'data vulnerable to\n'
                                       'attack\n'},
    'flawfindertmpnam1tempnam1': {   'categories': ['security'],
                                     'description': 'Creating and using '
                                                    'insecure temporary files '
                                                    'can leave application and '
                                                    'system data vulnerable '
                                                    'to\n'
                                                    'attack.\n',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '1',
                                     'title': 'Creating and using insecure '
                                              'temporary files can leave '
                                              'application and system data '
                                              'vulnerable to\n'
                                              'attack.\n'},
    'flawfinderulimit1': {   'categories': ['security'],
                             'description': 'Use getrlimit(2), setrlimit(2), '
                                            'and sysconf(3) instead.\n',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Use getrlimit(2), setrlimit(2), and '
                                      'sysconf(3) instead.\n'},
    'flawfinderumask1': {   'categories': ['security'],
                            'description': 'Ensure that umask is given most '
                                           'restrictive possible setting '
                                           '(e.g.,\n'
                                           '066 or 077)\n',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'Ensure that umask is given most '
                                     'restrictive possible setting (e.g.,\n'
                                     '066 or 077)\n'},
    'flawfinderusleep1': {   'categories': ['security'],
                             'description': 'Use nanosleep(2) or setitimer(2) '
                                            'instead.\n',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '1',
                             'title': 'Use nanosleep(2) or setitimer(2) '
                                      'instead.\n'},
    'flawfindervfork1': {   'categories': ['security'],
                            'description': 'Use fork() instead.\n',
                            'file': '%(issue.file)s',
                            'line': '%(issue.line)s',
                            'severity': '1',
                            'title': 'Use fork() instead.\n'}}
