# -*- coding: utf-8 -*-


issues_data = {
  "flawfinderdrand481erand481jrand481lcong481lrand481mrand481nrand481random1seed481setstate1srand1strfry1srandom1g_rand_boolean1g_rand_int1g_rand_int_range1g_rand_double1g_rand_double_range1g_random_boolean1g_random_int1g_random_int_range1g_random_double1g_random_double_range1": {
    "title": "Use a more secure technique for acquiring random values.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use a more secure technique for acquiring random values.\n"
  },
  "flawfindermkstemp1": {
    "title": "Some older Unix-like systems create temp files with permission to write by\nall by default, so be sure to set the umask to override this. Also, some older\nUnix systems might fail to use O_EXCL when opening the file, so make sure that\nO_EXCL is used by the library.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Some older Unix-like systems create temp files with permission to write by\nall by default, so be sure to set the umask to override this. Also, some older\nUnix systems might fail to use O_EXCL when opening the file, so make sure that\nO_EXCL is used by the library.\n"
  },
  "flawfinderfopen1open1": {
    "title": "Check when opening files - can an attacker redirect it (via symlinks).\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Check when opening files - can an attacker redirect it (via symlinks).\n"
  },
  "flawfindersnprintf1vsnprintf1_snprintf1_sntprintf1_vsntprintf1": {
    "title": "Use a constant for the format specification.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use a constant for the format specification.\n"
  },
  "flawfinderlstrcat1wcscat1_tcscat1_mbscat1": {
    "title": "Buffer overflows is not checked\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Buffer overflows is not checked\n"
  },
  "flawfinderlstrcpyn1wcsncpy1_tcsncpy1_mbsnbcpy1": {
    "title": "Easily used incorrectly\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Easily used incorrectly\n"
  },
  "flawfinderulimit1": {
    "title": "Use getrlimit(2), setrlimit(2), and sysconf(3) instead.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use getrlimit(2), setrlimit(2), and sysconf(3) instead.\n"
  },
  "flawfindercuserid1": {
    "title": "Use getpwuid(geteuid()) and extract the desired information instead.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use getpwuid(geteuid()) and extract the desired information instead.\n"
  },
  "flawfindersyslog1": {
    "title": "Use a constant format string for syslog.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use a constant format string for syslog.\n"
  },
  "flawfinderstrncat1": {
    "title": "Consider strcat_s, strlcat, snprintf, or automatically resizing strings.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Consider strcat_s, strlcat, snprintf, or automatically resizing strings.\n"
  },
  "flawfinderstrlen1wcslen1_tcslen1_mbslen1": {
    "title": "Does not handle strings that are not \\\\0-terminated.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Does not handle strings that are not \\\\0-terminated.\n"
  },
  "flawfindergetchar1fgetc1getc1read1_gettc1": {
    "title": "CWE-20: Check buffer boundaries if used in a loop including recursive loops\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "CWE-20: Check buffer boundaries if used in a loop including recursive loops\n"
  },
  "flawfinderStrCat1StrCatA1StrcatW1lstrcatA1lstrcatW1strCatBuff1StrCatBuffA1StrCatBuffW1StrCatChainW1_tccat1_mbccat1_ftcscat1StrCatN1StrCatNA1StrCatNW1StrNCat1StrNCatA1StrNCatW1lstrncat1lstrcatnA1lstrcatnW1": {
    "title": "Buffer overflow is not checked.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Buffer overflow is not checked.\n"
  },
  "flawfinderEVP_rc4_401EVP_rc2_40_cbc1EVP_rc2_64_cbc1": {
    "title": "Use a different patent-free encryption algorithm with a larger keysize, such as 3DES or AES.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use a different patent-free encryption algorithm with a larger keysize, such as 3DES or AES.\n"
  },
  "flawfinderequal1mismatch1is_permutation1": {
    "title": "This function is often discouraged by most C++ coding standards in favor of its safer\nalternatives provided since C++14. Consider using a form of this function that checks the\nsecond iterator before potentially overflowing it.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This function is often discouraged by most C++ coding standards in favor of its safer\nalternatives provided since C++14. Consider using a form of this function that checks the\nsecond iterator before potentially overflowing it.\n"
  },
  "flawfindergetpass1": {
    "title": "Make the specific calls to do exactly what you want.  If you continue to use it, or write your\nown, be sure to zero the password as soon as possible to avoid leaving the cleartext password\nvisible in the process' address space.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make the specific calls to do exactly what you want.  If you continue to use it, or write your\nown, be sure to zero the password as soon as possible to avoid leaving the cleartext password\nvisible in the process' address space.\n"
  },
  "flawfinderfscanf1sscanf1vsscanf1vfscanf1_ftscanf1fwscanf1vfwscanf1vswscanf1": {
    "title": "Specify a limit to %s, or use a different input function.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Specify a limit to %s, or use a different input function.\n"
  },
  "flawfinderexecl1execlp1execle1execv1execvp1popen1WinExec1ShellExecute1": {
    "title": "try using a library call that implements the same functionality if available.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "try using a library call that implements the same functionality if available.\n"
  },
  "flawfindergets1_getts1": {
    "title": "Use fgets() instead.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use fgets() instead.\n"
  },
  "flawfindermktemp1": {
    "title": "Creating and using insecure temporary files can leave application and system data vulnerable to\nattack (CWE-377).\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Creating and using insecure temporary files can leave application and system data vulnerable to\nattack (CWE-377).\n"
  },
  "flawfinderatoi1atol1_wtoi1_wtoi641": {
    "title": "If source untrusted, check both minimum and maximum, even if the input had no minus sign (large\nnumbers can roll over into negative number; consider saving to an unsigned value if that is\nintended).\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If source untrusted, check both minimum and maximum, even if the input had no minus sign (large\nnumbers can roll over into negative number; consider saving to an unsigned value if that is\nintended).\n"
  },
  "flawfindermemalign1": {
    "title": "Use posix_memalign instead (defined in POSIX's 1003.1d).  Don't switch to valloc(); it is\nmarked as obsolete in BSD 4.3, as legacy in SUSv2, and is no longer defined in SUSv3.  In some\ncases, malloc()'s alignment may be sufficient.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use posix_memalign instead (defined in POSIX's 1003.1d).  Don't switch to valloc(); it is\nmarked as obsolete in BSD 4.3, as legacy in SUSv2, and is no longer defined in SUSv3.  In some\ncases, malloc()'s alignment may be sufficient.\n"
  },
  "flawfinderstrcpyA1strcpyW1StrCpy1StrCpyA1lstrcpyA1lstrcpyW1_tccpy1_mbccpy1_ftcscpy1_mbsncpy1StrCpyN1StrCpyNA1StrCpyNW1StrNCpy1strcpynA1StrNCpyA1StrNCpyW1lstrcpynA1lstrcpynW1": {
    "title": "Consider using snprintf, strcpy_s, or strlcpy (warning: strncpy easily misused).\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Consider using snprintf, strcpy_s, or strlcpy (warning: strncpy easily misused).\n"
  },
  "flawfinderstrtrns1": {
    "title": "Ensure that destination is at least as long as the source.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Ensure that destination is at least as long as the source.\n"
  },
  "flawfindergetopt1getopt_long1": {
    "title": "Check implementation on installation, or limit the size of all string inputs.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Check implementation on installation, or limit the size of all string inputs.\n"
  },
  "flawfindertmpnam1tempnam1": {
    "title": "Creating and using insecure temporary files can leave application and system data vulnerable to\nattack.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Creating and using insecure temporary files can leave application and system data vulnerable to\nattack.\n"
  },
  "flawfinderSetSecurityDescriptorDacl1": {
    "title": "Never create NULL ACLs; an attacker can set it to Everyone (Deny\nAll Access)\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Never create NULL ACLs; an attacker can set it to Everyone (Deny\nAll Access)\n"
  },
  "flawfinderg_get_tmp_dir1": {
    "title": "Check environment variables carefully before using them.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Check environment variables carefully before using them.\n"
  },
  "flawfinderstreadd1strecpy1": {
    "title": "Ensure the destination has 4 times the size of the source, to leave room for expansion.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Ensure the destination has 4 times the size of the source, to leave room for expansion.\n"
  },
  "flawfindersystem1": {
    "title": "try using a library call that implements the same functionality if available.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "try using a library call that implements the same functionality if available.\n"
  },
  "flawfinderlstrcpy1wcscpy1_tcscpy1_mbscpy1": {
    "title": "Consider using a function version that stops copying at the end of the buffer.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Consider using a function version that stops copying at the end of the buffer.\n"
  },
  "flawfinderlstrcatn1wcsncat1_tcsncat1_mbsnbcat1": {
    "title": "Consider strcat_s, strlcat, or automatically resizing strings.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Consider strcat_s, strlcat, or automatically resizing strings.\n"
  },
  "flawfinderstrcat1": {
    "title": "Consider using strcat_s, strncat, strlcat, or snprintf (warning: strncat is easily misused).\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Consider using strcat_s, strncat, strlcat, or snprintf (warning: strncat is easily misused).\n"
  },
  "flawfindermemcpy1CopyMemory1bcopy1": {
    "title": "Make sure destination can always hold the source data.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure destination can always hold the source data.\n"
  },
  "flawfinderLoadLibrary1": {
    "title": "Use LoadLibraryEx with one of the search flags, or call SetSearchPathMode to use a safe search\npath, or pass a full path to the library.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use LoadLibraryEx with one of the search flags, or call SetSearchPathMode to use a safe search\npath, or pass a full path to the library.\n"
  },
  "flawfinderrealpath1": {
    "title": "Ensure that the destination buffer is at least of size MAXPATHLEN, andto protect against\nimplementation problems, the input argument should also be checked to ensure it is no larger\nthan MAXPATHLEN.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Ensure that the destination buffer is at least of size MAXPATHLEN, andto protect against\nimplementation problems, the input argument should also be checked to ensure it is no larger\nthan MAXPATHLEN.\n"
  },
  "flawfindergetlogin1": {
    "title": "Use getpwuid(geteuid()) and extract the desired information instead.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use getpwuid(geteuid()) and extract the desired information instead.\n"
  },
  "flawfindergetpw1": {
    "title": "Use getpwuid() instead.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use getpwuid() instead.\n"
  },
  "flawfinderumask1": {
    "title": "Ensure that umask is given most restrictive possible setting (e.g.,\n066 or 077)\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Ensure that umask is given most restrictive possible setting (e.g.,\n066 or 077)\n"
  },
  "flawfinderCreateProcess1": {
    "title": "Specify the application path in the first argument, NOT as part of the second, or embedded\nspaces could allow an attacker to force a different program to run.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Specify the application path in the first argument, NOT as part of the second, or embedded\nspaces could allow an attacker to force a different program to run.\n"
  },
  "flawfinderCreateProcessAsUser1CreateProcessWithLogon1": {
    "title": "Especially watch out for embedded spaces.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Especially watch out for embedded spaces.\n"
  },
  "flawfinderRpcImpersonateClient1ImpersonateLoggedOnUser1CoImpersonateClient1ImpersonateNamedPipeClient1ImpersonateDdeClientWindow1ImpersonateSecurityContext1SetThreadToken1": {
    "title": "Make sure the return value is checked, and do not continue if a failure is reported.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure the return value is checked, and do not continue if a failure is reported.\n"
  },
  "flawfinderchown1": {
    "title": "Use fchown( ) instead.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use fchown( ) instead.\n"
  },
  "flawfindersprintf1vsprintf1swprintf1vswprintf1_stprintf1_vstprintf1": {
    "title": "Use sprintf_s, snprintf, or vsnprintf.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use sprintf_s, snprintf, or vsnprintf.\n"
  },
  "flawfindervfork1": {
    "title": "Use fork() instead.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use fork() instead.\n"
  },
  "flawfinderstrncpy1": {
    "title": "Easily used incorrectly\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Easily used incorrectly\n"
  },
  "flawfindergetwd1": {
    "title": "Use getcwd instead.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use getcwd instead.\n"
  },
  "flawfinderInitializeCriticalSection1": {
    "title": "Use InitializeCriticalSectionAndSpinCount instead.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use InitializeCriticalSectionAndSpinCount instead.\n"
  },
  "flawfinderreadlink1": {
    "title": "Reconsider approach.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Reconsider approach.\n"
  },
  "flawfinderMultiByteToWideChar1": {
    "title": "The software does not properly handle when an input contains Unicode encoding.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The software does not properly handle when an input contains Unicode encoding.\n"
  },
  "flawfinderscanf1vscanf1wscanf1_tscanf1vwscanf1": {
    "title": "Specify a limit to %s, or use a different input function.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Specify a limit to %s, or use a different input function.\n"
  },
  "flawfinderGetTempFileName1": {
    "title": "Temporary file race condition in certain cases.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Temporary file race condition in certain cases.\n"
  },
  "flawfindercrypt1crypt_r1": {
    "title": "Use a different algorithm, such as SHA-256, with a larger, non-repeating salt.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use a different algorithm, such as SHA-256, with a larger, non-repeating salt.\n"
  },
  "flawfindergetenv1curl_getenv1": {
    "title": "Check environment variables carefully before using them.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Check environment variables carefully before using them.\n"
  },
  "flawfindergsignal1ssignal1": {
    "title": "Switch to raise/signal, or some other signalling approach.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Switch to raise/signal, or some other signalling approach.\n"
  },
  "flawfinderfprintf1vfprintf1_ftprintf1_vftprintf1fwprintf1fvwprintf1": {
    "title": "Use a constant for the format specification.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use a constant for the format specification.\n"
  },
  "flawfinderaccess1": {
    "title": "Set up the correct permissions (e.g., using setuid()) and try to open the file directly.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Set up the correct permissions (e.g., using setuid()) and try to open the file directly.\n"
  },
  "flawfinderstrccpy1strcadd1": {
    "title": "Ensure that destination buffer is sufficiently large.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Ensure that destination buffer is sufficiently large.\n"
  },
  "flawfinderchmod1": {
    "title": "Use fchmod( ) instead.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use fchmod( ) instead.\n"
  },
  "flawfinderprintf1vprintf1vwprintf1vfwprintf1_vtprintf1wprintf1": {
    "title": "Use a constant for the format specification.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use a constant for the format specification.\n"
  },
  "flawfinderchgrp1": {
    "title": "Use fchgrp( ) instead.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use fchgrp( ) instead.\n"
  },
  "flawfinderEVP_des_ecb1EVP_des_cbc1EVP_des_cfb1EVP_des_ofb1EVP_desx_cbc1": {
    "title": "Use a different patent-free encryption algorithm with a larger keysize, such as 3DES or AES.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use a different patent-free encryption algorithm with a larger keysize, such as 3DES or AES.\n"
  },
  "flawfinderLoadLibraryEx1": {
    "title": "Use a flag like LOAD_LIBRARY_SEARCH_SYSTEM32 or LOAD_LIBRARY_SEARCH_APPLICATION_DIR to search\nonly desired folders.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use a flag like LOAD_LIBRARY_SEARCH_SYSTEM32 or LOAD_LIBRARY_SEARCH_APPLICATION_DIR to search\nonly desired folders.\n"
  },
  "flawfindertmpfile1": {
    "title": "Creating and using insecure temporary files can leave application and system data vulnerable to\nattack\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Creating and using insecure temporary files can leave application and system data vulnerable to\nattack\n"
  },
  "flawfinderg_get_home_dir1": {
    "title": "Check environment variables carefully before using them.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Check environment variables carefully before using them.\n"
  },
  "flawfinderchroot1": {
    "title": "Make sure the program immediately chdir(\"/\"), closes file descriptors, and drops root\nprivileges, and that all necessary files (and no more!) are in the new root.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure the program immediately chdir(\"/\"), closes file descriptors, and drops root\nprivileges, and that all necessary files (and no more!) are in the new root.\n"
  },
  "flawfinderchar1TCHAR1wchar_t1": {
    "title": "Perform bounds checking, use functions that limit length, or ensure that the size is larger\nthan the maximum possible length.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Perform bounds checking, use functions that limit length, or ensure that the size is larger\nthan the maximum possible length.\n"
  },
  "flawfinderstrcpy1": {
    "title": "Consider using snprintf, strcpy_s, or strlcpy (warning: strncpy easily misused).\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Consider using snprintf, strcpy_s, or strlcpy (warning: strncpy easily misused).\n"
  },
  "flawfinderusleep1": {
    "title": "Use nanosleep(2) or setitimer(2) instead.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use nanosleep(2) or setitimer(2) instead.\n"
  },
  "flawfinderAddAccessAllowedAce1": {
    "title": "Make sure that you set inheritance by hand if you wish it to inherit.\n",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Make sure that you set inheritance by hand if you wish it to inherit.\n"
  }
}
