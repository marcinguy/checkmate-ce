issues_data = {   'QF1001': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': "Apply De Morgan's law"},
    'QF1002': {   'categories': ['security'],
                  'description': 'An untagged switch that compares a single '
                                 'variable against a series of\n'
                                 'values can be replaced with a tagged switch.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Convert untagged switch to tagged switch'},
    'QF1003': {   'categories': ['security'],
                  'description': 'A series of if/else-if checks comparing the '
                                 'same variable against\n'
                                 'values can be replaced with a tagged switch.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Convert if/else-if chain to tagged switch'},
    'QF1004': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Use strings.ReplaceAll instead of strings.Replace '
                           'with n == -1'},
    'QF1005': {   'categories': ['security'],
                  'description': 'Some uses of math.Pow can be simplified to '
                                 'basic multiplication.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Expand call to math.Pow'},
    'QF1006': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Lift if+break into loop condition'},
    'QF1007': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Merge conditional assignment into variable '
                           'declaration'},
    'QF1008': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Omit embedded fields from selector expression'},
    'QF1009': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Use time.Time.Equal instead of == operator'},
    'QF1010': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Convert slice of bytes to string when printing it'},
    'QF1011': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Omit redundant type from variable declaration'},
    'QF1012': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Use fmt.Fprintf(x, ...) instead of '
                           'x.Write(fmt.Sprintf(...))'},
    'S1000': {   'categories': ['security'],
                 'description': 'Select statements with a single case can be '
                                'replaced with a simple\n'
                                'send or receive.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Use plain channel send or receive instead of '
                          'single-case select'},
    'S1001': {   'categories': ['security'],
                 'description': 'Use copy() for copying elements from one '
                                'slice to another. For\n'
                                'arrays of identical size, you can use simple '
                                'assignment.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Replace for loop with call to copy'},
    'S1002': {   'categories': ['security'],
                 'description': '',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Omit comparison with boolean constant'},
    'S1003': {   'categories': ['security'],
                 'description': '',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Replace call to strings.Index with '
                          'strings.Contains'},
    'S1004': {   'categories': ['security'],
                 'description': '',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Replace call to bytes.Compare with bytes.Equal'},
    'S1005': {   'categories': ['security'],
                 'description': 'In many cases, assigning to the blank '
                                'identifier is unnecessary.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Drop unnecessary use of the blank identifier'},
    'S1006': {   'categories': ['security'],
                 'description': 'For infinite loops, using for { ... } is the '
                                'most idiomatic choice.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': "Use 'for { ... }' for infinite loops"},
    'S1007': {   'categories': ['security'],
                 'description': 'Raw string literals use backticks instead of '
                                'quotation marks and do not support\n'
                                'any escape sequences. This means that the '
                                'backslash can be used\n'
                                'freely, without the need of escaping.\n'
                                '\n'
                                'Since regular expressions have their own '
                                'escape sequences, raw strings\n'
                                'can improve their readability.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Simplify regular expression by using raw string '
                          'literal'},
    'S1008': {   'categories': ['security'],
                 'description': '',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Simplify returning boolean expression'},
    'S1009': {   'categories': ['security'],
                 'description': 'The len function is defined for all slices, '
                                'even nil ones, which have\n'
                                'a length of zero. It is not necessary to '
                                'check if a slice is not nil\n'
                                'before checking that its length is not zero.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Omit redundant nil check on slices'},
    'S1010': {   'categories': ['security'],
                 'description': 'When slicing, the second index defaults to '
                                'the length of the value,\n'
                                'making s[n:len(s)] and s[n:] equivalent.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Omit default slice index'},
    'S1011': {   'categories': ['security'],
                 'description': '',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Use a single append to concatenate two slices'},
    'S1012': {   'categories': ['security'],
                 'description': 'The time.Since helper has the same effect as '
                                'using time.Now().Sub(x)\n'
                                'but is easier to read.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Replace time.Now().Sub(x) with time.Since(x)'},
    'S1016': {   'categories': ['security'],
                 'description': 'Two struct types with identical fields can be '
                                'converted between each\n'
                                'other. In older versions of Go, the fields '
                                'had to have identical\n'
                                'struct tags. Since Go 1.8, however, struct '
                                'tags are ignored during\n'
                                'conversions. It is thus not necessary to '
                                'manually copy every field\n'
                                'individually.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Use a type conversion instead of manually copying '
                          'struct fields'},
    'S1017': {   'categories': ['security'],
                 'description': 'Instead of using strings.HasPrefix and manual '
                                'slicing, use the\n'
                                'strings.TrimPrefix function. If the string '
                                "doesn't start with the\n"
                                'prefix, the original string will be returned. '
                                'Using strings.TrimPrefix\n'
                                'reduces complexity, and avoids common bugs, '
                                'such as off-by-one\n'
                                'mistakes.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Replace manual trimming with strings.TrimPrefix'},
    'S1018': {   'categories': ['security'],
                 'description': 'copy() permits using the same source and '
                                'destination slice, even with\n'
                                'overlapping ranges. This makes it ideal for '
                                'sliding elements in a\n'
                                'slice.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': "Use 'copy' for sliding elements"},
    'S1019': {   'categories': ['security'],
                 'description': "The 'make' function has default values for "
                                'the length and capacity\n'
                                'arguments. For channels, the length defaults '
                                'to zero, and for slices,\n'
                                'the capacity defaults to the length.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': "Simplify 'make' call by omitting redundant "
                          'arguments'},
    'S1020': {   'categories': ['security'],
                 'description': '',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Omit redundant nil check in type assertion'},
    'S1021': {   'categories': ['security'],
                 'description': '',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Merge variable declaration and assignment'},
    'S1023': {   'categories': ['security'],
                 'description': 'Functions that have no return value do not '
                                'need a return statement as\n'
                                'the final statement of the function.\n'
                                '\n'
                                'Switches in Go do not have automatic '
                                'fallthrough, unlike languages\n'
                                'like C. It is not necessary to have a break '
                                'statement as the final\n'
                                'statement in a case block.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Omit redundant control flow'},
    'S1024': {   'categories': ['security'],
                 'description': 'The time.Until helper has the same effect as '
                                'using x.Sub(time.Now())\n'
                                'but is easier to read.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Replace x.Sub(time.Now()) with time.Until(x)'},
    'S1025': {   'categories': ['security'],
                 'description': 'In many instances, there are easier and more '
                                'efficient ways of getting\n'
                                "a value's string representation. Whenever a "
                                "value's underlying type is\n"
                                'a string already, or the type has a String '
                                'method, they should be used\n'
                                'directly.\n'
                                '\n'
                                'Given the following shared definitions\n'
                                '\n'
                                '```go\n'
                                'type T1 string\n'
                                'type T2 int\n'
                                '\n'
                                'func (T2) String() string { return "Hello, '
                                'world" }\n'
                                '\n'
                                'var x string\n'
                                'var y T1\n'
                                'var z T2\n'
                                '```\n'
                                '\n'
                                'we can simplify\n'
                                '\n'
                                '```go\n'
                                'fmt.Sprintf("%s", x)\n'
                                'fmt.Sprintf("%s", y)\n'
                                'fmt.Sprintf("%s", z)\n'
                                '```\n'
                                '\n'
                                'to\n'
                                '\n'
                                '```go\n'
                                'x\n'
                                'string(y)\n'
                                'z.String()\n'
                                '```',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Don\'t use fmt.Sprintf("%s", x) unnecessarily'},
    'S1028': {   'categories': ['security'],
                 'description': '',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Simplify error construction with fmt.Errorf'},
    'S1029': {   'categories': ['security'],
                 'description': 'Ranging over a string will yield byte offsets '
                                'and runes. If the offset\n'
                                "isn't used, this is functionally equivalent "
                                'to converting the string\n'
                                'to a slice of runes and ranging over that. '
                                'Ranging directly over the\n'
                                'string will be more performant, however, as '
                                'it avoids allocating a new\n'
                                'slice, the size of which depends on the '
                                'length of the string.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Range over the string directly'},
    'S1030': {   'categories': ['security'],
                 'description': 'bytes.Buffer has both a String and a Bytes '
                                'method. It is almost never\n'
                                'necessary to use string(buf.Bytes()) or '
                                '[]byte(buf.String()) – simply\n'
                                'use the other method.\n'
                                '\n'
                                'The only exception to this are map lookups. '
                                'Due to a compiler optimization,\n'
                                'm[string(buf.Bytes())] is more efficient than '
                                'm[buf.String()].',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Use bytes.Buffer.String or bytes.Buffer.Bytes'},
    'S1031': {   'categories': ['security'],
                 'description': 'You can use range on nil slices and maps, the '
                                'loop will simply never\n'
                                'execute. This makes an additional nil check '
                                'around the loop\n'
                                'unnecessary.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Omit redundant nil check around loop'},
    'S1032': {   'categories': ['security'],
                 'description': 'The sort.Ints, sort.Float64s and sort.Strings '
                                'functions are easier to\n'
                                'read than sort.Sort(sort.IntSlice(x)), '
                                'sort.Sort(sort.Float64Slice(x))\n'
                                'and sort.Sort(sort.StringSlice(x)).',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Use sort.Ints(x), sort.Float64s(x), and '
                          'sort.Strings(x)'},
    'S1033': {   'categories': ['security'],
                 'description': 'Calling delete on a nil map is a no-op.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': "Unnecessary guard around call to 'delete'"},
    'S1034': {   'categories': ['security'],
                 'description': '',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Use result of type assertion to simplify cases'},
    'S1035': {   'categories': ['security'],
                 'description': 'The methods on net/http.Header, namely Add, '
                                'Del, Get\n'
                                'and Set, already canonicalize the given '
                                'header name.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Redundant call to net/http.CanonicalHeaderKey in '
                          'method call on net/http.Header'},
    'S1036': {   'categories': ['security'],
                 'description': "When accessing a map key that doesn't exist "
                                'yet, one receives a zero\n'
                                'value. Often, the zero value is a suitable '
                                'value, for example when\n'
                                'using append or doing integer math.\n'
                                '\n'
                                'The following\n'
                                '\n'
                                '```go\n'
                                'if _, ok := m["foo"]; ok {\n'
                                '    m["foo"] = append(m["foo"], "bar")\n'
                                '} else {\n'
                                '    m["foo"] = []string{"bar"}\n'
                                '}\n'
                                '```\n'
                                '\n'
                                'can be simplified to\n'
                                '\n'
                                '```go\n'
                                'm["foo"] = append(m["foo"], "bar")\n'
                                '```\n'
                                '\n'
                                'and\n'
                                '\n'
                                '```go\n'
                                'if _, ok := m2["k"]; ok {\n'
                                '    m2["k"] += 4\n'
                                '} else {\n'
                                '    m2["k"] = 4\n'
                                '}\n'
                                '```\n'
                                '\n'
                                'can be simplified to\n'
                                '\n'
                                '```go\n'
                                'm["k"] += 4\n'
                                '```',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Unnecessary guard around map access'},
    'S1037': {   'categories': ['security'],
                 'description': 'Using a select statement with a single case '
                                'receiving\n'
                                'from the result of time.After is a very '
                                'elaborate way of sleeping that\n'
                                'can much simpler be expressed with a simple '
                                'call to time.Sleep.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Elaborate way of sleeping'},
    'S1038': {   'categories': ['security'],
                 'description': 'Instead of using fmt.Print(fmt.Sprintf(...)), '
                                'one can use fmt.Printf(...).',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Unnecessarily complex way of printing formatted '
                          'string'},
    'S1039': {   'categories': ['security'],
                 'description': 'Calling fmt.Sprint with a single string '
                                'argument is unnecessary\n'
                                'and identical to using the string directly.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Unnecessary use of fmt.Sprint'},
    'S1040': {   'categories': ['security'],
                 'description': 'The type assertion x.(SomeInterface), when x '
                                'already has type\n'
                                'SomeInterface, can only fail if x is nil. '
                                'Usually, this is\n'
                                'left-over code from when x had a different '
                                'type and you can safely\n'
                                'delete the type assertion. If you want to '
                                'check that x is not nil,\n'
                                'consider being explicit and using an actual '
                                'if x == nil comparison\n'
                                'instead of relying on the type assertion '
                                'panicking.',
                 'file': '%(issue.file)s',
                 'line': '%(issue.line)s',
                 'severity': '1',
                 'title': 'Type assertion to current type'},
    'SA1000': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Invalid regular expression'},
    'SA1001': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Invalid template'},
    'SA1002': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Invalid format in time.Parse'},
    'SA1003': {   'categories': ['security'],
                  'description': 'The encoding/binary package can only '
                                 'serialize types with known sizes.\n'
                                 'This precludes the use of the int and uint '
                                 'types, as their sizes\n'
                                 'differ on different architectures. '
                                 "Furthermore, it doesn't support\n"
                                 'serializing maps, channels, strings, or '
                                 'functions.\n'
                                 '\n'
                                 "Before Go 1.8, bool wasn't supported, "
                                 'either.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Unsupported argument to functions in '
                           'encoding/binary'},
    'SA1004': {   'categories': ['security'],
                  'description': 'The time.Sleep function takes a '
                                 'time.Duration as its only argument.\n'
                                 'Durations are expressed in nanoseconds. '
                                 'Thus, calling time.Sleep(1)\n'
                                 'will sleep for 1 nanosecond. This is a '
                                 'common source of bugs, as sleep\n'
                                 'functions in other languages often accept '
                                 'seconds or milliseconds.\n'
                                 '\n'
                                 'The time package provides constants such as '
                                 'time.Second to express\n'
                                 'large durations. These can be combined with '
                                 'arithmetic to express\n'
                                 'arbitrary durations, for example 5 * '
                                 'time.Second for 5 seconds.\n'
                                 '\n'
                                 'If you truly meant to sleep for a tiny '
                                 'amount of time, use\n'
                                 'n * time.Nanosecond to signal to Staticcheck '
                                 'that you did mean to sleep\n'
                                 'for some amount of nanoseconds.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Suspiciously small untyped constant in time.Sleep'},
    'SA1005': {   'categories': ['security'],
                  'description': 'os/exec runs programs directly (using '
                                 'variants of the fork and exec\n'
                                 'system calls on Unix systems). This '
                                 "shouldn't be confused with running\n"
                                 'a command in a shell. The shell will allow '
                                 'for features such as input\n'
                                 'redirection, pipes, and general scripting. '
                                 'The shell is also\n'
                                 "responsible for splitting the user's input "
                                 'into a program name and its\n'
                                 'arguments. For example, the equivalent to\n'
                                 '\n'
                                 '```go\n'
                                 'ls / /tmp\n'
                                 '```\n'
                                 '\n'
                                 'would be\n'
                                 '\n'
                                 '```go\n'
                                 'exec.Command("ls", "/", "/tmp")\n'
                                 '```\n'
                                 '\n'
                                 'If you want to run a command in a shell, '
                                 'consider using something like\n'
                                 'the following – but be aware that not all '
                                 'systems, particularly\n'
                                 'Windows, will have a /bin/sh program:\n'
                                 '\n'
                                 '```go\n'
                                 'exec.Command("/bin/sh", "-c", "ls | grep '
                                 'Awesome")\n'
                                 '```',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Invalid first argument to exec.Command'},
    'SA1006': {   'categories': ['security'],
                  'description': 'Using fmt.Printf with a dynamic first '
                                 'argument can lead to unexpected\n'
                                 'output. The first argument is a format '
                                 'string, where certain character\n'
                                 'combinations have special meaning. If, for '
                                 'example, a user were to\n'
                                 'enter a string such as\n'
                                 '\n'
                                 '```go\n'
                                 'Interest rate: 5%\n'
                                 '```\n'
                                 '\n'
                                 'and you printed it with\n'
                                 '\n'
                                 '```go\n'
                                 'fmt.Printf(s)\n'
                                 '```\n'
                                 '\n'
                                 'it would lead to the following output:\n'
                                 '\n'
                                 '```go\n'
                                 'Interest rate: 5%!(NOVERB).\n'
                                 '```\n'
                                 '\n'
                                 'Similarly, forming the first parameter via '
                                 'string concatenation with\n'
                                 'user input should be avoided for the same '
                                 'reason. When printing user\n'
                                 'input, either use a variant of fmt.Print, or '
                                 'use the %s Printf verb\n'
                                 'and pass the string as an argument.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Printf with dynamic first argument and no further '
                           'arguments'},
    'SA1007': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Invalid URL in net/url.Parse'},
    'SA1008': {   'categories': ['security'],
                  'description': 'Keys in http.Header maps are canonical, '
                                 'meaning they follow a specific\n'
                                 'combination of uppercase and lowercase '
                                 'letters. Methods such as\n'
                                 'http.Header.Add and http.Header.Del convert '
                                 'inputs into this canonical\n'
                                 'form before manipulating the map.\n'
                                 '\n'
                                 'When manipulating http.Header maps directly, '
                                 'as opposed to using the\n'
                                 'provided methods, care should be taken to '
                                 'stick to canonical form in\n'
                                 'order to avoid inconsistencies. The '
                                 'following piece of code\n'
                                 'demonstrates one such inconsistency:\n'
                                 '\n'
                                 '```go\n'
                                 'h := http.Header{}\n'
                                 'h["etag"] = []string{"1234"}\n'
                                 'h.Add("etag", "5678")\n'
                                 'fmt.Println(h)\n'
                                 '\n'
                                 '// Output:\n'
                                 '// map[Etag:[5678] etag:[1234]]\n'
                                 '```\n'
                                 '\n'
                                 'The easiest way of obtaining the canonical '
                                 'form of a key is to use\n'
                                 'http.CanonicalHeaderKey.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Non-canonical key in http.Header map'},
    'SA1010': {   'categories': ['security'],
                  'description': 'If n >= 0, the function returns at most n '
                                 'matches/submatches. To\n'
                                 'return all results, specify a negative '
                                 'number.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': '(*regexp.Regexp).FindAll called with n == 0, which '
                           'will always return zero results'},
    'SA1011': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': "Various methods in the 'strings' package expect "
                           'valid UTF-8, but invalid input is provided'},
    'SA1012': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'A nil context.Context is being passed to a '
                           'function, consider using context.TODO instead'},
    'SA1013': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'io.Seeker.Seek is being called with the whence '
                           'constant as the first argument, but it should be '
                           'the second'},
    'SA1014': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Non-pointer value passed to Unmarshal or Decode'},
    'SA1015': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Using time.Tick in a way that will leak. Consider '
                           'using time.NewTicker, and only use time.Tick in '
                           'tests, commands and endless functions'},
    'SA1016': {   'categories': ['security'],
                  'description': 'Not all signals can be intercepted by a '
                                 'process. Specifically, on\n'
                                 'UNIX-like systems, the syscall.SIGKILL and '
                                 'syscall.SIGSTOP signals are\n'
                                 'never passed to the process, but instead '
                                 'handled directly by the\n'
                                 'kernel. It is therefore pointless to try and '
                                 'handle these signals.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Trapping a signal that cannot be trapped'},
    'SA1017': {   'categories': ['security'],
                  'description': 'The os/signal package uses non-blocking '
                                 'channel sends when delivering\n'
                                 'signals. If the receiving end of the channel '
                                 "isn't ready and the\n"
                                 'channel is either unbuffered or full, the '
                                 'signal will be dropped. To\n'
                                 'avoid missing signals, the channel should be '
                                 'buffered and of the\n'
                                 'appropriate size. For a channel used for '
                                 'notification of just one\n'
                                 'signal value, a buffer of size 1 is '
                                 'sufficient.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Channels used with os/signal.Notify should be '
                           'buffered'},
    'SA1018': {   'categories': ['security'],
                  'description': 'With n == 0, zero instances will be '
                                 'replaced. To replace all\n'
                                 'instances, use a negative number, or use '
                                 'strings.ReplaceAll.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'strings.Replace called with n == 0, which does '
                           'nothing'},
    'SA1019': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Using a deprecated function, variable, constant or '
                           'field'},
    'SA1020': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Using an invalid host:port pair with a '
                           'net.Listen-related function'},
    'SA1021': {   'categories': ['security'],
                  'description': 'A net.IP stores an IPv4 or IPv6 address as a '
                                 'slice of bytes. The\n'
                                 'length of the slice for an IPv4 address, '
                                 'however, can be either 4 or\n'
                                 '16 bytes long, using different ways of '
                                 'representing IPv4 addresses. In\n'
                                 'order to correctly compare two net.IPs, the '
                                 'net.IP.Equal method should\n'
                                 'be used, as it takes both representations '
                                 'into account.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Using bytes.Equal to compare two net.IP'},
    'SA1023': {   'categories': ['security'],
                  'description': 'Write must not modify the slice data, even '
                                 'temporarily.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Modifying the buffer in an io.Writer '
                           'implementation'},
    'SA1024': {   'categories': ['security'],
                  'description': 'The strings.TrimLeft and strings.TrimRight '
                                 'functions take cutsets, not\n'
                                 'prefixes. A cutset is treated as a set of '
                                 'characters to remove from a\n'
                                 'string. For example,\n'
                                 '\n'
                                 '```go\n'
                                 'strings.TrimLeft("42133word", "1234")\n'
                                 '```\n'
                                 '\n'
                                 'will result in the string "word" – any '
                                 'characters that are 1, 2, 3 or\n'
                                 '4 are cut from the left of the string.\n'
                                 '\n'
                                 'In order to remove one string from another, '
                                 'use strings.TrimPrefix instead.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'A string cutset contains duplicate characters'},
    'SA1025': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': "It is not possible to use (*time.Timer).Reset's "
                           'return value correctly'},
    'SA1026': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Cannot marshal channels or functions'},
    'SA1027': {   'categories': ['security'],
                  'description': 'On ARM, x86-32, and 32-bit MIPS, it is the '
                                 "caller's responsibility to\n"
                                 'arrange for 64-bit alignment of 64-bit words '
                                 'accessed atomically. The\n'
                                 'first word in a variable or in an allocated '
                                 'struct, array, or slice\n'
                                 'can be relied upon to be 64-bit aligned.\n'
                                 '\n'
                                 'You can use the structlayout tool to inspect '
                                 'the alignment of fields\n'
                                 'in a struct.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Atomic access to 64-bit variable must be 64-bit '
                           'aligned'},
    'SA1028': {   'categories': ['security'],
                  'description': 'The first argument of sort.Slice must be a '
                                 'slice.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'sort.Slice can only be used on slices'},
    'SA1029': {   'categories': ['security'],
                  'description': 'The provided key must be comparable and '
                                 'should not be\n'
                                 'of type string or any other built-in type to '
                                 'avoid collisions between\n'
                                 'packages using context. Users of WithValue '
                                 'should define their own\n'
                                 'types for keys.\n'
                                 '\n'
                                 'To avoid allocating when assigning to an '
                                 'interface{},\n'
                                 'context keys often have concrete type '
                                 'struct{}. Alternatively,\n'
                                 "exported context key variables' static type "
                                 'should be a pointer or\n'
                                 'interface.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Inappropriate key in call to context.WithValue'},
    'SA1030': {   'categories': ['security'],
                  'description': 'This check validates the format, number base '
                                 'and bit size arguments of\n'
                                 'the various parsing and formatting functions '
                                 'in strconv.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Invalid argument in call to a strconv function'},
    'SA2000': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'sync.WaitGroup.Add called inside the goroutine, '
                           'leading to a race condition'},
    'SA2001': {   'categories': ['security'],
                  'description': 'Empty critical sections of the kind\n'
                                 '\n'
                                 '```go\n'
                                 'mu.Lock()\n'
                                 'mu.Unlock()\n'
                                 '```\n'
                                 '\n'
                                 'are very often a typo, and the following was '
                                 'intended instead:\n'
                                 '\n'
                                 '```go\n'
                                 'mu.Lock()\n'
                                 'defer mu.Unlock()\n'
                                 '```\n'
                                 '\n'
                                 'Do note that sometimes empty critical '
                                 'sections can be useful, as a\n'
                                 'form of signaling to wait on another '
                                 'goroutine. Many times, there are\n'
                                 'simpler ways of achieving the same effect. '
                                 "When that isn't the case,\n"
                                 'the code should be amply commented to avoid '
                                 'confusion. Combining such\n'
                                 'comments with a //lint:ignore directive can '
                                 'be used to suppress this\n'
                                 'rare false positive.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Empty critical section, did you mean to defer the '
                           'unlock?'},
    'SA2002': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Called testing.T.FailNow or SkipNow in a '
                           "goroutine, which isn't allowed"},
    'SA2003': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Deferred Lock right after locking, likely meant to '
                           'defer Unlock instead'},
    'SA3000': {   'categories': ['security'],
                  'description': "Test executables (and in turn 'go test') "
                                 'exit with a non-zero status\n'
                                 'code if any tests failed. When specifying '
                                 'your own TestMain function,\n'
                                 'it is your responsibility to arrange for '
                                 'this, by calling os.Exit with\n'
                                 'the correct code. The correct code is '
                                 'returned by (*testing.M).Run, so\n'
                                 'the usual way of implementing TestMain is to '
                                 'end it with\n'
                                 'os.Exit(m.Run()).',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': "TestMain doesn't call os.Exit, hiding test "
                           'failures'},
    'SA3001': {   'categories': ['security'],
                  'description': 'The testing package dynamically sets b.N to '
                                 'improve the reliability of\n'
                                 'benchmarks and uses it in computations to '
                                 'determine the duration of a\n'
                                 'single operation. Benchmark code must not '
                                 'alter b.N as this would\n'
                                 'falsify results.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Assigning to b.N in benchmarks distorts the '
                           'results'},
    'SA4000': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Binary operator has identical expressions on both '
                           'sides'},
    'SA4001': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': '&*x gets simplified to x, it does not copy x'},
    'SA4003': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Comparing unsigned values against negative values '
                           'is pointless'},
    'SA4004': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'The loop exits unconditionally after one '
                           'iteration'},
    'SA4005': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Field assignment that will never be observed. Did '
                           'you mean to use a pointer receiver?'},
    'SA4006': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'A value assigned to a variable is never read '
                           'before being overwritten. Forgotten error check or '
                           'dead code?'},
    'SA4008': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'The variable in the loop condition never changes, '
                           'are you incrementing the wrong variable?'},
    'SA4009': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'A function argument is overwritten before its '
                           'first use'},
    'SA4010': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'The result of append will never be observed '
                           'anywhere'},
    'SA4011': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Break statement with no effect. Did you mean to '
                           'break out of an outer loop?'},
    'SA4012': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Comparing a value against NaN even though no value '
                           'is equal to NaN'},
    'SA4013': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Negating a boolean twice (!!b) is the same as '
                           'writing b. This is either redundant, or a typo.'},
    'SA4014': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'An if/else if chain has repeated conditions and no '
                           "side-effects; if the condition didn't match the "
                           "first time, it won't match the second time, "
                           'either'},
    'SA4015': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Calling functions like math.Ceil on floats '
                           "converted from integers doesn't do anything "
                           'useful'},
    'SA4016': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Certain bitwise operations, such as x ^ 0, do not '
                           'do anything useful'},
    'SA4017': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Discarding the return values of a function without '
                           'side effects, making the call pointless'},
    'SA4018': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Self-assignment of variables'},
    'SA4019': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Multiple, identical build constraints in the same '
                           'file'},
    'SA4020': {   'categories': ['security'],
                  'description': 'In a type switch like the following\n'
                                 '\n'
                                 '```go\n'
                                 'type T struct{}\n'
                                 'func (T) Read(b []byte) (int, error) { '
                                 'return 0, nil }\n'
                                 '\n'
                                 'var v interface{} = T{}\n'
                                 '\n'
                                 'switch v.(type) {\n'
                                 'case io.Reader:\n'
                                 '    // ...\n'
                                 'case T:\n'
                                 '    // unreachable\n'
                                 '}\n'
                                 '```\n'
                                 '\n'
                                 'the second case clause can never be reached '
                                 'because T implements\n'
                                 'io.Reader and case clauses are evaluated in '
                                 'source order.\n'
                                 '\n'
                                 'Another example:\n'
                                 '\n'
                                 '```go\n'
                                 'type T struct{}\n'
                                 'func (T) Read(b []byte) (int, error) { '
                                 'return 0, nil }\n'
                                 'func (T) Close() error { return nil }\n'
                                 '\n'
                                 'var v interface{} = T{}\n'
                                 '\n'
                                 'switch v.(type) {\n'
                                 'case io.Reader:\n'
                                 '    // ...\n'
                                 'case io.ReadCloser:\n'
                                 '    // unreachable\n'
                                 '}\n'
                                 '```\n'
                                 '\n'
                                 'Even though T has a Close method and thus '
                                 'implements io.ReadCloser,\n'
                                 'io.Reader will always match first. The '
                                 'method set of io.Reader is a\n'
                                 'subset of io.ReadCloser. Thus it is '
                                 'impossible to match the second\n'
                                 'case without matching the first case.\n'
                                 '\n'
                                 '\n'
                                 '#### Structurally equivalent interfaces\n'
                                 '\n'
                                 'A special case of the previous example are '
                                 'structurally identical\n'
                                 'interfaces. Given these declarations\n'
                                 '\n'
                                 '```go\n'
                                 'type T error\n'
                                 'type V error\n'
                                 '\n'
                                 'func doSomething() error {\n'
                                 '    err, ok := doAnotherThing()\n'
                                 '    if ok {\n'
                                 '        return T(err)\n'
                                 '    }\n'
                                 '\n'
                                 '    return U(err)\n'
                                 '}\n'
                                 '```\n'
                                 '\n'
                                 'the following type switch will have an '
                                 'unreachable case clause:\n'
                                 '\n'
                                 '```go\n'
                                 'switch doSomething().(type) {\n'
                                 'case T:\n'
                                 '    // ...\n'
                                 'case V:\n'
                                 '    // unreachable\n'
                                 '}\n'
                                 '```\n'
                                 '\n'
                                 'T will always match before V because they '
                                 'are structurally equivalent\n'
                                 "and therefore doSomething()'s return value "
                                 'implements both.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Unreachable case clause in a type switch'},
    'SA4021': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': "'x = append(y)' is equivalent to 'x = y'"},
    'SA4022': {   'categories': ['security'],
                  'description': "Code such as 'if &x == nil' is meaningless, "
                                 'because taking the address of a variable '
                                 'always yields a non-nil pointer.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Comparing the address of a variable against nil'},
    'SA4023': {   'categories': ['security'],
                  'description': 'Under the covers, interfaces are implemented '
                                 'as two elements, a\n'
                                 'type T and a value V. V is a concrete value '
                                 'such as an int,\n'
                                 'struct or pointer, never an interface '
                                 'itself, and has type T. For\n'
                                 'instance, if we store the int value 3 in an '
                                 'interface, the\n'
                                 'resulting interface value has, '
                                 'schematically, (T=int, V=3). The\n'
                                 "value V is also known as the interface's "
                                 'dynamic value, since a\n'
                                 'given interface variable might hold '
                                 'different values V (and\n'
                                 'corresponding types T) during the execution '
                                 'of the program.\n'
                                 '\n'
                                 'An interface value is nil only if the V and '
                                 'T are both\n'
                                 'unset, (T=nil, V is not set), In particular, '
                                 'a nil interface will\n'
                                 'always hold a nil type. If we store a nil '
                                 'pointer of type *int\n'
                                 'inside an interface value, the inner type '
                                 'will be *int regardless\n'
                                 'of the value of the pointer: (T=*int, '
                                 'V=nil). Such an interface\n'
                                 'value will therefore be non-nil even when '
                                 'the pointer value V\n'
                                 'inside is nil.\n'
                                 '\n'
                                 'This situation can be confusing, and arises '
                                 'when a nil value is\n'
                                 'stored inside an interface value such as an '
                                 'error return:\n'
                                 '\n'
                                 '```go\n'
                                 'func returnsError() error {\n'
                                 '    var p *MyError = nil\n'
                                 '    if bad() {\n'
                                 '        p = ErrBad\n'
                                 '    }\n'
                                 '    return p // Will always return a non-nil '
                                 'error.\n'
                                 '}\n'
                                 '```\n'
                                 '\n'
                                 'If all goes well, the function returns a nil '
                                 'p, so the return\n'
                                 'value is an error interface value holding '
                                 '(T=*MyError, V=nil).\n'
                                 'This means that if the caller compares the '
                                 'returned error to nil,\n'
                                 'it will always look as if there was an error '
                                 'even if nothing bad\n'
                                 'happened. To return a proper nil error to '
                                 'the caller, the\n'
                                 'function must return an explicit nil:\n'
                                 '\n'
                                 '```go\n'
                                 'func returnsError() error {\n'
                                 '    if bad() {\n'
                                 '        return ErrBad\n'
                                 '    }\n'
                                 '    return nil\n'
                                 '}\n'
                                 '```\n'
                                 '\n'
                                 "It's a good idea for functions that return "
                                 'errors always to use\n'
                                 'the error type in their signature (as we did '
                                 'above) rather than a\n'
                                 'concrete type such as *MyError, to help '
                                 'guarantee the error is\n'
                                 'created correctly. As an example, os.Open '
                                 'returns an error even\n'
                                 "though, if not nil, it's always of concrete "
                                 'type *os.PathError.\n'
                                 '\n'
                                 'Similar situations to those described here '
                                 'can arise whenever\n'
                                 'interfaces are used. Just keep in mind that '
                                 'if any concrete value\n'
                                 'has been stored in the interface, the '
                                 'interface will not be nil.\n'
                                 'For more information, see The Laws of\n'
                                 'Reflection '
                                 '(https://golang.org/doc/articles/laws_of_reflection.html).\n'
                                 '\n'
                                 'This text has been copied from\n'
                                 'https://golang.org/doc/faq#nil_error, '
                                 'licensed under the Creative\n'
                                 'Commons Attribution 3.0 License.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Impossible comparison of interface value with '
                           'untyped nil'},
    'SA4024': {   'categories': ['security'],
                  'description': 'Return values of the len and cap builtins '
                                 'cannot be negative.\n'
                                 '\n'
                                 'See https://golang.org/pkg/builtin/#len and '
                                 'https://golang.org/pkg/builtin/#cap.\n'
                                 '\n'
                                 'Example:\n'
                                 '\n'
                                 '```go\n'
                                 'if len(slice) < 0 {\n'
                                 '    fmt.Println("unreachable code")\n'
                                 '}\n'
                                 '```',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Checking for impossible return value from a '
                           'builtin function'},
    'SA4025': {   'categories': ['security'],
                  'description': 'When dividing two integer constants, the '
                                 'result will\n'
                                 'also be an integer. Thus, a division such as '
                                 '2 / 3 results in 0.\n'
                                 'This is true for all of the following '
                                 'examples:\n'
                                 '\n'
                                 '\t_ = 2 / 3\n'
                                 '\tconst _ = 2 / 3\n'
                                 '\tconst _ float64 = 2 / 3\n'
                                 '\t_ = float64(2 / 3)\n'
                                 '\n'
                                 'Staticcheck will flag such divisions if both '
                                 'sides of the division are\n'
                                 'integer literals, as it is highly unlikely '
                                 'that the division was\n'
                                 'intended to truncate to zero. Staticcheck '
                                 'will not flag integer\n'
                                 'division involving named constants, to avoid '
                                 'noisy positives.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Integer division of literals that results in zero'},
    'SA4026': {   'categories': ['security'],
                  'description': 'In IEEE 754 floating point math, zero has a '
                                 'sign and can be positive\n'
                                 'or negative. This can be useful in certain '
                                 'numerical code.\n'
                                 '\n'
                                 'Go constants, however, cannot express '
                                 'negative zero. This means that\n'
                                 'the literals -0.0 and 0.0 have the same '
                                 'ideal value (zero) and\n'
                                 'will both represent positive zero at '
                                 'runtime.\n'
                                 '\n'
                                 'To explicitly and reliably create a negative '
                                 'zero, you can use the\n'
                                 'math.Copysign function: math.Copysign(0, '
                                 '-1).',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Go constants cannot express negative zero'},
    'SA4027': {   'categories': ['security'],
                  'description': '(*net/url.URL).Query parses the current '
                                 'value of net/url.URL.RawQuery\n'
                                 'and returns it as a map of type '
                                 'net/url.Values. Subsequent changes to\n'
                                 'this map will not affect the URL unless the '
                                 'map gets encoded and\n'
                                 "assigned to the URL's RawQuery.\n"
                                 '\n'
                                 'As a consequence, the following code pattern '
                                 'is an expensive no-op:\n'
                                 'u.Query().Add(key, value).',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': '(*net/url.URL).Query returns a copy, modifying it '
                           "doesn't change the URL"},
    'SA4028': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'x % 1 is always zero'},
    'SA4029': {   'categories': ['security'],
                  'description': 'sort.Float64Slice, sort.IntSlice, and '
                                 'sort.StringSlice are\n'
                                 'types, not functions. Doing x = '
                                 'sort.StringSlice(x) does nothing,\n'
                                 'especially not sort any values. The correct '
                                 'usage is\n'
                                 'sort.Sort(sort.StringSlice(x)) or '
                                 'sort.StringSlice(x).Sort(),\n'
                                 'but there are more convenient helpers, '
                                 'namely sort.Float64s,\n'
                                 'sort.Ints, and sort.Strings.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Ineffective attempt at sorting slice'},
    'SA4030': {   'categories': ['security'],
                  'description': 'Functions in the math/rand package that '
                                 'accept upper limits, such\n'
                                 'as Intn, generate random numbers in the '
                                 'half-open interval [0,n). In\n'
                                 'other words, the generated numbers will be '
                                 '>= 0 and < n – they\n'
                                 "don't include n. rand.Intn(1) therefore "
                                 "doesn't generate 0\n"
                                 'or 1, it always generates 0.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Ineffective attempt at generating random number'},
    'SA4031': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Checking never-nil value against nil'},
    'SA5000': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Assignment to nil map'},
    'SA5001': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Deferring Close before checking for a possible '
                           'error'},
    'SA5002': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': "The empty for loop ('for {}') spins and can block "
                           'the scheduler'},
    'SA5003': {   'categories': ['security'],
                  'description': 'Defers are scoped to the surrounding '
                                 'function, not the surrounding\n'
                                 'block. In a function that never returns, '
                                 'i.e. one containing an\n'
                                 'infinite loop, defers will never execute.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Defers in infinite loops will never execute'},
    'SA5004': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': "'for { select { ...' with an empty default branch "
                           'spins'},
    'SA5005': {   'categories': ['security'],
                  'description': 'A finalizer is a function associated with an '
                                 'object that runs when the\n'
                                 'garbage collector is ready to collect said '
                                 'object, that is when the\n'
                                 'object is no longer referenced by anything.\n'
                                 '\n'
                                 'If the finalizer references the object, '
                                 'however, it will always remain\n'
                                 'as the final reference to that object, '
                                 'preventing the garbage\n'
                                 'collector from collecting the object. The '
                                 'finalizer will never run,\n'
                                 'and the object will never be collected, '
                                 'leading to a memory leak. That\n'
                                 'is why the finalizer should instead use its '
                                 'first argument to operate\n'
                                 'on the object. That way, the number of '
                                 'references can temporarily go\n'
                                 'to zero before the object is being passed to '
                                 'the finalizer.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'The finalizer references the finalized object, '
                           'preventing garbage collection'},
    'SA5007': {   'categories': ['security'],
                  'description': 'A function that calls itself recursively '
                                 'needs to have an exit\n'
                                 'condition. Otherwise it will recurse '
                                 'forever, until the system runs\n'
                                 'out of memory.\n'
                                 '\n'
                                 'This issue can be caused by simple bugs such '
                                 'as forgetting to add an\n'
                                 'exit condition. It can also happen "on '
                                 'purpose". Some languages have\n'
                                 'tail call optimization which makes certain '
                                 'infinite recursive calls\n'
                                 'safe to use. Go, however, does not implement '
                                 'TCO, and as such a loop\n'
                                 'should be used instead.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Infinite recursive call'},
    'SA5008': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Invalid struct tag'},
    'SA5009': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Invalid Printf call'},
    'SA5010': {   'categories': ['security'],
                  'description': 'Some type assertions can be statically '
                                 'proven to be\n'
                                 'impossible. This is the case when the method '
                                 'sets of both\n'
                                 'arguments of the type assertion conflict '
                                 'with each other, for\n'
                                 'example by containing the same method with '
                                 'different\n'
                                 'signatures.\n'
                                 '\n'
                                 'The Go compiler already applies this check '
                                 'when asserting from an\n'
                                 'interface value to a concrete type. If the '
                                 'concrete type misses\n'
                                 'methods from the interface, or if function '
                                 "signatures don't match,\n"
                                 'then the type assertion can never succeed.\n'
                                 '\n'
                                 'This check applies the same logic when '
                                 'asserting from one interface to\n'
                                 'another. If both interface types contain the '
                                 'same method but with\n'
                                 'different signatures, then the type '
                                 'assertion can never succeed,\n'
                                 'either.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Impossible type assertion'},
    'SA5011': {   'categories': ['security'],
                  'description': 'A pointer is being dereferenced '
                                 'unconditionally, while\n'
                                 'also being checked against nil in another '
                                 'place. This suggests that\n'
                                 'the pointer may be nil and dereferencing it '
                                 'may panic. This is\n'
                                 'commonly a result of improperly ordered code '
                                 'or missing return\n'
                                 'statements. Consider the following '
                                 'examples:\n'
                                 '\n'
                                 '```go\n'
                                 'func fn(x *int) {\n'
                                 '    fmt.Println(*x)\n'
                                 '\n'
                                 '    // This nil check is equally important '
                                 'for the previous dereference\n'
                                 '    if x != nil {\n'
                                 '        foo(*x)\n'
                                 '    }\n'
                                 '}\n'
                                 '\n'
                                 'func TestFoo(t *testing.T) {\n'
                                 '    x := compute()\n'
                                 '    if x == nil {\n'
                                 '        t.Errorf("nil pointer received")\n'
                                 '    }\n'
                                 '\n'
                                 '    // t.Errorf does not abort the test, so '
                                 'if x is nil, the next line will panic.\n'
                                 '    foo(*x)\n'
                                 '}\n'
                                 '```\n'
                                 '\n'
                                 'Staticcheck tries to deduce which functions '
                                 'abort control flow.\n'
                                 'For example, it is aware that a function '
                                 'will not continue\n'
                                 'execution after a call to panic or '
                                 'log.Fatal. However, sometimes\n'
                                 'this detection fails, in particular in the '
                                 'presence of\n'
                                 'conditionals. Consider the following '
                                 'example:\n'
                                 '\n'
                                 '```go\n'
                                 'func Log(msg string, level int) {\n'
                                 '    fmt.Println(msg)\n'
                                 '    if level == levelFatal {\n'
                                 '        os.Exit(1)\n'
                                 '    }\n'
                                 '}\n'
                                 '\n'
                                 'func Fatal(msg string) {\n'
                                 '    Log(msg, levelFatal)\n'
                                 '}\n'
                                 '\n'
                                 'func fn(x *int) {\n'
                                 '    if x == nil {\n'
                                 '        Fatal("unexpected nil pointer")\n'
                                 '    }\n'
                                 '    fmt.Println(*x)\n'
                                 '}\n'
                                 '```\n'
                                 '\n'
                                 'Staticcheck will flag the dereference of x, '
                                 'even though it is perfectly\n'
                                 'safe. Staticcheck is not able to deduce that '
                                 'a call to\n'
                                 'Fatal will exit the program. For the time '
                                 'being, the easiest\n'
                                 'workaround is to modify the definition of '
                                 'Fatal like so:\n'
                                 '\n'
                                 '```go\n'
                                 'func Fatal(msg string) {\n'
                                 '    Log(msg, levelFatal)\n'
                                 '    panic("unreachable")\n'
                                 '}\n'
                                 '```\n'
                                 '\n'
                                 'We also hard-code functions from common '
                                 'logging packages such as\n'
                                 "logrus. Please file an issue if we're "
                                 'missing support for a\n'
                                 'popular package.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Possible nil pointer dereference'},
    'SA5012': {   'categories': ['security'],
                  'description': 'Some functions that take slices as '
                                 'parameters expect the slices to have an even '
                                 'number of elements. \n'
                                 'Often, these functions treat elements in a '
                                 'slice as pairs. \n'
                                 'For example, strings.NewReplacer takes pairs '
                                 'of old and new strings, \n'
                                 'and calling it with an odd number of '
                                 'elements would be an error.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Passing odd-sized slice to function expecting even '
                           'size'},
    'SA6000': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Using regexp.Match or related in a loop, should '
                           'use regexp.Compile'},
    'SA6001': {   'categories': ['security'],
                  'description': 'Map keys must be comparable, which precludes '
                                 'the use of byte slices.\n'
                                 'This usually leads to using string keys and '
                                 'converting byte slices to\n'
                                 'strings.\n'
                                 '\n'
                                 'Normally, a conversion of a byte slice to a '
                                 'string needs to copy the data and\n'
                                 'causes allocations. The compiler, however, '
                                 'recognizes m[string(b)] and\n'
                                 'uses the data of b directly, without copying '
                                 'it, because it knows that\n'
                                 "the data can't change during the map lookup. "
                                 'This leads to the\n'
                                 'counter-intuitive situation that\n'
                                 '\n'
                                 '```go\n'
                                 'k := string(b)\n'
                                 'println(m[k])\n'
                                 'println(m[k])\n'
                                 '```\n'
                                 '\n'
                                 'will be less efficient than\n'
                                 '\n'
                                 '```go\n'
                                 'println(m[string(b)])\n'
                                 'println(m[string(b)])\n'
                                 '```\n'
                                 '\n'
                                 'because the first version needs to copy and '
                                 'allocate, while the second\n'
                                 'one does not.\n'
                                 '\n'
                                 'For some history on this optimization, check '
                                 'out commit\n'
                                 'f5f5a8b6209f84961687d993b93ea0d397f5d5bf in '
                                 'the Go repository.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Missing an optimization opportunity when indexing '
                           'maps by byte slices'},
    'SA6002': {   'categories': ['security'],
                  'description': 'A sync.Pool is used to avoid unnecessary '
                                 'allocations and reduce the\n'
                                 'amount of work the garbage collector has to '
                                 'do.\n'
                                 '\n'
                                 'When passing a value that is not a pointer '
                                 'to a function that accepts\n'
                                 'an interface, the value needs to be placed '
                                 'on the heap, which means an\n'
                                 'additional allocation. Slices are a common '
                                 'thing to put in sync.Pools,\n'
                                 "and they're structs with 3 fields (length, "
                                 'capacity, and a pointer to\n'
                                 'an array). In order to avoid the extra '
                                 'allocation, one should store a\n'
                                 'pointer to the slice instead.\n'
                                 '\n'
                                 'See the comments on '
                                 'https://go-review.googlesource.com/c/go/+/24371\n'
                                 'that discuss this problem.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Storing non-pointer values in sync.Pool allocates '
                           'memory'},
    'SA6003': {   'categories': ['security'],
                  'description': 'You may want to loop over the runes in a '
                                 'string. Instead of converting\n'
                                 'the string to a slice of runes and looping '
                                 'over that, you can loop\n'
                                 'over the string itself. That is,\n'
                                 '\n'
                                 '```go\n'
                                 'for _, r := range s {}\n'
                                 '```\n'
                                 '\n'
                                 'and\n'
                                 '\n'
                                 '```go\n'
                                 'for _, r := range []rune(s) {}\n'
                                 '```\n'
                                 '\n'
                                 'will yield the same values. The first '
                                 'version, however, will be faster\n'
                                 'and avoid unnecessary memory allocations.\n'
                                 '\n'
                                 'Do note that if you are interested in the '
                                 'indices, ranging over a\n'
                                 'string and over a slice of runes will yield '
                                 'different indices. The\n'
                                 'first one yields byte offsets, while the '
                                 'second one yields indices in\n'
                                 'the slice of runes.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Converting a string to a slice of runes before '
                           'ranging over it'},
    'SA6005': {   'categories': ['security'],
                  'description': 'Converting two strings to the same case and '
                                 'comparing them like so\n'
                                 '\n'
                                 '```go\n'
                                 'if strings.ToLower(s1) == '
                                 'strings.ToLower(s2) {\n'
                                 '    ...\n'
                                 '}\n'
                                 '```\n'
                                 '\n'
                                 'is significantly more expensive than '
                                 'comparing them with\n'
                                 'strings.EqualFold(s1, s2). This is due to '
                                 'memory usage as well as\n'
                                 'computational complexity.\n'
                                 '\n'
                                 'strings.ToLower will have to allocate memory '
                                 'for the new strings, as\n'
                                 'well as convert both strings fully, even if '
                                 'they differ on the very\n'
                                 'first byte. strings.EqualFold, on the other '
                                 'hand, compares the strings\n'
                                 "one character at a time. It doesn't need to "
                                 'create two intermediate\n'
                                 'strings and can return as soon as the first '
                                 'non-matching character has\n'
                                 'been found.\n'
                                 '\n'
                                 'For a more in-depth explanation of this '
                                 'issue, see\n'
                                 'https://blog.digitalocean.com/how-to-efficiently-compare-strings-in-go/',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Inefficient string comparison with strings.ToLower '
                           'or strings.ToUpper'},
    'SA9001': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Defers in range loops may not run when you expect '
                           'them to'},
    'SA9002': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Using a non-octal os.FileMode that looks like it '
                           'was meant to be in octal.'},
    'SA9003': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Empty body in an if or else branch'},
    'SA9004': {   'categories': ['security'],
                  'description': 'In a constant declaration such as the '
                                 'following:\n'
                                 '\n'
                                 '```go\n'
                                 'const (\n'
                                 '    First byte = 1\n'
                                 '    Second     = 2\n'
                                 ')\n'
                                 '```\n'
                                 '\n'
                                 'the constant Second does not have the same '
                                 'type as the constant First.\n'
                                 "This construct shouldn't be confused with\n"
                                 '\n'
                                 '```go\n'
                                 'const (\n'
                                 '    First byte = iota\n'
                                 '    Second\n'
                                 ')\n'
                                 '```\n'
                                 '\n'
                                 'where First and Second do indeed have the '
                                 'same type. The type is only\n'
                                 'passed on when no explicit value is assigned '
                                 'to the constant.\n'
                                 '\n'
                                 'When declaring enumerations with explicit '
                                 'values it is therefore\n'
                                 'important not to write\n'
                                 '\n'
                                 '```go\n'
                                 'const (\n'
                                 '      EnumFirst EnumType = 1\n'
                                 '      EnumSecond         = 2\n'
                                 '      EnumThird          = 3\n'
                                 ')\n'
                                 '```\n'
                                 '\n'
                                 'This discrepancy in types can cause various '
                                 'confusing behaviors and\n'
                                 'bugs.\n'
                                 '\n'
                                 '\n'
                                 '#### Wrong type in variable declarations\n'
                                 '\n'
                                 'The most obvious issue with such incorrect '
                                 'enumerations expresses\n'
                                 'itself as a compile error:\n'
                                 '\n'
                                 '```go\n'
                                 'package pkg\n'
                                 '\n'
                                 'const (\n'
                                 '    EnumFirst  uint8 = 1\n'
                                 '    EnumSecond       = 2\n'
                                 ')\n'
                                 '\n'
                                 'func fn(useFirst bool) {\n'
                                 '    x := EnumSecond\n'
                                 '    if useFirst {\n'
                                 '        x = EnumFirst\n'
                                 '    }\n'
                                 '}\n'
                                 '```\n'
                                 '\n'
                                 'fails to compile with\n'
                                 '\n'
                                 '```go\n'
                                 './const.go:11:5: cannot use EnumFirst (type '
                                 'uint8) as type int in assignment\n'
                                 '```\n'
                                 '\n'
                                 '\n'
                                 '#### Losing method sets\n'
                                 '\n'
                                 'A more subtle issue occurs with types that '
                                 'have methods and optional\n'
                                 'interfaces. Consider the following:\n'
                                 '\n'
                                 '```go\n'
                                 'package main\n'
                                 '\n'
                                 'import "fmt"\n'
                                 '\n'
                                 'type Enum int\n'
                                 '\n'
                                 'func (e Enum) String() string {\n'
                                 '    return "an enum"\n'
                                 '}\n'
                                 '\n'
                                 'const (\n'
                                 '    EnumFirst  Enum = 1\n'
                                 '    EnumSecond      = 2\n'
                                 ')\n'
                                 '\n'
                                 'func main() {\n'
                                 '    fmt.Println(EnumFirst)\n'
                                 '    fmt.Println(EnumSecond)\n'
                                 '}\n'
                                 '```\n'
                                 '\n'
                                 'This code will output\n'
                                 '\n'
                                 '```go\n'
                                 'an enum\n'
                                 '2\n'
                                 '```\n'
                                 '\n'
                                 'as EnumSecond has no explicit type, and thus '
                                 'defaults to int.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Only the first constant has an explicit type'},
    'SA9005': {   'categories': ['security'],
                  'description': 'The encoding/json and encoding/xml packages '
                                 'only operate on exported\n'
                                 'fields in structs, not unexported ones. It '
                                 'is usually an error to try\n'
                                 'to (un)marshal structs that only consist of '
                                 'unexported fields.\n'
                                 '\n'
                                 'This check will not flag calls involving '
                                 'types that define custom\n'
                                 'marshaling behavior, e.g. via MarshalJSON '
                                 'methods. It will also not\n'
                                 'flag empty structs.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Trying to marshal a struct with no public fields '
                           'nor custom marshaling'},
    'SA9006': {   'categories': ['security'],
                  'description': 'Bit shifting a value past its size will '
                                 'always clear the value.\n'
                                 '\n'
                                 'For instance:\n'
                                 '\n'
                                 '```go\n'
                                 'v := int8(42)\n'
                                 'v >>= 8\n'
                                 '```\n'
                                 '\n'
                                 'will always result in 0.\n'
                                 '\n'
                                 'This check flags bit shifting operations on '
                                 'fixed size integer values only.\n'
                                 'That is, int, uint and uintptr are never '
                                 'flagged to avoid potential false\n'
                                 'positives in somewhat exotic but valid bit '
                                 'twiddling tricks:\n'
                                 '\n'
                                 '```go\n'
                                 '// Clear any value above 32 bits if integers '
                                 'are more than 32 bits.\n'
                                 'func f(i int) int {\n'
                                 '    v := i >> 32\n'
                                 '    v = v << 32\n'
                                 '    return i-v\n'
                                 '}\n'
                                 '```',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Dubious bit shifting of a fixed size integer '
                           'value'},
    'SA9007': {   'categories': ['security'],
                  'description': 'It is virtually never correct to delete '
                                 'system directories such as\n'
                                 "/tmp or the user's home directory. However, "
                                 'it can be fairly easy to\n'
                                 'do by mistake, for example by mistakingly '
                                 'using os.TempDir instead\n'
                                 'of ioutil.TempDir, or by forgetting to add a '
                                 'suffix to the result\n'
                                 'of os.UserHomeDir.\n'
                                 '\n'
                                 'Writing\n'
                                 '\n'
                                 '```go\n'
                                 'd := os.TempDir()\n'
                                 'defer os.RemoveAll(d)\n'
                                 '```\n'
                                 '\n'
                                 'in your unit tests will have a devastating '
                                 'effect on the stability of your system.\n'
                                 '\n'
                                 'This check flags attempts at deleting the '
                                 'following directories:\n'
                                 '\n'
                                 '- os.TempDir\n'
                                 '- os.UserCacheDir\n'
                                 '- os.UserConfigDir\n'
                                 '- os.UserHomeDir',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': "Deleting a directory that shouldn't be deleted"},
    'SA9008': {   'categories': ['security'],
                  'description': 'When declaring variables as part of an if '
                                 "statement (like in 'if\n"
                                 "foo := ...; foo {'), the same variables will "
                                 'also be in the scope of\n'
                                 'the else branch. This means that in the '
                                 'following example\n'
                                 '\n'
                                 '```go\n'
                                 'if x, ok := x.(int); ok {\n'
                                 '    // ...\n'
                                 '} else {\n'
                                 '    fmt.Printf("unexpected type %T", x)\n'
                                 '}\n'
                                 '```\n'
                                 '\n'
                                 'x in the else branch will refer to the x '
                                 'from x, ok\n'
                                 ':=; it will not refer to the x that is being '
                                 'type-asserted. The\n'
                                 'result of a failed type assertion is the '
                                 'zero value of the type that\n'
                                 'is being asserted to, so x in the else '
                                 'branch will always have the\n'
                                 'value 0 and the type int.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'else branch of a type assertion is probably not '
                           'reading the right value'},
    'ST1000': {   'categories': ['security'],
                  'description': 'Packages must have a package comment that is '
                                 'formatted according to\n'
                                 'the guidelines laid out in\n'
                                 'https://github.com/golang/go/wiki/CodeReviewComments#package-comments.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Incorrect or missing package comment'},
    'ST1001': {   'categories': ['security'],
                  'description': "Dot imports that aren't in external test "
                                 'packages are discouraged.\n'
                                 '\n'
                                 'The dot_import_whitelist option can be used '
                                 'to whitelist certain\n'
                                 'imports.\n'
                                 '\n'
                                 'Quoting Go Code Review Comments:\n'
                                 '\n'
                                 '> The import . form can be useful in tests '
                                 'that, due to circular\n'
                                 '> dependencies, cannot be made part of the '
                                 'package being tested:\n'
                                 '> \n'
                                 '>     package foo_test\n'
                                 '> \n'
                                 '>     import (\n'
                                 '>         "bar/testutil" // also imports '
                                 '"foo"\n'
                                 '>         . "foo"\n'
                                 '>     )\n'
                                 '> \n'
                                 '> In this case, the test file cannot be in '
                                 'package foo because it\n'
                                 '> uses bar/testutil, which imports foo. So '
                                 'we use the import .\n'
                                 '> form to let the file pretend to be part of '
                                 'package foo even though\n'
                                 '> it is not. Except for this one case, do '
                                 'not use import . in your\n'
                                 '> programs. It makes the programs much '
                                 'harder to read because it is\n'
                                 '> unclear whether a name like Quux is a '
                                 'top-level identifier in the\n'
                                 '> current package or in an imported package.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Dot imports are discouraged'},
    'ST1003': {   'categories': ['security'],
                  'description': 'Identifiers, such as variable and package '
                                 'names, follow certain rules.\n'
                                 '\n'
                                 'See the following links for details:\n'
                                 '\n'
                                 '- '
                                 'https://golang.org/doc/effective_go.html#package-names\n'
                                 '- '
                                 'https://golang.org/doc/effective_go.html#mixed-caps\n'
                                 '- '
                                 'https://github.com/golang/go/wiki/CodeReviewComments#initialisms\n'
                                 '- '
                                 'https://github.com/golang/go/wiki/CodeReviewComments#variable-names',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Poorly chosen identifier'},
    'ST1005': {   'categories': ['security'],
                  'description': 'Error strings follow a set of guidelines to '
                                 'ensure uniformity and good\n'
                                 'composability.\n'
                                 '\n'
                                 'Quoting Go Code Review Comments:\n'
                                 '\n'
                                 '> Error strings should not be capitalized '
                                 '(unless beginning with\n'
                                 '> proper nouns or acronyms) or end with '
                                 'punctuation, since they are\n'
                                 '> usually printed following other context. '
                                 'That is, use\n'
                                 '> fmt.Errorf("something bad") not '
                                 'fmt.Errorf("Something bad"), so\n'
                                 '> that log.Printf("Reading %s: %v", '
                                 'filename, err) formats without a\n'
                                 '> spurious capital letter mid-message.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Incorrectly formatted error string'},
    'ST1006': {   'categories': ['security'],
                  'description': 'Quoting Go Code Review Comments:\n'
                                 '\n'
                                 "> The name of a method's receiver should be "
                                 'a reflection of its\n'
                                 '> identity; often a one or two letter '
                                 'abbreviation of its type\n'
                                 '> suffices (such as "c" or "cl" for '
                                 '"Client"). Don\'t use generic\n'
                                 '> names such as "me", "this" or "self", '
                                 'identifiers typical of\n'
                                 '> object-oriented languages that place more '
                                 'emphasis on methods as\n'
                                 '> opposed to functions. The name need not be '
                                 'as descriptive as that\n'
                                 '> of a method argument, as its role is '
                                 'obvious and serves no\n'
                                 '> documentary purpose. It can be very short '
                                 'as it will appear on\n'
                                 '> almost every line of every method of the '
                                 'type; familiarity admits\n'
                                 '> brevity. Be consistent, too: if you call '
                                 'the receiver "c" in one\n'
                                 '> method, don\'t call it "cl" in another.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Poorly chosen receiver name'},
    'ST1008': {   'categories': ['security'],
                  'description': "A function's error value should be its last "
                                 'return value.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': "A function's error value should be its last return "
                           'value'},
    'ST1011': {   'categories': ['security'],
                  'description': 'time.Duration values represent an amount of '
                                 'time, which is represented\n'
                                 'as a count of nanoseconds. An expression '
                                 'like 5 * time.Microsecond\n'
                                 'yields the value 5000. It is therefore not '
                                 'appropriate to suffix a\n'
                                 'variable of type time.Duration with any time '
                                 'unit, such as Msec or\n'
                                 'Milli.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Poorly chosen name for variable of type '
                           'time.Duration'},
    'ST1012': {   'categories': ['security'],
                  'description': 'Error variables that are part of an API '
                                 'should be called errFoo or\n'
                                 'ErrFoo.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Poorly chosen name for error variable'},
    'ST1013': {   'categories': ['security'],
                  'description': 'HTTP has a tremendous number of status '
                                 'codes. While some of those are\n'
                                 'well known (200, 400, 404, 500), most of '
                                 'them are not. The net/http\n'
                                 'package provides constants for all status '
                                 'codes that are part of the\n'
                                 'various specifications. It is recommended to '
                                 'use these constants\n'
                                 'instead of hard-coding magic numbers, to '
                                 'vastly improve the\n'
                                 'readability of your code.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Should use constants for HTTP error codes, not '
                           'magic numbers'},
    'ST1015': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': "A switch's default case should be the first or "
                           'last case'},
    'ST1016': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Use consistent method receiver names'},
    'ST1017': {   'categories': ['security'],
                  'description': 'Yoda conditions are conditions of the kind '
                                 "'if 42 == x', where the\n"
                                 'literal is on the left side of the '
                                 'comparison. These are a common\n'
                                 'idiom in languages in which assignment is an '
                                 'expression, to avoid bugs\n'
                                 "of the kind 'if (x = 42)'. In Go, which "
                                 "doesn't allow for this kind of\n"
                                 "bug, we prefer the more idiomatic 'if x == "
                                 "42'.",
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': "Don't use Yoda conditions"},
    'ST1018': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Avoid zero-width and control characters in string '
                           'literals'},
    'ST1019': {   'categories': ['security'],
                  'description': 'Go allows importing the same package '
                                 'multiple times, as long as\n'
                                 'different import aliases are being used. '
                                 'That is, the following\n'
                                 'bit of code is valid:\n'
                                 '\n'
                                 '```go\n'
                                 'import (\n'
                                 '    "fmt"\n'
                                 '    fumpt "fmt"\n'
                                 '    format "fmt"\n'
                                 '    _ "fmt"\n'
                                 ')\n'
                                 '```\n'
                                 '\n'
                                 'However, this is very rarely done on '
                                 'purpose. Usually, it is a\n'
                                 'sign of code that got refactored, '
                                 'accidentally adding duplicate\n'
                                 'import statements. It is also a rarely known '
                                 'feature, which may\n'
                                 'contribute to confusion.\n'
                                 '\n'
                                 'Do note that sometimes, this feature may be '
                                 'used\n'
                                 'intentionally (see for example\n'
                                 'https://github.com/golang/go/commit/3409ce39bfd7584523b7a8c150a310cea92d879d)\n'
                                 '– if you want to allow this pattern in your '
                                 "code base, you're\n"
                                 'advised to disable this check.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Importing the same package multiple times'},
    'ST1020': {   'categories': ['security'],
                  'description': 'Doc comments work best as complete '
                                 'sentences, which\n'
                                 'allow a wide variety of automated '
                                 'presentations. The first sentence\n'
                                 'should be a one-sentence summary that starts '
                                 'with the name being\n'
                                 'declared.\n'
                                 '\n'
                                 'If every doc comment begins with the name of '
                                 'the item it describes,\n'
                                 'you can use the doc subcommand of the go '
                                 'tool and run the output\n'
                                 'through grep.\n'
                                 '\n'
                                 'See '
                                 'https://golang.org/doc/effective_go.html#commentary '
                                 'for more\n'
                                 'information on how to write good '
                                 'documentation.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'The documentation of an exported function should '
                           "start with the function's name"},
    'ST1021': {   'categories': ['security'],
                  'description': 'Doc comments work best as complete '
                                 'sentences, which\n'
                                 'allow a wide variety of automated '
                                 'presentations. The first sentence\n'
                                 'should be a one-sentence summary that starts '
                                 'with the name being\n'
                                 'declared.\n'
                                 '\n'
                                 'If every doc comment begins with the name of '
                                 'the item it describes,\n'
                                 'you can use the doc subcommand of the go '
                                 'tool and run the output\n'
                                 'through grep.\n'
                                 '\n'
                                 'See '
                                 'https://golang.org/doc/effective_go.html#commentary '
                                 'for more\n'
                                 'information on how to write good '
                                 'documentation.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'The documentation of an exported type should start '
                           "with type's name"},
    'ST1022': {   'categories': ['security'],
                  'description': 'Doc comments work best as complete '
                                 'sentences, which\n'
                                 'allow a wide variety of automated '
                                 'presentations. The first sentence\n'
                                 'should be a one-sentence summary that starts '
                                 'with the name being\n'
                                 'declared.\n'
                                 '\n'
                                 'If every doc comment begins with the name of '
                                 'the item it describes,\n'
                                 'you can use the doc subcommand of the go '
                                 'tool and run the output\n'
                                 'through grep.\n'
                                 '\n'
                                 'See '
                                 'https://golang.org/doc/effective_go.html#commentary '
                                 'for more\n'
                                 'information on how to write good '
                                 'documentation.',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'The documentation of an exported variable or '
                           "constant should start with variable's name"},
    'ST1023': {   'categories': ['security'],
                  'description': '',
                  'file': '%(issue.file)s',
                  'line': '%(issue.line)s',
                  'severity': '1',
                  'title': 'Redundant type in variable declaration'}}
