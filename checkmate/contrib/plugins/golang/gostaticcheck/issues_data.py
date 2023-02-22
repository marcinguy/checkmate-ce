# -*- coding: utf-8 -*-


issues_data = {
  "SA4020": {
    "title": "Unreachable case clause in a type switch",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "In a type switch like the following\n\n```go\ntype T struct{}\nfunc (T) Read(b []byte) (int, error) { return 0, nil }\n\nvar v interface{} = T{}\n\nswitch v.(type) {\ncase io.Reader:\n    // ...\ncase T:\n    // unreachable\n}\n```\n\nthe second case clause can never be reached because T implements\nio.Reader and case clauses are evaluated in source order.\n\nAnother example:\n\n```go\ntype T struct{}\nfunc (T) Read(b []byte) (int, error) { return 0, nil }\nfunc (T) Close() error { return nil }\n\nvar v interface{} = T{}\n\nswitch v.(type) {\ncase io.Reader:\n    // ...\ncase io.ReadCloser:\n    // unreachable\n}\n```\n\nEven though T has a Close method and thus implements io.ReadCloser,\nio.Reader will always match first. The method set of io.Reader is a\nsubset of io.ReadCloser. Thus it is impossible to match the second\ncase without matching the first case.\n\n\n#### Structurally equivalent interfaces\n\nA special case of the previous example are structurally identical\ninterfaces. Given these declarations\n\n```go\ntype T error\ntype V error\n\nfunc doSomething() error {\n    err, ok := doAnotherThing()\n    if ok {\n        return T(err)\n    }\n\n    return U(err)\n}\n```\n\nthe following type switch will have an unreachable case clause:\n\n```go\nswitch doSomething().(type) {\ncase T:\n    // ...\ncase V:\n    // unreachable\n}\n```\n\nT will always match before V because they are structurally equivalent\nand therefore doSomething()'s return value implements both."
  },
  "SA3001": {
    "title": "Assigning to b.N in benchmarks distorts the results",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The testing package dynamically sets b.N to improve the reliability of\nbenchmarks and uses it in computations to determine the duration of a\nsingle operation. Benchmark code must not alter b.N as this would\nfalsify results."
  },
  "SA3000": {
    "title": "TestMain doesn't call os.Exit, hiding test failures",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Test executables (and in turn 'go test') exit with a non-zero status\ncode if any tests failed. When specifying your own TestMain function,\nit is your responsibility to arrange for this, by calling os.Exit with\nthe correct code. The correct code is returned by (*testing.M).Run, so\nthe usual way of implementing TestMain is to end it with\nos.Exit(m.Run())."
  },
  "SA9008": {
    "title": "else branch of a type assertion is probably not reading the right value",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "When declaring variables as part of an if statement (like in 'if\nfoo := ...; foo {'), the same variables will also be in the scope of\nthe else branch. This means that in the following example\n\n```go\nif x, ok := x.(int); ok {\n    // ...\n} else {\n    fmt.Printf(\"unexpected type %T\", x)\n}\n```\n\nx in the else branch will refer to the x from x, ok\n:=; it will not refer to the x that is being type-asserted. The\nresult of a failed type assertion is the zero value of the type that\nis being asserted to, so x in the else branch will always have the\nvalue 0 and the type int."
  },
  "SA9005": {
    "title": "Trying to marshal a struct with no public fields nor custom marshaling",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The encoding/json and encoding/xml packages only operate on exported\nfields in structs, not unexported ones. It is usually an error to try\nto (un)marshal structs that only consist of unexported fields.\n\nThis check will not flag calls involving types that define custom\nmarshaling behavior, e.g. via MarshalJSON methods. It will also not\nflag empty structs."
  },
  "SA9004": {
    "title": "Only the first constant has an explicit type",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "In a constant declaration such as the following:\n\n```go\nconst (\n    First byte = 1\n    Second     = 2\n)\n```\n\nthe constant Second does not have the same type as the constant First.\nThis construct shouldn't be confused with\n\n```go\nconst (\n    First byte = iota\n    Second\n)\n```\n\nwhere First and Second do indeed have the same type. The type is only\npassed on when no explicit value is assigned to the constant.\n\nWhen declaring enumerations with explicit values it is therefore\nimportant not to write\n\n```go\nconst (\n      EnumFirst EnumType = 1\n      EnumSecond         = 2\n      EnumThird          = 3\n)\n```\n\nThis discrepancy in types can cause various confusing behaviors and\nbugs.\n\n\n#### Wrong type in variable declarations\n\nThe most obvious issue with such incorrect enumerations expresses\nitself as a compile error:\n\n```go\npackage pkg\n\nconst (\n    EnumFirst  uint8 = 1\n    EnumSecond       = 2\n)\n\nfunc fn(useFirst bool) {\n    x := EnumSecond\n    if useFirst {\n        x = EnumFirst\n    }\n}\n```\n\nfails to compile with\n\n```go\n./const.go:11:5: cannot use EnumFirst (type uint8) as type int in assignment\n```\n\n\n#### Losing method sets\n\nA more subtle issue occurs with types that have methods and optional\ninterfaces. Consider the following:\n\n```go\npackage main\n\nimport \"fmt\"\n\ntype Enum int\n\nfunc (e Enum) String() string {\n    return \"an enum\"\n}\n\nconst (\n    EnumFirst  Enum = 1\n    EnumSecond      = 2\n)\n\nfunc main() {\n    fmt.Println(EnumFirst)\n    fmt.Println(EnumSecond)\n}\n```\n\nThis code will output\n\n```go\nan enum\n2\n```\n\nas EnumSecond has no explicit type, and thus defaults to int."
  },
  "SA9007": {
    "title": "Deleting a directory that shouldn't be deleted",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "It is virtually never correct to delete system directories such as\n/tmp or the user's home directory. However, it can be fairly easy to\ndo by mistake, for example by mistakingly using os.TempDir instead\nof ioutil.TempDir, or by forgetting to add a suffix to the result\nof os.UserHomeDir.\n\nWriting\n\n```go\nd := os.TempDir()\ndefer os.RemoveAll(d)\n```\n\nin your unit tests will have a devastating effect on the stability of your system.\n\nThis check flags attempts at deleting the following directories:\n\n- os.TempDir\n- os.UserCacheDir\n- os.UserConfigDir\n- os.UserHomeDir"
  },
  "SA9006": {
    "title": "Dubious bit shifting of a fixed size integer value",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Bit shifting a value past its size will always clear the value.\n\nFor instance:\n\n```go\nv := int8(42)\nv >>= 8\n```\n\nwill always result in 0.\n\nThis check flags bit shifting operations on fixed size integer values only.\nThat is, int, uint and uintptr are never flagged to avoid potential false\npositives in somewhat exotic but valid bit twiddling tricks:\n\n```go\n// Clear any value above 32 bits if integers are more than 32 bits.\nfunc f(i int) int {\n    v := i >> 32\n    v = v << 32\n    return i-v\n}\n```"
  },
  "SA9001": {
    "title": "Defers in range loops may not run when you expect them to",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA9003": {
    "title": "Empty body in an if or else branch",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA9002": {
    "title": "Using a non-octal os.FileMode that looks like it was meant to be in octal.",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA1030": {
    "title": "Invalid argument in call to a strconv function",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "This check validates the format, number base and bit size arguments of\nthe various parsing and formatting functions in strconv."
  },
  "S1018": {
    "title": "Use 'copy' for sliding elements",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "copy() permits using the same source and destination slice, even with\noverlapping ranges. This makes it ideal for sliding elements in a\nslice."
  },
  "S1019": {
    "title": "Simplify 'make' call by omitting redundant arguments",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The 'make' function has default values for the length and capacity\narguments. For channels, the length defaults to zero, and for slices,\nthe capacity defaults to the length."
  },
  "S1016": {
    "title": "Use a type conversion instead of manually copying struct fields",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Two struct types with identical fields can be converted between each\nother. In older versions of Go, the fields had to have identical\nstruct tags. Since Go 1.8, however, struct tags are ignored during\nconversions. It is thus not necessary to manually copy every field\nindividually."
  },
  "QF1012": {
    "title": "Use fmt.Fprintf(x, ...) instead of x.Write(fmt.Sprintf(...))",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "QF1011": {
    "title": "Omit redundant type from variable declaration",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "QF1010": {
    "title": "Convert slice of bytes to string when printing it",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "S1012": {
    "title": "Replace time.Now().Sub(x) with time.Since(x)",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The time.Since helper has the same effect as using time.Now().Sub(x)\nbut is easier to read."
  },
  "S1010": {
    "title": "Omit default slice index",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "When slicing, the second index defaults to the length of the value,\nmaking s[n:len(s)] and s[n:] equivalent."
  },
  "S1011": {
    "title": "Use a single append to concatenate two slices",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA6005": {
    "title": "Inefficient string comparison with strings.ToLower or strings.ToUpper",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Converting two strings to the same case and comparing them like so\n\n```go\nif strings.ToLower(s1) == strings.ToLower(s2) {\n    ...\n}\n```\n\nis significantly more expensive than comparing them with\nstrings.EqualFold(s1, s2). This is due to memory usage as well as\ncomputational complexity.\n\nstrings.ToLower will have to allocate memory for the new strings, as\nwell as convert both strings fully, even if they differ on the very\nfirst byte. strings.EqualFold, on the other hand, compares the strings\none character at a time. It doesn't need to create two intermediate\nstrings and can return as soon as the first non-matching character has\nbeen found.\n\nFor a more in-depth explanation of this issue, see\nhttps://blog.digitalocean.com/how-to-efficiently-compare-strings-in-go/"
  },
  "SA6000": {
    "title": "Using regexp.Match or related in a loop, should use regexp.Compile",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA6001": {
    "title": "Missing an optimization opportunity when indexing maps by byte slices",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Map keys must be comparable, which precludes the use of byte slices.\nThis usually leads to using string keys and converting byte slices to\nstrings.\n\nNormally, a conversion of a byte slice to a string needs to copy the data and\ncauses allocations. The compiler, however, recognizes m[string(b)] and\nuses the data of b directly, without copying it, because it knows that\nthe data can't change during the map lookup. This leads to the\ncounter-intuitive situation that\n\n```go\nk := string(b)\nprintln(m[k])\nprintln(m[k])\n```\n\nwill be less efficient than\n\n```go\nprintln(m[string(b)])\nprintln(m[string(b)])\n```\n\nbecause the first version needs to copy and allocate, while the second\none does not.\n\nFor some history on this optimization, check out commit\nf5f5a8b6209f84961687d993b93ea0d397f5d5bf in the Go repository."
  },
  "SA6002": {
    "title": "Storing non-pointer values in sync.Pool allocates memory",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A sync.Pool is used to avoid unnecessary allocations and reduce the\namount of work the garbage collector has to do.\n\nWhen passing a value that is not a pointer to a function that accepts\nan interface, the value needs to be placed on the heap, which means an\nadditional allocation. Slices are a common thing to put in sync.Pools,\nand they're structs with 3 fields (length, capacity, and a pointer to\nan array). In order to avoid the extra allocation, one should store a\npointer to the slice instead.\n\nSee the comments on https://go-review.googlesource.com/c/go/+/24371\nthat discuss this problem."
  },
  "SA6003": {
    "title": "Converting a string to a slice of runes before ranging over it",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "You may want to loop over the runes in a string. Instead of converting\nthe string to a slice of runes and looping over that, you can loop\nover the string itself. That is,\n\n```go\nfor _, r := range s {}\n```\n\nand\n\n```go\nfor _, r := range []rune(s) {}\n```\n\nwill yield the same values. The first version, however, will be faster\nand avoid unnecessary memory allocations.\n\nDo note that if you are interested in the indices, ranging over a\nstring and over a slice of runes will yield different indices. The\nfirst one yields byte offsets, while the second one yields indices in\nthe slice of runes."
  },
  "S1029": {
    "title": "Range over the string directly",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Ranging over a string will yield byte offsets and runes. If the offset\nisn't used, this is functionally equivalent to converting the string\nto a slice of runes and ranging over that. Ranging directly over the\nstring will be more performant, however, as it avoids allocating a new\nslice, the size of which depends on the length of the string."
  },
  "S1028": {
    "title": "Simplify error construction with fmt.Errorf",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "S1023": {
    "title": "Omit redundant control flow",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Functions that have no return value do not need a return statement as\nthe final statement of the function.\n\nSwitches in Go do not have automatic fallthrough, unlike languages\nlike C. It is not necessary to have a break statement as the final\nstatement in a case block."
  },
  "S1021": {
    "title": "Merge variable declaration and assignment",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "S1020": {
    "title": "Omit redundant nil check in type assertion",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "QF1005": {
    "title": "Expand call to math.Pow",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Some uses of math.Pow can be simplified to basic multiplication."
  },
  "S1025": {
    "title": "Don't use fmt.Sprintf(\"%s\", x) unnecessarily",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "In many instances, there are easier and more efficient ways of getting\na value's string representation. Whenever a value's underlying type is\na string already, or the type has a String method, they should be used\ndirectly.\n\nGiven the following shared definitions\n\n```go\ntype T1 string\ntype T2 int\n\nfunc (T2) String() string { return \"Hello, world\" }\n\nvar x string\nvar y T1\nvar z T2\n```\n\nwe can simplify\n\n```go\nfmt.Sprintf(\"%s\", x)\nfmt.Sprintf(\"%s\", y)\nfmt.Sprintf(\"%s\", z)\n```\n\nto\n\n```go\nx\nstring(y)\nz.String()\n```"
  },
  "S1024": {
    "title": "Replace x.Sub(time.Now()) with time.Until(x)",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The time.Until helper has the same effect as using x.Sub(time.Now())\nbut is easier to read."
  },
  "S1034": {
    "title": "Use result of type assertion to simplify cases",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "S1035": {
    "title": "Redundant call to net/http.CanonicalHeaderKey in method call on net/http.Header",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The methods on net/http.Header, namely Add, Del, Get\nand Set, already canonicalize the given header name."
  },
  "S1036": {
    "title": "Unnecessary guard around map access",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "When accessing a map key that doesn't exist yet, one receives a zero\nvalue. Often, the zero value is a suitable value, for example when\nusing append or doing integer math.\n\nThe following\n\n```go\nif _, ok := m[\"foo\"]; ok {\n    m[\"foo\"] = append(m[\"foo\"], \"bar\")\n} else {\n    m[\"foo\"] = []string{\"bar\"}\n}\n```\n\ncan be simplified to\n\n```go\nm[\"foo\"] = append(m[\"foo\"], \"bar\")\n```\n\nand\n\n```go\nif _, ok := m2[\"k\"]; ok {\n    m2[\"k\"] += 4\n} else {\n    m2[\"k\"] = 4\n}\n```\n\ncan be simplified to\n\n```go\nm[\"k\"] += 4\n```"
  },
  "S1037": {
    "title": "Elaborate way of sleeping",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Using a select statement with a single case receiving\nfrom the result of time.After is a very elaborate way of sleeping that\ncan much simpler be expressed with a simple call to time.Sleep."
  },
  "S1030": {
    "title": "Use bytes.Buffer.String or bytes.Buffer.Bytes",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "bytes.Buffer has both a String and a Bytes method. It is almost never\nnecessary to use string(buf.Bytes()) or []byte(buf.String()) \u2013 simply\nuse the other method.\n\nThe only exception to this are map lookups. Due to a compiler optimization,\nm[string(buf.Bytes())] is more efficient than m[buf.String()]."
  },
  "SA2001": {
    "title": "Empty critical section, did you mean to defer the unlock?",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Empty critical sections of the kind\n\n```go\nmu.Lock()\nmu.Unlock()\n```\n\nare very often a typo, and the following was intended instead:\n\n```go\nmu.Lock()\ndefer mu.Unlock()\n```\n\nDo note that sometimes empty critical sections can be useful, as a\nform of signaling to wait on another goroutine. Many times, there are\nsimpler ways of achieving the same effect. When that isn't the case,\nthe code should be amply commented to avoid confusion. Combining such\ncomments with a //lint:ignore directive can be used to suppress this\nrare false positive."
  },
  "S1032": {
    "title": "Use sort.Ints(x), sort.Float64s(x), and sort.Strings(x)",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The sort.Ints, sort.Float64s and sort.Strings functions are easier to\nread than sort.Sort(sort.IntSlice(x)), sort.Sort(sort.Float64Slice(x))\nand sort.Sort(sort.StringSlice(x))."
  },
  "S1033": {
    "title": "Unnecessary guard around call to 'delete'",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Calling delete on a nil map is a no-op."
  },
  "S1038": {
    "title": "Unnecessarily complex way of printing formatted string",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Instead of using fmt.Print(fmt.Sprintf(...)), one can use fmt.Printf(...)."
  },
  "S1039": {
    "title": "Unnecessary use of fmt.Sprint",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Calling fmt.Sprint with a single string argument is unnecessary\nand identical to using the string directly."
  },
  "S1009": {
    "title": "Omit redundant nil check on slices",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The len function is defined for all slices, even nil ones, which have\na length of zero. It is not necessary to check if a slice is not nil\nbefore checking that its length is not zero."
  },
  "S1008": {
    "title": "Simplify returning boolean expression",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "S1040": {
    "title": "Type assertion to current type",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The type assertion x.(SomeInterface), when x already has type\nSomeInterface, can only fail if x is nil. Usually, this is\nleft-over code from when x had a different type and you can safely\ndelete the type assertion. If you want to check that x is not nil,\nconsider being explicit and using an actual if x == nil comparison\ninstead of relying on the type assertion panicking."
  },
  "S1006": {
    "title": "Use 'for { ... }' for infinite loops",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "For infinite loops, using for { ... } is the most idiomatic choice."
  },
  "QF1004": {
    "title": "Use strings.ReplaceAll instead of strings.Replace with n == -1",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA1008": {
    "title": "Non-canonical key in http.Header map",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Keys in http.Header maps are canonical, meaning they follow a specific\ncombination of uppercase and lowercase letters. Methods such as\nhttp.Header.Add and http.Header.Del convert inputs into this canonical\nform before manipulating the map.\n\nWhen manipulating http.Header maps directly, as opposed to using the\nprovided methods, care should be taken to stick to canonical form in\norder to avoid inconsistencies. The following piece of code\ndemonstrates one such inconsistency:\n\n```go\nh := http.Header{}\nh[\"etag\"] = []string{\"1234\"}\nh.Add(\"etag\", \"5678\")\nfmt.Println(h)\n\n// Output:\n// map[Etag:[5678] etag:[1234]]\n```\n\nThe easiest way of obtaining the canonical form of a key is to use\nhttp.CanonicalHeaderKey."
  },
  "SA2000": {
    "title": "sync.WaitGroup.Add called inside the goroutine, leading to a race condition",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "S1017": {
    "title": "Replace manual trimming with strings.TrimPrefix",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Instead of using strings.HasPrefix and manual slicing, use the\nstrings.TrimPrefix function. If the string doesn't start with the\nprefix, the original string will be returned. Using strings.TrimPrefix\nreduces complexity, and avoids common bugs, such as off-by-one\nmistakes."
  },
  "SA2002": {
    "title": "Called testing.T.FailNow or SkipNow in a goroutine, which isn't allowed",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA2003": {
    "title": "Deferred Lock right after locking, likely meant to defer Unlock instead",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4003": {
    "title": "Comparing unsigned values against negative values is pointless",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4000": {
    "title": "Binary operator has identical expressions on both sides",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4001": {
    "title": "&*x gets simplified to x, it does not copy x",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4006": {
    "title": "A value assigned to a variable is never read before being overwritten. Forgotten error check or dead code?",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4004": {
    "title": "The loop exits unconditionally after one iteration",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4005": {
    "title": "Field assignment that will never be observed. Did you mean to use a pointer receiver?",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4008": {
    "title": "The variable in the loop condition never changes, are you incrementing the wrong variable?",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4009": {
    "title": "A function argument is overwritten before its first use",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA1016": {
    "title": "Trapping a signal that cannot be trapped",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Not all signals can be intercepted by a process. Specifically, on\nUNIX-like systems, the syscall.SIGKILL and syscall.SIGSTOP signals are\nnever passed to the process, but instead handled directly by the\nkernel. It is therefore pointless to try and handle these signals."
  },
  "SA1017": {
    "title": "Channels used with os/signal.Notify should be buffered",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The os/signal package uses non-blocking channel sends when delivering\nsignals. If the receiving end of the channel isn't ready and the\nchannel is either unbuffered or full, the signal will be dropped. To\navoid missing signals, the channel should be buffered and of the\nappropriate size. For a channel used for notification of just one\nsignal value, a buffer of size 1 is sufficient."
  },
  "SA1014": {
    "title": "Non-pointer value passed to Unmarshal or Decode",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA1015": {
    "title": "Using time.Tick in a way that will leak. Consider using time.NewTicker, and only use time.Tick in tests, commands and endless functions",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA1012": {
    "title": "A nil context.Context is being passed to a function, consider using context.TODO instead",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA1013": {
    "title": "io.Seeker.Seek is being called with the whence constant as the first argument, but it should be the second",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA1010": {
    "title": "(*regexp.Regexp).FindAll called with n == 0, which will always return zero results",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "If n >= 0, the function returns at most n matches/submatches. To\nreturn all results, specify a negative number."
  },
  "SA1011": {
    "title": "Various methods in the 'strings' package expect valid UTF-8, but invalid input is provided",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "ST1022": {
    "title": "The documentation of an exported variable or constant should start with variable's name",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Doc comments work best as complete sentences, which\nallow a wide variety of automated presentations. The first sentence\nshould be a one-sentence summary that starts with the name being\ndeclared.\n\nIf every doc comment begins with the name of the item it describes,\nyou can use the doc subcommand of the go tool and run the output\nthrough grep.\n\nSee https://golang.org/doc/effective_go.html#commentary for more\ninformation on how to write good documentation."
  },
  "ST1023": {
    "title": "Redundant type in variable declaration",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "ST1020": {
    "title": "The documentation of an exported function should start with the function's name",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Doc comments work best as complete sentences, which\nallow a wide variety of automated presentations. The first sentence\nshould be a one-sentence summary that starts with the name being\ndeclared.\n\nIf every doc comment begins with the name of the item it describes,\nyou can use the doc subcommand of the go tool and run the output\nthrough grep.\n\nSee https://golang.org/doc/effective_go.html#commentary for more\ninformation on how to write good documentation."
  },
  "ST1021": {
    "title": "The documentation of an exported type should start with type's name",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Doc comments work best as complete sentences, which\nallow a wide variety of automated presentations. The first sentence\nshould be a one-sentence summary that starts with the name being\ndeclared.\n\nIf every doc comment begins with the name of the item it describes,\nyou can use the doc subcommand of the go tool and run the output\nthrough grep.\n\nSee https://golang.org/doc/effective_go.html#commentary for more\ninformation on how to write good documentation."
  },
  "SA1018": {
    "title": "strings.Replace called with n == 0, which does nothing",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "With n == 0, zero instances will be replaced. To replace all\ninstances, use a negative number, or use strings.ReplaceAll."
  },
  "SA1019": {
    "title": "Using a deprecated function, variable, constant or field",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "QF1008": {
    "title": "Omit embedded fields from selector expression",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "ST1016": {
    "title": "Use consistent method receiver names",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4011": {
    "title": "Break statement with no effect. Did you mean to break out of an outer loop?",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4010": {
    "title": "The result of append will never be observed anywhere",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4013": {
    "title": "Negating a boolean twice (!!b) is the same as writing b. This is either redundant, or a typo.",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4012": {
    "title": "Comparing a value against NaN even though no value is equal to NaN",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4015": {
    "title": "Calling functions like math.Ceil on floats converted from integers doesn't do anything useful",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4014": {
    "title": "An if/else if chain has repeated conditions and no side-effects; if the condition didn't match the first time, it won't match the second time, either",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4017": {
    "title": "Discarding the return values of a function without side effects, making the call pointless",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4016": {
    "title": "Certain bitwise operations, such as x ^ 0, do not do anything useful",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4019": {
    "title": "Multiple, identical build constraints in the same file",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4018": {
    "title": "Self-assignment of variables",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA1005": {
    "title": "Invalid first argument to exec.Command",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "os/exec runs programs directly (using variants of the fork and exec\nsystem calls on Unix systems). This shouldn't be confused with running\na command in a shell. The shell will allow for features such as input\nredirection, pipes, and general scripting. The shell is also\nresponsible for splitting the user's input into a program name and its\narguments. For example, the equivalent to\n\n```go\nls / /tmp\n```\n\nwould be\n\n```go\nexec.Command(\"ls\", \"/\", \"/tmp\")\n```\n\nIf you want to run a command in a shell, consider using something like\nthe following \u2013 but be aware that not all systems, particularly\nWindows, will have a /bin/sh program:\n\n```go\nexec.Command(\"/bin/sh\", \"-c\", \"ls | grep Awesome\")\n```"
  },
  "SA1004": {
    "title": "Suspiciously small untyped constant in time.Sleep",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The time.Sleep function takes a time.Duration as its only argument.\nDurations are expressed in nanoseconds. Thus, calling time.Sleep(1)\nwill sleep for 1 nanosecond. This is a common source of bugs, as sleep\nfunctions in other languages often accept seconds or milliseconds.\n\nThe time package provides constants such as time.Second to express\nlarge durations. These can be combined with arithmetic to express\narbitrary durations, for example 5 * time.Second for 5 seconds.\n\nIf you truly meant to sleep for a tiny amount of time, use\nn * time.Nanosecond to signal to Staticcheck that you did mean to sleep\nfor some amount of nanoseconds."
  },
  "SA1007": {
    "title": "Invalid URL in net/url.Parse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA1006": {
    "title": "Printf with dynamic first argument and no further arguments",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Using fmt.Printf with a dynamic first argument can lead to unexpected\noutput. The first argument is a format string, where certain character\ncombinations have special meaning. If, for example, a user were to\nenter a string such as\n\n```go\nInterest rate: 5%\n```\n\nand you printed it with\n\n```go\nfmt.Printf(s)\n```\n\nit would lead to the following output:\n\n```go\nInterest rate: 5%!(NOVERB).\n```\n\nSimilarly, forming the first parameter via string concatenation with\nuser input should be avoided for the same reason. When printing user\ninput, either use a variant of fmt.Print, or use the %s Printf verb\nand pass the string as an argument."
  },
  "SA1001": {
    "title": "Invalid template",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA1000": {
    "title": "Invalid regular expression",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA1003": {
    "title": "Unsupported argument to functions in encoding/binary",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The encoding/binary package can only serialize types with known sizes.\nThis precludes the use of the int and uint types, as their sizes\ndiffer on different architectures. Furthermore, it doesn't support\nserializing maps, channels, strings, or functions.\n\nBefore Go 1.8, bool wasn't supported, either."
  },
  "SA1002": {
    "title": "Invalid format in time.Parse",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA5012": {
    "title": "Passing odd-sized slice to function expecting even size",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Some functions that take slices as parameters expect the slices to have an even number of elements. \nOften, these functions treat elements in a slice as pairs. \nFor example, strings.NewReplacer takes pairs of old and new strings, \nand calling it with an odd number of elements would be an error."
  },
  "SA5010": {
    "title": "Impossible type assertion",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Some type assertions can be statically proven to be\nimpossible. This is the case when the method sets of both\narguments of the type assertion conflict with each other, for\nexample by containing the same method with different\nsignatures.\n\nThe Go compiler already applies this check when asserting from an\ninterface value to a concrete type. If the concrete type misses\nmethods from the interface, or if function signatures don't match,\nthen the type assertion can never succeed.\n\nThis check applies the same logic when asserting from one interface to\nanother. If both interface types contain the same method but with\ndifferent signatures, then the type assertion can never succeed,\neither."
  },
  "SA5011": {
    "title": "Possible nil pointer dereference",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A pointer is being dereferenced unconditionally, while\nalso being checked against nil in another place. This suggests that\nthe pointer may be nil and dereferencing it may panic. This is\ncommonly a result of improperly ordered code or missing return\nstatements. Consider the following examples:\n\n```go\nfunc fn(x *int) {\n    fmt.Println(*x)\n\n    // This nil check is equally important for the previous dereference\n    if x != nil {\n        foo(*x)\n    }\n}\n\nfunc TestFoo(t *testing.T) {\n    x := compute()\n    if x == nil {\n        t.Errorf(\"nil pointer received\")\n    }\n\n    // t.Errorf does not abort the test, so if x is nil, the next line will panic.\n    foo(*x)\n}\n```\n\nStaticcheck tries to deduce which functions abort control flow.\nFor example, it is aware that a function will not continue\nexecution after a call to panic or log.Fatal. However, sometimes\nthis detection fails, in particular in the presence of\nconditionals. Consider the following example:\n\n```go\nfunc Log(msg string, level int) {\n    fmt.Println(msg)\n    if level == levelFatal {\n        os.Exit(1)\n    }\n}\n\nfunc Fatal(msg string) {\n    Log(msg, levelFatal)\n}\n\nfunc fn(x *int) {\n    if x == nil {\n        Fatal(\"unexpected nil pointer\")\n    }\n    fmt.Println(*x)\n}\n```\n\nStaticcheck will flag the dereference of x, even though it is perfectly\nsafe. Staticcheck is not able to deduce that a call to\nFatal will exit the program. For the time being, the easiest\nworkaround is to modify the definition of Fatal like so:\n\n```go\nfunc Fatal(msg string) {\n    Log(msg, levelFatal)\n    panic(\"unreachable\")\n}\n```\n\nWe also hard-code functions from common logging packages such as\nlogrus. Please file an issue if we're missing support for a\npopular package."
  },
  "SA4031": {
    "title": "Checking never-nil value against nil",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "S1031": {
    "title": "Omit redundant nil check around loop",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "You can use range on nil slices and maps, the loop will simply never\nexecute. This makes an additional nil check around the loop\nunnecessary."
  },
  "ST1018": {
    "title": "Avoid zero-width and control characters in string literals",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "S1000": {
    "title": "Use plain channel send or receive instead of single-case select",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Select statements with a single case can be replaced with a simple\nsend or receive."
  },
  "S1003": {
    "title": "Replace call to strings.Index with strings.Contains",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "QF1007": {
    "title": "Merge conditional assignment into variable declaration",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "S1002": {
    "title": "Omit comparison with boolean constant",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "ST1005": {
    "title": "Incorrectly formatted error string",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Error strings follow a set of guidelines to ensure uniformity and good\ncomposability.\n\nQuoting Go Code Review Comments:\n\n> Error strings should not be capitalized (unless beginning with\n> proper nouns or acronyms) or end with punctuation, since they are\n> usually printed following other context. That is, use\n> fmt.Errorf(\"something bad\") not fmt.Errorf(\"Something bad\"), so\n> that log.Printf(\"Reading %s: %v\", filename, err) formats without a\n> spurious capital letter mid-message."
  },
  "ST1006": {
    "title": "Poorly chosen receiver name",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Quoting Go Code Review Comments:\n\n> The name of a method's receiver should be a reflection of its\n> identity; often a one or two letter abbreviation of its type\n> suffices (such as \"c\" or \"cl\" for \"Client\"). Don't use generic\n> names such as \"me\", \"this\" or \"self\", identifiers typical of\n> object-oriented languages that place more emphasis on methods as\n> opposed to functions. The name need not be as descriptive as that\n> of a method argument, as its role is obvious and serves no\n> documentary purpose. It can be very short as it will appear on\n> almost every line of every method of the type; familiarity admits\n> brevity. Be consistent, too: if you call the receiver \"c\" in one\n> method, don't call it \"cl\" in another."
  },
  "SA4028": {
    "title": "x % 1 is always zero",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4029": {
    "title": "Ineffective attempt at sorting slice",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "sort.Float64Slice, sort.IntSlice, and sort.StringSlice are\ntypes, not functions. Doing x = sort.StringSlice(x) does nothing,\nespecially not sort any values. The correct usage is\nsort.Sort(sort.StringSlice(x)) or sort.StringSlice(x).Sort(),\nbut there are more convenient helpers, namely sort.Float64s,\nsort.Ints, and sort.Strings."
  },
  "ST1003": {
    "title": "Poorly chosen identifier",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Identifiers, such as variable and package names, follow certain rules.\n\nSee the following links for details:\n\n- https://golang.org/doc/effective_go.html#package-names\n- https://golang.org/doc/effective_go.html#mixed-caps\n- https://github.com/golang/go/wiki/CodeReviewComments#initialisms\n- https://github.com/golang/go/wiki/CodeReviewComments#variable-names"
  },
  "SA4024": {
    "title": "Checking for impossible return value from a builtin function",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Return values of the len and cap builtins cannot be negative.\n\nSee https://golang.org/pkg/builtin/#len and https://golang.org/pkg/builtin/#cap.\n\nExample:\n\n```go\nif len(slice) < 0 {\n    fmt.Println(\"unreachable code\")\n}\n```"
  },
  "SA4025": {
    "title": "Integer division of literals that results in zero",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "When dividing two integer constants, the result will\nalso be an integer. Thus, a division such as 2 / 3 results in 0.\nThis is true for all of the following examples:\n\n\t_ = 2 / 3\n\tconst _ = 2 / 3\n\tconst _ float64 = 2 / 3\n\t_ = float64(2 / 3)\n\nStaticcheck will flag such divisions if both sides of the division are\ninteger literals, as it is highly unlikely that the division was\nintended to truncate to zero. Staticcheck will not flag integer\ndivision involving named constants, to avoid noisy positives."
  },
  "QF1006": {
    "title": "Lift if+break into loop condition",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4027": {
    "title": "(*net/url.URL).Query returns a copy, modifying it doesn't change the URL",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "(*net/url.URL).Query parses the current value of net/url.URL.RawQuery\nand returns it as a map of type net/url.Values. Subsequent changes to\nthis map will not affect the URL unless the map gets encoded and\nassigned to the URL's RawQuery.\n\nAs a consequence, the following code pattern is an expensive no-op:\nu.Query().Add(key, value)."
  },
  "ST1008": {
    "title": "A function's error value should be its last return value",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A function's error value should be its last return value."
  },
  "SA4021": {
    "title": "'x = append(y)' is equivalent to 'x = y'",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA4022": {
    "title": "Comparing the address of a variable against nil",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Code such as 'if &x == nil' is meaningless, because taking the address of a variable always yields a non-nil pointer."
  },
  "SA4023": {
    "title": "Impossible comparison of interface value with untyped nil",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Under the covers, interfaces are implemented as two elements, a\ntype T and a value V. V is a concrete value such as an int,\nstruct or pointer, never an interface itself, and has type T. For\ninstance, if we store the int value 3 in an interface, the\nresulting interface value has, schematically, (T=int, V=3). The\nvalue V is also known as the interface's dynamic value, since a\ngiven interface variable might hold different values V (and\ncorresponding types T) during the execution of the program.\n\nAn interface value is nil only if the V and T are both\nunset, (T=nil, V is not set), In particular, a nil interface will\nalways hold a nil type. If we store a nil pointer of type *int\ninside an interface value, the inner type will be *int regardless\nof the value of the pointer: (T=*int, V=nil). Such an interface\nvalue will therefore be non-nil even when the pointer value V\ninside is nil.\n\nThis situation can be confusing, and arises when a nil value is\nstored inside an interface value such as an error return:\n\n```go\nfunc returnsError() error {\n    var p *MyError = nil\n    if bad() {\n        p = ErrBad\n    }\n    return p // Will always return a non-nil error.\n}\n```\n\nIf all goes well, the function returns a nil p, so the return\nvalue is an error interface value holding (T=*MyError, V=nil).\nThis means that if the caller compares the returned error to nil,\nit will always look as if there was an error even if nothing bad\nhappened. To return a proper nil error to the caller, the\nfunction must return an explicit nil:\n\n```go\nfunc returnsError() error {\n    if bad() {\n        return ErrBad\n    }\n    return nil\n}\n```\n\nIt's a good idea for functions that return errors always to use\nthe error type in their signature (as we did above) rather than a\nconcrete type such as *MyError, to help guarantee the error is\ncreated correctly. As an example, os.Open returns an error even\nthough, if not nil, it's always of concrete type *os.PathError.\n\nSimilar situations to those described here can arise whenever\ninterfaces are used. Just keep in mind that if any concrete value\nhas been stored in the interface, the interface will not be nil.\nFor more information, see The Laws of\nReflection (https://golang.org/doc/articles/laws_of_reflection.html).\n\nThis text has been copied from\nhttps://golang.org/doc/faq#nil_error, licensed under the Creative\nCommons Attribution 3.0 License."
  },
  "SA5009": {
    "title": "Invalid Printf call",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA5008": {
    "title": "Invalid struct tag",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA5001": {
    "title": "Deferring Close before checking for a possible error",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA5000": {
    "title": "Assignment to nil map",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA5003": {
    "title": "Defers in infinite loops will never execute",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Defers are scoped to the surrounding function, not the surrounding\nblock. In a function that never returns, i.e. one containing an\ninfinite loop, defers will never execute."
  },
  "SA5002": {
    "title": "The empty for loop ('for {}') spins and can block the scheduler",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA5005": {
    "title": "The finalizer references the finalized object, preventing garbage collection",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A finalizer is a function associated with an object that runs when the\ngarbage collector is ready to collect said object, that is when the\nobject is no longer referenced by anything.\n\nIf the finalizer references the object, however, it will always remain\nas the final reference to that object, preventing the garbage\ncollector from collecting the object. The finalizer will never run,\nand the object will never be collected, leading to a memory leak. That\nis why the finalizer should instead use its first argument to operate\non the object. That way, the number of references can temporarily go\nto zero before the object is being passed to the finalizer."
  },
  "SA5004": {
    "title": "'for { select { ...' with an empty default branch spins",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA5007": {
    "title": "Infinite recursive call",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A function that calls itself recursively needs to have an exit\ncondition. Otherwise it will recurse forever, until the system runs\nout of memory.\n\nThis issue can be caused by simple bugs such as forgetting to add an\nexit condition. It can also happen \"on purpose\". Some languages have\ntail call optimization which makes certain infinite recursive calls\nsafe to use. Go, however, does not implement TCO, and as such a loop\nshould be used instead."
  },
  "S1007": {
    "title": "Simplify regular expression by using raw string literal",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Raw string literals use backticks instead of quotation marks and do not support\nany escape sequences. This means that the backslash can be used\nfreely, without the need of escaping.\n\nSince regular expressions have their own escape sequences, raw strings\ncan improve their readability."
  },
  "ST1000": {
    "title": "Incorrect or missing package comment",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Packages must have a package comment that is formatted according to\nthe guidelines laid out in\nhttps://github.com/golang/go/wiki/CodeReviewComments#package-comments."
  },
  "ST1001": {
    "title": "Dot imports are discouraged",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Dot imports that aren't in external test packages are discouraged.\n\nThe dot_import_whitelist option can be used to whitelist certain\nimports.\n\nQuoting Go Code Review Comments:\n\n> The import . form can be useful in tests that, due to circular\n> dependencies, cannot be made part of the package being tested:\n> \n>     package foo_test\n> \n>     import (\n>         \"bar/testutil\" // also imports \"foo\"\n>         . \"foo\"\n>     )\n> \n> In this case, the test file cannot be in package foo because it\n> uses bar/testutil, which imports foo. So we use the import .\n> form to let the file pretend to be part of package foo even though\n> it is not. Except for this one case, do not use import . in your\n> programs. It makes the programs much harder to read because it is\n> unclear whether a name like Quux is a top-level identifier in the\n> current package or in an imported package."
  },
  "ST1013": {
    "title": "Should use constants for HTTP error codes, not magic numbers",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "HTTP has a tremendous number of status codes. While some of those are\nwell known (200, 400, 404, 500), most of them are not. The net/http\npackage provides constants for all status codes that are part of the\nvarious specifications. It is recommended to use these constants\ninstead of hard-coding magic numbers, to vastly improve the\nreadability of your code."
  },
  "ST1012": {
    "title": "Poorly chosen name for error variable",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Error variables that are part of an API should be called errFoo or\nErrFoo."
  },
  "ST1011": {
    "title": "Poorly chosen name for variable of type time.Duration",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "time.Duration values represent an amount of time, which is represented\nas a count of nanoseconds. An expression like 5 * time.Microsecond\nyields the value 5000. It is therefore not appropriate to suffix a\nvariable of type time.Duration with any time unit, such as Msec or\nMilli."
  },
  "ST1017": {
    "title": "Don't use Yoda conditions",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Yoda conditions are conditions of the kind 'if 42 == x', where the\nliteral is on the left side of the comparison. These are a common\nidiom in languages in which assignment is an expression, to avoid bugs\nof the kind 'if (x = 42)'. In Go, which doesn't allow for this kind of\nbug, we prefer the more idiomatic 'if x == 42'."
  },
  "QF1009": {
    "title": "Use time.Time.Equal instead of == operator",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "ST1015": {
    "title": "A switch's default case should be the first or last case",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "S1005": {
    "title": "Drop unnecessary use of the blank identifier",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "In many cases, assigning to the blank identifier is unnecessary."
  },
  "S1004": {
    "title": "Replace call to bytes.Compare with bytes.Equal",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "ST1019": {
    "title": "Importing the same package multiple times",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Go allows importing the same package multiple times, as long as\ndifferent import aliases are being used. That is, the following\nbit of code is valid:\n\n```go\nimport (\n    \"fmt\"\n    fumpt \"fmt\"\n    format \"fmt\"\n    _ \"fmt\"\n)\n```\n\nHowever, this is very rarely done on purpose. Usually, it is a\nsign of code that got refactored, accidentally adding duplicate\nimport statements. It is also a rarely known feature, which may\ncontribute to confusion.\n\nDo note that sometimes, this feature may be used\nintentionally (see for example\nhttps://github.com/golang/go/commit/3409ce39bfd7584523b7a8c150a310cea92d879d)\n\u2013 if you want to allow this pattern in your code base, you're\nadvised to disable this check."
  },
  "SA4030": {
    "title": "Ineffective attempt at generating random number",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Functions in the math/rand package that accept upper limits, such\nas Intn, generate random numbers in the half-open interval [0,n). In\nother words, the generated numbers will be >= 0 and < n \u2013 they\ndon't include n. rand.Intn(1) therefore doesn't generate 0\nor 1, it always generates 0."
  },
  "S1001": {
    "title": "Replace for loop with call to copy",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use copy() for copying elements from one slice to another. For\narrays of identical size, you can use simple assignment."
  },
  "QF1001": {
    "title": "Apply De Morgan's law",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "QF1002": {
    "title": "Convert untagged switch to tagged switch",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "An untagged switch that compares a single variable against a series of\nvalues can be replaced with a tagged switch."
  },
  "QF1003": {
    "title": "Convert if/else-if chain to tagged switch",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A series of if/else-if checks comparing the same variable against\nvalues can be replaced with a tagged switch."
  },
  "SA1029": {
    "title": "Inappropriate key in call to context.WithValue",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The provided key must be comparable and should not be\nof type string or any other built-in type to avoid collisions between\npackages using context. Users of WithValue should define their own\ntypes for keys.\n\nTo avoid allocating when assigning to an interface{},\ncontext keys often have concrete type struct{}. Alternatively,\nexported context key variables' static type should be a pointer or\ninterface."
  },
  "SA1028": {
    "title": "sort.Slice can only be used on slices",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The first argument of sort.Slice must be a slice."
  },
  "SA1027": {
    "title": "Atomic access to 64-bit variable must be 64-bit aligned",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "On ARM, x86-32, and 32-bit MIPS, it is the caller's responsibility to\narrange for 64-bit alignment of 64-bit words accessed atomically. The\nfirst word in a variable or in an allocated struct, array, or slice\ncan be relied upon to be 64-bit aligned.\n\nYou can use the structlayout tool to inspect the alignment of fields\nin a struct."
  },
  "SA1026": {
    "title": "Cannot marshal channels or functions",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA1025": {
    "title": "It is not possible to use (*time.Timer).Reset's return value correctly",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
  },
  "SA1024": {
    "title": "A string cutset contains duplicate characters",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The strings.TrimLeft and strings.TrimRight functions take cutsets, not\nprefixes. A cutset is treated as a set of characters to remove from a\nstring. For example,\n\n```go\nstrings.TrimLeft(\"42133word\", \"1234\")\n```\n\nwill result in the string \"word\" \u2013 any characters that are 1, 2, 3 or\n4 are cut from the left of the string.\n\nIn order to remove one string from another, use strings.TrimPrefix instead."
  },
  "SA1023": {
    "title": "Modifying the buffer in an io.Writer implementation",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Write must not modify the slice data, even temporarily."
  },
  "SA4026": {
    "title": "Go constants cannot express negative zero",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "In IEEE 754 floating point math, zero has a sign and can be positive\nor negative. This can be useful in certain numerical code.\n\nGo constants, however, cannot express negative zero. This means that\nthe literals -0.0 and 0.0 have the same ideal value (zero) and\nwill both represent positive zero at runtime.\n\nTo explicitly and reliably create a negative zero, you can use the\nmath.Copysign function: math.Copysign(0, -1)."
  },
  "SA1021": {
    "title": "Using bytes.Equal to compare two net.IP",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "A net.IP stores an IPv4 or IPv6 address as a slice of bytes. The\nlength of the slice for an IPv4 address, however, can be either 4 or\n16 bytes long, using different ways of representing IPv4 addresses. In\norder to correctly compare two net.IPs, the net.IP.Equal method should\nbe used, as it takes both representations into account."
  },
  "SA1020": {
    "title": "Using an invalid host:port pair with a net.Listen-related function",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": ""
    }
}

