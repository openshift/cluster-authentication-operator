package v1helpers

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// shellEscapePattern determines if a string should be enclosed in single quotes
// so that it can safely be passed to shell command line.
var shellEscapePattern *regexp.Regexp

func init() {
	// some characters have special meaning to the shell and may need to be escaped
	// the following regexp defines safe characters that don't require escaping
	shellEscapePattern = regexp.MustCompile(`[^\w@%+=:,./-]`)
}

// ToShellEscapedArguments process the given arguments and determines if they should be escaped so that they can be safely passed as shell command line arguments.
// unstructuredArgs holds unprocessed arguments usually retrieved from an operator's configuration file under a specific key.
//
// Use ToFlagSlice function to get a slice of string flags.
func ToShellEscapedArguments(unstructuredArgs map[string]interface{}) (map[string][]string, error) {
	ret := map[string][]string{}
	for argName, argRawValue := range unstructuredArgs {
		var argsSlice []string
		var found bool
		var err error

		argsSlice, found, err = unstructured.NestedStringSlice(unstructuredArgs, argName)
		if !found || err != nil {
			str, found, err := unstructured.NestedString(unstructuredArgs, argName)
			if !found || err != nil {
				return nil, fmt.Errorf("unable to process an argument, incorrect value %v under %v key, expected []string or string", argRawValue, argName)
			}
			argsSlice = append(argsSlice, str)
		}

		escapedArgsSlice := make([]string, len(argsSlice))
		for index, str := range argsSlice {
			escapedArgsSlice[index] = maybeQuote(str)
		}

		ret[argName] = escapedArgsSlice
	}

	return ret, nil
}

// ToFlagSlice transforms the provided arguments to a slice of string flags.
// A flag name is taken directly from the key and the value is simply attached.
// A flag is repeated iff it has more than one value.
func ToFlagSlice(args map[string][]string) []string {
	var keys []string
	for key := range args {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var flags []string
	for _, key := range keys {
		for _, token := range args[key] {
			flags = append(flags, fmt.Sprintf("--%s=%v", key, token))
		}
	}
	return flags
}

// maybeQuote returns a shell-escaped version of the string s. The returned value
// is a string that can safely be used as one token in a shell command line.
//
// note: this method was copied from https://github.com/alessio/shellescape/blob/0d13ae33b78a20a5d91c54ca7e216e1b75aaedef/shellescape.go#L30
func maybeQuote(s string) string {
	if len(s) == 0 {
		return "''"
	}
	if shellEscapePattern.MatchString(s) {
		return "'" + strings.Replace(s, "'", "'\"'\"'", -1) + "'"
	}

	return s
}
