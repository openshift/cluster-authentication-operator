package arguments

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var (
	shellEscapePattern = regexp.MustCompile(`[^\w@%+=:,./-]`)
)

// ServerArguments is a simple abstraction to flags / options that can be used
// for any binary. As a flag can be used several times to create a slice of
// arguments, the value of the map must be a slice of strings.
// Modeled after net/url/Values.
type ServerArguments map[string][]string

// Parse parses the ServerArguments from an unstructured json blob into
// ServerArguments type.
func Parse(raw map[string]interface{}) (ServerArguments, error) {
	args := make(ServerArguments)

	for argName, argValue := range raw {
		var argsSlice []string

		argsSlice, found, err := unstructured.NestedStringSlice(raw, argName)
		if !found || err != nil {
			str, found, err := unstructured.NestedString(raw, argName)
			if !found || err != nil {
				return nil, fmt.Errorf(
					"unable to create server arguments, incorrect value %v under %s key, expected []string or string",
					argValue, argName,
				)
			}

			argsSlice = append(argsSlice, str)
		}

		args[argName] = argsSlice
	}

	return args, nil
}

// shellEscape returns a shell-escaped version of the string s. The returned value
// is a string that can safely be used as one token in a shell command line.
//
// note: this method was copied from https://github.com/alessio/shellescape/blob/0d13ae33b78a20a5d91c54ca7e216e1b75aaedef/shellescape.go#L30
func shellEscape(s string) string {
	if len(s) == 0 {
		return "''"
	}
	if shellEscapePattern.MatchString(s) {
		return "'" + strings.Replace(s, "'", "'\"'\"'", -1) + "'"
	}

	return s
}

// Encode encodes the ServerArguments into a single string that can be used in a
// template for string replacement.
// By default every newline starts without indents.
func Encode(args ServerArguments) string {
	return EncodeWithDelimiter(args, " \\\n")
}

// EncodeWithDelimiter encodes the ServerArguments into a single string that
// can be used in a template for string replacement.
// The delimiter that is used in between of the server arguments must be set.
func EncodeWithDelimiter(args ServerArguments, delimiter string) string {
	if len(args) == 0 {
		return ""
	}

	keys := make([]string, 0, len(args))
	for key := range args {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var buf strings.Builder
	for _, key := range keys {
		values := args[key]
		for _, value := range values {
			if buf.Len() > 0 {
				buf.WriteString(delimiter)
			}
			buf.WriteString("--")
			buf.WriteString(shellEscape(key))
			buf.WriteByte('=')
			buf.WriteString(shellEscape(value))
		}
	}

	return buf.String()
}
