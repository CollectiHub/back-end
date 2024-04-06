package util

import "regexp"

func GetFieldNameFromPqErrorDetails(detail string) string {
	re := regexp.MustCompile(`\((?P<field>[^=]+)\)=\([^)]+\)`)
	matches := re.FindStringSubmatch(detail)
	fieldIndex := re.SubexpIndex("field")

	if len(matches) < fieldIndex {
		return ""
	}

	return matches[fieldIndex]
}
