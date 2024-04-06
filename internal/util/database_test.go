package util

import "testing"

func TestGetFieldNameFromPqErrorDetails(t *testing.T) {
	t.Run("should return field name", func(t *testing.T) {
		detail := "Key (slug)=(test1) already exists."
		got := GetFieldNameFromPqErrorDetails(detail)

		if got != "slug" {
			t.Errorf("GetFieldNameFromPqErrorDetails() = %s; want slug", got)
		}
	})

	t.Run("should return empty string", func(t *testing.T) {
		detail := "Key ()=(value) already exists."

		got := GetFieldNameFromPqErrorDetails(detail)

		if got != "" {
			t.Errorf("GetFieldNameFromPqErrorDetails() = %s; want empty string", got)
		}
	})
}
