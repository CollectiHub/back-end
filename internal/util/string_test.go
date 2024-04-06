package util

import "testing"

func TestDecapitalize(t *testing.T) {
	t.Run("should return empty string", func(t *testing.T) {
		got := Decapitalize("")
		expected := ""

		if got != expected {
			t.Errorf("Decapitalize(\"\") = \"%s\"; want \"\"", got)
		}
	})

	t.Run("should return decapitalized string", func(t *testing.T) {
		got := Decapitalize("Hello")
		expected := "hello"

		if got != expected {
			t.Errorf("Decapitalize(\"Hello\") = \"%s\"; want \"hello\"", got)
		}
	})
}

func TestGetJsonFieldName(t *testing.T) {
	type testStruct struct {
		Field1 string `json:"field1"`
		Field2 string `json:"field2,omitempty"`
		Field3 string `json:"-"`
	}

	t.Run("should return empty string", func(t *testing.T) {
		got := GetJsonFieldName(testStruct{}, "Field3")
		expected := ""

		if got != expected {
			t.Errorf("GetJsonFieldName(testStruct{}, \"Field3\") = \"%s\"; want \"\"", got)
		}
	})

	t.Run("should return json field name", func(t *testing.T) {
		got := GetJsonFieldName(testStruct{}, "Field1")
		expected := "field1"

		if got != expected {
			t.Errorf("GetJsonFieldName(testStruct{}, \"Field1\") = \"%s\"; want \"field1\"", got)
		}
	})

	t.Run("should return json field name without leftovers", func(t *testing.T) {
		got := GetJsonFieldName(testStruct{}, "Field2")
		expected := "field2"

		if got != expected {
			t.Errorf("GetJsonFieldName(testStruct{}, \"Field2\") = \"%s\"; want \"field2\"", got)
		}
	})
}

func TestGenerateRandomString(t *testing.T) {
	t.Run("should return empty string", func(t *testing.T) {
		got := GenerateRandomString(0)
		expected := ""

		if got != expected {
			t.Errorf("GenerateRandomString(0) = \"%s\"; want \"\"", got)
		}
	})

	t.Run("should return random string", func(t *testing.T) {
		got := len(GenerateRandomString(5))
		expected := 5

		if got != expected {
			t.Errorf("len GenerateRandomString(5) = %d; want 5", got)
		}
	})
}

func TestGenerateRandomNumberString(t *testing.T) {
	t.Run("should return empty string", func(t *testing.T) {
		got := GenerateRandomNumberString(0)
		expected := ""

		if got != expected {
			t.Errorf("GenerateRandomNumberString(0) = \"%s\"; want \"\"", got)
		}
	})

	t.Run("should return random number string", func(t *testing.T) {
		got := len(GenerateRandomNumberString(5))
		expected := 5

		if got != expected {
			t.Errorf("len GenerateRandomNumberString(5) = %d; want 5", got)
		}
	})

	t.Run("should return only numbers", func(t *testing.T) {
		got := GenerateRandomNumberString(5)

		for _, ch := range got {
			if ch < 48 || ch > 57 {
				t.Errorf("GenerateRandomNumberString() char %c, expected number", ch)
			}
		}
	})
}
