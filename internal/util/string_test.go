package util

import "testing"

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
