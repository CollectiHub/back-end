package util

import "testing"

func TestHashedPassword(t *testing.T) {
	t.Run("should return hashed password", func(t *testing.T) {
		got, err := HashPassword("password")
		if err != nil {
			t.Errorf("HashPassword() error = %v; want nil", err)
		}

		if got == "" {
			t.Errorf("HashPassword() = \"%s\"; want hashed password", got)
		}
	})
}

func TestVerifyPassword(t *testing.T) {
	t.Run("should return nil", func(t *testing.T) {
		hashedPassword, _ := HashPassword("password")
		err := VerifyPassword(hashedPassword, "password")

		if err != nil {
			t.Errorf("VerifyPassword() error = %v; want nil", err)
		}
	})

	t.Run("should return error", func(t *testing.T) {
		hashedPassword, _ := HashPassword("password")
		err := VerifyPassword(hashedPassword, "wrong-password")

		if err == nil {
			t.Errorf("VerifyPassword() error = nil; want error")
		}
	})
}
