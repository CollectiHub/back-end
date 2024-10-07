package types

import (
	"database/sql/driver"
	"errors"
)

type VerificationType string

const (
	EmailVerificationType VerificationType = "email-verification"
	PasswordResetType     VerificationType = "password-reset"
)

func (vt *VerificationType) Scan(value interface{}) error {
	if v, ok := value.(string); ok {
		*vt = VerificationType(v)
		return nil
	}

	if v, ok := value.([]byte); ok {
		*vt = VerificationType(v)
		return nil
	}

	return errors.New("value scanning error")
}

func (vt VerificationType) Value() (driver.Value, error) {
	return string(vt), nil
}

type UserRole string

const (
	REGULAR UserRole = "regular"
	ADMIN   UserRole = "admin"
)

func (ur *UserRole) Scan(value interface{}) error {
	if v, ok := value.(string); ok {
		*ur = UserRole(v)
		return nil
	}

	if v, ok := value.([]byte); ok {
		*ur = UserRole(v)
		return nil
	}

	return errors.New("value scanning error")
}

func (ur UserRole) Value() (driver.Value, error) {
	return string(ur), nil
}

type CollectionCardStatus string

const (
	CardCollected    CollectionCardStatus = "collected"
	CardNotCollected CollectionCardStatus = "not-collected"
)

func (ccs *CollectionCardStatus) Scan(value interface{}) error {
	if v, ok := value.(string); ok {
		*ccs = CollectionCardStatus(v)
		return nil
	}

	if v, ok := value.([]byte); ok {
		*ccs = CollectionCardStatus(v)
		return nil
	}

	return errors.New("value scanning error")
}

func (ccs CollectionCardStatus) Value() (driver.Value, error) {
	return string(ccs), nil
}

type HealthCheckStatus string

const (
	HEALTH_CHECK_STATUS_OK HealthCheckStatus = "ok"
)
