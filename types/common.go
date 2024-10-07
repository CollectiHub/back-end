package types

import (
	"database/sql"
	"encoding/json"
)

type NullableString struct {
	sql.NullString
}

func (s *NullableString) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		s.Valid = false
		return nil
	}

	var tmp string
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	s.String = tmp
	s.Valid = true
	return nil
}

func (s NullableString) MarshalJSON() ([]byte, error) {
	if s.Valid {
		return json.Marshal(s.String)
	} else {
		return json.Marshal(nil)
	}
}
