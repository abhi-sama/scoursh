package main

import (
	"database/sql"
	"fmt"
)

// getUser builds the query text with fmt.Sprintf instead of a
// parameterised placeholder - true positive for SAST-GO-SQL_CONCAT-01.
func getUser(db *sql.DB, id string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
	return db.Query(query)
}
