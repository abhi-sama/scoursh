package main

import "database/sql"

// getUser passes id through a parameterised placeholder rather than
// building the query text itself - safe equivalent for
// SAST-GO-SQL_CONCAT-01.
func getUser(db *sql.DB, id string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE id = ?", id)
}
