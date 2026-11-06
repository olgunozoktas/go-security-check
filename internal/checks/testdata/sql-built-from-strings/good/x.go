package x

import "database/sql"

func get(db *sql.DB, id string) {
	db.Query("SELECT * FROM users WHERE id = ?", id)
	db.Exec("UPDATE t SET a = 1 " + "WHERE b = 2")
}
