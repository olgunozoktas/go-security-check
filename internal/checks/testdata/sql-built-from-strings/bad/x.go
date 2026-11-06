package x

import (
	"database/sql"
	"fmt"
)

func get(db *sql.DB, id string) {
	db.Query("SELECT * FROM users WHERE id = " + id)
	db.ExecContext(nil, fmt.Sprintf("DELETE FROM t WHERE id=%s", id))
}
