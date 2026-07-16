package vulnsamples

import (
	"database/sql"
	"fmt"
	"net/http"
)

func getUser(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("sqlite3", "./app.db")
	id := r.FormValue("id")
	
	// Unsafe: fmt.Sprintf in query
	rows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id))
	_ = rows
	
	// Unsafe: concatenation
	db.Exec("DELETE FROM users WHERE id = '" + id + "'")
}
