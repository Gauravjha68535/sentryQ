package vulnsamples

import (
	"database/sql"
	"net/http"
)

func getUser(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("sqlite3", "./app.db")
	id := r.FormValue("id")
	
	// Safe: parameterized query
	rows, _ := db.Query("SELECT * FROM users WHERE id = $1", id)
	_ = rows
	
	// Safe: prepared statement
	stmt, _ := db.Prepare("SELECT * FROM users WHERE id = ?")
	stmt.Query(id)
}
