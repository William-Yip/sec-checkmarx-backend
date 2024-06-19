package test

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"net/http"
	"os"
)

func main() {
	// Example of using md5, which is insecure
	data := []byte("example data")
	hash := md5.Sum(data)
	fmt.Printf("MD5: %x\n", hash)

	// Example of SQL injection vulnerability
	http.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("username")
		db, err := sql.Open("mysql", "user:password@/dbname")
		if err != nil {
			fmt.Fprintf(w, "Error: %s", err)
			return
		}
		defer db.Close()

		query := fmt.Sprintf("SELECT * FROM users WHERE username='%s'", username)
		rows, err := db.Query(query, username)
		if err != nil {
			fmt.Fprintf(w, "Error: %s", err)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var id int
			var name string
			if err := rows.Scan(&id, &name); err != nil {
				fmt.Fprintf(w, "Error: %s", err)
				return
			}
			fmt.Fprintf(w, "User: %d, %s\n", id, name)
		}
	})

	// Example of exposing sensitive information
	secret := os.Getenv("SECRET_KEY")
	fmt.Printf("Secret key: %s\n", secret)

	http.ListenAndServe(":8080", nil)
}
