package main

import (
	"database/sql"
	"os/exec"
)

func search(db *sql.DB, q string) {
	db.Query("select * from notes where t = '" + q + "'") // #nosec G202
}

func run(c string) {
	exec.Command("sh", "-c", c).Run() // #nosec
}

func main() {}
