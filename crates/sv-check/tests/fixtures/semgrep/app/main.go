// A small Go program with one of each fault in it, for semgrep to find. Not for running.
package main

import (
	"crypto/des"
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
)

func find(db *sql.DB, r *http.Request) {
	db.Query(fmt.Sprintf("select * from notes where name = '%s'", r.URL.Query().Get("name")))
}

func weak(key []byte) {
	des.NewCipher(key)
	md5.Sum(key)
}

func token() int {
	return rand.Int()
}

func client() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

func main() {}
