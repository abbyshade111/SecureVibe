package main

import (
	"encoding/xml"
	"net/http"
)

// Go parses XML from its standard library too. go.mod declares nothing at all.
func handler(w http.ResponseWriter, r *http.Request) {
	var v struct{ Name string }
	_ = xml.NewDecoder(r.Body).Decode(&v)
}
